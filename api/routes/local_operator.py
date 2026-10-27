"""Tenant- and actor-scoped durable operator sessions and bounded task polling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
)
from pydantic import BaseModel, ConfigDict, Field

from api.auth import (
    SERVICE_TOKEN_STATE_ATTR,
    Role,
    TenantPrincipal,
    TokenUser,
    get_current_user,
    get_settings,
    require_tenant,
)
from api.settings import Settings

router = APIRouter(prefix="/operator", tags=["operator"])
Identifier = Annotated[
    str, Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
]
PathId = Annotated[
    str, Path(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
]


tenant_principal = require_tenant(Role.viewer)


def operator_principal(
    request: Request,
    principal: Annotated[TenantPrincipal, Depends(tenant_principal)],
    settings: Annotated[Settings, Depends(get_settings)],
    tenant_id: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
) -> TenantPrincipal:
    if not settings.operator_enabled:
        raise HTTPException(status_code=404, detail="Operator is disabled")
    if getattr(request.state, SERVICE_TOKEN_STATE_ATTR, None) is not None:
        raise HTTPException(
            status_code=403, detail="Operator requires a console session"
        )
    if tenant_id is None or not tenant_id.strip():
        raise HTTPException(
            status_code=422, detail="Explicit nonblank tenant_id is required"
        )
    return principal


Principal = Annotated[TenantPrincipal, Depends(operator_principal)]
OperatorSettings = Annotated[Settings, Depends(get_settings)]


@dataclass(frozen=True)
class OperatorContext:
    principal: TenantPrincipal
    auth_session_id: str


def operator_reader(
    principal: Principal,
    user: Annotated[TokenUser, Depends(get_current_user)],
) -> OperatorContext:
    if not user.session_id or not user.session_id.strip():
        raise HTTPException(
            status_code=403,
            detail="Operator history requires a current console session",
        )
    return OperatorContext(principal=principal, auth_session_id=user.session_id)


Reader = Annotated[OperatorContext, Depends(operator_reader)]


def operator_writer(context: Reader) -> OperatorContext:
    if not context.principal.at_least(Role.operator):
        raise HTTPException(status_code=403, detail="Operator role required")
    return context


Writer = Annotated[OperatorContext, Depends(operator_writer)]


def operator_admin(context: Reader) -> OperatorContext:
    if not context.principal.at_least(Role.admin):
        raise HTTPException(status_code=403, detail="Admin role required")
    return context


Admin = Annotated[OperatorContext, Depends(operator_admin)]


class OperatorStatus(BaseModel):
    enabled: bool
    provider: str
    model: str
    external_inference: bool
    runtime_status: Literal["not_checked", "ready", "unavailable"] = "not_checked"
    # Deprecated alias of ``manifest_attested``; removed after one release.
    runtime_verified: bool = False
    manifest_attested: bool = False
    model_integrity: Literal["not_checked", "manifest_attested"] = "not_checked"
    model_sha256: str | None = None
    runtime_revision: str | None = None
    runtime_image: str | None = None
    context_tokens: int | None = None
    parallel: int | None = None
    verified_at: str | None = None
    profile: str | None = None
    analysis_available: bool = False
    analysis_task_supported: bool = True
    task_submission_enabled: bool = False
    durable_sessions_available: bool = True
    quality_status: Literal["quality_unverified"] = "quality_unverified"


class CreateSession(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SubmitTask(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    tool: Literal["summarize_run", "analyze_run"]
    run_id: Identifier
    language: Literal["ru", "en"] = "ru"


def _call(
    settings: Settings,
    principal: TenantPrincipal | OperatorContext,
    action: str,
    **kwargs,
):
    from api.services.local_operator import store

    if isinstance(principal, OperatorContext):
        kwargs["auth_session_id"] = principal.auth_session_id
        principal = principal.principal
    try:
        result = getattr(store, action)(
            settings,
            tenant_id=principal.tenant_id,
            username=principal.username,
            **kwargs,
        )
        if result is None and action in {"get_session", "get_task", "cancel_task"}:
            raise HTTPException(status_code=404, detail="Operator resource not found")
        if result is False and action == "delete_session":
            raise HTTPException(status_code=404, detail="Operator resource not found")
        return result
    except store.OperatorStoreError as exc:
        code = {
            "not_found": 404,
            "access_revoked": 403,
            "idempotency_conflict": 409,
            "queue_full": 429,
            "active_tasks": 409,
            "legal_hold": 409,
            "invalid_input": 422,
        }.get(exc.code, 409)
        raise HTTPException(status_code=code, detail=exc.code) from None


@router.get("/status", response_model=OperatorStatus)
def operator_status(principal: Principal, settings: OperatorSettings) -> OperatorStatus:
    if not settings.operator_enabled:
        raise HTTPException(status_code=404, detail="Operator is disabled")
    from api.services.local_operator.config import OperatorConfig

    try:
        config = OperatorConfig.from_settings(settings)
    except ValueError:
        raise HTTPException(
            status_code=503, detail="Operator configuration is invalid"
        ) from None
    from api.services.local_operator.runtime import probe_cached
    runtime = probe_cached(settings)
    return OperatorStatus(
        enabled=True,
        provider=config.provider,
        model=config.model,
        external_inference=config.provider != "local",
        task_submission_enabled=getattr(settings, "operator_worker_enabled", False),
        analysis_available=runtime["runtime_status"] == "ready" and settings.operator_worker_enabled,
        **runtime,
    )


@router.post("/sessions", status_code=201)
def create_session(body: CreateSession, principal: Writer, settings: OperatorSettings):
    return _call(settings, principal, "create_session")


@router.get("/sessions")
def list_sessions(
    principal: Reader,
    settings: OperatorSettings,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=10000)] = 0,
):
    return _call(settings, principal, "list_sessions", limit=limit, offset=offset)


@router.get("/sessions/{session_id}")
def get_session(session_id: PathId, principal: Reader, settings: OperatorSettings):
    return _call(settings, principal, "get_session", session_id=session_id)


@router.delete("/sessions/{session_id}", status_code=204)
def delete_session(session_id: PathId, principal: Writer, settings: OperatorSettings):
    _call(settings, principal, "delete_session", session_id=session_id)
    return Response(status_code=204)


@router.post("/sessions/{session_id}/tasks", status_code=202)
def submit_task(
    session_id: PathId,
    body: SubmitTask,
    principal: Writer,
    settings: OperatorSettings,
    idempotency_key: Annotated[
        str,
        Header(
            alias="Idempotency-Key",
            min_length=1,
            max_length=128,
            pattern=r"^[\x21-\x7e]+$",
        ),
    ],
):
    if not getattr(settings, "operator_worker_enabled", False):
        raise HTTPException(status_code=409, detail="Operator worker is disabled")
    from api.services import runs

    if (
        runs.get_run_dir(settings, body.run_id, tenant_id=principal.principal.tenant_id)
        is None
    ):
        raise HTTPException(status_code=404, detail="Run not found")
    return _call(
        settings,
        principal,
        "submit_task",
        kind=body.tool,
        session_id=session_id,
        run_id=body.run_id,
        language=body.language,
        idempotency_key=idempotency_key,
    )


@router.get("/tasks/{task_id}")
def get_task(task_id: PathId, principal: Reader, settings: OperatorSettings):
    return _call(settings, principal, "get_task", task_id=task_id)


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: PathId, principal: Writer, settings: OperatorSettings):
    return _call(settings, principal, "cancel_task", task_id=task_id)
