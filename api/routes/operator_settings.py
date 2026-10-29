"""Installation-wide AI-operator endpoint settings, connection test and model discovery.

Platform admin only (``platform`` ``config.write``): the endpoint is shared by
every tenant, and a test points the API at an admin-chosen URL. Enablement,
worker and the hosted-egress permission stay deployment-owned — see
:mod:`api.services.local_operator.overrides`.
"""

from __future__ import annotations

import dataclasses
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from api.auth import TokenUser, get_settings, require_platform_permission
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.settings import Settings

class CredentialSafeRoute(APIRoute):
    """Validation errors must not echo submitted keys (including malformed JSON)."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe_handler(request):
            try:
                return await handler(request)
            except RequestValidationError:
                raise HTTPException(status_code=422, detail="invalid_operator_settings") from None

        return safe_handler


router = APIRouter(prefix="/operator/settings", tags=["operator"], route_class=CredentialSafeRoute)

PlatformAdmin = Annotated[TokenUser, Depends(require_platform_permission(permission_catalog.CONFIG_WRITE))]
OperatorSettings = Annotated[Settings, Depends(get_settings)]


class EndpointSettings(BaseModel):
    """Fields left out (or ``null``) inherit the deployment's value.

    ``api_key``: omitted keeps the stored key while the endpoint is unchanged,
    ``""`` clears it, a value replaces it. It is never returned.
    """

    model_config = ConfigDict(extra="forbid", strict=True)
    provider: Literal["local", "openrouter", "omnirouter", "openai_compatible"] | None = None
    base_url: Annotated[str, Field(max_length=2048)] | None = None
    model: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    api_key: Annotated[str, Field(max_length=4096)] | None = Field(default=None, repr=False)
    allow_external: bool | None = None
    timeout_seconds: Annotated[float, Field(gt=0, le=120)] | None = None
    max_output_tokens: Annotated[int, Field(gt=0, le=8192)] | None = None


class ConnectionTest(EndpointSettings):
    #: Also send one tiny chat completion (costs tokens on a hosted provider).
    completion: bool = False


def _fail(exc: ValueError):
    code = str(exc)
    if code == "operator_settings_changed_concurrently":
        raise HTTPException(status_code=409, detail=code) from None
    status = 503 if code in {"operator_settings_unavailable", "operator_settings_unreadable",
                             "operator_settings_storage_unavailable"} else 422
    raise HTTPException(status_code=status, detail=code) from None


def _changes(body: EndpointSettings) -> dict:
    return body.model_dump(exclude_unset=True, exclude={"completion"})


@router.get("")
def get_operator_settings(_: PlatformAdmin, settings: OperatorSettings):
    from api.services.local_operator import overrides

    try:
        return overrides.snapshot(settings)
    except ValueError as exc:
        _fail(exc)


@router.put("")
def put_operator_settings(body: EndpointSettings, user: PlatformAdmin, settings: OperatorSettings, audit: AuditDep):
    from api.services.local_operator import overrides

    try:
        overrides.update(settings, _changes(body), username=user.username, audit=audit)
        return overrides.snapshot(settings)
    except ValueError as exc:
        _fail(exc)


@router.delete("", status_code=204)
def reset_operator_settings(user: PlatformAdmin, settings: OperatorSettings, audit: AuditDep):
    from api.services.local_operator import overrides

    try:
        overrides.reset(settings, username=user.username, audit=audit)
    except ValueError as exc:
        _fail(exc)
    return Response(status_code=204)


def _candidate_config(settings: Settings, changes: dict):
    """The unsaved candidate (or the effective config with no changes), validated as enabled."""
    from api.services.local_operator import overrides
    from api.services.local_operator.config import OperatorConfig

    previous = overrides.load(settings)[0]
    if changes:
        stored = overrides.build(settings, previous, changes)
    else:
        stored = previous
        overrides.validate(settings, stored)
    candidate = overrides.apply(settings, stored)
    return OperatorConfig.from_settings(dataclasses.replace(candidate, operator_enabled=True))


@router.post("/test")
async def test_operator_connection(body: ConnectionTest, _: PlatformAdmin, settings: OperatorSettings, audit: AuditDep):
    """Reachability, credential, model presence and (optionally) one completion.

    Nothing is saved. Failures are stable codes in the 200 body; only an
    invalid candidate is a 422, because nothing was attempted.
    """
    from fastapi.concurrency import run_in_threadpool

    from api.services.local_operator.connection import check

    try:
        config = await run_in_threadpool(_candidate_config, settings, _changes(body))
    except ValueError as exc:
        _fail(exc)
    from api.services.local_operator import overrides

    await run_in_threadpool(
        overrides.audit_test, audit, config=config, completion=body.completion
    )
    return await check(config, completion=body.completion)


@router.get("/models")
async def discover_operator_models(_: PlatformAdmin, settings: OperatorSettings):
    """Models the effective endpoint lists; unreachable/unsupported is a 502 with a code."""
    from fastapi.concurrency import run_in_threadpool

    from api.services.local_operator.providers import InferenceProvider, OperatorProviderError

    try:
        config = await run_in_threadpool(_candidate_config, settings, {})
    except ValueError as exc:
        _fail(exc)
    try:
        models = await InferenceProvider(config).list_models()
    except OperatorProviderError as exc:
        raise HTTPException(status_code=502, detail=exc.args[0]) from None
    return {"provider": config.provider, "model": config.model,
            "models": [dataclasses.asdict(model) for model in models]}
