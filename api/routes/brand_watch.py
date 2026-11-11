"""Brand-watch routes (M1). Prefix ``/brand-watch``.

Read routes use ``require_tenant(Role.viewer)``, the same rank gate every
other read collection uses — a viewer has an empty-enough permission set that
gating the page on ``brand_watch.read`` alone would lock the console role out
of a page it is meant to open. The permission is still granted to viewer,
auditor, operator and admin so a service token issued with that role can be
checked by name.

Claim mirrors ``POST /agent/jobs/claim``: ``require_agent``, tenant bind, and
then a capability filter. A sensor that did not declare ``brand_watch`` is
handed nothing. The handler never calls the scan-job claim.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from api.auth import (
    AgentPrincipal,
    Role,
    TenantPrincipal,
    require_agent,
    require_permission,
    require_tenant,
)
from api.services import agents as agents_service
from api.services import brand_watch
from api.settings import Settings, get_settings

router = APIRouter(prefix="/brand-watch", tags=["brand-watch"])


class ProfileCreate(BaseModel):
    name: str
    official_domains: list[str]
    brand_strings: list[str]
    whitelist: list[str] = Field(default_factory=list)
    reference: dict[str, Any] = Field(default_factory=dict)
    our_brand: bool = False


class ApproveBody(BaseModel):
    our_brand: bool


class DispositionBody(BaseModel):
    disposition: str


class ResultBody(BaseModel):
    observations: list[dict[str, Any]] = Field(default_factory=list)


def _settings_dep(settings: Annotated[Settings, Depends(get_settings)]) -> Settings:
    return settings


def _refuse(exc: Exception) -> HTTPException:
    if isinstance(exc, brand_watch.QuotaExceeded):
        return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    if isinstance(exc, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, brand_watch.BrandWatchError):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    raise exc


@router.get("/profiles")
def list_profiles(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[dict[str, Any]]:
    return brand_watch.list_profiles(settings, principal.tenant_id)


@router.post("/profiles", status_code=status.HTTP_201_CREATED)
def create_profile(
    body: ProfileCreate,
    principal: Annotated[TenantPrincipal, Depends(require_permission("brand_watch.write"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        return brand_watch.create_profile(
            settings,
            tenant_id=principal.tenant_id,
            name=body.name,
            official_domains=body.official_domains,
            brand_strings=body.brand_strings,
            whitelist=body.whitelist,
            reference=body.reference,
            our_brand=body.our_brand,
        )
    except (brand_watch.BrandWatchError, LookupError) as exc:
        raise _refuse(exc) from exc


@router.post("/profiles/{profile_id}/approve")
def approve_profile(
    profile_id: str,
    body: ApproveBody,
    principal: Annotated[TenantPrincipal, Depends(require_permission("brand_watch.write"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        return brand_watch.approve_profile(
            settings,
            tenant_id=principal.tenant_id,
            profile_id=profile_id,
            approved_by=principal.username,
            our_brand=body.our_brand,
        )
    except (brand_watch.BrandWatchError, LookupError) as exc:
        raise _refuse(exc) from exc


@router.get("/profiles/{profile_id}/candidates")
def list_candidates(
    profile_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[dict[str, Any]]:
    try:
        return brand_watch.list_candidates(settings, principal.tenant_id, profile_id)
    except LookupError as exc:
        raise _refuse(exc) from exc


@router.get("/diff")
def diff(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    since: Annotated[datetime | None, Query()] = None,
) -> list[dict[str, Any]]:
    moment = since.replace(tzinfo=None) if since is not None and since.tzinfo else since
    return brand_watch.diff_since(settings, principal.tenant_id, since=moment)


@router.post("/candidates/{candidate_id}/disposition")
def disposition(
    candidate_id: str,
    body: DispositionBody,
    principal: Annotated[TenantPrincipal, Depends(require_permission("brand_watch.disposition"))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        return brand_watch.set_disposition(
            settings,
            tenant_id=principal.tenant_id,
            candidate_id=candidate_id,
            disposition=body.disposition,
        )
    except (brand_watch.BrandWatchError, LookupError) as exc:
        raise _refuse(exc) from exc


def _agent_for(request: Request, principal: AgentPrincipal, agent_id: str):
    cached = getattr(request.state, "agent_info", None)
    if cached is not None and getattr(cached, "agent_id", None) == agent_id:
        return cached
    return agents_service.get_agent(agent_id)


@router.post("/jobs/claim")
def claim_job(
    request: Request,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
    agent_id: str,
) -> dict[str, Any] | Response:
    if agent_id != principal.agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent identity mismatch")
    agent = _agent_for(request, principal, agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown agent_id")
    if agent.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant agent access denied")
    claimed = brand_watch.claim_job(
        settings,
        tenant_id=principal.tenant_id,
        agent_id=agent_id,
        capabilities=list(agent.capabilities or []),
    )
    if claimed is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return claimed


@router.post("/jobs/{job_id}/result")
def post_result(
    job_id: str,
    body: ResultBody,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        return brand_watch.apply_result(
            settings,
            tenant_id=principal.tenant_id,
            job_id=job_id,
            observations=body.observations,
        )
    except LookupError as exc:
        raise _refuse(exc) from exc
