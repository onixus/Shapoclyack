from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, PlainTextResponse

from api.auth import ROLE_RANK, Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    AliveHostItem,
    LeakIdentifiersResponse,
    OrgProfileControlsSummary,
    OrgProfileDetail,
    Page,
    PortAggregateItem,
    PromoteDomainResponse,
    RunDetail,
    RunSummary,
    VulnerabilityItem,
)
from api.services import runs as runs_service
from api.settings import Settings

router = APIRouter(prefix="/runs", tags=["runs"])


def _run_tenant_filter(principal: TenantPrincipal) -> str | None:
    """Tenant a request may read runs from, or ``None`` for no restriction.

    Mirrors the jobs/agents rule (ROADMAP P0): a platform admin who named no
    tenant keeps the pre-P0 fleet-wide view, everyone else is pinned to the
    tenant resolved from their memberships.
    """
    if principal.is_platform_admin and not principal.tenant_requested:
        return None
    return principal.tenant_id


@router.get("", response_model=Page[RunSummary])
def list_runs(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    page: PageParams,
) -> Page[RunSummary]:
    # `sort` is accepted for uniformity but ignored: runs are ordered by
    # run_id, the only key readable without opening every run's JSON.
    items, total = runs_service.list_runs(
        settings,
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        order=page.order,
        tenant_id=_run_tenant_filter(principal),
    )
    return build_page(items, total, page)


@router.get("/{run_id}", response_model=RunDetail)
def get_run(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RunDetail:
    detail = runs_service.get_run_detail(settings, run_id, tenant_id=_run_tenant_filter(principal))
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return detail


@router.get("/{run_id}/hosts", response_model=list[AliveHostItem])
def get_hosts(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=20000)] = 10000,
) -> list[AliveHostItem]:
    items = runs_service.get_hosts(
        settings, run_id, limit=limit, tenant_id=_run_tenant_filter(principal)
    )
    if items is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return items


@router.get("/{run_id}/ports", response_model=list[PortAggregateItem])
def get_ports(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=20000)] = 10000,
) -> list[PortAggregateItem]:
    items = runs_service.get_ports(
        settings, run_id, limit=limit, tenant_id=_run_tenant_filter(principal)
    )
    if items is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return items


@router.get("/{run_id}/vulnerabilities", response_model=list[VulnerabilityItem])
def get_vulnerabilities(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=10000)] = 5000,
    host: Annotated[str | None, Query(description="Filter findings by target host/IP")] = None,
    port: Annotated[str | None, Query(description="Filter findings by port")] = None,
) -> list[VulnerabilityItem]:
    items = runs_service.get_vulnerabilities(
        settings,
        run_id,
        limit=limit,
        host=host,
        port=port,
        tenant_id=_run_tenant_filter(principal),
    )
    if items is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return items


@router.get("/{run_id}/diff")
def get_diff(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    detail = runs_service.get_run_detail(settings, run_id, tenant_id=_run_tenant_filter(principal))
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if detail.diff is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diff not available for this run")
    return detail.diff


@router.get("/{run_id}/artifacts/{artifact_path:path}", response_class=PlainTextResponse)
def get_artifact(
    run_id: str,
    artifact_path: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    if runs_service.is_screenshot_path(artifact_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    if runs_service.is_restricted_artifact(artifact_path) and (
        ROLE_RANK[principal.role] < ROLE_RANK[Role.operator]
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    text = runs_service.read_artifact_text(
        settings,
        run_id,
        artifact_path,
        tenant_id=_run_tenant_filter(principal),
        allow_restricted=True,
    )
    if text is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return text


# Media types for the download endpoint below. Anything not listed (or with no
# extension) falls back to application/octet-stream so the browser downloads it
# as a binary blob rather than trying to render it.
_ARTIFACT_MEDIA_TYPES = {
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".xml": "application/xml",
    ".html": "text/html",
    ".log": "text/plain",
    ".png": "image/png",
}


@router.get("/{run_id}/download/{artifact_path:path}")
def download_artifact(
    run_id: str,
    artifact_path: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Binary-safe artifact download. Unlike the text endpoint above (which
    UTF-8-decodes and truncates to 1 MB — fine for previewing JSON/TXT but
    corrupts binaries like ``summary.pdf``), this streams the raw file with an
    attachment disposition and a content-type derived from its extension."""
    if runs_service.is_restricted_artifact(artifact_path) and (
        ROLE_RANK[principal.role] < ROLE_RANK[Role.operator]
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    if runs_service.is_screenshot_path(artifact_path):
        if ROLE_RANK[principal.role] < ROLE_RANK[Role.operator]:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
        target = runs_service.resolve_artifact(
            settings,
            run_id,
            artifact_path,
            tenant_id=_run_tenant_filter(principal),
            allow_screenshots=True,
        )
    else:
        target = runs_service.resolve_artifact(
            settings,
            run_id,
            artifact_path,
            tenant_id=_run_tenant_filter(principal),
            allow_restricted=True,
        )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    media_type = _ARTIFACT_MEDIA_TYPES.get(target.suffix.lower(), "application/octet-stream")
    return FileResponse(target, media_type=media_type, filename=target.name)


@router.get("/{run_id}/screenshots")
def list_screenshots(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Redacted screenshots for this run. Operator-only — they can still hold PII."""
    manifest = runs_service.list_screenshots(
        settings, run_id, tenant_id=_run_tenant_filter(principal)
    )
    if manifest is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return manifest


@router.get("/{run_id}/controls", response_model=OrgProfileControlsSummary)
def get_controls(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> OrgProfileControlsSummary:
    """Security controls matrix & NIST risk evaluation for this run (org_profile M3)."""
    raw = runs_service.get_controls(
        settings, run_id, tenant_id=_run_tenant_filter(principal)
    )
    if raw is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Controls summary not found for this run")
    return OrgProfileControlsSummary(**raw)


@router.get("/{run_id}/org-profile", response_model=OrgProfileDetail)
def get_org_profile(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> OrgProfileDetail:
    """Combined organization profile (ownership, related domains, controls) for this run (org_profile M4).

    The ``ownership`` block holds RDAP registrant/abuse contacts and is a
    restricted artifact, so it is only populated for operator+ principals --
    the same boundary the artifact preview and download endpoints enforce.
    """
    data = runs_service.get_org_profile(
        settings,
        run_id,
        tenant_id=_run_tenant_filter(principal),
        allow_restricted=ROLE_RANK[principal.role] >= ROLE_RANK[Role.operator],
    )
    if data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Org profile data not found for this run")
    return OrgProfileDetail(**data)


@router.post("/{run_id}/related-domains/{domain}/promote", response_model=PromoteDomainResponse)
def promote_related_domain(
    run_id: str,
    domain: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> PromoteDomainResponse:
    """Promote a discovered related domain into future scope (operator-only action, org_profile M4)."""
    try:
        res = runs_service.promote_related_domain(
            settings, run_id, domain, tenant_id=_run_tenant_filter(principal)
        )
    except runs_service.PromoteDomainError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    if res is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return PromoteDomainResponse(**res)


@router.get("/{run_id}/leaks/identifiers", response_model=LeakIdentifiersResponse)
def get_leak_identifiers(
    run_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LeakIdentifiersResponse:
    """Full unmasked compromised account identifiers for this run (operator-only, org_profile M5)."""
    data = runs_service.get_leak_identifiers(
        settings, run_id, tenant_id=_run_tenant_filter(principal)
    )
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Leak identifiers not found for this run",
        )
    return LeakIdentifiersResponse(**data)



