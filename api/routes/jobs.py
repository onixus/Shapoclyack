from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status

from api.auth import (
    Role,
    TenantPrincipal,
    get_settings,
    require_permission,
    require_tenant,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.routes._pagination import PageParams, build_page
from api.schemas import JobInfo, JobSummary, Page, StartScanRequest
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import maintenance
from api.services import quotas
from api.services import scan_scopes
from api.settings import Settings

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=Page[JobInfo])
def list_jobs(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
    settings: Annotated[Settings, Depends(get_settings)],
    surface: Annotated[
        Literal["external", "internal", "mixed", "unknown"] | None, Query()
    ] = None,
) -> Page[JobInfo]:
    """``surface`` splits the queue into internet-facing and internal scans;
    ``unknown`` selects the jobs carrying no classification (see
    api/services/scan_surface.py)."""
    items, total = jobs_service.list_jobs(
        settings,
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        sort=page.sort,
        order=page.order,
        surface=surface,
        # A platform admin who named no tenant keeps the pre-P0 fleet-wide
        # view; everyone else is pinned to their own tenant.
        tenant_id=None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id,
    )
    return build_page(items, total, page)


def _scope(principal: TenantPrincipal) -> str | None:
    """Tenant a read is confined to. A platform admin who named no tenant keeps
    the pre-P0 fleet-wide view; everyone else is pinned to their own."""
    return None if principal.is_platform_admin and not principal.tenant_requested else principal.tenant_id


# Declared before /{job_id} so "summary" is not read as a job id.
@router.get("/summary", response_model=JobSummary)
def get_job_summary(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Queue depth by status and by surface, for a scan console's header."""
    return jobs_service.summary(settings, tenant_id=_scope(principal))


@router.get("/{job_id}", response_model=JobInfo)
def get_job(
    job_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JobInfo:
    job = jobs_service.get_job(settings, job_id)
    # A job in another tenant is reported as missing, not forbidden: a 403
    # would confirm the id exists to someone with no right to know.
    if job is None or (not principal.is_platform_admin and job.tenant_id != principal.tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


@router.post("/{job_id}/cancel", response_model=JobInfo)
def cancel_job(
    job_id: str,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.SCAN_CANCEL))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> JobInfo:
    """Stop a scan (ROADMAP P1.3, #360).

    A queued job comes back `cancelled`: nothing has taken it, so refusing to
    hand it out is the whole stop. A scan an agent is already running comes
    back `cancelling` — the request rides the agent's next heartbeat and the
    job reaches `cancelled` when the agent confirms, or when the grace period
    expires without it. Answers 409 for a job that has already finished, and
    for a *local* scan that has started: that one runs as a subprocess inside
    one API replica, which is not necessarily this one, so there is nothing to
    signal and nothing truthful to report.

    Gated on `scan.cancel` rather than on the operator rank (#318): stopping
    somebody else's scan is an authority an installation may want to grant on
    its own. Every one of the roles that could cancel before holds it.
    """
    try:
        return jobs_service.cancel_job(
            settings,
            job_id,
            username=principal.username,
            # A platform admin may cancel in any tenant; everyone else is
            # pinned, and the mismatch is reported as 404 below so the id is
            # not confirmed to someone with no right to know it exists.
            tenant_id=None if principal.is_platform_admin else principal.tenant_id,
            audit=audit,
        )
    except (LookupError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from exc
    except job_states.InvalidJobTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("", response_model=JobInfo, status_code=status.HTTP_202_ACCEPTED)
def start_job(
    body: StartScanRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> JobInfo:
    # The body's tenant_id is advisory: outside of a platform admin it may
    # only name the tenant the caller already resolved into, so a scan can
    # never be launched in someone else's tenant.
    requested = (body.tenant_id or "").strip()
    if requested and requested != principal.tenant_id and not principal.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to tenant {requested}",
        )
    tenant_id = requested if (requested and principal.is_platform_admin) else principal.tenant_id
    body = body.model_copy(update={"tenant_id": tenant_id})
    key = (idempotency_key or "").strip()[:200]
    try:
        if key:
            # A retry after a timeout must not queue a second scan of the same
            # targets (ROADMAP P1.5). 200 rather than 202 says "this already
            # existed" — the scan was accepted by the earlier call, not this one.
            existing = jobs_service.find_by_idempotency_key(
                settings, tenant_id=tenant_id, key=key, request=body
            )
            if existing is not None:
                jobs_service.note_start_replay()
                response.status_code = status.HTTP_200_OK
                return existing
        return jobs_service.start_scan(
            settings, body, username=principal.username, idempotency_key=key or None
        )
    except jobs_service.IdempotencyMismatch as exc:
        # 409, not 422: the body is fine, the *key* is taken by another
        # request. Replaying the earlier job here would report a scan of
        # targets this caller never asked for.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except jobs_service.IdempotentReplay as replay:
        # Two requests with one key raced past the lookup above; the database
        # picked a winner and this one accepted nothing either.
        jobs_service.note_start_replay()
        response.status_code = status.HTTP_200_OK
        return replay.job
    except quotas.QuotaExceeded as exc:
        # 429 rather than 403: unlike a scope refusal this one expires by
        # itself, so the answer can say when — an integration that retries on
        # 429 with Retry-After does the right thing without being taught
        # anything about quotas.
        headers = (
            {"Retry-After": str(exc.retry_after_seconds)}
            if exc.retry_after_seconds is not None
            else None
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers=headers,
        ) from exc
    except scan_scopes.ScanScopeDenied as exc:
        # 403, not 422: the targets are well-formed, this tenant is simply not
        # approved for them (#226). The refusal is already in the audit trail.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except maintenance.MaintenanceBlocked as exc:
        # 409, neither 403 nor 429 (#352): the caller is entitled to this scan
        # and has asked for nothing too often — the tenant's own calendar is in
        # a state that forbids it, and that state changes. `Retry-After` is set
        # when the block has a knowable end (a blackout closes, an allowed
        # window opens) and deliberately omitted under a change freeze, where a
        # retry time would be an invention. The window that said no is named in
        # the body, and the refusal is already in audit_events.
        blocked_headers = (
            {"Retry-After": str(exc.retry_after_seconds)}
            if exc.retry_after_seconds is not None
            else None
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
            headers=blocked_headers,
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
