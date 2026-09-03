from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import JobInfo, Page, StartScanRequest
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import quotas
from api.services import scan_scopes
from api.settings import Settings

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=Page[JobInfo])
def list_jobs(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Page[JobInfo]:
    items, total = jobs_service.list_jobs(
        settings,
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        sort=page.sort,
        order=page.order,
        # A platform admin who named no tenant keeps the pre-P0 fleet-wide
        # view; everyone else is pinned to their own tenant.
        tenant_id=None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id,
    )
    return build_page(items, total, page)


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
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JobInfo:
    """Cancel a job that has not started executing (ROADMAP P1.3).

    Answers 409 for a job that is already running or finished: cancellation
    only prevents execution, it cannot stop a scan already in flight.
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
    if key:
        # A retry after a timeout must not queue a second scan of the same
        # targets (ROADMAP P1.5). 200 rather than 202 says "this already
        # existed" — the scan was accepted by the earlier call, not this one.
        existing = jobs_service.find_by_idempotency_key(settings, tenant_id=tenant_id, key=key)
        if existing is not None:
            jobs_service.note_start_replay()
            response.status_code = status.HTTP_200_OK
            return existing
    try:
        return jobs_service.start_scan(
            settings, body, username=principal.username, idempotency_key=key or None
        )
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
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
