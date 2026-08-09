from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import JobInfo, Page, StartScanRequest
from api.services import job_states
from api.services import jobs as jobs_service
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
    try:
        return jobs_service.start_scan(settings, body, username=principal.username)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
