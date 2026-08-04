from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TokenUser, get_settings, require_role
from api.routes._pagination import PageParams, build_page
from api.schemas import JobInfo, Page, StartScanRequest
from api.services import jobs as jobs_service
from api.settings import Settings

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=Page[JobInfo])
def list_jobs(
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
    page: PageParams,
    tenant_id: Annotated[str | None, Query()] = None,
) -> Page[JobInfo]:
    items, total = jobs_service.list_jobs(
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        sort=page.sort,
        order=page.order,
        tenant_id=tenant_id,
    )
    return build_page(items, total, page)


@router.get("/{job_id}", response_model=JobInfo)
def get_job(
    job_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> JobInfo:
    job = jobs_service.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


@router.post("", response_model=JobInfo, status_code=status.HTTP_202_ACCEPTED)
def start_job(
    body: StartScanRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> JobInfo:
    try:
        return jobs_service.start_scan(settings, body, username=user.username)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
