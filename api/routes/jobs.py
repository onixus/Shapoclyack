from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TokenUser, get_settings, require_role
from api.schemas import JobInfo, StartScanRequest
from api.services import jobs as jobs_service
from api.settings import Settings

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=list[JobInfo])
def list_jobs(
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> list[JobInfo]:
    return jobs_service.list_jobs()


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
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
