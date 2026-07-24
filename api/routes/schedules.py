from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TokenUser, require_role
from api.schemas import CreateScheduleRequest, ScheduleInfo, UpdateScheduleRequest
from api.services import scan_schedules
from api.services import tenants as tenants_service

router = APIRouter(prefix="/schedules", tags=["schedules"])

_TARGET_KEYS = ("ranges", "domains", "ports", "ports_udp")
_SCAN_OPTION_KEYS = ("mode", "delta", "skip_nse", "notify", "export_defectdojo")


@router.get("", response_model=list[ScheduleInfo])
def list_schedules(
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
    tenant_id: Annotated[str | None, Query()] = None,
) -> list[dict]:
    return scan_schedules.list_schedules(tenant_id=tenant_id)


@router.post("", response_model=ScheduleInfo, status_code=status.HTTP_201_CREATED)
def create_schedule(
    body: CreateScheduleRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> dict:
    tenant_id = (body.tenant_id or tenants_service.DEFAULT_TENANT_ID).strip()
    scan_options = {k: getattr(body, k) for k in _SCAN_OPTION_KEYS}
    targets = {k: getattr(body, k) for k in _TARGET_KEYS}
    try:
        return scan_schedules.create_schedule(
            tenant_id=tenant_id,
            name=body.name,
            cron=body.cron,
            interval_seconds=body.interval_seconds,
            scan_options=scan_options,
            targets=targets,
            created_by=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/{schedule_id}", response_model=ScheduleInfo)
def get_schedule(
    schedule_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> dict:
    schedule = scan_schedules.get_schedule(schedule_id)
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return schedule


@router.patch("/{schedule_id}", response_model=ScheduleInfo)
def update_schedule(
    schedule_id: str,
    body: UpdateScheduleRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> dict:
    fields = body.model_dump(exclude_unset=True)
    scan_options = {k: fields.pop(k) for k in _SCAN_OPTION_KEYS if k in fields}
    targets = {k: fields.pop(k) for k in _TARGET_KEYS if k in fields}
    if scan_options:
        fields["scan_options"] = scan_options
    if targets:
        fields["targets"] = targets
    try:
        schedule = scan_schedules.update_schedule(schedule_id, **fields)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return schedule


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> None:
    if not scan_schedules.delete_schedule(schedule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
