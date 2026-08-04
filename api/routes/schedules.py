from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TenantPrincipal, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import CreateScheduleRequest, Page, ScheduleInfo, UpdateScheduleRequest
from api.services import scan_schedules

router = APIRouter(prefix="/schedules", tags=["schedules"])

_TARGET_KEYS = ("ranges", "domains", "ports", "ports_udp")
_SCAN_OPTION_KEYS = ("mode", "delta", "skip_nse", "notify", "export_defectdojo")


def _require_own_schedule(schedule_id: str, principal: TenantPrincipal) -> dict:
    """404 for a schedule in another tenant — the id's existence is not the
    caller's business (same rule as GET /jobs/{id})."""
    schedule = scan_schedules.get_schedule(schedule_id)
    if schedule is None or (
        not principal.is_platform_admin and schedule.get("tenant_id") != principal.tenant_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return schedule


@router.get("", response_model=Page[ScheduleInfo])
def list_schedules(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
) -> Page[ScheduleInfo]:
    items, total = scan_schedules.list_schedules(
        # Unscoped platform admin keeps the cross-tenant view (as for jobs/agents).
        tenant_id=None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id,
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        sort=page.sort,
        order=page.order,
    )
    return build_page(items, total, page)


@router.post("", response_model=ScheduleInfo, status_code=status.HTTP_201_CREATED)
def create_schedule(
    body: CreateScheduleRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict:
    # As for POST /jobs: outside of a platform admin the body may not name a
    # tenant the caller has not already resolved into.
    requested = (body.tenant_id or "").strip()
    if requested and requested != principal.tenant_id and not principal.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to tenant {requested}",
        )
    tenant_id = requested if (requested and principal.is_platform_admin) else principal.tenant_id
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
            created_by=principal.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/{schedule_id}", response_model=ScheduleInfo)
def get_schedule(
    schedule_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict:
    schedule = _require_own_schedule(schedule_id, principal)
    return schedule


@router.patch("/{schedule_id}", response_model=ScheduleInfo)
def update_schedule(
    schedule_id: str,
    body: UpdateScheduleRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict:
    _require_own_schedule(schedule_id, principal)
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
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> None:
    _require_own_schedule(schedule_id, principal)
    if not scan_schedules.delete_schedule(schedule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
