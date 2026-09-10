"""The maintenance calendar and the change freeze (#352).

Three routers, because the resources are three. The windows are their own
collection under ``/api/maintenance-windows``; the freeze is one switch per
tenant at ``/api/change-freeze``, resolved from the caller's tenant (or
``?tenant_id=`` for a platform admin) rather than carried in the path — a path
parameter named ``tenant_id`` cannot coexist with the query parameter
``require_tenant`` itself declares; and ``/api/tenants/{id}/maintenance-windows``
is the provider's read-only view of one customer's calendar.

Role: **tenant admin**, not platform admin. Unlike the approved scan scope —
which is the provider deciding what a customer may point the platform at — the
calendar is the customer's own operational knowledge. Who is in a change freeze
this week is a thing only they know, and a control they have to open a ticket
to use is a control that gets bypassed by disabling the schedules instead. A
platform admin can still act in any tenant through ``?tenant_id=``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from api.auth import Role, TenantPrincipal, TokenUser, get_settings, require_role, require_tenant
from api.routes._audit import AuditDep
from api.schemas import (
    ChangeFreezeInfo,
    ChangeFreezeRequest,
    CreateMaintenanceWindowRequest,
    MaintenanceCalendarInfo,
    MaintenanceWindowInfo,
    UpdateMaintenanceWindowRequest,
)
from api.services import maintenance
from api.settings import Settings

router = APIRouter(prefix="/maintenance-windows", tags=["maintenance"])
freeze_router = APIRouter(prefix="/change-freeze", tags=["maintenance"])
tenant_router = APIRouter(prefix="/tenants", tags=["maintenance"])


def _require_own_window(
    settings: Settings, window_id: str, principal: TenantPrincipal
) -> dict:
    """404 for a window in another tenant — the id's existence is not the
    caller's business (same rule as GET /schedules/{id})."""
    window = maintenance.get_window(settings, window_id)
    if window is None or (
        not principal.is_platform_admin and window.get("tenant_id") != principal.tenant_id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found"
        )
    return window


@router.get("", response_model=MaintenanceCalendarInfo)
def get_calendar(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """The tenant's windows, whether each is open now, and the verdict a scan
    started this second would get.

    One response rather than a list plus a status call: the console shows the
    banner and the table together, and two requests would let them disagree.
    Readable by an operator — somebody about to press "start scan" should be
    able to see why it will be refused — while writing is admin.
    """
    return maintenance.calendar_status(settings, principal.tenant_id)


@router.post("", response_model=MaintenanceWindowInfo, status_code=status.HTTP_201_CREATED)
def create_window(
    body: CreateMaintenanceWindowRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> dict:
    # As for POST /schedules: outside of a platform admin the body may not name
    # a tenant the caller has not already resolved into.
    requested = (body.tenant_id or "").strip()
    if requested and requested != principal.tenant_id and not principal.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to tenant {requested}",
        )
    tenant_id = requested if (requested and principal.is_platform_admin) else principal.tenant_id
    fields = body.model_dump(exclude={"tenant_id"})
    try:
        return maintenance.create_window(
            settings,
            tenant_id=tenant_id,
            fields=fields,
            created_by=principal.username,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.patch("/{window_id}", response_model=MaintenanceWindowInfo)
def update_window(
    window_id: str,
    body: UpdateMaintenanceWindowRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> dict:
    _require_own_window(settings, window_id, principal)
    try:
        window = maintenance.update_window(
            settings,
            window_id,
            fields=body.model_dump(exclude_unset=True),
            updated_by=principal.username,
            audit=audit,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if window is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found"
        )
    return window


@router.delete("/{window_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_window(
    window_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> Response:
    _require_own_window(settings, window_id, principal)
    if not maintenance.delete_window(settings, window_id, audit=audit):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Maintenance window not found"
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@freeze_router.get("", response_model=ChangeFreezeInfo)
def get_change_freeze(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Whether this tenant is frozen, and who froze it.

    The tenant is the one ``require_tenant`` resolved — from ``?tenant_id=``
    when the caller is entitled to it, from their memberships otherwise — so
    there is nothing here to check: an unentitled tenant never reaches this
    body.
    """
    try:
        return maintenance.change_freeze(settings, principal.tenant_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@freeze_router.put("", response_model=ChangeFreezeInfo)
def set_change_freeze(
    body: ChangeFreezeRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> dict:
    """Freeze or thaw the tenant. Refuses every scan start while it is on.

    Not behind a step-up like the scan-scope approval: a freeze *narrows* what
    the platform may do, and a control whose only failure mode is "no scans
    ran" should be the cheapest one on the page to reach.
    """
    try:
        return maintenance.set_change_freeze(
            settings,
            principal.tenant_id,
            frozen=body.change_freeze,
            note=body.note,
            actor=principal.username,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@tenant_router.get("/{tenant_id}/maintenance-windows", response_model=MaintenanceCalendarInfo)
def get_tenant_calendar(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """One tenant's calendar, for a platform admin auditing the fleet.

    The provider's cross-check on the customer's own control: a tenant whose
    scans stopped three weeks ago because somebody left a freeze on is the
    support ticket this route answers without an impersonation.
    """
    try:
        maintenance.change_freeze(settings, tenant_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return maintenance.calendar_status(settings, tenant_id)
