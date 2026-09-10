"""Per-tenant notification channels for finished runs (#351).

Writes require the tenant ``admin`` role, exactly as webhook subscriptions do
next door and for the same reason: a channel sends this tenant's exposure data
to a destination of the creator's choosing, which is closer to granting access
than to configuring a preference. Reads are ``operator`` — an operator has to
be able to see why the Slack channel went quiet.

Cross-tenant behaviour is the shape every tenant-scoped route here uses: a
channel belonging to another tenant answers ``404``, because whether an id
exists is not the caller's business, and an unscoped platform admin keeps the
installation-wide view.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TenantPrincipal, require_tenant
from api.routes._audit import AuditDep
from api.schemas import (
    CreateNotificationChannelRequest,
    NotificationChannelInfo,
    UpdateNotificationChannelRequest,
)
from api.services.integrations import channel_transports as transports
from api.services.integrations import channels

router = APIRouter(prefix="/notification-channels", tags=["notification-channels"])

#: The service raises these for a request it cannot honour; all of them are
#: ``ValueError`` subclasses, so the tuple is documentation rather than
#: dispatch — it says which failures are the *caller's* 422 and not a 500.
_BAD_REQUEST = (ValueError, transports.ChannelSpecError)


def _require_own_channel(channel_id: str, principal: TenantPrincipal) -> dict:
    channel = channels.get_channel(channel_id)
    if channel is None or (
        not principal.is_platform_admin and channel.get("tenant_id") != principal.tenant_id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification channel not found"
        )
    return channel


def _scope(principal: TenantPrincipal) -> str | None:
    """Unscoped platform admin keeps the cross-tenant view (as for webhooks)."""
    if principal.is_platform_admin and not principal.tenant_requested:
        return None
    return principal.tenant_id


@router.get("", response_model=list[NotificationChannelInfo])
def list_notification_channels(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> list[dict]:
    """This tenant's channels. Unpaginated — the table is capped per tenant."""
    return channels.list_channels(_scope(principal))


@router.post("", response_model=NotificationChannelInfo, status_code=status.HTTP_201_CREATED)
def create_notification_channel(
    body: CreateNotificationChannelRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    audit: AuditDep,
) -> dict:
    requested = (body.tenant_id or "").strip()
    if requested and requested != principal.tenant_id and not principal.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to tenant {requested}",
        )
    tenant_id = requested if (requested and principal.is_platform_admin) else principal.tenant_id
    try:
        return channels.create_channel(
            tenant_id=tenant_id,
            name=body.name,
            kind=body.kind,
            endpoint=body.endpoint,
            secret=body.secret,
            config=body.config,
            min_severity=body.min_severity,
            enabled=body.enabled,
            created_by=principal.username,
            audit=audit,
        )
    except _BAD_REQUEST as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.get("/{channel_id}", response_model=NotificationChannelInfo)
def get_notification_channel(
    channel_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict:
    return _require_own_channel(channel_id, principal)


@router.patch("/{channel_id}", response_model=NotificationChannelInfo)
def update_notification_channel(
    channel_id: str,
    body: UpdateNotificationChannelRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    audit: AuditDep,
) -> dict:
    _require_own_channel(channel_id, principal)
    try:
        channel = channels.update_channel(
            channel_id, audit=audit, **body.model_dump(exclude_unset=True)
        )
    except _BAD_REQUEST as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if channel is None:  # pragma: no cover - deleted between the two reads
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification channel not found"
        )
    return channel


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_notification_channel(
    channel_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    audit: AuditDep,
) -> None:
    _require_own_channel(channel_id, principal)
    if not channels.delete_channel(channel_id, audit=audit):  # pragma: no cover - raced delete
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification channel not found"
        )
