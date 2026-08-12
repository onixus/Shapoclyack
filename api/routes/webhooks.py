"""Webhook subscriptions and their delivery trail (ROADMAP P2 / Phase 10.3).

Writes require the tenant ``admin`` role rather than ``operator``, which is
what schedules use: a subscription sends this tenant's exposure data to an
address of the creator's choosing, so creating one is closer to granting
access than to scheduling a scan.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TenantPrincipal, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    CreateWebhookRequest,
    Page,
    UpdateWebhookRequest,
    WebhookDeliveryInfo,
    WebhookInfo,
)
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import webhooks

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _require_own_webhook(subscription_id: str, principal: TenantPrincipal) -> dict:
    """404 for a webhook in another tenant — as for jobs and schedules, the
    id's existence is not the caller's business."""
    subscription = webhooks.get_subscription(subscription_id)
    if subscription is None or (
        not principal.is_platform_admin and subscription.get("tenant_id") != principal.tenant_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return subscription


def _scope(principal: TenantPrincipal) -> str | None:
    """Unscoped platform admin keeps the cross-tenant view (as for schedules)."""
    if principal.is_platform_admin and not principal.tenant_requested:
        return None
    return principal.tenant_id


@router.get("", response_model=Page[WebhookInfo])
def list_webhooks(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
) -> Page[WebhookInfo]:
    items, total = webhooks.list_subscriptions(
        tenant_id=_scope(principal),
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        sort=page.sort,
        order=page.order,
    )
    return build_page(items, total, page)


@router.post("", response_model=WebhookInfo, status_code=status.HTTP_201_CREATED)
def create_webhook(
    body: CreateWebhookRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> dict:
    requested = (body.tenant_id or "").strip()
    if requested and requested != principal.tenant_id and not principal.is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"No access to tenant {requested}",
        )
    tenant_id = requested if (requested and principal.is_platform_admin) else principal.tenant_id
    try:
        return webhooks.create_subscription(
            tenant_id=tenant_id,
            name=body.name,
            url=body.url,
            event_kinds=body.event_kinds,
            min_severity=body.min_severity,
            secret=body.secret,
            headers=body.headers,
            enabled=body.enabled,
            created_by=principal.username,
        )
    except (ValueError, delivery_transport.WebhookTargetError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


# Declared before /{subscription_id} so "deliveries" is not read as an id.
@router.get("/deliveries", response_model=Page[WebhookDeliveryInfo])
def list_all_deliveries(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
    delivery_status: Annotated[
        str | None,
        Query(
            alias="status",
            description="pending | delivered | dead. dead is the dead-letter queue.",
        ),
    ] = None,
) -> Page[WebhookDeliveryInfo]:
    try:
        items, total = webhooks.list_deliveries(
            tenant_id=_scope(principal),
            status=delivery_status,
            offset=page.offset,
            limit=page.limit,
            q=page.q,
            sort=page.sort,
            order=page.order,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return build_page(items, total, page)


@router.post("/deliveries/{delivery_id}/retry", response_model=WebhookDeliveryInfo)
def retry_delivery(
    delivery_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> dict:
    """Take one delivery back out of the DLQ; the dispatcher picks it up next tick."""
    existing = webhooks.get_delivery(delivery_id)
    if existing is None or (
        not principal.is_platform_admin and existing.get("tenant_id") != principal.tenant_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    requeued = webhooks.requeue_delivery(delivery_id)
    if requeued is None:  # pragma: no cover - deleted between the two reads
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    return requeued


@router.get("/{subscription_id}", response_model=WebhookInfo)
def get_webhook(
    subscription_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict:
    return _require_own_webhook(subscription_id, principal)


@router.patch("/{subscription_id}", response_model=WebhookInfo)
def update_webhook(
    subscription_id: str,
    body: UpdateWebhookRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> dict:
    _require_own_webhook(subscription_id, principal)
    try:
        subscription = webhooks.update_subscription(
            subscription_id, **body.model_dump(exclude_unset=True)
        )
    except (ValueError, delivery_transport.WebhookTargetError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if subscription is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return subscription


@router.delete("/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    subscription_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> None:
    _require_own_webhook(subscription_id, principal)
    if not webhooks.delete_subscription(subscription_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")


@router.post("/{subscription_id}/rotate-secret", response_model=WebhookInfo)
def rotate_webhook_secret(
    subscription_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> dict:
    """Issue a new signing secret. Returned once, as at creation."""
    _require_own_webhook(subscription_id, principal)
    subscription = webhooks.rotate_secret(subscription_id)
    if subscription is None:  # pragma: no cover - deleted between the two reads
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return subscription


@router.post(
    "/{subscription_id}/test",
    response_model=WebhookDeliveryInfo,
    status_code=status.HTTP_202_ACCEPTED,
)
def test_webhook(
    subscription_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> dict:
    """Queue a signed ``test`` delivery through the normal path.

    202, not 200: the response says the ping is queued, not that the receiver
    answered. Poll ``GET /webhooks/{id}/deliveries`` for the outcome.
    """
    _require_own_webhook(subscription_id, principal)
    delivery_id = webhooks.enqueue_test_delivery(
        subscription_id, requested_by=principal.username
    )
    if delivery_id is None:  # pragma: no cover - deleted between the two reads
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    delivery = webhooks.get_delivery(delivery_id)
    assert delivery is not None
    return delivery


@router.get("/{subscription_id}/deliveries", response_model=Page[WebhookDeliveryInfo])
def list_webhook_deliveries(
    subscription_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
    delivery_status: Annotated[str | None, Query(alias="status")] = None,
) -> Page[WebhookDeliveryInfo]:
    _require_own_webhook(subscription_id, principal)
    try:
        items, total = webhooks.list_deliveries(
            subscription_id=subscription_id,
            status=delivery_status,
            offset=page.offset,
            limit=page.limit,
            q=page.q,
            sort=page.sort,
            order=page.order,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return build_page(items, total, page)
