"""Webhook subscriptions, routing policy and the delivery queue (Phase 10.3).

The database half of the integration: which tenant wants which events where
(``webhook_subscriptions``), and every attempt to get one there
(``webhook_deliveries`` — queue, dead-letter queue and audit trail in one
table, see the model docstring).

Nothing here opens a socket: ``delivery.py`` owns the wire, this module owns
the state machine around it. That split is what lets the dispatch loop be
tested end-to-end against a stub transport, and it is why a receiver that
hangs cannot hold a database transaction open — a delivery is *claimed* in one
short transaction, POSTed outside any transaction, and recorded in a second.

The loop itself lives in ``secure_webhooks``, the facade the package exports
under this module's name: claiming has to filter on the #151 kill switch, so
one dispatcher is one claim query.  This module keeps the pieces that loop
calls — ``claim_visibility_seconds``, ``backoff_seconds``, ``_record_result``
(#255: a second copy of the loop here was shadowed by the facade, so fixing a
bug in it changed nothing).
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, or_, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import asset_events, metrics, pagination
from api.services import tenants as tenants_service
from api.services import vulnerabilities as vulns_service
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import tickets as ticket_transport
from api.settings import Settings
from scanner.pipeline.report import SEVERITY_ORDER

LOG = logging.getLogger("shapoclyack.webhooks")

_settings: Settings | None = None

# Kinds whose payload carries a severity, and so are subject to min_severity.
# Every other kind is delivered regardless of the filter: "critical only" is a
# statement about vulnerabilities, and silently swallowing a decommission or a
# newly opened port because it has no CVSS would be a filter nobody asked for.
_SEVERITY_BEARING_KINDS = ("new_cve",)

DELIVERY_STATUSES = ("pending", "delivered", "dead")

# Synthetic kind for POST /webhooks/{id}/test. Not in EVENT_KINDS on purpose:
# it can never come off the event bus, only from an operator pressing "test".
TEST_EVENT_KIND = "test"


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "webhooks.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.WebhookDelivery).delete()
        session.query(models.WebhookSubscription).delete()


# --------------------------------------------------------------------------
# Subscriptions
# --------------------------------------------------------------------------


def _subscription_to_dict(row: models.WebhookSubscription) -> dict[str, Any]:
    """Serialise a subscription. The secret is never part of the result.

    Only ``has_secret`` is exposed: the value is write-only, as with any shared
    secret an operator pastes into a form. It is shown exactly once, in the
    response to the request that set it (see ``create_subscription``).
    """
    return {
        "subscription_id": row.subscription_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "url": row.url,
        "enabled": row.enabled,
        "event_kinds": list(row.event_kinds or []),
        "min_severity": row.min_severity,
        "has_secret": bool(row.secret),
        "headers": dict(row.headers or {}),
        "transport": row.transport or "webhook",
        "transport_config": dict(row.transport_config or {}),
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
        "last_delivery_at": _iso(row.last_delivery_at),
        "last_status": row.last_status,
    }


def _validate_event_kinds(kinds: list[str] | None) -> list[str]:
    if not kinds:
        return []
    cleaned: list[str] = []
    for raw in kinds:
        kind = str(raw).strip()
        if kind not in asset_events.EVENT_KINDS:
            raise ValueError(
                f"unknown event kind {kind!r}; known kinds: {', '.join(asset_events.EVENT_KINDS)}"
            )
        if kind not in cleaned:
            cleaned.append(kind)
    return cleaned


def _validate_min_severity(value: str | None) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    severity = str(value).strip().lower()
    if severity not in SEVERITY_ORDER:
        raise ValueError(
            f"unknown severity {value!r}; expected one of {', '.join(SEVERITY_ORDER)}"
        )
    return severity


def create_subscription(
    *,
    tenant_id: str,
    name: str,
    url: str,
    event_kinds: list[str] | None = None,
    min_severity: str | None = None,
    secret: str | None = None,
    headers: dict[str, Any] | None = None,
    enabled: bool = True,
    created_by: str | None = None,
    transport: str | None = None,
    transport_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a subscription. The returned dict carries ``secret`` once.

    A generated secret is the default rather than an option: an unsigned
    webhook is a URL anyone who learns it can forge events into, and making
    signing the thing you opt *out* of is the safer default for a stream that
    says "this host just grew a critical CVE".
    """
    settings = _require_settings()
    name = (name or "").strip()
    if not name:
        raise ValueError("webhook name required")
    if tenants_service.get_tenant(tenant_id) is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")

    url = delivery_transport.validate_url(
        url, allow_private=settings.webhook_allow_private_targets
    )
    kinds = _validate_event_kinds(event_kinds)
    severity = _validate_min_severity(min_severity)
    clean_headers = delivery_transport.sanitize_headers(headers)
    kind = ticket_transport.validate_transport(transport)
    config = ticket_transport.validate_transport_config(kind, transport_config)
    if kind == "webhook":
        secret_value = (secret or "").strip() or secrets.token_urlsafe(32)
    else:
        secret_value = (secret or "").strip() or None
        has_auth = any(k.lower() == "authorization" for k in clean_headers)
        if not secret_value and not has_auth:
            raise ValueError(
                f"{kind} subscription needs a secret (API token) or an Authorization header"
            )

    now = _now()
    row = models.WebhookSubscription(
        subscription_id=f"wh_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        name=name,
        url=url,
        enabled=bool(enabled),
        event_kinds=kinds,
        min_severity=severity,
        secret=secret_value,
        headers=clean_headers,
        transport=kind,
        transport_config=config,
        created_at=now,
        created_by=created_by,
        updated_at=now,
    )
    with get_session(settings.postgres_url) as session:
        existing = session.execute(
            select(func.count())
            .select_from(models.WebhookSubscription)
            .where(models.WebhookSubscription.tenant_id == tenant_id)
        ).scalar_one()
        if existing >= settings.webhook_max_subscriptions_per_tenant:
            raise ValueError(
                f"tenant {tenant_id} already has {existing} webhooks "
                f"(limit {settings.webhook_max_subscriptions_per_tenant})"
            )
        session.add(row)
        session.flush()
        result = _subscription_to_dict(row)
    result["secret"] = secret_value
    return result


SUBSCRIPTION_SORT_COLUMNS = {
    "created_at": models.WebhookSubscription.created_at,
    "name": models.WebhookSubscription.name,
    "url": models.WebhookSubscription.url,
    "enabled": models.WebhookSubscription.enabled,
    "last_delivery_at": models.WebhookSubscription.last_delivery_at,
    "tenant_id": models.WebhookSubscription.tenant_id,
}


def list_subscriptions(
    tenant_id: str | None = None,
    *,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    sort: str | None = None,
    order: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    settings = _require_settings()
    sort_column = SUBSCRIPTION_SORT_COLUMNS.get(sort or "", models.WebhookSubscription.created_at)
    direction = sort_column.asc() if (order or "").lower() == "asc" else sort_column.desc()

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.WebhookSubscription.tenant_id == tenant_id)
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(models.WebhookSubscription.name).like(needle),
                    func.lower(models.WebhookSubscription.url).like(needle),
                    func.lower(models.WebhookSubscription.subscription_id).like(needle),
                )
            )
        total = session.execute(
            select(func.count()).select_from(models.WebhookSubscription).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.WebhookSubscription)
            .where(*filters)
            .order_by(direction, models.WebhookSubscription.subscription_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()
    return [_subscription_to_dict(row) for row in rows], total


def get_subscription(subscription_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookSubscription, subscription_id)
        return _subscription_to_dict(row) if row else None


def update_subscription(subscription_id: str, **fields: Any) -> dict[str, Any] | None:
    settings = _require_settings()
    rotated: str | None = None
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookSubscription, subscription_id)
        if row is None:
            return None
        if "name" in fields:
            name = str(fields["name"]).strip()
            if not name:
                raise ValueError("webhook name required")
            row.name = name
        if "url" in fields:
            row.url = delivery_transport.validate_url(
                str(fields["url"]), allow_private=settings.webhook_allow_private_targets
            )
        if "enabled" in fields:
            row.enabled = bool(fields["enabled"])
        if "event_kinds" in fields:
            row.event_kinds = _validate_event_kinds(fields["event_kinds"])
        if "min_severity" in fields:
            row.min_severity = _validate_min_severity(fields["min_severity"])
        if "headers" in fields:
            row.headers = delivery_transport.sanitize_headers(fields["headers"])
        if "transport" in fields or "transport_config" in fields:
            kind = ticket_transport.validate_transport(
                fields["transport"] if "transport" in fields else row.transport
            )
            cfg = fields["transport_config"] if "transport_config" in fields else (row.transport_config or {})
            row.transport = kind
            row.transport_config = ticket_transport.validate_transport_config(kind, cfg)
        if "secret" in fields:
            # An explicit empty string clears signing; a non-empty value sets
            # it; ``rotate_secret`` (below) is the "give me a new one" path.
            rotated = str(fields["secret"] or "")
            row.secret = rotated or None
        row.updated_at = _now()
        session.flush()
        result = _subscription_to_dict(row)
    if rotated:
        result["secret"] = rotated
    return result


def rotate_secret(subscription_id: str) -> dict[str, Any] | None:
    """Generate a fresh HMAC signing secret and return it once.

    Ticket transports use ``secret`` as the tracker API token, so rotating
    it to a random value would silently break Jira/ServiceNow/DefectDojo.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookSubscription, subscription_id)
        if row is None:
            return None
        if (row.transport or "webhook") != "webhook":
            raise ValueError(
                "rotate-secret is for webhook HMAC keys; PATCH secret with the tracker token instead"
            )
    return update_subscription(subscription_id, secret=secrets.token_urlsafe(32))


def delete_subscription(subscription_id: str) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookSubscription, subscription_id)
        if row is None:
            return False
        # Deliveries cascade with the subscription: the audit trail is "what did
        # we send to this endpoint", and the endpoint is gone. A tenant-level
        # export before deletion is a reporting feature, not a retention one.
        session.execute(
            delete(models.WebhookDelivery).where(
                models.WebhookDelivery.subscription_id == subscription_id
            )
        )
        session.delete(row)
        return True


# --------------------------------------------------------------------------
# Routing policy
# --------------------------------------------------------------------------


def event_severity(envelope: dict[str, Any]) -> str | None:
    data = envelope.get("data")
    if not isinstance(data, dict):
        return None
    severity = data.get("severity")
    return str(severity).strip().lower() if severity else None


def matches(subscription: dict[str, Any], envelope: dict[str, Any]) -> bool:
    """Whether one event should be delivered to one subscription."""
    if not subscription.get("enabled"):
        return False
    kind = str(envelope.get("kind") or "")
    kinds = subscription.get("event_kinds") or []
    if kinds and kind not in kinds:
        return False
    minimum = subscription.get("min_severity")
    if minimum and kind in _SEVERITY_BEARING_KINDS:
        severity = event_severity(envelope) or "unknown"
        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(minimum, 0):
            return False
    return True


# --------------------------------------------------------------------------
# Delivery queue
# --------------------------------------------------------------------------


def _delivery_to_dict(row: models.WebhookDelivery) -> dict[str, Any]:
    return {
        "delivery_id": row.delivery_id,
        "tenant_id": row.tenant_id,
        "subscription_id": row.subscription_id,
        "event_id": row.event_id,
        "event_kind": row.event_kind,
        "status": row.status,
        "attempts": row.attempts,
        "next_attempt_at": _iso(row.next_attempt_at),
        "last_status_code": row.last_status_code,
        "last_error": row.last_error,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "delivered_at": _iso(row.delivered_at),
    }


def _build_payload(
    *, delivery_id: str, subscription_id: str, envelope: dict[str, Any]
) -> dict[str, Any]:
    return {
        "delivery_id": delivery_id,
        "subscription_id": subscription_id,
        "tenant_id": envelope.get("tenant_id"),
        "kind": envelope.get("kind"),
        "event_id": envelope.get("event_id"),
        "occurred_at": envelope.get("occurred_at"),
        "event": envelope,
    }


def enqueue_event(envelope: dict[str, Any]) -> list[str]:
    """Fan one asset event out to the tenant's matching subscriptions.

    Returns the ids of the deliveries created. Re-enqueueing the same
    ``(subscription, event_id)`` is a no-op rather than a second call: the
    JetStream consumer is at-least-once, and a redelivered message must not
    page anyone twice.
    """
    settings = _require_settings()
    tenant_id = str(envelope.get("tenant_id") or "").strip()
    kind = str(envelope.get("kind") or "").strip()
    event_id = str(envelope.get("event_id") or "").strip()
    if not tenant_id or not kind or not event_id:
        LOG.debug("Ignoring asset event without tenant/kind/event_id: %r", envelope)
        return []

    now = _now()
    created: list[str] = []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.WebhookSubscription).where(
                models.WebhookSubscription.tenant_id == tenant_id,
                models.WebhookSubscription.enabled.is_(True),
            )
        ).scalars().all()
        if not rows:
            return []
        existing = set(
            session.execute(
                select(models.WebhookDelivery.subscription_id).where(
                    models.WebhookDelivery.event_id == event_id,
                    models.WebhookDelivery.subscription_id.in_(
                        [row.subscription_id for row in rows]
                    ),
                )
            ).scalars().all()
        )
        for row in rows:
            if row.subscription_id in existing:
                continue
            if not matches(_subscription_to_dict(row), envelope):
                continue
            delivery_id = f"whd_{uuid.uuid4().hex[:16]}"
            queued = models.WebhookDelivery(
                delivery_id=delivery_id,
                tenant_id=tenant_id,
                subscription_id=row.subscription_id,
                event_id=event_id,
                event_kind=kind,
                payload=_build_payload(
                    delivery_id=delivery_id,
                    subscription_id=row.subscription_id,
                    envelope=envelope,
                ),
                status="pending",
                attempts=0,
                # Due immediately; the dispatcher picks it up on its next tick.
                next_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
            # The SELECT above catches the ordinary redelivery; the unique
            # constraint catches two replicas fanning out the same event at
            # once. Inserting inside a SAVEPOINT keeps that race a no-op for
            # one row instead of aborting the whole batch's transaction.
            if insert_if_absent(session, queued, f"{row.subscription_id}:{event_id}"):
                created.append(delivery_id)
        session.flush()
    for _ in created:
        metrics.WEBHOOK_DELIVERIES_TOTAL.labels(outcome="queued").inc()
    return created


def enqueue_test_delivery(subscription_id: str, *, requested_by: str | None = None) -> str | None:
    """Queue a synthetic ping so an operator can prove the receiver works.

    It goes through the same queue, signing and retry path as a real event —
    a "test" that took a shortcut would prove only that the shortcut works.
    """
    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookSubscription, subscription_id)
        if row is None:
            return None
        delivery_id = f"whd_{uuid.uuid4().hex[:16]}"
        event_id = f"test-{uuid.uuid4().hex[:16]}"
        envelope = {
            "kind": TEST_EVENT_KIND,
            "tenant_id": row.tenant_id,
            "event_id": event_id,
            "occurred_at": _iso(now),
            "source": "operator",
            "data": {"requested_by": requested_by, "subscription_id": subscription_id},
        }
        session.add(
            models.WebhookDelivery(
                delivery_id=delivery_id,
                tenant_id=row.tenant_id,
                subscription_id=subscription_id,
                event_id=event_id,
                event_kind=TEST_EVENT_KIND,
                payload=_build_payload(
                    delivery_id=delivery_id,
                    subscription_id=subscription_id,
                    envelope=envelope,
                ),
                status="pending",
                attempts=0,
                next_attempt_at=now,
                created_at=now,
                updated_at=now,
            )
        )
    metrics.WEBHOOK_DELIVERIES_TOTAL.labels(outcome="queued").inc()
    return delivery_id


DELIVERY_SORT_COLUMNS = {
    "created_at": models.WebhookDelivery.created_at,
    "updated_at": models.WebhookDelivery.updated_at,
    "status": models.WebhookDelivery.status,
    "attempts": models.WebhookDelivery.attempts,
    "event_kind": models.WebhookDelivery.event_kind,
}


def list_deliveries(
    *,
    tenant_id: str | None = None,
    subscription_id: str | None = None,
    status: str | None = None,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    sort: str | None = None,
    order: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """The audit trail, and — filtered to ``status="dead"`` — the DLQ view."""
    settings = _require_settings()
    if status and status not in DELIVERY_STATUSES:
        raise ValueError(f"unknown status {status!r}; expected one of {', '.join(DELIVERY_STATUSES)}")
    sort_column = DELIVERY_SORT_COLUMNS.get(sort or "", models.WebhookDelivery.created_at)
    direction = sort_column.asc() if (order or "").lower() == "asc" else sort_column.desc()

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.WebhookDelivery.tenant_id == tenant_id)
        if subscription_id:
            filters.append(models.WebhookDelivery.subscription_id == subscription_id)
        if status:
            filters.append(models.WebhookDelivery.status == status)
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(models.WebhookDelivery.event_kind).like(needle),
                    func.lower(models.WebhookDelivery.event_id).like(needle),
                    func.lower(models.WebhookDelivery.delivery_id).like(needle),
                )
            )
        total = session.execute(
            select(func.count()).select_from(models.WebhookDelivery).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.WebhookDelivery)
            .where(*filters)
            .order_by(direction, models.WebhookDelivery.delivery_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()
    return [_delivery_to_dict(row) for row in rows], total


def get_delivery(delivery_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookDelivery, delivery_id)
        return _delivery_to_dict(row) if row else None


def requeue_delivery(delivery_id: str) -> dict[str, Any] | None:
    """Take one delivery back out of the DLQ.

    Only ``dead`` rows are replayable (#152). A successful delivery must not
    be POSTed again through this API — that is a second notification of a
    fact the receiver already accepted. ``pending`` is returned unchanged so
    a double-click on retry is a no-op rather than a reset of the ladder.

    ``attempts`` is reset, so a redelivery gets the full retry ladder again
    rather than dying on its first failure — the operator requeues *because*
    something changed at the receiver, and the previous attempt count describes
    the old state of the world. The count that was reached is preserved in the
    log line, and every attempt is still bounded by ``webhook_max_attempts``.
    """
    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookDelivery, delivery_id)
        if row is None:
            return None
        if row.status == "pending":
            return _delivery_to_dict(row)
        if row.status != "dead":
            raise ValueError(
                f"delivery {delivery_id} is {row.status}; "
                "only dead-lettered rows can be replayed"
            )
        LOG.info(
            "Requeueing webhook delivery %s (was %s after %s attempts)",
            delivery_id,
            row.status,
            row.attempts,
        )
        row.status = "pending"
        row.attempts = 0
        row.next_attempt_at = now
        row.updated_at = now
        session.flush()
        return _delivery_to_dict(row)


def claim_visibility_seconds(*, timeout_seconds: int, batch_len: int) -> int:
    """How long a claimed batch stays off the due queue.

    The dispatcher POSTs the claimed rows serially. Each POST can take the
    full ``webhook_timeout_seconds``. A lease of ``timeout * 3`` (the old
    constant) expired in the middle of a large batch, so a second replica
    reclaimed a row still being sent and the receiver got a duplicate (#152).
    The window covers one timeout per claimed row plus two timeouts of slack,
    and is never shorter than 30s.

    This is the only place the window is computed; ``secure_webhooks._claim_due``
    is the only caller.  It briefly was not — the facade carried its own
    ``timeout * 3`` and this batch-aware formula sat on the shadowed copy of the
    loop, which is exactly the duplicate POST above (#255).
    """
    return max(30, int(timeout_seconds) * (max(int(batch_len), 1) + 2))


def backoff_seconds(attempts: int, settings: Settings) -> int:
    """Delay before attempt ``attempts + 1``, exponential and capped."""
    exponent = max(0, attempts - 1)
    # Cap the exponent before shifting: attempts is bounded by max_attempts in
    # practice, but a requeued row read from the database is not a value this
    # function should trust into a 2**large.
    exponent = min(exponent, 20)
    return min(
        settings.webhook_retry_base_seconds * (2**exponent),
        settings.webhook_retry_max_seconds,
    )


def _record_result(
    *,
    delivery_id: str,
    result: delivery_transport.DeliveryResult,
    now: datetime,
) -> str:
    """Write one attempt's outcome back. Returns the resulting status."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookDelivery, delivery_id)
        if row is None:  # pragma: no cover - deleted mid-flight
            return "gone"
        # A late POST from a duplicate claim must not un-deliver a row the
        # receiver already accepted (#152).
        if row.status == "delivered":
            return "delivered"
        row.last_status_code = result.status_code
        row.last_error = result.error
        row.updated_at = now
        if result.ok:
            row.status = "delivered"
            row.delivered_at = now
            row.next_attempt_at = None
        elif result.retryable and row.attempts < settings.webhook_max_attempts:
            row.status = "pending"
            row.next_attempt_at = now + timedelta(seconds=backoff_seconds(row.attempts, settings))
        else:
            row.status = "dead"
            row.next_attempt_at = None
        status = row.status

        subscription = session.get(models.WebhookSubscription, row.subscription_id)
        if subscription is not None:
            subscription.last_delivery_at = now
            subscription.last_status = "delivered" if result.ok else (result.error or "failed")[:200]
        session.flush()
    return status


def link_created_ticket(
    *,
    tenant_id: str,
    payload: dict[str, Any],
    transport: str,
    ticket_key: str | None,
    ticket_url: str | None,
) -> bool:
    """Attach a newly created ticket to the matching tracked finding.

    No-op when there is no finding, when the finding already has a ticket
    (an operator-set link wins), or when the adapter returned no key/url.
    Never raises: a ticket that exists in Jira must not fail the delivery
    because the tracker row is missing.
    """
    if not ticket_key and not ticket_url:
        return False
    if transport not in ticket_transport.TICKET_TRANSPORTS:
        return False
    envelope = payload.get("event") if isinstance(payload.get("event"), dict) else payload
    host = str(envelope.get("host") or "").strip()
    data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
    cve = str(data.get("cve") or envelope.get("cve") or "").strip() or None
    script_id = str(data.get("script_id") or "").strip() or None
    port = envelope.get("port")
    port_s = "" if port is None else str(port).strip()
    if not host or (not cve and not script_id):
        return False
    settings = _require_settings()
    try:
        with get_session(settings.postgres_url) as session:
            asset_ids = list(
                session.execute(
                    select(models.AssetIdentifier.asset_id).where(
                        models.AssetIdentifier.tenant_id == tenant_id,
                        func.lower(models.AssetIdentifier.identifier_value) == host.lower(),
                    )
                ).scalars().all()
            )
            if not asset_ids:
                return False
            query = select(models.Vulnerability).where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.asset_id.in_(asset_ids),
            )
            if cve:
                query = query.where(func.upper(models.Vulnerability.cve) == cve.upper())
            else:
                query = query.where(models.Vulnerability.script_id == script_id)
            if port_s:
                query = query.where(models.Vulnerability.port == port_s)
            rows = list(session.execute(query).scalars().all())
            if not rows:
                return False
            rows.sort(key=lambda row: 0 if row.state != "CLOSED" else 1)
            target = rows[0]
            if target.ticket_key or target.ticket_url:
                return False
            vuln_id = target.vuln_id
        linked = vulns_service.set_ticket(
            settings,
            tenant_id=tenant_id,
            vuln_id=vuln_id,
            system=transport,
            key=ticket_key,
            url=ticket_url,
            actor="shapoclyack",
            note="opened by ticket transport",
        )
        return linked is not None
    except Exception:  # noqa: BLE001
        LOG.warning(
            "ticket link failed transport=%s tenant=%s host=%s cve=%s",
            transport,
            tenant_id,
            host,
            cve,
            exc_info=True,
        )
        return False


def queue_depth() -> dict[str, int]:
    """Rows per status — the gauge the dispatcher reports each tick."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.WebhookDelivery.status, func.count())
            .group_by(models.WebhookDelivery.status)
        ).all()
    counts = {status: 0 for status in DELIVERY_STATUSES}
    for status, count in rows:
        counts[str(status)] = int(count)
    return counts


def prune_deliveries(*, now: datetime | None = None) -> int:
    """Delete terminal deliveries past the retention window. 0 days disables it.

    Pending rows are never pruned regardless of age: one still due is work, and
    one stuck due to a clock jump is a bug worth seeing rather than tidying
    away.
    """
    settings = _require_settings()
    days = settings.webhook_delivery_retention_days
    if days <= 0:
        return 0
    cutoff = (now or _now()) - timedelta(days=days)
    with get_session(settings.postgres_url) as session:
        result = session.execute(
            delete(models.WebhookDelivery).where(
                models.WebhookDelivery.status.in_(("delivered", "dead")),
                models.WebhookDelivery.updated_at < cutoff,
            )
        )
    deleted = int(result.rowcount or 0)
    if deleted:
        LOG.info("Pruned %s webhook deliveries older than %s days", deleted, days)
    return deleted
