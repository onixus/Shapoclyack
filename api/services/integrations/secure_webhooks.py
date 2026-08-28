"""Security boundary for webhook subscription reads and queue dispatch.

The Phase 10.3 implementation predates the P0 hardening in #151.  Keeping the
security policy in this small facade avoids duplicating the queue model while
making two invariants explicit at the package boundary:

* configured header *values* are write-only, just like the signing secret;
* a disabled subscription cannot be claimed or sent from the queued backlog.

Everything not overridden here is delegated to the original ``webhooks``
module.  The package exports this facade as ``webhooks`` so existing callers do
not need a second API surface.
"""

from __future__ import annotations

import importlib
import logging
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import metrics
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import tickets as ticket_transport

_base = importlib.import_module("api.services.integrations.webhooks")
LOG = logging.getLogger("shapoclyack.webhooks")

_REDACTED = "***"


def __getattr__(name: str) -> Any:
    """Delegate the unchanged Phase 10.3 surface to the base module."""
    return getattr(_base, name)


def _redact_subscription(value: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy whose configured header values cannot leave the service."""
    if value is None:
        return None
    result = dict(value)
    configured_headers = result.get("headers") or {}
    if isinstance(configured_headers, dict):
        result["headers"] = {str(name): _REDACTED for name in configured_headers}
    else:  # Defensive: the DB column is JSON and old/manual rows may be malformed.
        result["headers"] = {}
    return result


def create_subscription(*args: Any, **kwargs: Any) -> dict[str, Any]:
    result = _base.create_subscription(*args, **kwargs)
    redacted = _redact_subscription(result)
    assert redacted is not None
    return redacted


def get_subscription(subscription_id: str) -> dict[str, Any] | None:
    return _redact_subscription(_base.get_subscription(subscription_id))


def list_subscriptions(*args: Any, **kwargs: Any) -> tuple[list[dict[str, Any]], int]:
    items, total = _base.list_subscriptions(*args, **kwargs)
    return [item for value in items if (item := _redact_subscription(value)) is not None], total


def update_subscription(subscription_id: str, **fields: Any) -> dict[str, Any] | None:
    return _redact_subscription(_base.update_subscription(subscription_id, **fields))


def rotate_secret(subscription_id: str) -> dict[str, Any] | None:
    return _redact_subscription(_base.rotate_secret(subscription_id))


def _claim_due(session: Any, *, now: datetime, limit: int) -> list[models.WebhookDelivery]:
    """Claim only deliveries whose subscription is enabled at claim time.

    ``of=`` is load-bearing (#238). A bare ``FOR UPDATE SKIP LOCKED`` over this
    join locks the *subscription* row too, and every delivery of a subscription
    shares one such row. One dispatcher holding it made the whole backlog
    invisible to its peers — and worse, the peer locked each delivery tuple
    before reaching the locked subscription tuple, so ``SKIP LOCKED`` dropped
    the joined row while the delivery lock stayed held for the rest of that
    transaction. Those rows were then claimed by nobody and sent by nobody:
    the opposite of the "replicas divide the queue" guarantee in #152.
    Restricting the lock to ``webhook_deliveries`` keeps the kill switch's
    enabled-at-claim-time filter while leaving the subscription row unlocked.

    The visibility window comes from ``_base.claim_visibility_seconds`` and
    scales with the size of the batch: the rows are POSTed serially, so a fixed
    lease expires mid-batch on a large one and hands a row still being sent to
    the next replica (#255).
    """
    settings = _base._require_settings()
    rows = session.execute(
        select(models.WebhookDelivery)
        .join(
            models.WebhookSubscription,
            models.WebhookSubscription.subscription_id == models.WebhookDelivery.subscription_id,
        )
        .where(
            models.WebhookDelivery.status == "pending",
            models.WebhookDelivery.next_attempt_at <= now,
            models.WebhookSubscription.enabled.is_(True),
        )
        .order_by(models.WebhookDelivery.next_attempt_at)
        .limit(limit)
        .with_for_update(skip_locked=True, of=models.WebhookDelivery)
    ).scalars().all()

    visibility = timedelta(
        seconds=_base.claim_visibility_seconds(
            timeout_seconds=settings.webhook_timeout_seconds,
            batch_len=len(rows),
        )
    )
    for row in rows:
        row.attempts += 1
        row.next_attempt_at = now + visibility
        row.updated_at = now
    session.flush()
    return rows


def _subscription_snapshot(
    subscription_id: str,
) -> tuple[str, str | None, dict[str, Any], str, dict[str, Any]] | None:
    """Load the latest enabled target immediately before a wire attempt."""
    settings = _base._require_settings()
    with get_session(settings.postgres_url) as session:
        subscription = session.get(models.WebhookSubscription, subscription_id)
        if subscription is None or not subscription.enabled:
            return None
        return (
            subscription.url,
            subscription.secret,
            dict(subscription.headers or {}),
            subscription.transport or "webhook",
            dict(subscription.transport_config or {}),
        )


def _subscription_is_enabled(subscription_id: str) -> bool:
    settings = _base._require_settings()
    with get_session(settings.postgres_url) as session:
        subscription = session.get(models.WebhookSubscription, subscription_id)
        return bool(subscription is not None and subscription.enabled)


def _release_claim(*delivery_ids: str, now: datetime) -> None:
    """Undo the attempt bookkeeping for claims that never became a send.

    Two callers, one invariant: a claim that did not reach the wire must not
    cost retry budget and must not sit out the visibility window.

    * the #151 kill switch won the claim/send race — while the subscription is
      disabled the joined claim query ignores the row anyway, so re-enabling
      resumes the backlog on the next tick;
    * the batch aborted before this row was reached (#256).

    The rows remain pending and due, in one transaction for the whole set.
    """
    if not delivery_ids:
        return
    settings = _base._require_settings()
    with get_session(settings.postgres_url) as session:
        for delivery_id in delivery_ids:
            row = session.get(models.WebhookDelivery, delivery_id)
            if row is None or row.status != "pending":
                continue
            row.attempts = max(0, row.attempts - 1)
            row.next_attempt_at = now
            row.updated_at = now
        session.flush()


def dispatch_once(
    *,
    limit: int | None = None,
    post: Callable[..., delivery_transport.DeliveryResult] | None = None,
) -> dict[str, int]:
    """Dispatch one queue batch while enforcing the subscription kill switch.

    Raises whatever the loop raised, but never at the cost of the batch: the
    claims this tick did not get to are released back to the queue first
    (#256).
    """
    settings = _base._require_settings()
    send = post or delivery_transport.post
    outcome = {"attempted": 0, "delivered": 0, "retrying": 0, "dead": 0}

    now = _base._now()
    claimed: list[tuple[str, str, dict[str, Any], str, str, str]] = []
    with get_session(settings.postgres_url) as session:
        for row in _claim_due(
            session,
            now=now,
            limit=limit or settings.webhook_dispatch_batch_size,
        ):
            claimed.append(
                (
                    row.delivery_id,
                    row.subscription_id,
                    dict(row.payload or {}),
                    row.tenant_id,
                    row.event_kind,
                    row.event_id,
                )
            )

    # The claim is a lease over the whole batch, so a failure anywhere in the
    # loop — recording an outcome, a metric, the ticket back-link — strands
    # every row not reached yet: claimed, unsent, and invisible until the
    # window expires (#256).  Pop as we go so the tail is exactly the rows this
    # tick never attempted, and hand them back through the same release path
    # the kill switch uses.  The row that raised stays claimed on purpose: its
    # POST may well have arrived, and re-sending it now is the duplicate #152
    # forbids.  Its window still expires, so it is retried, just not blindly.
    remaining = list(claimed)
    try:
        while remaining:
            claim = remaining.pop(0)
            delivery_id, subscription_id, payload, tenant_id, event_kind, event_id = claim
            snapshot = _subscription_snapshot(subscription_id)
            if snapshot is None:
                _release_claim(delivery_id, now=_base._now())
                continue

            url, secret, headers, transport, transport_config = snapshot
            try:
                # Narrow the remaining disable race to the actual wire call.  We do
                # not keep a database transaction open across network I/O: that
                # would turn a receiver timeout into a pool-exhaustion primitive.
                if not _subscription_is_enabled(subscription_id):
                    _release_claim(delivery_id, now=_base._now())
                    continue

                outcome["attempted"] += 1
                if transport in ticket_transport.TICKET_TRANSPORTS:
                    result = ticket_transport.deliver(
                        transport=transport,
                        base_url=url,
                        payload=payload,
                        secret=secret,
                        extra_headers=headers,
                        config=transport_config,
                        timeout_seconds=settings.webhook_timeout_seconds,
                        allow_private=settings.webhook_allow_private_targets,
                        post_fn=send,
                    )
                else:
                    body, request_headers = delivery_transport.build_request(
                        payload=payload,
                        secret=secret,
                        extra_headers=headers,
                        delivery_id=delivery_id,
                        tenant_id=tenant_id,
                        event_kind=event_kind,
                        event_id=event_id,
                    )
                    result = send(
                        url,
                        body,
                        request_headers,
                        timeout_seconds=settings.webhook_timeout_seconds,
                        allow_private=settings.webhook_allow_private_targets,
                    )
            except Exception as exc:  # noqa: BLE001 - one bad receiver must not stall the queue
                LOG.exception("Webhook delivery %s raised before/while sending", delivery_id)
                outcome["attempted"] += 1
                result = delivery_transport.DeliveryResult(
                    ok=False,
                    status_code=None,
                    error=f"{type(exc).__name__}: {exc}"[:500],
                    retryable=False,
                )

            metrics.WEBHOOK_DELIVERY_DURATION_SECONDS.observe(result.duration_seconds)
            status = _base._record_result(delivery_id=delivery_id, result=result, now=_base._now())
            if status == "delivered":
                outcome["delivered"] += 1
                metrics.WEBHOOK_DELIVERIES_TOTAL.labels(outcome="delivered").inc()
                if transport in ticket_transport.TICKET_TRANSPORTS:
                    _base.link_created_ticket(
                        tenant_id=tenant_id,
                        payload=payload,
                        transport=transport,
                        ticket_key=result.ticket_key,
                        ticket_url=result.ticket_url,
                    )
            elif status == "pending":
                outcome["retrying"] += 1
                metrics.WEBHOOK_DELIVERIES_TOTAL.labels(outcome="retrying").inc()
            elif status == "dead":
                outcome["dead"] += 1
                metrics.WEBHOOK_DELIVERIES_TOTAL.labels(outcome="dead").inc()
                LOG.warning(
                    "Webhook delivery %s dead-lettered (kind=%s status_code=%s error=%s)",
                    delivery_id,
                    event_kind,
                    result.status_code,
                    result.error,
                )
    except Exception:  # noqa: BLE001 - re-raised below, the queue must not keep the tail
        LOG.exception(
            "Webhook dispatch batch aborted at delivery %s, releasing %d unattempted claims",
            delivery_id,
            len(remaining),
        )
        _release_claim(*(claim[0] for claim in remaining), now=_base._now())
        raise

    return outcome
