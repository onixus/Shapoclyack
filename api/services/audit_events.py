"""Publishing the administrative audit trail onto the event bus (#328).

#327 gave the platform a trail: ``audit_events`` rows written **in the same
transaction as the change they describe**, readable through ``GET /api/audit``.
That is the source of truth and stays the source of truth. What it is not is a
feed — a SIEM cannot poll a paginated console endpoint, and an operator who
wanted a webhook when a role changes had five asset events to choose from and
nothing else (``asset_events.EVENT_KINDS``).

This module is the publish side of that row. Subject::

    events.audit.{tenant_token}

Same shape and the same encoder as ``events.asset.{tenant}.{kind}``, for the
same reason: a routing policy or a NATS ACL is per-tenant first. There is no
kind token after the tenant, unlike the asset subjects — an audit action is a
dotted verb (``user.role_change``) and putting it in the subject would make
every new action a new subject token for every ACL to learn. The action travels
in the envelope, and the envelope's ``kind`` is ``audit.<action>``, which is
what a webhook subscription filters on.

A row whose ``tenant_id`` is NULL is a platform-level act — creating a console
account, changing installation-wide config — and publishes under the reserved
token ``_platform``. ``tenants._validate_tenant_id`` requires an id to start
with an alphanumeric, so no real tenant can ever claim that subject.

**Published after the commit, never before it.** :func:`arm` hangs three
listeners on the caller's :class:`~sqlalchemy.orm.Session`: ``after_flush``
snapshots the rows the flush inserted (their ids exist by then),
``after_commit`` publishes those snapshots, ``after_soft_rollback`` throws them
away. A change that rolled back therefore emits nothing, and a change that
committed emits exactly what the database kept. The reverse order — publish,
then commit — would have made the bus the thing that lies.

**A broker that is down loses a notification, never a row.** Publication is
best-effort exactly like ``asset_events``: the failure is counted on
``octo_audit_events_published_total{outcome="error"|"skipped"}`` and logged at
WARNING, and the row is already committed. A failed connection is also
*remembered* for :data:`_BROKER_RETRY_SECONDS` — unlike the asset events, these
are published from administrative requests, and re-discovering an unreachable
broker costs ten seconds of somebody's ``PATCH /api/users/{id}/role``. With ``OCTO_NATS_URL`` unset nothing
is published at all — the honest statement being that such an installation has
no event bus, so its audit trail is readable over the API and forwardable by
``api.services.audit_syslog_forwarder`` in its ``db`` mode, and nowhere else.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

from sqlalchemy import event as sa_event

from api.db import models
from api.services import metrics, nats_bus
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.audit_events")

#: Envelope ``kind`` prefix. ``audit.user.role_change`` and friends.
KIND_PREFIX = "audit."
#: The subscription form that means "every audit action". A subscription may
#: also name one exact kind (``audit.user.delete``); see
#: ``webhooks._validate_event_kinds``.
KIND_WILDCARD = "audit.*"

#: Subject token for a row with no tenant — a platform-level act. Defined by
#: ``nats_bus`` because that is where the subject is built; re-exported here so
#: a reader of this module does not have to go looking.
PLATFORM_SUBJECT_TENANT = nats_bus.PLATFORM_SUBJECT_TENANT

#: Ceiling on one commit's publish loop. This runs inside the request that made
#: the change, after its transaction closed, so a broker that accepts
#: connections and then fails every publish must not hold the response open.
#: One request writes one or two audit rows, so the bound is a backstop.
PUBLISH_DEADLINE_SECONDS = 5.0

# One retry, like asset_events: the row is already durable and the envelope is
# content-deduped by JetStream, so a slow retry ladder costs the request more
# than the notification is worth.
_PUBLISH_RETRIES = 1

#: How long a failed broker lookup is remembered. ``nats_bus.get_bus`` does not
#: cache a failure, and reaching an unreachable broker costs it its connect and
#: stream budget — about ten seconds — every time it is asked. Audit rows are
#: written by administrative requests, so without this a broker that is down
#: adds that to *every* role change, token issue and user create until it comes
#: back. One request pays it; the ones in the next half minute do not.
_BROKER_RETRY_SECONDS = 30.0

# Key under which the pending snapshots live on ``Session.info``, and the flag
# that keeps :func:`arm` from stacking a second set of listeners on a session
# that records more than one change.
_PENDING_KEY = "shapoclyack_audit_events_pending"
_ARMED_KEY = "shapoclyack_audit_events_armed"

_settings: Settings | None = None
# Monotonic deadline before which the broker is assumed still down. Plain
# module state and deliberately unlocked: a race costs one extra connect
# attempt, and a lock here would be held across that attempt.
_broker_down_until: float = 0.0


def configure(settings: Settings) -> None:
    global _settings, _broker_down_until
    _settings = settings
    # A reconfiguration is a new URL as far as this is concerned; the old one's
    # verdict says nothing about it.
    _broker_down_until = 0.0


def _nats_url() -> str:
    return (_settings.nats_url or "").strip() if _settings is not None else ""


def event_kind(action: str) -> str:
    """``user.role_change`` → ``audit.user.role_change``."""
    return f"{KIND_PREFIX}{action}"


def subject_tenant(tenant_id: str | None) -> str:
    """The subject token for a row's tenant, or the platform token for NULL."""
    return (tenant_id or "").strip() or PLATFORM_SUBJECT_TENANT


def event_id(row: models.AuditEvent) -> str:
    """Stable identity for one audit row, used as the JetStream ``Nats-Msg-Id``.

    Keyed on the primary key, which is what makes it stable: the row is
    append-only (#329) and its id is never reused, so a republish of the same
    row — a retried commit hook, a replay out of ``db`` mode — is dropped inside
    the stream's duplicate window instead of paging someone twice. The tenant
    is folded in so the id is not derivable across tenants from a row count
    alone.
    """
    raw = f"{subject_tenant(row.tenant_id)}|{row.id}|{row.action}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


def build_envelope(row: models.AuditEvent) -> dict[str, Any]:
    """One committed audit row as a bus envelope.

    Shaped like the asset envelope on purpose — ``kind``/``tenant_id``/
    ``event_id``/``occurred_at``/``source``/``data`` — so
    ``webhooks.enqueue_event`` and ``webhooks.matches`` need no second code
    path, and a receiver that already parses one parses the other.

    ``before``/``after`` are copied as they are stored, which is to say already
    redacted and size-capped by :func:`api.services.audit.record`. Nothing here
    re-reads the resource.
    """
    return {
        "kind": event_kind(row.action or ""),
        "tenant_id": row.tenant_id,
        "event_id": event_id(row),
        "occurred_at": (row.occurred_at.isoformat() + "Z") if row.occurred_at else None,
        "source": "audit",
        "data": {
            "audit_id": row.id,
            "action": row.action,
            "actor": row.actor,
            "actor_type": row.actor_type,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "before": row.before,
            "after": row.after,
            "client_ip": row.client_ip,
            "user_agent": row.user_agent,
            "request_id": row.request_id,
        },
    }


def arm(session) -> None:
    """Make ``session`` publish its audit rows once they are committed.

    Idempotent per session, and the flag that makes it so is never cleared:
    :func:`api.services.audit.record` calls this on every row, and a request
    that changes three things must not end up with three copies of the same
    listener publishing three copies of each event. Clearing the flag on
    rollback would reopen exactly that, since the session lives on and the
    listeners hung on it do too.
    """
    if session.info.get(_ARMED_KEY):
        return
    session.info[_ARMED_KEY] = True
    sa_event.listen(session, "after_flush", _after_flush)
    sa_event.listen(session, "after_commit", _after_commit)
    sa_event.listen(session, "after_soft_rollback", _after_soft_rollback)


def _after_flush(session, _flush_context) -> None:
    """Snapshot the audit rows this flush inserted, ids and all.

    ``after_flush`` rather than ``after_commit``: by the time the commit hook
    runs ``session.new`` is empty and there is nothing left to enumerate, while
    at this point the INSERTs have run and the primary keys are populated.
    Snapshotting to plain dicts here also means the publish never touches a
    detached ORM object.
    """
    pending = session.info.setdefault(_PENDING_KEY, [])
    for obj in session.new:
        if isinstance(obj, models.AuditEvent):
            pending.append(build_envelope(obj))


def _after_commit(session) -> None:
    envelopes = session.info.pop(_PENDING_KEY, None)
    if not envelopes:
        return
    publish_envelopes(_nats_url(), envelopes)


def _after_soft_rollback(session, _previous_transaction) -> None:
    """Drop what the rolled-back transaction would have announced.

    ``after_soft_rollback`` covers the real rollback and the SAVEPOINT one
    alike. Over-clearing is the safe direction: a dropped event is a missed
    notification, an event published for a change that never landed is a trail
    that lies.
    """
    session.info.pop(_PENDING_KEY, None)


def publish_envelopes(
    nats_url: str,
    envelopes: list[dict[str, Any]],
    *,
    deadline_seconds: float = PUBLISH_DEADLINE_SECONDS,
) -> int:
    """Publish audit envelopes to ``events.audit.{tenant}``. Returns the count published.

    Never raises. The caller is a commit hook inside somebody's request and the
    change it describes is already durable — there is no failure here worth
    turning into a 500.
    """
    global _broker_down_until
    if not envelopes:
        return 0
    if nats_url and time.monotonic() < _broker_down_until:
        # Known down, and re-establishing that would cost this request ten
        # seconds it cannot spend. Counted as skipped, exactly like the attempt
        # that discovered it.
        for _ in envelopes:
            metrics.AUDIT_EVENTS_PUBLISHED_TOTAL.labels(outcome="skipped").inc()
        LOG.debug(
            "Skipping %s audit events: the broker was unreachable less than %.0fs ago",
            len(envelopes),
            _BROKER_RETRY_SECONDS,
        )
        return 0
    bus = nats_bus.get_bus(nats_url) if nats_url else None
    if bus is None:
        for _ in envelopes:
            metrics.AUDIT_EVENTS_PUBLISHED_TOTAL.labels(outcome="skipped").inc()
        if nats_url:
            _broker_down_until = time.monotonic() + _BROKER_RETRY_SECONDS
            LOG.warning(
                "NATS is configured but unavailable; %s audit events were not published "
                "and the next %.0fs of them will be skipped without retrying "
                "(the rows are committed and readable via GET /api/audit)",
                len(envelopes),
                _BROKER_RETRY_SECONDS,
            )
        return 0
    _broker_down_until = 0.0

    started = time.monotonic()
    published = 0
    for index, envelope in enumerate(envelopes):
        if time.monotonic() - started > deadline_seconds:
            LOG.warning(
                "Audit event publish exceeded %.0fs; abandoning %s of %s events",
                deadline_seconds,
                len(envelopes) - index,
                len(envelopes),
            )
            for _ in envelopes[index:]:
                metrics.AUDIT_EVENTS_PUBLISHED_TOTAL.labels(outcome="skipped").inc()
            break
        try:
            ok = bus.publish_audit_event(envelope, retries=_PUBLISH_RETRIES)
        except Exception:  # noqa: BLE001 - a notification must not fail the request
            LOG.exception("Audit event publish raised (kind=%s)", envelope.get("kind"))
            ok = False
        if not ok:
            LOG.warning(
                "Audit event %s (%s) was not published; the row is committed",
                envelope.get("event_id"),
                envelope.get("kind"),
            )
        metrics.AUDIT_EVENTS_PUBLISHED_TOTAL.labels(
            outcome="published" if ok else "error"
        ).inc()
        published += int(ok)
    return published
