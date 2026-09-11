"""Remediation-workflow events on the webhook machine (#349).

Phase 10.2 gave the platform five *discovery* events — a new asset, a new open
port, a new CVE, an expiring certificate, a decommissioned host
(``asset_events.EVENT_KINDS``) — and 10.3 a delivery queue for them. What no
event described was the work that follows a finding: nobody was told when a
remediation deadline was about to pass or had passed, when an accepted risk was
about to expire, when a finding changed hands, when a scan failed, when a
report was ready, or when an agent went quiet. An operator could see every one
of those by opening the console, and only by opening the console.

These are the eight kinds that close that gap. They travel the *same* envelope
shape as the asset and audit events (``kind``/``tenant_id``/``event_id``/
``occurred_at``/``source``/``data``), so ``webhooks.enqueue_event``,
``webhooks.matches`` and every receiver that already parses one parses these
too.

**Queued directly, published to the bus as well.** An asset event is built by
the scanner and reaches the queue over JetStream, because the scanner has no
database and in agent mode no tenant either. A workflow event has neither
problem: every one of them is produced inside the API, in a process that is
already holding the connection ``webhook_deliveries`` lives on. So
:func:`emit` writes the queue itself — the way ``POST /webhooks/{id}/test``
already does — and *then* publishes to ``events.workflow.{tenant}.{kind}`` for
the consumers that are not webhooks (a SIEM, another tool on the bus). Two
consequences, both wanted:

* an installation with no ``OCTO_NATS_URL`` still gets its SLA notifications,
  which would not be true if the bus were on the delivery path;
* there is no third JetStream fan-out consumer to deploy, and therefore no
  ``filter_subject`` widening of the two that exist (#152).

**Opt-in per subscription.** A subscription with an empty ``event_kinds`` means
"every asset event" and deliberately keeps meaning exactly that: a receiver
somebody configured for new criticals must not start taking a message every
time an operator reassigns a finding because a version was bumped. Naming a
kind is how a tenant asks for these — the same rule #328 set for the audit
trail, for the same reason.

**Nothing here can fail its caller, and nothing here can make it wait.**
:func:`emit` is called from inside an operator's request (a transition, an
assignment) and from a worker tick; the change it describes is already
committed by the time it runs. Every failure is counted on
``octo_workflow_events_total`` and logged, and none of them propagates — a
missed notification is not a reason to answer 500 for a transition that
happened. Cost matters as much as propagation: a broker that will not answer
is *remembered* for :data:`_BROKER_RETRY_SECONDS`, because re-establishing a
connection that is not there costs ten seconds and an operator's request has
none to spend (the guard #328 wrote for the audit events, ``audit_events``).

**A claim covers work that happened.** :func:`emit_once` claims an occurrence
before announcing it and gives the claim back with :func:`release` if the
fan-out failed, so a notification lost to a database hiccup is retried by the
next tick rather than suppressed until the marker is pruned.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import metrics, nats_bus
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.workflow_events")

#: The eight kinds #349 names. Validated against on the subscription side, and
#: a token in the bus subject, so an unknown kind is refused rather than
#: allowed to invent a subject.
WORKFLOW_EVENT_KINDS = (
    "sla_due_soon",
    "sla_breached",
    "exception_expiring",
    "vuln_state_changed",
    "vuln_assigned",
    "scan_failed",
    "report_generated",
    "agent_offline",
)

#: Kinds whose ``data`` carries a finding's ``severity``, and which are
#: therefore subject to a subscription's ``min_severity``. The other three are
#: not about a finding at all: filtering a failed scan or an offline agent by
#: CVSS would drop it silently for every "critical only" subscription.
SEVERITY_BEARING_KINDS = (
    "sla_due_soon",
    "sla_breached",
    "exception_expiring",
    "vuln_state_changed",
    "vuln_assigned",
)

#: Marker ``kind`` used by the escalation worker's daily digest. Not an event
#: kind — it never leaves the platform — but it is claimed once per recipient
#: per day through the same table, so it lives next to the kinds it shares a
#: constraint with.
MARKER_KIND_DIGEST = "owner_digest"

#: Marker ``kind`` used by the escalation worker for the escalation *write*
#: (reassign, severity bump), as opposed to the ``sla_breached`` event that
#: reports it. Also not an event kind: it exists so the write happens once per
#: breached deadline rather than on every tick, which is the difference between
#: "escalated once" and "taken back off whoever picked it up, every fifteen
#: minutes".
MARKER_KIND_ESCALATION = "sla_escalated"

# One retry, as in ``asset_events``: the delivery row is already durable and
# the envelope is content-deduped by JetStream, so a slow retry ladder buys
# nothing an operator would notice.
_PUBLISH_RETRIES = 1

#: How long an unreachable broker is remembered, and the same guard #328 put in
#: ``audit_events.publish_envelopes`` — for a sharper reason here. Every
#: emitter in this module sits on a write path: an operator's transition, an
#: agent posting its results, a report, and a worker tick with up to
#: ``OCTO_SLA_ESCALATION_MAX_FINDINGS`` findings in it. ``nats_bus.get_bus``
#: caches only success, so with ``OCTO_NATS_URL`` set and the broker down every
#: single publish would re-run ``NatsBus.start()`` and spend
#: ``connect_timeout + _STREAM_BUDGET + 5`` seconds on it — ten seconds an
#: operator's request does not have, and 500 of them in one tick that holds the
#: leader lock. So the first failure is remembered and the publishes in the
#: window after it are skipped without retrying. The webhook queue row is
#: written before this and is unaffected.
_BROKER_RETRY_SECONDS = 30.0

#: ``(url, monotonic deadline)`` of the last broker that would not answer.
_broker_down: tuple[str, float] = ("", 0.0)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def event_id(*, tenant_id: str, kind: str, subject_id: str, marker: str = "") -> str:
    """Stable identity for one occurrence, used as the ``Nats-Msg-Id`` and the
    de-duplication key of ``webhook_deliveries``.

    Content-derived rather than randomised, exactly like the asset events, and
    for a sharper reason here: :func:`emit` writes the queue *and* publishes to
    the bus, so a consumer that fans the bus back into the same queue must land
    on the row that already exists instead of creating a second one.

    ``marker`` is what makes two occurrences of the same predicate distinct —
    the deadline for an SLA event, the report id for a generated report, the
    change timestamp for a transition. Two events with the same marker are the
    same event said twice.
    """
    raw = f"{tenant_id}|{kind}|{subject_id}|{marker}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


def build_envelope(
    *,
    kind: str,
    tenant_id: str,
    subject_id: str,
    marker: str = "",
    data: dict[str, Any] | None = None,
    source: str = "workflow",
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    """One workflow event as a bus/webhook envelope.

    ``subject_id`` is top-level because it is the one field every consumer
    needs and no two kinds spell differently: a vuln_id, a job_id, a
    report_id, an agent_id. Everything kind-specific stays under ``data``, so a
    receiver reading ``sla_breached`` does not have to guess which top-level
    keys belong to ``agent_offline``.
    """
    return {
        "kind": kind,
        "tenant_id": tenant_id,
        "event_id": event_id(
            tenant_id=tenant_id, kind=kind, subject_id=subject_id, marker=marker
        ),
        "subject_id": subject_id,
        "occurred_at": _iso(occurred_at or _now()),
        "source": source,
        "data": dict(data or {}),
    }


def emit(
    settings: Settings,
    kind: str,
    *,
    tenant_id: str | None,
    subject_id: str,
    marker: str = "",
    data: dict[str, Any] | None = None,
    source: str = "workflow",
    occurred_at: datetime | None = None,
) -> bool:
    """Queue one workflow event for the tenant's webhooks, and publish it.

    Returns whether anything was queued *or* published; ``False`` is the
    ordinary answer for a tenant with no matching subscription and no broker,
    which is not a failure. Never raises — see the module docstring.
    """
    return _emit(
        settings,
        kind,
        tenant_id=tenant_id,
        subject_id=subject_id,
        marker=marker,
        data=data,
        source=source,
        occurred_at=occurred_at,
    )[0]


def _emit(
    settings: Settings,
    kind: str,
    *,
    tenant_id: str | None,
    subject_id: str,
    marker: str = "",
    data: dict[str, Any] | None = None,
    source: str = "workflow",
    occurred_at: datetime | None = None,
) -> tuple[bool, bool]:
    """The body of :func:`emit`, reporting the fan-out failure separately.

    Returns ``(delivered, failed)``. :func:`emit_once` needs the second half:
    a claim it has taken for an event that then failed to reach the queue has
    to be given back, or the occurrence is suppressed until the marker is
    pruned.
    """
    tenant = (tenant_id or "").strip()
    if not settings.workflow_events_enabled or not tenant:
        return False, False
    if kind not in WORKFLOW_EVENT_KINDS:
        # A subject token is built from this value, so an unvalidated kind
        # would let a caller's typo create its own subject tree.
        LOG.error("Refusing to emit unknown workflow event kind %r", kind)
        return False, False

    envelope = build_envelope(
        kind=kind,
        tenant_id=tenant,
        subject_id=subject_id,
        marker=marker,
        data=data,
        source=source,
        occurred_at=occurred_at,
    )
    queued = _enqueue(envelope)
    published = _publish(settings, envelope)
    if queued is None:
        outcome = "error"
    elif queued:
        outcome = "queued"
    else:
        outcome = "no_subscription"
    metrics.WORKFLOW_EVENTS_TOTAL.labels(kind=kind, outcome=outcome).inc()
    return bool(queued or published), queued is None


def _enqueue(envelope: dict[str, Any]) -> int | None:
    """Fan the envelope out to ``webhook_deliveries``. Returns rows created.

    ``None`` is the fan-out having failed, which the caller reports as
    ``outcome="error"`` — distinct from ``0``, a tenant with no matching
    subscription, which is the ordinary case.

    Imported inside the function because ``webhooks`` imports this module for
    its kind vocabulary — the same shape as
    ``vulnerabilities._ticket_endpoint``, and for the same reason.
    """
    from api.services.integrations import webhooks as webhooks_service

    try:
        return len(webhooks_service.enqueue_event(envelope))
    except Exception:  # noqa: BLE001 - a notification must not fail its caller
        # Reached in two real cases: the webhooks service was never configured
        # (a service-level test that builds no app), and a database error on
        # the fan-out. Neither is a reason to fail the transition, the scan or
        # the worker tick that produced the event.
        LOG.exception(
            "Could not queue workflow event %s (%s)",
            envelope.get("event_id"),
            envelope.get("kind"),
        )
        return None


def _publish(settings: Settings, envelope: dict[str, Any]) -> bool:
    """Best-effort publish to ``events.workflow.{tenant}.{kind}``.

    Off the notification path on purpose (the queue row above is the
    notification), so an unreachable broker costs an off-bus consumer one
    event and costs the tenant's webhooks nothing — provided it does not cost
    the caller ten seconds per event, which is what :data:`_BROKER_RETRY_SECONDS`
    is for.
    """
    global _broker_down
    nats_url = (settings.nats_url or "").strip()
    if not nats_url:
        return False
    down_url, down_until = _broker_down
    if nats_url == down_url and time.monotonic() < down_until:
        LOG.debug(
            "Skipping the bus copy of workflow event %s: the broker was "
            "unreachable less than %.0fs ago",
            envelope.get("event_id"),
            _BROKER_RETRY_SECONDS,
        )
        return False
    try:
        bus = nats_bus.get_bus(nats_url)
        if bus is None:
            _broker_down = (nats_url, time.monotonic() + _BROKER_RETRY_SECONDS)
            LOG.warning(
                "NATS is configured but unavailable; workflow event %s was not "
                "published and the next %.0fs of them will be skipped without "
                "retrying (the webhook deliveries are queued regardless)",
                envelope.get("event_id"),
                _BROKER_RETRY_SECONDS,
            )
            return False
        _broker_down = ("", 0.0)
        return bool(bus.publish_workflow_event(envelope, retries=_PUBLISH_RETRIES))
    except Exception:  # noqa: BLE001 - see the module docstring
        _broker_down = (nats_url, time.monotonic() + _BROKER_RETRY_SECONDS)
        LOG.warning(
            "Workflow event %s was not published to the bus; it is queued for webhooks",
            envelope.get("event_id"),
            exc_info=True,
        )
        return False


# --------------------------------------------------------------------------
# Once-only markers
# --------------------------------------------------------------------------


def claim(
    settings: Settings,
    *,
    tenant_id: str,
    kind: str,
    subject_id: str,
    marker: str = "",
    now: datetime | None = None,
) -> bool:
    """Record that this occurrence is being announced. ``False`` if it already was.

    The INSERT is the claim (``models.WorkflowEventMarker``): the unique
    constraint decides, so two replicas that both believe they lead announce it
    once between them. Raising here would abort the worker's tick, so a
    database error is treated as "somebody else has it" — the failure direction
    that under-notifies rather than the one that pages a tenant in a loop. That
    is not a lasting loss: an INSERT that failed left no marker, so the next
    tick asks again.

    A claim taken for work that then did not happen is given back with
    :func:`release`.
    """
    stamp = now or _now()
    row = models.WorkflowEventMarker(
        marker_id=f"wem_{uuid.uuid4().hex[:16]}",
        tenant_id=tenant_id,
        kind=kind,
        subject_id=subject_id,
        marker=marker,
        created_at=stamp.replace(tzinfo=None),
    )
    try:
        with get_session(settings.postgres_url) as session:
            return insert_if_absent(session, row, f"{tenant_id}:{kind}:{subject_id}:{marker}")
    except Exception:  # noqa: BLE001 - see above
        LOG.exception(
            "Could not claim workflow marker %s/%s for %s", kind, marker, subject_id
        )
        return False


def release(
    settings: Settings,
    *,
    tenant_id: str,
    kind: str,
    subject_id: str,
    marker: str = "",
) -> bool:
    """Give a claim back, so a later tick may take it again. Rows deleted > 0.

    The counterpart to :func:`claim`, for the two places where the work the
    claim covers did not happen: a fan-out that raised (:func:`emit_once`) and
    a digest the relay refused (``sla_escalation._send_digests``). Without it
    the table records "already announced" for something nobody was told about,
    and the occurrence stays suppressed until ``prune_markers`` reaches it —
    ``OCTO_WORKFLOW_MARKER_RETENTION_DAYS`` later, a year by default.

    Never raises, for the same reason :func:`claim` does not; a release that
    fails leaves the claim standing, which is the direction that repeats
    nothing.
    """
    try:
        with get_session(settings.postgres_url) as session:
            result = session.execute(
                delete(models.WorkflowEventMarker).where(
                    models.WorkflowEventMarker.tenant_id == tenant_id,
                    models.WorkflowEventMarker.kind == kind,
                    models.WorkflowEventMarker.subject_id == subject_id,
                    models.WorkflowEventMarker.marker == marker,
                )
            )
    except Exception:  # noqa: BLE001 - see above
        LOG.exception(
            "Could not release workflow marker %s/%s for %s", kind, marker, subject_id
        )
        return False
    return bool(result.rowcount or 0)


def emit_once(
    settings: Settings,
    kind: str,
    *,
    tenant_id: str,
    subject_id: str,
    marker: str,
    event_marker: str | None = None,
    data: dict[str, Any] | None = None,
    source: str = "workflow",
    now: datetime | None = None,
) -> bool:
    """Claim the occurrence and emit it, or do nothing if it was already said.

    Claim first, then emit. The other order would announce the event and then
    discover it had already been announced, which is the duplicate this table
    exists to prevent.

    A fan-out that *failed* gives the claim back, so the occurrence is
    announced by the next tick instead of staying suppressed for
    ``OCTO_WORKFLOW_MARKER_RETENTION_DAYS``. What remains uncovered is a
    process killed between the claim and the emit — one notification, and a
    lost notification is the cheaper failure than a loop of duplicates.

    ``event_marker`` keys the *envelope* differently from the claim, for the
    one kind where the two are not the same question: ``agent_offline`` is
    claimed per agent (the episode of silence, held until the agent is back)
    and emitted per ``last_seen_at`` (the beat it fell silent after), so two
    episodes are two envelopes on the bus rather than one said twice. It
    defaults to ``marker``, which is every other caller.
    """
    if not claim(
        settings,
        tenant_id=tenant_id,
        kind=kind,
        subject_id=subject_id,
        marker=marker,
        now=now,
    ):
        return False
    delivered, failed = _emit(
        settings,
        kind,
        tenant_id=tenant_id,
        subject_id=subject_id,
        marker=marker if event_marker is None else event_marker,
        data=data,
        source=source,
        occurred_at=now,
    )
    if failed:
        # The queue never took it, so nothing was announced and the marker is
        # a lie. Releasing it costs at most a duplicate bus copy (JetStream
        # de-duplicates the envelope by its ``event_id`` inside the stream's
        # window) and buys the retry the docs promise.
        release(
            settings, tenant_id=tenant_id, kind=kind, subject_id=subject_id, marker=marker
        )
    return delivered


def marker_exists(
    settings: Settings, *, tenant_id: str, kind: str, subject_id: str, marker: str = ""
) -> bool:
    """Whether this occurrence has already been claimed. Read-only, and used by
    the tests — the emitters ask :func:`claim`, which answers the same question
    and takes the row in one statement."""
    with get_session(settings.postgres_url) as session:
        found = session.execute(
            select(models.WorkflowEventMarker.marker_id).where(
                models.WorkflowEventMarker.tenant_id == tenant_id,
                models.WorkflowEventMarker.kind == kind,
                models.WorkflowEventMarker.subject_id == subject_id,
                models.WorkflowEventMarker.marker == marker,
            )
        ).scalar_one_or_none()
    return found is not None


def prune_markers(settings: Settings, *, now: datetime | None = None) -> int:
    """Delete markers older than the retention window. Returns rows deleted.

    Pruning a marker re-arms its event, which is the point: a finding still
    breached a year after it was announced is worth raising a second time. It
    also keeps the table from growing without bound in an installation whose
    findings outlive their assets. ``0`` days disables the sweep.
    """
    days = int(settings.workflow_marker_retention_days or 0)
    if days <= 0:
        return 0
    cutoff = (now or _now()).replace(tzinfo=None) - timedelta(days=days)
    with get_session(settings.postgres_url) as session:
        result = session.execute(
            delete(models.WorkflowEventMarker).where(
                models.WorkflowEventMarker.created_at < cutoff
            )
        )
    return int(result.rowcount or 0)


def reset_for_tests(settings: Settings) -> None:
    global _broker_down
    _broker_down = ("", 0.0)
    with get_session(settings.postgres_url) as session:
        session.query(models.WorkflowEventMarker).delete()
