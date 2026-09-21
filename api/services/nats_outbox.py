"""Publications the broker refused, and the reconciler that lands them later.

P2 of ``docs/architecture-review-2026-09-18.ru.md``, both halves of it.

**The defect.** ``results_ingest.publish_raw_results`` returns
``published=false`` when NATS is unreachable, and the upload path never looked
at the flag: the sensor's upload was answered 200, the artifacts were written,
the job went ``succeeded`` — and the message that feeds the analytical
projection was gone, with nothing left to replay it from. The next scan is not
a recovery: it produces its own run, not the one that was dropped.

**Where it is called from.** ``run_publisher._publish_to_bus``, the last step
of an accepted run's publication, and nowhere else. That module owns the
durable intent to publish a run (``run_publications``, migration ``0058``) —
the store, the run directory, the pointer, the projections — and this one owns
exactly the hop it ends on. The split is what keeps a broker outage from
costing the run itself: failing the publication on a refused bus message spent
its attempts, ended the row ``dead`` and left the run without its assets,
findings and notification, over a message for ClickHouse. So the hop hands the
message here and the publication closes. The two reconcilers retry disjoint
work and never the same row.

**The policy it unblocks.** NATS used to fail ``/readyz`` (``health``'s
``BLOCKING_CHECKS``), so a broker outage emptied the Service of every API
replica at once — the HTTP control plane went down with the broker although
job offers have an HTTP claim fallback, uploads have an HTTP route, and most
CRUD never touches the bus at all. The review's condition for relaxing that is
exactly this module: *availability must not hide the analytics falling behind*.
So the broker is advisory for readiness now, and the price is paid here — every
refused publication is a row, the reconciler drains it when the broker is back,
and a backlog that is not draining is what turns ``/api/health`` degraded and
raises ``octo_nats_outbox_backlog``.

**Shape.** One table, ``nats_outbox``, claimed with ``FOR UPDATE SKIP LOCKED``
like ``webhook_deliveries``: due-ness is a property of the row, so the
reconciler is safe in every replica without leader election. A published row is
deleted rather than kept — an ingest body is megabytes of base64, not an audit
trail. A row that exhausts ``nats_outbox_max_attempts`` goes ``dead`` and stays
for an operator to decide about (``docs/operations.md``, *NATS outbox*).

**Asset events are recorded too** (``kind="asset_event"``), and for a reason
the relaxed readiness policy created. They are the only source of the webhook
fan-out: ``webhook_worker`` subscribes to ``EVENTS`` and nothing else calls
``webhooks.enqueue_event``. While NATS blocked ``/readyz`` a broker outage took
the replicas out of the Service, so the upload that would have produced those
events was not accepted until the broker was back and the notification went out
late. With the broker advisory the upload is accepted, the run is published —
and ``asset.vulnerability.new`` for that hour would simply never be sent. A
late webhook is a cost; a webhook for a new critical CVE that is never sent is
not one this change gets to introduce quietly, so those envelopes are written
down here and published when the broker returns.

**What is deliberately not here.** Job offers are not recorded. An offer is a
notification of a row that is already in Postgres, an agent claims over HTTP
without one, and the reaper re-offers it — replaying a stale offer buys
nothing. Audit events are not recorded either: the rows are committed and
readable through ``GET /api/audit``, and ``OCTO_AUDIT_SYSLOG_SOURCE=db``
forwards them to a SIEM without the broker at all, so the publish is a second
copy of something durable rather than the only one.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import metrics as metrics_service
from api.services import nats_bus
from api.services import results_ingest
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.nats-outbox")

KIND_INGEST = "ingest"
KIND_ASSET_EVENT = "asset_event"

STATUS_PENDING = "pending"
STATUS_DEAD = "dead"

# Why a row was dead before it was ever tried. Read by ``requeue_dead``, which
# must not put such a row back on the due queue (``_is_replayable``).
_UNREPLAYABLE_ERROR = "archive was over the inline cap; there is no body to republish"


def _now() -> datetime:
    """Naive UTC, matching ``jobs`` and every timestamp column in this schema."""
    return datetime.now(UTC).replace(tzinfo=None)


def _is_replayable(kind: str, payload: Mapping[str, Any]) -> bool:
    """Whether republishing this body would actually deliver the run.

    An ingest payload for an archive over ``results_ingest``'s 4 MB inline cap
    carries ``archive_inline: false`` and no body at all. The broker accepts
    such a message, so a republish reports success, the row is deleted and the
    backlog drops to zero — while ClickHouse received nothing it can transform.
    That is a health signal that lies, and the worse half of the two ``dead``
    problems, because the green one is the one nobody investigates.

    A row that cannot be replayed is therefore recorded ``dead`` from the
    start: "an operator has to decide about this" is exactly what ``dead``
    means here, and for these runs the decision is a re-scan or a manual load,
    never a retry.
    """
    if kind != KIND_INGEST:
        # An asset event carries its whole envelope: there is no out-of-line
        # body it could be missing, so every recorded one can be replayed.
        return True
    return payload.get("archive_inline") is not False


def publish_ingest_or_record(
    settings: Settings,
    *,
    job_id: str,
    run_id: str,
    agent_id: str,
    exit_code: int,
    archive_bytes: bytes,
    error: str | None = None,
    tenant_id: str,
) -> dict[str, Any]:
    """Publish one run's raw results, recording the message if the broker refuses.

    The single entry point ``run_publisher`` calls in place of
    ``results_ingest.publish_raw_results``: the same arguments, the same
    :class:`results_ingest.IngestError` for an archive that does not validate
    (so the caller's translation to a 400 is unchanged), and the same result
    dict with an ``outbox_id`` added when the message was written down instead
    of sent.

    Never raises for a broker that is merely down — that is the case this
    exists to survive. A database failure *is* propagated, but not to the
    sensor: the only caller is ``run_publisher._publish_to_bus``, which runs
    inside ``_attempt`` and turns any exception into a failed publication
    attempt, and the upload itself was answered before the publication began
    (``publish_now`` never raises either). So a refusal we cannot record fails
    this publication and is retried by the publication reconciler — the loss
    the change is about is still prevented, by a retry on this side rather
    than by one the sensor makes.
    """
    result = results_ingest.publish_raw_results(
        nats_url=settings.nats_url,
        job_id=job_id,
        run_id=run_id,
        agent_id=agent_id,
        exit_code=exit_code,
        archive_bytes=archive_bytes,
        error=error,
        tenant_id=tenant_id,
    )
    if result.get("published"):
        _forget_recorded(settings, subject=str(result["subject"]), msg_id=str(result["msg_id"]))
        return result

    payload = results_ingest.build_gateway_payload(
        job_id=job_id,
        run_id=run_id,
        agent_id=agent_id,
        exit_code=exit_code,
        archive_bytes=archive_bytes,
        tenant_id=tenant_id,
        error=error,
    )
    outbox_id = record_failed_publish(
        settings,
        kind=KIND_INGEST,
        subject=str(result["subject"]),
        msg_id=str(result["msg_id"]),
        payload=payload,
        tenant_id=tenant_id,
        job_id=job_id,
        run_id=run_id,
    )
    return {**result, "outbox_id": outbox_id}


def _forget_recorded(settings: Settings, *, subject: str, msg_id: str) -> None:
    """Drop a pending row for a message that has just been delivered anyway.

    The caller of :func:`publish_ingest_or_record` may reach it twice for one
    message: ``run_publisher`` records the refusal, dies before it can close
    the publication row out, and the reconciler replays the same hop — which
    this time the broker accepts. Without this, the row left by the first pass
    is republished later and the run is on the stream twice. The stream's
    ``duplicate_window`` would drop the second copy, but only for as long as
    the window is, and "the same run is published once" should not rest on a
    broker setting alone.

    Pending rows only. A ``dead`` row is a decision an operator has not made
    yet, and deleting it here would take the question away rather than answer
    it — a delivered ``dead`` row is the unreplayable kind, whose body never
    reached ClickHouse to begin with.

    ``FOR UPDATE`` (blocking, not ``SKIP LOCKED``) for the same reason
    ``_claim_due`` takes the lock: a reconciler tick holding this row is about
    to publish it, and deleting it out from under that tick would be exactly
    the duplicate this function exists to prevent. Waiting for the claim's
    transaction to commit means we either delete a row nobody has taken, or
    find it already claimed — in which case its own publish is the one that
    lands and ``_record_attempt`` deletes it. What is still *not* covered is a
    tick that has already left its claim transaction: ``_claim_due`` commits
    before publishing (deliberately, so a batch's megabytes are not held under
    a row lock), and there is no column that tells a claimed row from an idle
    one. That window is the stream's ``duplicate_window`` to close, which is
    why the window is now checked rather than assumed
    (``nats_bus._report_stream_drift``).
    """
    if not settings.nats_outbox_enabled:
        return
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.NatsOutboxEntry)
            .where(
                models.NatsOutboxEntry.subject == subject,
                models.NatsOutboxEntry.msg_id == msg_id,
                models.NatsOutboxEntry.status == STATUS_PENDING,
            )
            .with_for_update()
        ).scalars().first()
        if row is None:
            return
        outbox_id = row.outbox_id
        session.delete(row)
    metrics_service.NATS_OUTBOX_TOTAL.labels(kind=KIND_INGEST, outcome="superseded").inc()
    LOG.info(
        "Recorded %s publish %s was delivered by a later attempt of the same message; "
        "dropping the row rather than republishing it",
        subject,
        outbox_id,
    )


def record_failed_publish(
    settings: Settings,
    *,
    kind: str,
    subject: str,
    msg_id: str,
    payload: dict[str, Any],
    tenant_id: str,
    job_id: str | None = None,
    run_id: str | None = None,
) -> str | None:
    """Write one refused publication down. Returns its id, or None if disabled.

    ``(subject, msg_id)`` is unique, so a second replica recording the same
    message — or the same upload retried by the sensor — keeps one row rather
    than queueing the run twice.
    """
    if not settings.nats_outbox_enabled:
        LOG.warning(
            "Dropping refused %s publish for job=%s: the outbox is disabled, so nothing "
            "durable is left behind here. The publication itself fails and is retried "
            "(OCTO_RUN_PUBLICATION_MAX_ATTEMPTS attempts over a few minutes); only an "
            "outage that outlives those loses the message for good, and then only a "
            "re-scan produces the run again",
            subject,
            job_id,
        )
        metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="dropped").inc()
        return None
    now = _now()
    outbox_id = uuid.uuid4().hex
    replayable = _is_replayable(kind, payload)
    row = models.NatsOutboxEntry(
        outbox_id=outbox_id,
        tenant_id=tenant_id,
        kind=kind,
        subject=subject,
        msg_id=msg_id,
        payload=payload,
        job_id=job_id,
        run_id=run_id,
        status=STATUS_PENDING if replayable else STATUS_DEAD,
        attempts=0,
        # Due immediately: the reconciler's own backoff starts after the first
        # failed retry, and a broker that came back a second ago should not
        # keep the backlog waiting. A body that cannot be replayed is never
        # due — see ``_is_replayable``.
        next_attempt_at=now if replayable else None,
        last_error=None if replayable else _UNREPLAYABLE_ERROR,
        created_at=now,
        updated_at=now,
    )
    with get_session(settings.postgres_url) as session:
        inserted = insert_if_absent(session, row, f"{subject}|{msg_id}")
        if not inserted:
            existing = session.execute(
                select(models.NatsOutboxEntry.outbox_id).where(
                    models.NatsOutboxEntry.subject == subject,
                    models.NatsOutboxEntry.msg_id == msg_id,
                )
            ).scalar_one_or_none()
            LOG.info(
                "Refused %s publish for job=%s is already recorded as %s",
                subject,
                job_id,
                existing,
            )
            return existing
    if not replayable:
        metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="unreplayable").inc()
        LOG.error(
            "Recorded refused %s publish job=%s run=%s as %s and marked it dead on "
            "arrival: %s. Republishing it would be accepted by the broker and deliver "
            "no results, so this run needs a re-scan or a manual load, not a retry",
            subject,
            job_id,
            run_id,
            outbox_id,
            _UNREPLAYABLE_ERROR,
        )
        return outbox_id
    metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="recorded").inc()
    LOG.warning(
        "Recorded refused %s publish job=%s run=%s as %s; the analytical projection "
        "lags until the broker accepts it",
        subject,
        job_id,
        run_id,
        outbox_id,
    )
    return outbox_id


def record_undelivered_asset_events(
    settings: Settings, envelopes: list[dict[str, Any]]
) -> int:
    """Write down asset events the broker did not take. Returns how many.

    Zero — and nothing written — when the outbox is disabled; the caller then
    counts them ``skipped`` as before, which is the configuration the
    ``ShapoclyackNatsOutboxDropping`` alert names.

    One session for the whole batch, unlike :func:`record_failed_publish`. A
    run that first discovers a /16 is capped at ``OCTO_ASSET_EVENTS_MAX_PER_RUN``
    envelopes (1000 by default) and a broker that is down refuses all of them,
    so a transaction per envelope would be a thousand round trips inside the
    request that is holding the sensor's upload. ``insert_if_absent`` scopes
    each row to its own SAVEPOINT, so the one duplicate a replayed upload
    brings does not take the other 999 down with it — and the ``event_id`` is
    content-derived, so that duplicate is the same event, not a second one.
    """
    if not envelopes:
        return 0
    if not settings.nats_outbox_enabled:
        return 0
    now = _now()
    recorded = 0
    with get_session(settings.postgres_url) as session:
        for envelope in envelopes:
            tenant_id = str(envelope.get("tenant_id") or "default")
            kind = str(envelope.get("kind") or "unknown")
            msg_id = str(envelope.get("event_id") or "")
            if not msg_id:
                # Without an id there is no dedupe key and no unique row; an
                # event built by ``asset_events.build_events`` always has one.
                continue
            subject = nats_bus.asset_event_subject(tenant_id, kind)
            row = models.NatsOutboxEntry(
                outbox_id=uuid.uuid4().hex,
                tenant_id=tenant_id,
                kind=KIND_ASSET_EVENT,
                subject=subject,
                msg_id=msg_id,
                payload=dict(envelope),
                job_id=str(envelope.get("job_id") or "") or None,
                run_id=str(envelope.get("run_id") or "") or None,
                status=STATUS_PENDING,
                attempts=0,
                next_attempt_at=now,
                last_error=None,
                created_at=now,
                updated_at=now,
            )
            if insert_if_absent(session, row, f"{subject}|{msg_id}"):
                recorded += 1
    if recorded:
        metrics_service.NATS_OUTBOX_TOTAL.labels(
            kind=KIND_ASSET_EVENT, outcome="recorded"
        ).inc(recorded)
        LOG.warning(
            "Recorded %s undelivered asset event(s) of %s for run %s; the webhooks "
            "they feed are sent when the broker accepts them",
            recorded,
            len(envelopes),
            envelopes[0].get("run_id"),
        )
    return recorded


def backlog(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Counts an operator (and ``/api/health``) reads: what is owed and how old.

    ``stale`` is the pending rows older than ``nats_outbox_backlog_alert_seconds``,
    which is the number that means "this is not a broker restart any more".
    """
    moment = now or _now()
    cutoff = moment - timedelta(seconds=settings.nats_outbox_backlog_alert_seconds)
    # One pass, not two. ``/readyz`` runs this on every replica on the kubelet's
    # period, so a second full aggregate over the same table doubled a cost that
    # grows exactly when the database is already having a bad day. The stale
    # count rides along as a conditional aggregate over the same GROUP BY, and
    # ``ix_nats_outbox_stale`` (``status, created_at``) covers the predicate,
    # which nothing indexed before.
    stale_count = func.count(
        case((models.NatsOutboxEntry.created_at < cutoff, 1), else_=None)
    )
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.NatsOutboxEntry.status, func.count(), stale_count).group_by(
                models.NatsOutboxEntry.status
            )
        ).all()
    counts = {STATUS_PENDING: 0, STATUS_DEAD: 0}
    stale = 0
    for status, count, older_than_cutoff in rows:
        counts[str(status)] = int(count)
        if str(status) == STATUS_PENDING:
            stale = int(older_than_cutoff)
    return {
        "pending": counts.get(STATUS_PENDING, 0),
        "dead": counts.get(STATUS_DEAD, 0),
        "stale": stale,
    }


def is_backlogged(settings: Settings) -> bool:
    """Whether the outbox owes the broker something it is not recovering.

    Fail-soft: a database that cannot answer is already the blocking Postgres
    check's business, and a probe that raises tells the kubelet the API is
    broken rather than that a query failed.
    """
    try:
        counts = backlog(settings)
    except Exception:  # noqa: BLE001
        LOG.warning("Could not read the NATS outbox backlog", exc_info=True)
        return False
    return bool(counts["stale"] or counts["dead"])


def _retry_delay_seconds(attempts: int, settings: Settings) -> int:
    """Delay before attempt ``attempts + 1``, exponential and capped.

    Same shape as ``webhooks.backoff_seconds``, including the clamp on the
    exponent: ``attempts`` is read back from a row and is not a value to trust
    into ``2**large``.
    """
    exponent = min(max(0, attempts - 1), 20)
    return min(
        settings.nats_outbox_retry_base_seconds * (2**exponent),
        settings.nats_outbox_retry_max_seconds,
    )


def _claim_due(session, *, now: datetime, limit: int, settings: Settings) -> list[Any]:
    """Take up to ``limit`` due rows, pushing them out of the due window.

    ``FOR UPDATE SKIP LOCKED`` plus a bumped ``next_attempt_at`` is what makes
    the reconciler safe in every replica: peers divide the backlog instead of
    republishing the same megabytes in parallel.
    """
    rows = list(
        session.execute(
            select(models.NatsOutboxEntry)
            .where(
                models.NatsOutboxEntry.status == STATUS_PENDING,
                models.NatsOutboxEntry.next_attempt_at <= now,
            )
            .order_by(models.NatsOutboxEntry.next_attempt_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars().all()
    )
    # The window has to cover the *whole* batch, not one row. ``reconcile_once``
    # commits this transaction — releasing the locks — and only then publishes
    # the claimed rows one by one, so the last row of a batch sits claimed for
    # as long as every row before it takes. One ingest body is up to ~5.3 MB of
    # base64 and ``publish_json`` retries three times on the way, so a batch of
    # ``nats_outbox_batch_size`` is tens of megabytes: a flat 30 s expired
    # mid-batch and a peer replica claimed and republished the same rows in
    # parallel — doubled traffic, doubled ``attempts`` (so a false ``dead``
    # sooner) and duplicates on the stream.
    # Being generous costs the reverse case: a replica that dies mid-batch
    # leaves its rows waiting one window rather than 30 s. That is the cheaper
    # mistake — the backlog is already behind, and duplicate publishes are not.
    per_row = max(30, settings.nats_outbox_retry_base_seconds)
    visibility = timedelta(seconds=per_row * max(1, len(rows)))
    for row in rows:
        row.attempts += 1
        row.next_attempt_at = now + visibility
        row.updated_at = now
    session.flush()
    return rows


def _republish(bus: Any, *, kind: str, subject: str, msg_id: str, payload: dict[str, Any]) -> bool:
    """Put one recorded message back on the stream it was meant for.

    Each kind goes back through the same ``nats_bus`` helper that sent it the
    first time rather than through a raw publish on the stored subject: that
    is what keeps the headers, the message id and — for ingest — the legacy
    ``ingest.raw_results`` copy identical to the original, so a replayed
    message reaches the same consumers the first attempt would have.
    """
    if kind == KIND_INGEST:
        return bus.publish_ingest(payload, msg_id=msg_id)
    if kind == KIND_ASSET_EVENT:
        return bus.publish_asset_event(payload)
    headers = {"tenant_id": str(payload.get("tenant_id") or "")}
    return bus.publish_json(subject, payload, msg_id=msg_id, headers=headers)


def reconcile_once(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """One pass over the due backlog. Returns ``{"republished", "failed", "dead"}``.

    Called by the worker below on a timer, and directly by the tests and by an
    operator's ``python -c`` when they would rather not wait for the tick.
    """
    outcome = {"republished": 0, "failed": 0, "dead": 0}
    if not settings.nats_outbox_enabled or not settings.nats_url:
        return outcome
    moment = now or _now()

    # Before claiming, not after: a claim spends an attempt and pushes the row
    # out of the due window, and a broker that is not there yet has refused
    # nothing. Otherwise a long outage would retire the backlog on the timer
    # alone, without a single publish having been tried.
    bus = nats_bus.get_bus(settings.nats_url)
    if bus is None:
        LOG.info("NATS still unreachable; the outbox backlog stays queued")
        _refresh_backlog_gauge(settings)
        return outcome

    with get_session(settings.postgres_url) as session:
        claimed = _claim_due(
            session,
            now=moment,
            limit=settings.nats_outbox_batch_size,
            settings=settings,
        )
        # Snapshotted before the publish so the bodies are plain dicts rather
        # than ORM state held across network I/O.
        work = [
            (row.outbox_id, row.kind, row.subject, row.msg_id, dict(row.payload or {}))
            for row in claimed
        ]

    for outbox_id, kind, subject, msg_id, payload in work:
        try:
            ok = _republish(bus, kind=kind, subject=subject, msg_id=msg_id, payload=payload)
        except Exception:  # noqa: BLE001
            LOG.exception("Outbox republish raised for %s (subject=%s)", outbox_id, subject)
            ok = False
        status = _record_attempt(settings, outbox_id=outbox_id, ok=ok, now=moment)
        if status == "gone":
            # A peer delivered and deleted this row while we held it claimed
            # outside the transaction. Counting it as ours would report a
            # backlog draining twice as fast as it is.
            continue
        if ok:
            outcome["republished"] += 1
            metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="republished").inc()
        elif status == STATUS_DEAD:
            outcome["dead"] += 1
            metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="dead").inc()
        else:
            outcome["failed"] += 1
    _refresh_backlog_gauge(settings)
    return outcome


def _record_attempt(settings: Settings, *, outbox_id: str, ok: bool, now: datetime) -> str:
    """Write one republish attempt back. Returns the resulting status."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.NatsOutboxEntry, outbox_id)
        if row is None:  # pragma: no cover - deleted by a peer mid-flight
            return "gone"
        if ok:
            # Deleted rather than marked published: the body is the run archive,
            # and the fact that it was delivered is on the stream now.
            session.delete(row)
            LOG.info(
                "Outbox republished %s on %s after %s attempt(s)",
                outbox_id,
                row.subject,
                row.attempts,
            )
            return "republished"
        row.updated_at = now
        row.last_error = "broker refused the publish"
        if row.attempts >= settings.nats_outbox_max_attempts:
            row.status = STATUS_DEAD
            row.next_attempt_at = None
            LOG.error(
                "Outbox entry %s is dead after %s attempts (subject=%s job=%s run=%s); "
                "the analytical projection will not have this run until it is replayed",
                outbox_id,
                row.attempts,
                row.subject,
                row.job_id,
                row.run_id,
            )
        else:
            row.next_attempt_at = now + timedelta(
                seconds=_retry_delay_seconds(row.attempts, settings)
            )
        return row.status


def requeue_dead(settings: Settings, *, tenant_id: str | None = None) -> int:
    """Put replayable dead rows back on the due queue. Returns how many.

    The operator's half of the DLQ, same idea as ``webhooks.requeue_delivery``:
    a broker that was down for longer than ``nats_outbox_max_attempts`` covers
    leaves rows nobody will retry, and the fix is a decision, not a timer.

    Rows whose body cannot be replayed (``_is_replayable``) are skipped rather
    than requeued. Requeueing one used to be the fastest way to a green health
    check over an empty ClickHouse: the broker accepts a body-less ingest
    message, the republish counts as success, the row is deleted and the
    backlog reads zero. They are logged and left ``dead``; ``discard_dead`` is
    how an operator gets rid of them once the run has been re-scanned.
    """
    now = _now()
    requeued = 0
    skipped = 0
    with get_session(settings.postgres_url) as session:
        for row in _dead_rows(session, tenant_id=tenant_id):
            if not _is_replayable(row.kind, dict(row.payload or {})):
                skipped += 1
                continue
            row.status = STATUS_PENDING
            row.attempts = 0
            row.next_attempt_at = now
            row.updated_at = now
            requeued += 1
        session.flush()
    if requeued:
        LOG.info("Requeued %s dead outbox entries", requeued)
    if skipped:
        LOG.warning(
            "Left %s dead outbox entries alone: %s. Republishing them would report "
            "success and deliver nothing; re-scan those runs, then discard_dead()",
            skipped,
            _UNREPLAYABLE_ERROR,
        )
    return requeued


def discard_dead(
    settings: Settings, *, tenant_id: str | None = None, outbox_id: str | None = None
) -> int:
    """Delete dead rows for good. Returns how many were removed.

    The exit ``dead`` had no other door to. ``is_backlogged`` is True while any
    row is ``dead``, so ``/api/health`` stayed degraded and
    ``octo_nats_outbox_backlog{status="dead"}`` stayed non-zero forever unless
    a republish eventually succeeded — and for a body that cannot be replayed
    at all, no republish ever will. An operator who has decided the run is not
    coming back (re-scanned, or no longer interesting) needs to say so.

    Only ``dead`` rows: a pending row is still the reconciler's, and deleting
    one would be the silent loss this whole module exists to prevent.
    """
    removed = 0
    by_kind: dict[str, int] = {}
    with get_session(settings.postgres_url) as session:
        for row in _dead_rows(session, tenant_id=tenant_id, outbox_id=outbox_id):
            LOG.warning(
                "Discarding dead outbox entry %s (subject=%s job=%s run=%s attempts=%s); "
                "this run is not reaching the analytical projection",
                row.outbox_id,
                row.subject,
                row.job_id,
                row.run_id,
                row.attempts,
            )
            by_kind[str(row.kind)] = by_kind.get(str(row.kind), 0) + 1
            session.delete(row)
            removed += 1
        session.flush()
    for kind, count in by_kind.items():
        metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="discarded").inc(count)
    if removed:
        _refresh_backlog_gauge(settings)
    return removed


def _dead_rows(
    session, *, tenant_id: str | None = None, outbox_id: str | None = None
) -> list[Any]:
    """The dead end of the table, narrowed the two ways an operator narrows it."""
    query = select(models.NatsOutboxEntry).where(
        models.NatsOutboxEntry.status == STATUS_DEAD
    )
    if tenant_id:
        query = query.where(models.NatsOutboxEntry.tenant_id == tenant_id)
    if outbox_id:
        query = query.where(models.NatsOutboxEntry.outbox_id == outbox_id)
    return list(session.execute(query).scalars().all())


def _refresh_backlog_gauge(settings: Settings) -> None:
    try:
        counts = backlog(settings)
    except Exception:  # noqa: BLE001
        LOG.debug("Could not refresh the outbox gauge", exc_info=True)
        return
    for status, value in counts.items():
        metrics_service.NATS_OUTBOX_BACKLOG.labels(status=status).set(value)


class OutboxReconciler:
    """Timer that drains the due end of ``nats_outbox``.

    Structured like ``job_reaper``/``webhook_worker``: a daemon thread with a
    crash-restart loop, started and stopped from the FastAPI lifespan, and safe
    in every replica without leader election for the reason in ``_claim_due``.
    """

    def __init__(self, *, settings: Settings, poll_interval_seconds: float | None = None) -> None:
        self._settings = settings
        # Floored here as well as in Settings, like the reaper: a caller
        # constructing this directly must not be able to spin the loop.
        self._poll_interval = max(
            1.0, poll_interval_seconds or float(settings.nats_outbox_interval_seconds)
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"ticks": 0, "republished": 0, "failed": 0, "dead": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-nats-outbox", daemon=True)
        self._thread.start()
        LOG.info(
            "NATS outbox reconciler started (poll_interval=%.0fs batch=%d max_attempts=%d)",
            self._poll_interval,
            self._settings.nats_outbox_batch_size,
            self._settings.nats_outbox_max_attempts,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("NATS outbox reconciler stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("NATS outbox reconciler tick failed")
            self._stop.wait(self._poll_interval)

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        outcome = reconcile_once(self._settings)
        for key in ("republished", "failed", "dead"):
            self._stats[key] += outcome[key]


_RECONCILER: OutboxReconciler | None = None


def start_worker(settings: Settings) -> OutboxReconciler | None:
    global _RECONCILER
    # No broker configured is not a degraded installation: with no bus there is
    # nothing to publish and nothing to recover.
    if not settings.nats_outbox_enabled or not settings.nats_url:
        return None
    if _RECONCILER is not None:
        return _RECONCILER
    worker = OutboxReconciler(settings=settings)
    worker.start()
    _RECONCILER = worker
    return worker


def stop_worker() -> None:
    global _RECONCILER
    if _RECONCILER is not None:
        _RECONCILER.stop()
        _RECONCILER = None


def reconciler_stats() -> dict[str, int] | None:
    if _RECONCILER is None:
        return None
    return _RECONCILER.stats

