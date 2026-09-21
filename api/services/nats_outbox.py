"""Publications the broker refused, and the reconciler that lands them later.

P2 of ``docs/architecture-review-2026-09-18.ru.md``, both halves of it.

**The defect.** ``results_ingest.publish_raw_results`` returns
``published=false`` when NATS is unreachable, and ``jobs.complete_job`` never
looked at the flag: the sensor's upload was answered 200, the artifacts were
written, the job went ``succeeded`` — and the message that feeds the analytical
projection was gone, with nothing left to replay it from. The next scan is not
a recovery: it produces its own run, not the one that was dropped.

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

**What is deliberately not here.** Job offers are not recorded. An offer is a
notification of a row that is already in Postgres, an agent claims over HTTP
without one, and the reaper re-offers it — replaying a stale offer buys
nothing. Asset and audit events are not recorded either: those have their own
skip-and-count paths and their own follow-ups in the review. The table's
``kind`` column and the generic republish are what let a later change add them
without a migration.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import metrics as metrics_service
from api.services import nats_bus
from api.services import results_ingest
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.nats-outbox")

KIND_INGEST = "ingest"

STATUS_PENDING = "pending"
STATUS_DEAD = "dead"


def _now() -> datetime:
    """Naive UTC, matching ``jobs`` and every timestamp column in this schema."""
    return datetime.now(UTC).replace(tzinfo=None)


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

    The single entry point ``complete_job`` calls in place of
    ``results_ingest.publish_raw_results``: same arguments, same
    :class:`results_ingest.IngestError` for an archive that does not validate
    (so the caller's translation to a 400 is unchanged), and the same result
    dict with an ``outbox_id`` added when the message was written down instead
    of sent.

    Never raises for a broker that is merely down — that is the case this
    exists to survive. It does propagate a database failure: a refusal we
    cannot record is the silent loss the whole change is about, and the upload
    is better answered with an error the sensor will retry.
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
        LOG.error(
            "Dropping refused %s publish for job=%s: the outbox is disabled, so this "
            "message is lost and only a re-scan can produce it again",
            subject,
            job_id,
        )
        metrics_service.NATS_OUTBOX_TOTAL.labels(kind=kind, outcome="dropped").inc()
        return None
    now = _now()
    outbox_id = uuid.uuid4().hex
    row = models.NatsOutboxEntry(
        outbox_id=outbox_id,
        tenant_id=tenant_id,
        kind=kind,
        subject=subject,
        msg_id=msg_id,
        payload=payload,
        job_id=job_id,
        run_id=run_id,
        status=STATUS_PENDING,
        attempts=0,
        # Due immediately: the reconciler's own backoff starts after the first
        # failed retry, and a broker that came back a second ago should not
        # keep the backlog waiting.
        next_attempt_at=now,
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


def backlog(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Counts an operator (and ``/api/health``) reads: what is owed and how old.

    ``stale`` is the pending rows older than ``nats_outbox_backlog_alert_seconds``,
    which is the number that means "this is not a broker restart any more".
    """
    moment = now or _now()
    cutoff = moment - timedelta(seconds=settings.nats_outbox_backlog_alert_seconds)
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.NatsOutboxEntry.status, func.count()).group_by(
                models.NatsOutboxEntry.status
            )
        ).all()
        stale = session.execute(
            select(func.count())
            .select_from(models.NatsOutboxEntry)
            .where(
                models.NatsOutboxEntry.status == STATUS_PENDING,
                models.NatsOutboxEntry.created_at < cutoff,
            )
        ).scalar_one()
    counts = {STATUS_PENDING: 0, STATUS_DEAD: 0}
    for status, count in rows:
        counts[str(status)] = int(count)
    return {
        "pending": counts.get(STATUS_PENDING, 0),
        "dead": counts.get(STATUS_DEAD, 0),
        "stale": int(stale),
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
    visibility = timedelta(seconds=max(30, settings.nats_outbox_retry_base_seconds))
    for row in rows:
        row.attempts += 1
        row.next_attempt_at = now + visibility
        row.updated_at = now
    session.flush()
    return rows


def _republish(bus: Any, *, kind: str, subject: str, msg_id: str, payload: dict[str, Any]) -> bool:
    """Put one recorded message back on the stream it was meant for.

    Ingest goes through ``publish_ingest`` rather than a raw publish so the
    legacy ``ingest.raw_results`` subject is fed too — a replayed message must
    reach the same consumers the original would have.
    """
    if kind == KIND_INGEST:
        return bus.publish_ingest(payload, msg_id=msg_id)
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
    """Put dead rows back on the due queue. Returns how many were requeued.

    The operator's half of the DLQ, same idea as ``webhooks.requeue_delivery``:
    a broker that was down for longer than ``nats_outbox_max_attempts`` covers
    leaves rows nobody will retry, and the fix is a decision, not a timer.
    """
    now = _now()
    requeued = 0
    with get_session(settings.postgres_url) as session:
        query = select(models.NatsOutboxEntry).where(
            models.NatsOutboxEntry.status == STATUS_DEAD
        )
        if tenant_id:
            query = query.where(models.NatsOutboxEntry.tenant_id == tenant_id)
        for row in session.execute(query).scalars().all():
            row.status = STATUS_PENDING
            row.attempts = 0
            row.next_attempt_at = now
            row.updated_at = now
            requeued += 1
        session.flush()
    if requeued:
        LOG.info("Requeued %s dead outbox entries", requeued)
    return requeued


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
