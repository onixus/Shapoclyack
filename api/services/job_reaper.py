"""Background sweep for jobs no executor is going to finish.

Lease expiry and cancellation timeout are row-level recovery policies, so they
live with the reaper instead of the general jobs service. Every API replica may
run the sweep: candidates are locked with FOR UPDATE SKIP LOCKED.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select

from api.db import models
from api.db.engine import get_session
from api.services import job_dispatch
from api.services import job_states
from api.services import job_store
from api.services import metrics as metrics_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.job-reaper")


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def reap_expired_leases(settings: Settings) -> dict[str, int]:
    """Requeue abandoned agent jobs and fail abandoned local jobs."""
    now = _now()
    outcome = {"requeued": 0, "failed": 0}
    requeued_agent_jobs: list[str] = []
    failed_for_metrics: list[tuple[str, datetime | None]] = []
    failed_events: list[dict[str, Any]] = []

    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.Job)
                .where(
                    models.Job.status.in_(tuple(job_states.IN_FLIGHT)),
                    models.Job.claimed_until.is_not(None),
                    models.Job.claimed_until < now,
                )
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )
        for row in rows:
            retriable = (
                row.execution == "agent"
                and row.attempts < settings.job_max_attempts
            )

            # Any result ingest tied to the expired attempt is void.
            row.ingest_token = None
            row.ingest_attempt = None
            row.ingest_agent_id = None
            row.ingest_started_at = None

            if retriable:
                job_states.check_transition(
                    row.job_id, row.status, job_states.QUEUED
                )
                row.status = job_states.QUEUED
                row.assigned_agent_id = None
                row.claimed_until = None
                row.started_at = None
                outcome["requeued"] += 1
                requeued_agent_jobs.append(row.job_id)
                LOG.warning(
                    "Requeued job %s: lease expired after attempt %d/%d",
                    row.job_id,
                    row.attempts,
                    settings.job_max_attempts,
                )
            else:
                job_states.check_transition(
                    row.job_id, row.status, job_states.FAILED
                )
                row.status = job_states.FAILED
                row.finished_at = now
                row.claimed_until = None
                row.error = (
                    f"Lease expired after {row.attempts} attempt(s): the "
                    f"{row.execution} executor stopped reporting and never returned"
                )
                outcome["failed"] += 1
                failed_for_metrics.append(
                    (row.execution or "local", row.started_at)
                )
                failed_events.append(job_store.scan_failure_event(row))
                LOG.warning(
                    "Failed job %s: lease expired after %d attempt(s) "
                    "(execution=%s)",
                    row.job_id,
                    row.attempts,
                    row.execution,
                )

    for name, count in outcome.items():
        if count:
            metrics_service.JOB_LEASE_EXPIRED_TOTAL.labels(outcome=name).inc(
                count
            )
    for execution, started_at in failed_for_metrics:
        job_store.record_job_metrics(
            settings, job_states.FAILED, execution, started_at, now
        )
    for failure in failed_events:
        workflow_events.emit(settings, "scan_failed", **failure)

    if outcome["requeued"] or outcome["failed"]:
        job_store.refresh_job_gauges(settings)

    if settings.nats_url:
        for job_id in requeued_agent_jobs:
            job_dispatch.publish_offer(settings, job_id)

    return outcome


def reap_stale_cancellations(settings: Settings) -> int:
    """Finish cancellation requests whose agent never confirmed the stop."""
    now = _now()
    deadline = now - timedelta(
        seconds=max(settings.job_cancel_grace_seconds, 1)
    )
    ingest_deadline = now - timedelta(
        seconds=max(settings.job_ingest_lease_seconds, 1)
    )

    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.Job)
                .where(
                    models.Job.status == job_states.CANCELLING,
                    models.Job.cancel_requested_at.is_not(None),
                    models.Job.cancel_requested_at < deadline,
                    or_(
                        models.Job.ingest_started_at.is_(None),
                        models.Job.ingest_started_at < ingest_deadline,
                    ),
                )
                .with_for_update(skip_locked=True)
            )
            .scalars()
            .all()
        )
        for row in rows:
            job_states.check_transition(
                row.job_id, row.status, job_states.CANCELLED
            )
            row.status = job_states.CANCELLED
            row.finished_at = now
            row.claimed_until = None
            row.error = (
                f"{row.error or 'Cancellation requested'}; agent "
                f"{row.assigned_agent_id or 'unknown'} did not confirm within "
                f"{settings.job_cancel_grace_seconds}s"
            )[:2000]
            LOG.warning(
                "Cancelled job %s without confirmation: agent %s stayed silent "
                "for %ds",
                row.job_id,
                row.assigned_agent_id,
                settings.job_cancel_grace_seconds,
            )
        count = len(rows)

    if count:
        metrics_service.JOB_CANCELLATIONS_TOTAL.labels(
            outcome="unconfirmed"
        ).inc(count)
        job_store.refresh_job_gauges(settings)
    return count


class JobReaper:
    def __init__(
        self,
        *,
        settings: Settings,
        poll_interval_seconds: float | None = None,
    ) -> None:
        self._settings = settings
        self._poll_interval = max(
            1.0,
            poll_interval_seconds
            or float(settings.job_reaper_interval_seconds),
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {
            "ticks": 0,
            "requeued": 0,
            "failed": 0,
            "cancelled": 0,
            "errors": 0,
        }

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="octo-job-reaper", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Job reaper started (poll_interval=%.0fs lease=%ds max_attempts=%d "
            "cancel_grace=%ds)",
            self._poll_interval,
            self._settings.job_lease_seconds,
            self._settings.job_max_attempts,
            self._settings.job_cancel_grace_seconds,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("Job reaper stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Job reaper tick failed")
            self._stop.wait(self._poll_interval)

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        outcome = reap_expired_leases(self._settings)
        self._stats["requeued"] += outcome["requeued"]
        self._stats["failed"] += outcome["failed"]
        self._stats["cancelled"] += reap_stale_cancellations(self._settings)


_REAPER: JobReaper | None = None


def start_worker(settings: Settings) -> JobReaper | None:
    global _REAPER
    if not settings.job_reaper_enabled:
        return None
    if _REAPER is not None:
        return _REAPER
    worker = JobReaper(settings=settings)
    worker.start()
    _REAPER = worker
    return worker


def stop_worker() -> None:
    global _REAPER
    if _REAPER is not None:
        _REAPER.stop()
        _REAPER = None


def reaper_stats() -> dict[str, int] | None:
    if _REAPER is None:
        return None
    return _REAPER.stats
