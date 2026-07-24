"""In-process dispatcher for per-tenant recurring scan schedules (Phase 8.5).

Polls ``api.services.scan_schedules.due_schedules`` on a fixed interval and
starts a job via the existing ``api.services.jobs.start_scan`` for each one
that's due — reusing 100% of the existing job/target/execution machinery.
Structured like ``api.services.ch_ingest_worker``: a daemon thread with a
crash-restart loop, started/stopped from the FastAPI lifespan instead of a
separate K8s Deployment/CronJob per tenant.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime

from api.schemas import StartScanRequest
from api.services import jobs as jobs_service
from api.services import scan_schedules
from api.settings import Settings

LOG = logging.getLogger("octo-man.schedule-dispatcher")

_RUNNING_STATUSES = {"queued", "running"}


class ScheduleDispatcher:
    def __init__(self, *, settings: Settings, poll_interval_seconds: float = 30.0) -> None:
        self._settings = settings
        self._poll_interval = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"ticks": 0, "dispatched": 0, "skipped_overlap": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-schedule-dispatcher", daemon=True)
        self._thread.start()
        LOG.info("Schedule dispatcher started (poll_interval=%.0fs)", self._poll_interval)

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("Schedule dispatcher stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Schedule dispatch tick failed")
            self._stop.wait(self._poll_interval)

    def _job_still_running(self, sched: dict) -> bool:
        last_job_id = sched.get("last_job_id")
        if not last_job_id:
            return False
        job = jobs_service.get_job(last_job_id)
        return job is not None and job.status in _RUNNING_STATUSES

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        now = datetime.now(UTC)
        for sched in scan_schedules.due_schedules(now):
            if self._job_still_running(sched):
                self._stats["skipped_overlap"] += 1
                LOG.info("Skipping schedule %s: previous job still running", sched["schedule_id"])
                continue
            try:
                self._dispatch(sched, now)
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Failed to dispatch schedule %s", sched["schedule_id"])

    def _dispatch(self, sched: dict, now: datetime) -> None:
        request = StartScanRequest(
            tenant_id=sched["tenant_id"],
            **sched["scan_options"],
            **sched["targets"],
        )
        job = jobs_service.start_scan(self._settings, request, username="scheduler")
        scan_schedules.record_dispatch(sched["schedule_id"], job_id=job.job_id, ran_at=now)
        self._stats["dispatched"] += 1
        LOG.info("Dispatched schedule %s -> job %s", sched["schedule_id"], job.job_id)


_DISPATCHER: ScheduleDispatcher | None = None


def start_worker(settings: Settings) -> ScheduleDispatcher | None:
    global _DISPATCHER
    if not settings.scheduler_dispatch_enabled:
        return None
    if _DISPATCHER is not None:
        return _DISPATCHER
    worker = ScheduleDispatcher(settings=settings)
    worker.start()
    _DISPATCHER = worker
    return worker


def stop_worker() -> None:
    global _DISPATCHER
    if _DISPATCHER is not None:
        _DISPATCHER.stop()
        _DISPATCHER = None


def dispatcher_stats() -> dict[str, int] | None:
    if _DISPATCHER is None:
        return None
    return _DISPATCHER.stats
