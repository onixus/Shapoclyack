"""In-process dispatcher for per-tenant recurring scan schedules (Phase 8.5).

Polls ``api.services.scan_schedules.due_schedules`` on a fixed interval and
starts a job via the existing ``api.services.jobs.start_scan`` for each one
that's due — reusing 100% of the existing job/target/execution machinery.
Structured like ``api.services.ch_ingest_worker``: a daemon thread with a
crash-restart loop, started/stopped from the FastAPI lifespan instead of a
separate K8s Deployment/CronJob per tenant.

The thread runs in every replica but only one replica dispatches: each tick
first asks ``api.services.leader_lock`` for the schedule-dispatcher advisory
lock and does nothing without it (ROADMAP P1.6). That replaces the previous
"run one API replica or set ``OCTO_SCHEDULER_DISPATCH_ENABLED=false`` on all
but one" operational rule. P1.5 idempotency keys stay load-bearing underneath:
leadership is not fenced, so a brief overlap during a handover must be a no-op
rather than a second scan.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime

from api.schemas import StartScanRequest
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import metrics as metrics_service
from api.services import quotas
from api.services import scan_schedules
from api.services.leader_lock import SCHEDULE_DISPATCHER_LOCK_ID, LeaderLock
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.schedule-dispatcher")

# Overlap protection: a schedule whose previous job has not reached a terminal
# state yet is skipped. Sourced from job_states so a new non-terminal state
# (P1.3 added `claimed`) cannot silently start counting as "finished".
_RUNNING_STATUSES = set(job_states.ACTIVE)


class ScheduleDispatcher:
    def __init__(self, *, settings: Settings, poll_interval_seconds: float = 30.0) -> None:
        self._settings = settings
        self._poll_interval = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url,
            object_id=SCHEDULE_DISPATCHER_LOCK_ID,
            name="schedule dispatcher",
        )
        self._stats = {
            "ticks": 0,
            "dispatched": 0,
            "skipped_overlap": 0,
            "skipped_not_leader": 0,
            "skipped_quota": 0,
            "errors": 0,
        }

    @property
    def stats(self) -> dict[str, int]:
        return {**self._stats, "is_leader": int(self._lock.is_leader)}

    @property
    def is_leader(self) -> bool:
        return self._lock.is_leader

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-schedule-dispatcher", daemon=True)
        self._thread.start()
        LOG.info(
            "Schedule dispatcher started (poll_interval=%.0fs, dispatches only while leader)",
            self._poll_interval,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        # After the thread is joined, so the loop cannot re-acquire behind us.
        self._lock.release()
        metrics_service.SCHEDULER_IS_LEADER.set(0)
        LOG.info("Schedule dispatcher stopped stats=%s", self.stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._lead():
                    self._tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Schedule dispatch tick failed")
            self._stop.wait(self._poll_interval)

    def _lead(self) -> bool:
        """Re-evaluate leadership every tick — it can be lost at any moment."""
        leader = self._lock.acquire()
        metrics_service.SCHEDULER_IS_LEADER.set(int(leader))
        if not leader:
            self._stats["skipped_not_leader"] += 1
        return leader

    def _job_still_running(self, sched: dict) -> bool:
        last_job_id = sched.get("last_job_id")
        if not last_job_id:
            return False
        job = jobs_service.get_job(self._settings, last_job_id)
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
        # Keyed on the schedule's own due time, not on this replica's clock, so
        # every replica dispatching the same tick computes the same key and
        # only one job is created (ROADMAP P1.5). Since P1.6 only the leader
        # gets here at all, but the key stays load-bearing: leadership is not
        # fenced, so an old leader that has not yet noticed it lost the lock can
        # briefly overlap with the new one, and this is what makes that overlap
        # a no-op instead of a second scan.
        key = f"schedule:{sched['schedule_id']}:{sched.get('next_run_at') or now.isoformat()}"
        try:
            job = jobs_service.start_scan(
                self._settings, request, username="scheduler", idempotency_key=key
            )
        except quotas.QuotaExceeded as exc:
            # Expected, not an error: the tenant has spent this month's
            # entitlement. Counting it in "errors" would page whoever watches
            # the dispatcher for a billing fact, and a traceback every tick
            # would bury the real failures — so it is a warning, its own stat,
            # and the schedule moves on to its next occurrence without
            # claiming a run that did not happen.
            self._stats["skipped_quota"] += 1
            LOG.warning("Schedule %s skipped: %s", sched["schedule_id"], exc)
            scan_schedules.record_skipped_dispatch(sched["schedule_id"], ran_at=now)
            return
        except jobs_service.IdempotentReplay as replay:
            # Another replica won this tick. Its job is the tick's job; record
            # it here too so the schedule's bookkeeping still moves forward if
            # the winner failed between starting the scan and recording it.
            job = replay.job
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
