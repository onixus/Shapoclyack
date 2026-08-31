"""In-process dispatcher for scheduled reports (Sprint 4).

Structurally the scan-schedule dispatcher (``api.services.schedule_dispatcher``)
with a different payload: a daemon thread per replica, a Postgres advisory lock
so only one of them acts, a fixed poll interval, and a crash-restart loop. That
similarity is the point — a second scheduling model in one product is a second
set of clock, overlap and leadership bugs to find.

One difference matters. The scan dispatcher relies on job idempotency keys to
make a brief double-run (leadership is not fenced) a no-op. There is no
equivalent for a report: sending the same PDF to a customer twice cannot be
de-duplicated after the fact. So the schedule's ``next_run_at`` is advanced
*before* the render, in its own transaction: a second dispatcher that wakes
during a handover finds nothing due. The cost is that a replica which dies
mid-render skips that occurrence rather than repeating it, which is the right
way round — a customer noticing a missing monthly report is a support ticket,
while a customer receiving two contradictory ones is a trust problem.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from api.services.leader_lock import REPORT_DISPATCHER_LOCK_ID, LeaderLock
from api.services.reports import delivery as report_delivery
from api.services.reports import store
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.report-dispatcher")


class ReportDispatcher:
    def __init__(self, *, settings: Settings, poll_interval_seconds: float | None = None) -> None:
        self._settings = settings
        self._poll_interval = float(
            poll_interval_seconds
            if poll_interval_seconds is not None
            else settings.report_dispatch_interval_seconds
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url,
            object_id=REPORT_DISPATCHER_LOCK_ID,
            name="report dispatcher",
        )
        self._stats: dict[str, Any] = {
            "ticks": 0,
            "generated": 0,
            "failed": 0,
            "delivered": 0,
            "delivery_failures": 0,
            "skipped_not_leader": 0,
            "errors": 0,
            "last_run_at": None,
            "pruned": 0,
        }
        self._last_prune: datetime | None = None

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats, "is_leader": int(self._lock.is_leader)}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="octo-report-dispatcher", daemon=True
        )
        self._thread.start()
        LOG.info("Report dispatcher started (poll_interval=%.0fs)", self._poll_interval)

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        self._lock.release()
        LOG.info("Report dispatcher stopped stats=%s", self.stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._lead():
                    self.tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Report dispatch tick failed")
            self._stop.wait(self._poll_interval)

    def _lead(self) -> bool:
        leader = self._lock.acquire()
        if not leader:
            self._stats["skipped_not_leader"] += 1
        return leader

    def tick(self, now: datetime | None = None) -> None:
        """One pass over the due schedules. Public so tests drive it directly."""

        now = now or datetime.now(UTC)
        self._stats["ticks"] += 1
        self._stats["last_run_at"] = now.isoformat().replace("+00:00", "Z")
        self._prune(now)
        for schedule in store.due_schedules(self._settings, now):
            try:
                # Claim the occurrence first — see the module docstring on why
                # this is not ordered the other way round.
                store.record_dispatch(
                    self._settings, schedule["schedule_id"], report_id=None, ran_at=now
                )
                self._run_schedule(schedule, now)
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Failed to run report schedule %s", schedule["schedule_id"])

    def _prune(self, now: datetime) -> None:
        """Retention sweep, at most hourly. Folded into this thread rather than
        given its own: it is a bounded DELETE that only the leader should run,
        which is exactly the thread already elected for that."""

        if self._last_prune is not None and now - self._last_prune < timedelta(hours=1):
            return
        self._last_prune = now
        try:
            result = store.prune_reports(self._settings, now=now)
        except Exception:  # noqa: BLE001
            self._stats["errors"] += 1
            LOG.exception("Report retention sweep failed")
            return
        self._stats["pruned"] += result["deleted"]

    def _run_schedule(self, schedule: dict[str, Any], now: datetime) -> None:
        report = store.generate(
            self._settings,
            tenant_id=schedule["tenant_id"],
            template_id=schedule["template_id"],
            fmt=schedule["format"],
            schedule_id=schedule["schedule_id"],
            actor="report-scheduler",
        )
        if report["status"] != "ready":
            self._stats["failed"] += 1
            LOG.warning(
                "Scheduled report %s failed: %s", report["report_id"], report.get("error")
            )
            store.record_dispatch(
                self._settings,
                schedule["schedule_id"],
                report_id=report["report_id"],
                ran_at=now,
            )
            return

        self._stats["generated"] += 1
        resolved = store.resolve_report_file(
            self._settings, report["report_id"], tenant_id=schedule["tenant_id"]
        )
        if resolved is None:
            self._stats["failed"] += 1
            LOG.warning("Report %s is ready but its file is missing", report["report_id"])
            return
        path, _media_type, _filename = resolved
        entries = report_delivery.deliver(
            self._settings,
            report=report,
            path=path,
            recipients=schedule.get("recipients") or [],
        )
        if entries:
            store.record_delivery(self._settings, report["report_id"], entries)
            self._stats["delivered"] += sum(
                1 for entry in entries if entry["status"] == "delivered"
            )
            self._stats["delivery_failures"] += sum(
                1 for entry in entries if entry["status"] == "failed"
            )
        store.record_dispatch(
            self._settings, schedule["schedule_id"], report_id=report["report_id"], ran_at=now
        )


_DISPATCHER: ReportDispatcher | None = None


def start_worker(settings: Settings) -> ReportDispatcher | None:
    global _DISPATCHER
    if not (settings.reports_enabled and settings.report_dispatch_enabled):
        return None
    if _DISPATCHER is not None:
        return _DISPATCHER
    worker = ReportDispatcher(settings=settings)
    worker.start()
    _DISPATCHER = worker
    return worker


def stop_worker() -> None:
    global _DISPATCHER
    if _DISPATCHER is not None:
        _DISPATCHER.stop()
        _DISPATCHER = None


def dispatcher_stats() -> dict[str, Any] | None:
    return None if _DISPATCHER is None else _DISPATCHER.stats
