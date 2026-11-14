"""In-process dispatcher for brand-watch jobs (M1).

Same thread and leader-lock shape as ``schedule_dispatcher``, but it enqueues
``brand_watch_jobs`` and never calls ``jobs.start_scan``. Daily cadence per
profile; a weekly rebuild replaces the candidate list and keeps disposition
of names that remain. It does not use the scan scheduler's cron.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

from api.services import brand_watch
from api.services.leader_lock import BRAND_WATCH_DISPATCHER_LOCK_ID, LeaderLock
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.brand-watch-dispatcher")

_WEEK = timedelta(days=7)


class BrandWatchDispatcher:
    def __init__(self, *, settings: Settings, poll_interval_seconds: float = 60.0) -> None:
        self._settings = settings
        self._poll_interval = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url,
            object_id=BRAND_WATCH_DISPATCHER_LOCK_ID,
            name="brand-watch dispatcher",
        )
        self._stats = {
            "ticks": 0,
            "enqueued": 0,
            "rebuilt": 0,
            "skipped_not_leader": 0,
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
        self._thread = threading.Thread(
            target=self._run, name="octo-brand-watch-dispatcher", daemon=True
        )
        self._thread.start()
        LOG.info("Brand-watch dispatcher started (poll_interval=%.0fs)", self._poll_interval)

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        self._lock.release()
        LOG.info("Brand-watch dispatcher stopped stats=%s", self.stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._lead():
                    self.tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Brand-watch dispatch tick failed")
            self._stop.wait(self._poll_interval)

    def _lead(self) -> bool:
        leader = self._lock.acquire()
        if not leader:
            self._stats["skipped_not_leader"] += 1
        return leader

    def tick(self, *, now: datetime | None = None) -> dict[str, int]:
        """One pass. Public so tests can run it without the thread."""
        from api.db.engine import get_session

        self._stats["ticks"] += 1
        moment = now or datetime.now(UTC).replace(tzinfo=None)
        enqueued = 0
        rebuilt = 0
        with get_session(self._settings.postgres_url) as session:
            session.expire_on_commit = False
            profiles = brand_watch.due_profiles(session, moment)
            for profile in profiles:
                if _rebuild_due(profile, moment):
                    try:
                        brand_watch.rebuild_candidates(
                            self._settings,
                            tenant_id=profile.tenant_id,
                            profile_id=profile.id,
                        )
                        rebuilt += 1
                    except Exception:  # noqa: BLE001
                        self._stats["errors"] += 1
                        LOG.exception("Brand-watch rebuild failed for %s", profile.id)
                job = brand_watch.enqueue_for_profile(session, profile, now=moment)
                if job is not None:
                    if job.mode == "http_allowed" and brand_watch.watch_mode(profile) != "http_allowed":
                        job.mode = "dns_only"
                        job.payload = {**(job.payload or {}), "mode": "dns_only"}
                    enqueued += 1
        self._stats["enqueued"] += enqueued
        self._stats["rebuilt"] += rebuilt
        return {"enqueued": enqueued, "rebuilt": rebuilt}


def _rebuild_due(profile, moment: datetime) -> bool:
    if profile.last_rebuilt_at is None:
        return True
    return moment - profile.last_rebuilt_at >= _WEEK


_DISPATCHER: BrandWatchDispatcher | None = None


def start_worker(settings: Settings) -> BrandWatchDispatcher | None:
    global _DISPATCHER
    if _DISPATCHER is not None:
        return _DISPATCHER
    worker = BrandWatchDispatcher(settings=settings)
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
