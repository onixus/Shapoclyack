"""Background sweep for jobs whose executor stopped renewing its lease (P1.4).

Structured like ``schedule_dispatcher``/``endpoint_retention``: a daemon thread
with a crash-restart loop, started and stopped from the FastAPI lifespan. The
work itself is one function, ``jobs.reap_expired_leases``; this module only
decides when to call it.

Unlike the schedule dispatcher, this worker is **safe in every replica** and
does not wait on leader election (P1.6). Expiry is a property of the row, not
of the observer, and the sweep takes its candidates with ``FOR UPDATE SKIP
LOCKED``, so concurrent reapers divide the work instead of duplicating it.
"""

from __future__ import annotations

import logging
import threading

from api.services import jobs as jobs_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.job-reaper")


class JobReaper:
    def __init__(self, *, settings: Settings, poll_interval_seconds: float | None = None) -> None:
        self._settings = settings
        self._poll_interval = poll_interval_seconds or float(settings.job_reaper_interval_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"ticks": 0, "requeued": 0, "failed": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-job-reaper", daemon=True)
        self._thread.start()
        LOG.info(
            "Job reaper started (poll_interval=%.0fs lease=%ds max_attempts=%d)",
            self._poll_interval,
            self._settings.job_lease_seconds,
            self._settings.job_max_attempts,
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
        outcome = jobs_service.reap_expired_leases(self._settings)
        self._stats["requeued"] += outcome["requeued"]
        self._stats["failed"] += outcome["failed"]


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
