"""Keeps software→CVE findings current after an inventory submission (M3).

Without this the lifecycle goes stale the moment it is populated: before M3 the
matcher only ever ran from ``POST /api/endpoint/.../cve-matches/refresh``, so a
tracked software finding would keep the SLA of a snapshot nobody re-matched,
and a host that had already been patched would stay open until an operator
clicked a button.

**Why not inside the ingest.** ``endpoint_inventory.ingest_snapshot`` already
does the expensive part of the submission — bounds checks, the software diff,
the change rows — under a per-agent rate limit, and re-matching every package
against the advisory feed inside that request would put a fleet-wide workload
on the agent's HTTP path. The ingest instead records the new
``latest_snapshot_id`` (which it did anyway) and calls :func:`notify` to
shorten this worker's wait.

**What the queue actually is.** The durable statement "this device needs
re-matching" is a comparison of ``endpoint_devices.latest_snapshot_id`` against
the ``snapshot_id`` its ``software_cve_matches`` rows were written from. That
survives a restart, is the same answer in every replica, and cannot drift from
reality the way an in-memory list would. :func:`notify` is latency only.

**Leader-locked**, like the schedule and report dispatchers and unlike the job
reaper: this worker takes no per-row claim, so two replicas would re-match the
same devices and write the same lifecycle events twice. Leadership is not
fenced, so the fold itself stays idempotent — a re-fold of the same snapshot
updates the assessment and writes no event (see
``api/services/software_findings.py``).
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import software_findings
from api.services.leader_lock import SOFTWARE_MATCH_LOCK_ID, LeaderLock
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.software-match")


def _now() -> datetime:
    return datetime.now(UTC)


def pending_device_ids(settings: Settings, *, tenant_id: str, limit: int) -> list[str]:
    """Devices whose matches were written from an older snapshot than the
    device's current one, worst-stale first is not needed — any order will do,
    because every one of them is due.

    A device with a snapshot and no match rows at all is included: it has never
    been matched, which is the same work.
    """
    with get_session(settings.postgres_url) as session:
        matched_snapshot = (
            select(
                models.SoftwareCveMatch.device_id.label("device_id"),
                models.SoftwareCveMatch.snapshot_id.label("snapshot_id"),
            )
            .where(models.SoftwareCveMatch.tenant_id == tenant_id)
            .distinct()
            .subquery()
        )
        rows = session.execute(
            select(models.EndpointDevice.device_id)
            .outerjoin(
                matched_snapshot,
                matched_snapshot.c.device_id == models.EndpointDevice.device_id,
            )
            .where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.latest_snapshot_id.is_not(None),
                (matched_snapshot.c.snapshot_id.is_(None))
                | (matched_snapshot.c.snapshot_id != models.EndpointDevice.latest_snapshot_id),
            )
            .limit(limit)
        ).scalars().all()
    # ``distinct()`` is over (device, snapshot) pairs, so a device mid-rewrite
    # can appear twice; the caller must not re-match it twice in one pass.
    return list(dict.fromkeys(rows))


def sweep_tenant(settings: Settings, tenant_id: str) -> dict[str, Any]:
    """One pass over one tenant's stale devices."""
    batch_size = max(1, settings.software_match_batch_size)
    device_ids = pending_device_ids(settings, tenant_id=tenant_id, limit=batch_size)
    if not device_ids:
        return {"devices": 0}
    stats = software_findings.ingest_devices(
        settings, tenant_id=tenant_id, device_ids=device_ids
    )
    LOG.info("Software match sweep: tenant=%s %s", tenant_id, stats.as_dict())
    return stats.as_dict()


def sweep(settings: Settings) -> dict[str, Any]:
    """One pass across every tenant. Fail-soft per tenant, like the retention
    sweep: one tenant with an unreadable advisory feed must not stop the rest."""
    from api.services import tenants as tenants_service

    totals: dict[str, Any] = {"tenants": 0, "devices": 0, "created": 0, "closed": 0, "errors": 0}
    try:
        tenant_ids = [t["tenant_id"] for t in tenants_service.list_tenants()]
    except Exception:  # noqa: BLE001 - a tenant-store hiccup must not kill the worker
        LOG.exception("Software match: could not list tenants")
        totals["errors"] += 1
        return totals

    for tenant_id in tenant_ids:
        totals["tenants"] += 1
        try:
            result = sweep_tenant(settings, tenant_id)
        except Exception:  # noqa: BLE001 - keep sweeping the remaining tenants
            totals["errors"] += 1
            LOG.exception("Software match sweep failed for tenant %s", tenant_id)
            continue
        for key in ("devices", "created", "closed"):
            totals[key] += int(result.get(key, 0))
    return totals


class SoftwareMatchWorker:
    def __init__(self, *, settings: Settings, interval_seconds: float | None = None) -> None:
        self._settings = settings
        self._interval = float(
            interval_seconds
            if interval_seconds is not None
            else settings.software_match_interval_seconds
        )
        self._stop = threading.Event()
        # Separate from ``_stop`` so a submission can shorten the wait without
        # the loop having to tell "time to work" from "time to exit".
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url,
            object_id=SOFTWARE_MATCH_LOCK_ID,
            name="software match worker",
        )
        self._stats: dict[str, Any] = {
            "runs": 0,
            "devices": 0,
            "created": 0,
            "closed": 0,
            "errors": 0,
            "skipped_not_leader": 0,
            "last_run_at": None,
        }

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats, "is_leader": int(self._lock.is_leader)}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-software-match", daemon=True)
        self._thread.start()
        LOG.info(
            "Software match worker started (interval=%.0fs, batch=%d, matches only while leader)",
            self._interval,
            self._settings.software_match_batch_size,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        # After the join, so the loop cannot re-acquire behind us.
        self._lock.release()
        LOG.info("Software match worker stopped stats=%s", self.stats)

    def notify(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._lock.acquire():
                    self.run_once()
                else:
                    self._stats["skipped_not_leader"] += 1
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Software match tick failed")
            self._wake.wait(self._interval)
            self._wake.clear()

    def run_once(self) -> dict[str, Any]:
        totals = sweep(self._settings)
        self._stats["runs"] += 1
        for key in ("devices", "created", "closed", "errors"):
            self._stats[key] += int(totals.get(key, 0))
        self._stats["last_run_at"] = _now().isoformat().replace("+00:00", "Z")
        return totals


_WORKER: SoftwareMatchWorker | None = None


def start_worker(settings: Settings) -> SoftwareMatchWorker | None:
    global _WORKER
    if not (settings.endpoint_inventory_enabled and settings.software_match_enabled):
        return None
    if _WORKER is not None:
        return _WORKER
    worker = SoftwareMatchWorker(settings=settings)
    worker.start()
    _WORKER = worker
    return worker


def stop_worker() -> None:
    global _WORKER
    if _WORKER is not None:
        _WORKER.stop()
        _WORKER = None


def notify() -> None:
    """Ask the worker to look now rather than at the end of its interval.

    A no-op when no worker runs in this process — the durable queue is the
    snapshot comparison, so nothing is lost, it just waits for a tick.
    """
    if _WORKER is not None:
        _WORKER.notify()


def worker_stats() -> dict[str, Any] | None:
    if _WORKER is None:
        return None
    return _WORKER.stats
