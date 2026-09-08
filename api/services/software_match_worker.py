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
``last_matched_snapshot_id`` — the snapshot the fold last ran over, whatever it
concluded. That survives a restart, is the same answer in every replica, and
cannot drift from reality the way an in-memory list would. :func:`notify` is
latency only.

It used to be derived from the match rows instead, which needed no column and
was wrong for the host the matcher has nothing to say about: every package
matchable, no advisory hits, no ``unknown`` placeholders, therefore zero rows
and no snapshot to compare — so the device was due again on the next tick, and
on every tick after that. With ``LIMIT batch_size`` and no ``ORDER BY``, a few
hundred such hosts permanently starve the devices that changed. Migration
``0033`` added the marker.

**A tick drains, it does not take one batch.**
``OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS`` is documented as a ceiling on how
stale a tracked software finding may be. One batch per tick made the real
ceiling ``due_devices / batch_size × interval`` — for 50k due devices at the
defaults, the better part of a working week. A tick now keeps taking batches
until the tenant has nothing due or ``OCTO_SOFTWARE_MATCH_TICK_BUDGET_SECONDS``
is spent, which bounds the tick without bounding the queue.

**One device cannot stop a tenant.** The fold takes each device in a SAVEPOINT
and holds a device that raised off with a capped backoff
(``software_findings._hold_off``). Before that, a whole batch shared one
transaction and the sweep caught at tenant level, so one poisonous device
failed its batch and was re-read at the head of the same batch on the next
tick, forever.

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
import time
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
    """Devices whose current snapshot has not been folded yet.

    "Folded", not "matched into rows": ``last_matched_snapshot_id`` is written
    for every verdict the fold reaches, so a host with nothing to report leaves
    the queue like any other. A device held off after a failure
    (``match_retry_after`` in the future) is still due, just not yet.

    Ordered oldest-inventory first. Any order is *correct* — every row is due —
    but the unordered ``LIMIT`` meant a device that could not be drained in one
    tick sat at the head of every batch, and the one that had just been
    patched waited behind it.
    """
    now = _now().replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.EndpointDevice.device_id)
            .where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.latest_snapshot_id.is_not(None),
                (models.EndpointDevice.last_matched_snapshot_id.is_(None))
                | (
                    models.EndpointDevice.last_matched_snapshot_id
                    != models.EndpointDevice.latest_snapshot_id
                ),
                (models.EndpointDevice.match_retry_after.is_(None))
                | (models.EndpointDevice.match_retry_after <= now),
            )
            .order_by(models.EndpointDevice.last_inventory_at.asc())
            .limit(limit)
        ).scalars().all()
    return list(dict.fromkeys(rows))


def sweep_tenant(
    settings: Settings, tenant_id: str, *, deadline: float | None = None
) -> dict[str, Any]:
    """Drain one tenant's due devices, in batches, until the budget runs out.

    ``deadline`` is a :func:`time.monotonic` reading, defaulting to
    ``OCTO_SOFTWARE_MATCH_TICK_BUDGET_SECONDS`` from now. Taking a single batch
    per tick made ``OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS`` a ceiling on nothing
    — the real one was ``due / batch_size × interval``, which for a large
    estate is days. Whatever is left when the budget expires is still due and
    is picked up by the next tick; the marker makes that resumption exact.
    """
    batch_size = max(1, settings.software_match_batch_size)
    if deadline is None:
        deadline = time.monotonic() + max(
            1.0, float(settings.software_match_tick_budget_seconds)
        )
    stats = software_findings.SoftwareFindingStats()
    batches = 0
    while True:
        device_ids = pending_device_ids(settings, tenant_id=tenant_id, limit=batch_size)
        if not device_ids:
            break
        stats.add(
            software_findings.ingest_devices(
                settings, tenant_id=tenant_id, device_ids=device_ids
            )
        )
        batches += 1
        if time.monotonic() >= deadline:
            LOG.info(
                "Software match sweep: tenant=%s out of tick budget after %d batches",
                tenant_id,
                batches,
            )
            break
    if not batches:
        return {"devices": 0}
    LOG.info("Software match sweep: tenant=%s %s", tenant_id, stats.as_dict())
    return stats.as_dict()


def sweep(settings: Settings) -> dict[str, Any]:
    """One pass across every tenant. Fail-soft per tenant, like the retention
    sweep: one tenant with an unreadable advisory feed must not stop the rest.

    The tick budget is shared across tenants and re-read per tenant, so a
    first tenant that used it all still leaves the rest one batch each rather
    than none — otherwise the tenant that happens to sort first would be the
    only one ever swept on a loaded installation.
    """
    from api.services import tenants as tenants_service

    totals: dict[str, Any] = {"tenants": 0, "devices": 0, "created": 0, "closed": 0, "errors": 0}
    try:
        tenant_ids = [t["tenant_id"] for t in tenants_service.list_tenants()]
    except Exception:  # noqa: BLE001 - a tenant-store hiccup must not kill the worker
        LOG.exception("Software match: could not list tenants")
        totals["errors"] += 1
        return totals

    budget = max(1.0, float(settings.software_match_tick_budget_seconds))
    started = time.monotonic()
    for index, tenant_id in enumerate(tenant_ids):
        totals["tenants"] += 1
        remaining = len(tenant_ids) - index
        share = max(0.0, budget - (time.monotonic() - started)) / remaining
        try:
            result = sweep_tenant(
                settings, tenant_id, deadline=time.monotonic() + share
            )
        except Exception:  # noqa: BLE001 - keep sweeping the remaining tenants
            totals["errors"] += 1
            LOG.exception("Software match sweep failed for tenant %s", tenant_id)
            continue
        for key in ("devices", "created", "closed", "errors"):
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
