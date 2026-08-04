"""Endpoint-inventory retention sweep (Agent_plan.md S9, decision 2).

Policy:

* ``endpoint_software_items`` of snapshots older than
  ``endpoint_snapshot_retention_days`` (default 90d) are deleted; the snapshot
  summary row (id, digest, counts, timestamps, collector warnings) is kept so
  the submission history stays queryable and idempotency keys stay honoured.
* ``endpoint_software_changes`` older than ``endpoint_change_retention_days``
  (default 365d) are deleted — they are the audit history and outlive the raw
  software rows they were derived from.

A device's **current** snapshot is never pruned even when it is older than the
retention window: ``endpoint_inventory.ingest_snapshot`` diffs the next
submission against ``EndpointDevice.latest_snapshot_id``'s software rows, so
pruning it would make a quiet device's next snapshot report its entire
software list as freshly installed.

Deletes are tenant-scoped and batched (``endpoint_retention_batch_size``) so a
sweep over a large installation never issues one unbounded statement.
Structured like ``api.services.schedule_dispatcher``: a daemon thread with a
crash-restart loop, started/stopped from the FastAPI lifespan.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.endpoint-retention")


def _now() -> datetime:
    return datetime.now(UTC)


def _delete_in_batches(session, model, id_column, where_clauses: list, batch_size: int) -> int:
    """Delete rows matching ``where_clauses`` ``batch_size`` at a time."""
    deleted = 0
    while True:
        ids = session.execute(
            select(id_column).where(*where_clauses).limit(batch_size)
        ).scalars().all()
        if not ids:
            return deleted
        session.execute(delete(model).where(id_column.in_(ids)))
        deleted += len(ids)
        if len(ids) < batch_size:
            return deleted


def sweep_tenant(settings: Settings, tenant_id: str, *, now: datetime | None = None) -> dict[str, int]:
    """Apply the retention policy for one tenant. Returns per-table delete counts."""
    now = now or _now()
    snapshot_cutoff = now - timedelta(days=settings.endpoint_snapshot_retention_days)
    change_cutoff = now - timedelta(days=settings.endpoint_change_retention_days)
    batch_size = max(1, settings.endpoint_retention_batch_size)

    with get_session(settings.postgres_url) as session:
        protected = set(
            session.execute(
                select(models.EndpointDevice.latest_snapshot_id).where(
                    models.EndpointDevice.tenant_id == tenant_id,
                    models.EndpointDevice.latest_snapshot_id.is_not(None),
                )
            ).scalars().all()
        )
        expired_snapshots = session.execute(
            select(models.EndpointInventorySnapshot.snapshot_id).where(
                models.EndpointInventorySnapshot.tenant_id == tenant_id,
                models.EndpointInventorySnapshot.received_at < snapshot_cutoff,
            )
        ).scalars().all()
        prunable = [sid for sid in expired_snapshots if sid not in protected]

        items_deleted = 0
        snapshots_pruned = 0
        for start in range(0, len(prunable), batch_size):
            chunk = prunable[start : start + batch_size]
            # Only count snapshots that still hold software rows, so a repeat
            # sweep over already-pruned history reports zero rather than
            # re-counting the same snapshots every interval.
            with_items = session.execute(
                select(models.EndpointSoftwareItem.snapshot_id)
                .where(
                    models.EndpointSoftwareItem.tenant_id == tenant_id,
                    models.EndpointSoftwareItem.snapshot_id.in_(chunk),
                )
                .distinct()
            ).scalars().all()
            if not with_items:
                continue
            items_deleted += _delete_in_batches(
                session,
                models.EndpointSoftwareItem,
                models.EndpointSoftwareItem.id,
                [
                    models.EndpointSoftwareItem.tenant_id == tenant_id,
                    models.EndpointSoftwareItem.snapshot_id.in_(with_items),
                ],
                batch_size,
            )
            snapshots_pruned += len(with_items)

        changes_deleted = _delete_in_batches(
            session,
            models.EndpointSoftwareChange,
            models.EndpointSoftwareChange.id,
            [
                models.EndpointSoftwareChange.tenant_id == tenant_id,
                models.EndpointSoftwareChange.observed_at < change_cutoff,
            ],
            batch_size,
        )

    return {
        "software_items_deleted": items_deleted,
        "changes_deleted": changes_deleted,
        "snapshots_pruned": snapshots_pruned,
    }


def sweep(settings: Settings, *, now: datetime | None = None) -> dict[str, Any]:
    """Run one retention sweep across every tenant. Fail-soft per tenant."""
    from api.services import tenants as tenants_service

    now = now or _now()
    started = time.perf_counter()
    totals = {
        "tenants": 0,
        "software_items_deleted": 0,
        "changes_deleted": 0,
        "snapshots_pruned": 0,
        "errors": 0,
    }
    try:
        tenant_ids = [t["tenant_id"] for t in tenants_service.list_tenants()]
    except Exception:  # noqa: BLE001 - a tenant-store hiccup must not kill the worker
        LOG.exception("Endpoint retention: could not list tenants")
        totals["errors"] += 1
        return totals

    for tenant_id in tenant_ids:
        totals["tenants"] += 1
        try:
            result = sweep_tenant(settings, tenant_id, now=now)
        except Exception:  # noqa: BLE001 - keep sweeping the remaining tenants
            totals["errors"] += 1
            LOG.exception("Endpoint retention sweep failed for tenant %s", tenant_id)
            continue
        for key, value in result.items():
            totals[key] += value

    metrics_service.ENDPOINT_RETENTION_DELETED_TOTAL.labels("endpoint_software_items").inc(
        totals["software_items_deleted"]
    )
    metrics_service.ENDPOINT_RETENTION_DELETED_TOTAL.labels("endpoint_software_changes").inc(
        totals["changes_deleted"]
    )
    metrics_service.ENDPOINT_RETENTION_RUN_DURATION_SECONDS.observe(time.perf_counter() - started)
    try:
        from api.services import endpoint_inventory

        tallied = endpoint_inventory.device_counts()
        metrics_service.ENDPOINT_DEVICES.labels("active").set(tallied["active"])
        metrics_service.ENDPOINT_DEVICES.labels("stale").set(tallied["stale"])
    except Exception:  # noqa: BLE001 - gauge refresh must not fail the sweep
        LOG.warning("Endpoint retention: could not refresh device gauge", exc_info=True)
    if totals["software_items_deleted"] or totals["changes_deleted"] or totals["errors"]:
        LOG.info("Endpoint retention sweep: %s", totals)
    return totals


class EndpointRetentionWorker:
    def __init__(self, *, settings: Settings, interval_seconds: float | None = None) -> None:
        self._settings = settings
        self._interval = float(
            interval_seconds
            if interval_seconds is not None
            else settings.endpoint_retention_interval_seconds
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats: dict[str, Any] = {
            "runs": 0,
            "software_items_deleted": 0,
            "changes_deleted": 0,
            "snapshots_pruned": 0,
            "errors": 0,
            "last_run_at": None,
        }

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="octo-endpoint-retention", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Endpoint retention worker started (interval=%.0fs, snapshots=%dd, changes=%dd)",
            self._interval,
            self._settings.endpoint_snapshot_retention_days,
            self._settings.endpoint_change_retention_days,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("Endpoint retention worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Endpoint retention tick failed")
            self._stop.wait(self._interval)

    def run_once(self) -> dict[str, Any]:
        totals = sweep(self._settings)
        self._stats["runs"] += 1
        for key in ("software_items_deleted", "changes_deleted", "snapshots_pruned", "errors"):
            self._stats[key] += totals[key]
        self._stats["last_run_at"] = _now().isoformat().replace("+00:00", "Z")
        return totals


_WORKER: EndpointRetentionWorker | None = None


def start_worker(settings: Settings) -> EndpointRetentionWorker | None:
    global _WORKER
    if not (settings.endpoint_inventory_enabled and settings.endpoint_retention_enabled):
        return None
    if _WORKER is not None:
        return _WORKER
    worker = EndpointRetentionWorker(settings=settings)
    worker.start()
    _WORKER = worker
    return worker


def stop_worker() -> None:
    global _WORKER
    if _WORKER is not None:
        _WORKER.stop()
        _WORKER = None


def worker_stats() -> dict[str, Any] | None:
    if _WORKER is None:
        return None
    return _WORKER.stats
