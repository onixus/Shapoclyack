"""Restart-safe periodic classification of registered assets (#578).

Each tick advances persisted tenant cursors by one bounded transaction. A
restart resumes the cursor; a completed pass starts again so changes made by
any importer are eventually observed without an unreliable in-memory event.
"""
from __future__ import annotations

import logging
import threading

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services.leader_lock import ASSET_GROUP_LOCK_ID, LeaderLock

LOG = logging.getLogger("shapoclyack.asset_groups")
_stop = threading.Event()
_thread: threading.Thread | None = None


def tick(settings) -> None:
    from api.services import asset_groups

    # Keyset tenants as well as assets: no unbounded tenant list in memory.
    after = ""
    while not _stop.is_set():
        with get_session(settings.postgres_url) as session:
            tenants = session.execute(
                select(models.AssetGroup.tenant_id)
                .where(models.AssetGroup.tenant_id > after)
                .distinct().order_by(models.AssetGroup.tenant_id).limit(100)
            ).scalars().all()
        if not tenants:
            return
        for tenant_id in tenants:
            if _stop.is_set():
                return
            try:
                asset_groups.reconcile_batch(
                    settings, tenant_id, limit=settings.asset_groups_batch_size,
                )
            except Exception:
                # One broken tenant never starves the remaining tenant pages.
                LOG.exception("Asset group reconciliation failed tenant=%s", tenant_id)
        after = tenants[-1]


def start_worker(settings) -> None:
    global _thread
    if not settings.asset_groups_enabled or (_thread and _thread.is_alive()):
        return
    _stop.clear()

    def loop():
        lock = LeaderLock(settings.postgres_url, object_id=ASSET_GROUP_LOCK_ID, name="asset-groups")
        try:
            while not _stop.wait(max(5, settings.asset_groups_interval_seconds)):
                try:
                    if lock.acquire():
                        tick(settings)
                except Exception:
                    LOG.exception("Asset group worker tick failed")
        finally:
            lock.release()

    _thread = threading.Thread(target=loop, daemon=True, name="asset-groups")
    _thread.start()


def stop_worker() -> None:
    _stop.set()
    if _thread:
        _thread.join(timeout=12)
        if _thread.is_alive():
            LOG.error("Asset group worker is still completing its bounded batch")
