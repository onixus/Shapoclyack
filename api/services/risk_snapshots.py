"""Historical risk score snapshots service (#144, Track C).

Takes and queries point-in-time snapshots of an organization's vulnerability
counts, NIST risk levels, and SLA breaches so the security dashboard can
render accurate risk trend charts over time.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session
from api.services import vulnerabilities as vulns_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.risk_snapshots")


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _to_dict(row: models.RiskScoreSnapshot) -> dict[str, Any]:
    return {
        "snapshot_id": row.snapshot_id,
        "tenant_id": row.tenant_id,
        "recorded_at": _iso(row.recorded_at),
        "estate_risk": row.estate_risk,
        "open_total": row.open_total,
        "total": row.total,
        "untriaged": row.untriaged,
        "unassigned": row.unassigned,
        "breached": row.breached,
        "worst_breached_severity": row.worst_breached_severity,
        "by_severity_open": dict(row.by_severity_open or {}),
        "by_risk_level_open": dict(row.by_risk_level_open or {}),
        "by_state": dict(row.by_state or {}),
        "by_sla": dict(row.by_sla or {}),
        "source": row.source,
    }


def take_snapshot(
    settings: Settings,
    *,
    tenant_id: str,
    source: str = "run",
    now: datetime | None = None,
) -> dict[str, Any]:
    """Capture current risk posture for a tenant and persist it to PostgreSQL."""
    recorded_at = now or _now()
    summary_data = vulns_service.summary(settings, tenant_id=tenant_id)

    snapshot_id = f"rsnap_{uuid.uuid4().hex[:16]}"
    snapshot = models.RiskScoreSnapshot(
        snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        recorded_at=recorded_at,
        estate_risk=summary_data.get("estate_risk"),
        open_total=summary_data.get("open_total", 0),
        total=summary_data.get("total", 0),
        untriaged=summary_data.get("untriaged", 0),
        unassigned=summary_data.get("unassigned", 0),
        breached=summary_data.get("breached", 0),
        worst_breached_severity=summary_data.get("worst_breached_severity"),
        by_severity_open=dict(summary_data.get("by_severity_open") or {}),
        by_risk_level_open=dict(summary_data.get("by_risk_level_open") or {}),
        by_state=dict(summary_data.get("by_state") or {}),
        by_sla=dict(summary_data.get("by_sla") or {}),
        source=source,
    )

    with get_session(settings.postgres_url) as session:
        session.add(snapshot)
        session.commit()
        session.refresh(snapshot)
        LOG.info(
            "Recorded risk snapshot %s for tenant %s (estate_risk=%s open=%s source=%s)",
            snapshot.snapshot_id,
            tenant_id,
            snapshot.estate_risk,
            snapshot.open_total,
            source,
        )
        return _to_dict(snapshot)


def list_snapshots(
    settings: Settings,
    *,
    tenant_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Retrieve the ``limit`` most recent snapshots, ordered chronologically.

    The query sorts **descending** and the page is reversed afterwards: a
    chart that asks for 30 points wants the last 30 days, and ``ASC`` with a
    ``LIMIT`` hands back the oldest rows instead — which froze the trend chart
    on the first days of the install once the table outgrew the limit (#228).
    """
    filters: list[Any] = []
    if tenant_id:
        filters.append(models.RiskScoreSnapshot.tenant_id == tenant_id)
    if since:
        filters.append(models.RiskScoreSnapshot.recorded_at >= since)
    if until:
        filters.append(models.RiskScoreSnapshot.recorded_at <= until)

    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.RiskScoreSnapshot)
                .where(*filters)
                .order_by(
                    models.RiskScoreSnapshot.recorded_at.desc(),
                    models.RiskScoreSnapshot.id.desc(),
                )
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [_to_dict(row) for row in reversed(rows)]


def prune_snapshots(
    settings: Settings,
    *,
    tenant_id: str | None = None,
    retention_days: int = 90,
    now: datetime | None = None,
) -> int:
    """Delete snapshots older than the configured retention threshold."""
    cutoff = (now or _now()) - timedelta(days=retention_days)
    filters: list[Any] = [models.RiskScoreSnapshot.recorded_at < cutoff]
    if tenant_id:
        filters.append(models.RiskScoreSnapshot.tenant_id == tenant_id)

    with get_session(settings.postgres_url) as session:
        result = session.execute(delete(models.RiskScoreSnapshot).where(*filters))
        session.commit()
        deleted = int(result.rowcount or 0)
        if deleted:
            LOG.info("Pruned %s risk snapshots older than %s days", deleted, retention_days)
        return deleted


# --------------------------------------------------------------------------
# Retention worker (#229)
# --------------------------------------------------------------------------
#
# One row per tenant per finished run: the table grows linearly and forever,
# and #187 ("bound data growth") predates migration 0023, so nothing swept it.
# Same shape as ``run_retention``: an in-process ticker in every replica. The
# delete is a plain range delete on ``(tenant_id, recorded_at)``, so replicas
# racing on the same rows is a no-op for whoever loses.

_worker: RiskSnapshotRetentionWorker | None = None


def sweep(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Prune expired snapshots across all tenants. Returns counts (deleted)."""
    days = settings.risk_snapshot_retention_days
    if days <= 0:
        return {"deleted": 0}
    deleted = prune_snapshots(settings, retention_days=days, now=now)
    return {"deleted": deleted}


class RiskSnapshotRetentionWorker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats: dict[str, Any] = {"last_run_at": None, "last": {}}

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="octo-risk-snapshot-retention", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Risk snapshot retention worker started (interval=%ds, days=%d)",
            self._settings.risk_snapshot_retention_interval_seconds,
            self._settings.risk_snapshot_retention_days,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        LOG.info("Risk snapshot retention worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._stats["last"] = sweep(self._settings)
                self._stats["last_run_at"] = _now().isoformat()
            except Exception:  # noqa: BLE001
                LOG.exception("Risk snapshot retention tick failed")
            self._stop.wait(self._settings.risk_snapshot_retention_interval_seconds)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)


def start_worker(settings: Settings) -> None:
    global _worker
    if not settings.risk_snapshot_retention_enabled:
        return
    if _worker is None:
        _worker = RiskSnapshotRetentionWorker(settings)
        _worker.start()


def stop_worker() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


def worker_stats() -> dict[str, Any] | None:
    return None if _worker is None else _worker.stats()
