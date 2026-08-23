"""Historical risk score snapshots service (#144, Track C).

Takes and queries point-in-time snapshots of an organization's vulnerability
counts, NIST risk levels, and SLA breaches so the security dashboard can
render accurate risk trend charts over time.
"""

from __future__ import annotations

import logging
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
    """Retrieve historical snapshots ordered chronologically for plotting."""
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
                .order_by(models.RiskScoreSnapshot.recorded_at.asc())
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [_to_dict(row) for row in rows]


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
