"""Per-tenant risk posture for the MSSP comparison (#139).

One pass over open findings and one over assets, grouped by tenant, so a
provider can compare customers without N round-trips. Internet-facing counts
are **operator-declared** ``exposure_level='internet'`` — not a scan
measurement (#171).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import nist_risk, vuln_states
from api.settings import Settings


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def list_posture(
    settings: Settings, *, tenant_ids: list[str] | None = None
) -> list[dict[str, Any]]:
    """Return one row per allowed tenant, worst ``estate_risk`` first."""
    now = _now()
    with get_session(settings.postgres_url) as session:
        tenant_rows = session.execute(select(models.Tenant)).scalars().all()
        allowed = set(tenant_ids) if tenant_ids is not None else None
        tenants = [
            row
            for row in tenant_rows
            if allowed is None or row.tenant_id in allowed
        ]

        vuln_filters: list[Any] = [models.Vulnerability.state.in_(tuple(vuln_states.ACTIVE))]
        asset_query = select(
            models.Asset.tenant_id,
            models.Asset.status,
            models.Asset.owner_email,
            models.Asset.exposure_level,
        )
        if allowed is not None:
            scope = tuple(allowed) or ("__none__",)
            vuln_filters.append(models.Vulnerability.tenant_id.in_(scope))
            asset_query = asset_query.where(models.Asset.tenant_id.in_(scope))

        findings = session.execute(
            select(
                models.Vulnerability.tenant_id,
                models.Vulnerability.risk_level,
                models.Vulnerability.assignee,
                models.Vulnerability.due_at,
                models.Vulnerability.exception_until,
                models.Vulnerability.in_kev,
            ).where(*vuln_filters)
        ).all()
        assets = session.execute(asset_query).all()

    by_tenant: dict[str, dict[str, Any]] = {}
    for tenant in tenants:
        by_tenant[tenant.tenant_id] = {
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
            "status": tenant.status,
            "estate_risk": None,
            "open_total": 0,
            "unassigned": 0,
            "breached": 0,
            "in_kev_open": 0,
            "unowned_assets": 0,
            "declared_internet_assets": 0,
        }

    for tenant_id, risk_level, assignee, due_at, exception_until, in_kev in findings:
        bucket = by_tenant.get(tenant_id)
        if bucket is None:
            continue
        bucket["open_total"] += 1
        if not assignee:
            bucket["unassigned"] += 1
        if in_kev:
            bucket["in_kev_open"] += 1
        level = str(risk_level) if risk_level in nist_risk.LEVEL_RANK else None
        if level and nist_risk.LEVEL_RANK[level] > nist_risk.LEVEL_RANK.get(
            bucket["estate_risk"] or "", -1
        ):
            bucket["estate_risk"] = level
        if due_at is not None:
            accepted = exception_until is not None and exception_until > now
            if not accepted and due_at <= now:
                bucket["breached"] += 1

    for tenant_id, status, owner_email, exposure_level in assets:
        bucket = by_tenant.get(tenant_id)
        if bucket is None:
            continue
        if status in ("active", "stale") and not owner_email:
            bucket["unowned_assets"] += 1
        if exposure_level == "internet" and status in ("active", "stale"):
            bucket["declared_internet_assets"] += 1

    rows = list(by_tenant.values())
    rows.sort(
        key=lambda row: (
            -nist_risk.LEVEL_RANK.get(row["estate_risk"] or "", -1),
            -int(row["open_total"]),
            str(row["name"] or row["tenant_id"]).lower(),
        )
    )
    return rows
