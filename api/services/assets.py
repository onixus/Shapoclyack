"""Cross-run asset inventory (Phase 7). Postgres-backed, additive to the
filesystem-backed per-run views in api/services/runs.py — those stay
untouched; this module correlates hosts across runs into a persistent
registry.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import runs as runs_service
from api.settings import Settings
from scanner.pipeline.asset_identity import (
    IdentityCandidate,
    identity_candidates_for_host,
    ip_identity_key,
)

LOG = logging.getLogger("octo-man.assets")


@dataclass(frozen=True)
class AssetUpsertStats:
    hosts_seen: int
    assets_created: int
    assets_updated: int
    marked_stale: int


def _now() -> datetime:
    return datetime.now(UTC)


def _host_records(run_dir: Path) -> list[dict]:
    alive = runs_service._load_json(run_dir / "alive_hosts.json")  # noqa: SLF001
    if isinstance(alive, list) and alive:
        return [row for row in alive if isinstance(row, dict) and row.get("host")]
    # Fallback: flat IP list (older / minimal output, no hostnames).
    return [{"host": ip} for ip in runs_service._read_lines(run_dir / "alive_ips.txt")]  # noqa: SLF001


def _find_existing_asset_id(
    session, tenant_id: str, candidates: list[IdentityCandidate]
) -> str | None:
    for candidate in candidates:
        row = session.execute(
            select(models.AssetIdentifier.asset_id).where(
                models.AssetIdentifier.tenant_id == tenant_id,
                models.AssetIdentifier.identifier_type == candidate.identifier_type,
                models.AssetIdentifier.identifier_value == candidate.identifier_value,
            )
        ).scalar_one_or_none()
        if row is not None:
            return row
    return None


def upsert_assets_from_run(settings: Settings, *, tenant_id: str, run_id: str) -> AssetUpsertStats:
    """Upsert one asset per host observed in ``run_id`` into the registry.

    One asset per *host record* in the run (not per identifier): when a host
    has both an IP and hostname(s), all of them attach to the same asset.
    Phase 7 does not correlate assets *across* separate host records (e.g. a
    bare-FQDN-only discovery later resolving to an IP seen elsewhere) — that
    is deferred (see scanner/pipeline/asset_identity.py).
    """
    run_dir = runs_service.get_run_dir(settings, run_id)
    if run_dir is None:
        return AssetUpsertStats(0, 0, 0, 0)

    hosts = _host_records(run_dir)
    now = _now()
    created = 0
    updated = 0

    with get_session(settings.postgres_url) as session:
        for entry in hosts:
            host_ip = str(entry.get("host") or "")
            names = entry.get("names") if isinstance(entry.get("names"), list) else []
            hostname = entry.get("hostname")
            all_names = [str(n) for n in names]
            if hostname:
                all_names.append(str(hostname))

            candidates = identity_candidates_for_host(tenant_id, host_ip=host_ip, hostnames=all_names)
            if not candidates:
                continue

            asset_id = _find_existing_asset_id(session, tenant_id, candidates)
            if asset_id is None:
                primary = next((c for c in candidates if c.identifier_type == "ip"), candidates[0])
                asset_id = primary.key

            asset = session.get(models.Asset, asset_id)
            if asset is None:
                asset = models.Asset(
                    asset_id=asset_id,
                    tenant_id=tenant_id,
                    status="active",
                    first_seen=now,
                    last_seen=now,
                )
                session.add(asset)
                created += 1
            else:
                asset.last_seen = now
                asset.status = "active"
                updated += 1

            for candidate in candidates:
                exists = session.execute(
                    select(models.AssetIdentifier.id).where(
                        models.AssetIdentifier.tenant_id == tenant_id,
                        models.AssetIdentifier.identifier_type == candidate.identifier_type,
                        models.AssetIdentifier.identifier_value == candidate.identifier_value,
                    )
                ).scalar_one_or_none()
                if exists is None:
                    session.add(
                        models.AssetIdentifier(
                            asset_id=asset_id,
                            tenant_id=tenant_id,
                            identifier_type=candidate.identifier_type,
                            identifier_value=candidate.identifier_value,
                        )
                    )

    marked_stale = mark_stale_assets(settings, tenant_id=tenant_id)
    return AssetUpsertStats(
        hosts_seen=len(hosts), assets_created=created, assets_updated=updated, marked_stale=marked_stale
    )


def mark_stale_assets(settings: Settings, *, tenant_id: str, stale_after_days: int | None = None) -> int:
    """Flip active assets not re-observed within the threshold to "stale".

    Purely a last_seen age rule, not "absent from this run" — tenants may
    legitimately scan narrow target subsets per run. "decommissioned" is
    never set automatically (operator-only, no endpoint built this phase).
    """
    days = stale_after_days if stale_after_days is not None else settings.asset_stale_days
    cutoff = _now() - timedelta(days=days)
    count = 0
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Asset).where(
                models.Asset.tenant_id == tenant_id,
                models.Asset.status == "active",
                models.Asset.last_seen < cutoff,
            )
        ).scalars()
        for asset in rows:
            asset.status = "stale"
            count += 1
    return count


def list_assets(
    settings: Settings,
    tenant_id: str,
    *,
    status: str | None = None,
    q: str | None = None,
    limit: int = 500,
) -> list[dict]:
    with get_session(settings.postgres_url) as session:
        stmt = select(models.Asset).where(models.Asset.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(models.Asset.status == status)
        stmt = stmt.order_by(models.Asset.last_seen.desc()).limit(limit)
        assets = session.execute(stmt).scalars().all()

        results: list[dict] = []
        for asset in assets:
            identifiers = session.execute(
                select(models.AssetIdentifier).where(models.AssetIdentifier.asset_id == asset.asset_id)
            ).scalars().all()
            if q:
                needle = q.strip().lower()
                if not any(needle in ident.identifier_value.lower() for ident in identifiers):
                    continue
            primary = next((i.identifier_value for i in identifiers if i.identifier_type == "ip"), None)
            results.append(
                {
                    "asset_id": asset.asset_id,
                    "tenant_id": asset.tenant_id,
                    "status": asset.status,
                    "first_seen": asset.first_seen,
                    "last_seen": asset.last_seen,
                    "primary_identifier": primary or (identifiers[0].identifier_value if identifiers else None),
                    "identifier_count": len(identifiers),
                    "asset_criticality": asset.asset_criticality,
                }
            )
        return results


def get_asset(settings: Settings, tenant_id: str, asset_id: str) -> dict | None:
    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        if asset is None or asset.tenant_id != tenant_id:
            return None
        identifiers = session.execute(
            select(models.AssetIdentifier).where(models.AssetIdentifier.asset_id == asset_id)
        ).scalars().all()
        tags = session.execute(
            select(models.AssetTag).where(models.AssetTag.asset_id == asset_id)
        ).scalars().all()
        return {
            "asset_id": asset.asset_id,
            "tenant_id": asset.tenant_id,
            "status": asset.status,
            "first_seen": asset.first_seen,
            "last_seen": asset.last_seen,
            "owner_email": asset.owner_email,
            "business_unit": asset.business_unit,
            "asset_criticality": asset.asset_criticality,
            "identifiers": [
                {"identifier_type": i.identifier_type, "identifier_value": i.identifier_value}
                for i in identifiers
            ],
            "tags": {t.key: t.value for t in tags},
        }


def get_asset_criticality_by_ip(settings: Settings, tenant_id: str, host_ip: str) -> int | None:
    """Single PK read: tenant+IP -> operator-set ``asset_criticality``, or
    ``None`` if unset/missing. Never raises — callers (risk scoring) treat
    any failure the same as "no override, fall back to the heuristic"."""
    asset_id = ip_identity_key(tenant_id, host_ip)
    try:
        with get_session(settings.postgres_url) as session:
            asset = session.get(models.Asset, asset_id)
            if asset is None or asset.tenant_id != tenant_id:
                return None
            return asset.asset_criticality
    except Exception:  # noqa: BLE001
        LOG.warning("asset_criticality lookup failed tenant=%s host=%s", tenant_id, host_ip)
        return None


def update_asset(
    settings: Settings, tenant_id: str, asset_id: str, updates: dict[str, Any]
) -> dict | None:
    """Partial update of operator-settable Asset fields (``owner_email``,
    ``business_unit``, ``asset_criticality``). Only keys present in
    ``updates`` are touched, so an explicit ``None`` clears a field while an
    omitted key leaves it untouched. Returns the updated asset (same shape as
    ``get_asset``), or ``None`` if the asset doesn't exist for this tenant.
    Raises ``ValueError`` if ``asset_criticality`` is present and not an int
    0-4.
    """
    if "asset_criticality" in updates and updates["asset_criticality"] is not None:
        val = updates["asset_criticality"]
        if not isinstance(val, int) or isinstance(val, bool) or not (0 <= val <= 4):
            raise ValueError("asset_criticality must be an integer 0-4")
    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        if asset is None or asset.tenant_id != tenant_id:
            return None
        for field in ("owner_email", "business_unit", "asset_criticality"):
            if field in updates:
                setattr(asset, field, updates[field])
    return get_asset(settings, tenant_id, asset_id)
