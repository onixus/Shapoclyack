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

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import asset_events
from api.services import runs as runs_service
from api.settings import Settings
from scanner.pipeline.asset_identity import (
    IdentityCandidate,
    IdentityCorrelation,
    cert_dns_by_ip,
    correlate_identities,
    forward_names_by_ip,
    identity_candidates_for_host,
    ip_identity_key,
)

LOG = logging.getLogger("shapoclyack.assets")

#: Operator-set vocabularies (#146). Closed lists so a CMDB import cannot
#: invent a fifth environment that the UI cannot render.
ENVIRONMENTS = ("production", "staging", "development", "lab", "other")
DATA_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
EXPOSURE_LEVELS = ("internet", "partner", "internal", "unknown")
CONTEXT_SOURCES = ("operator", "cmdb", "ad", "other")
CONTEXT_FIELDS = (
    "owner_email",
    "business_unit",
    "business_service",
    "environment",
    "data_classification",
    "exposure_level",
    "asset_criticality",
)


@dataclass(frozen=True)
class AssetUpsertStats:
    hosts_seen: int
    assets_created: int
    assets_updated: int
    marked_stale: int
    identities_linked: int = 0
    identities_merged: int = 0


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    """Postgres DateTime columns come back naive; in-session writes are UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


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


def _identifier_asset_id(session, tenant_id: str, kind: str, value: str) -> str | None:
    return session.execute(
        select(models.AssetIdentifier.asset_id).where(
            models.AssetIdentifier.tenant_id == tenant_id,
            models.AssetIdentifier.identifier_type == kind,
            models.AssetIdentifier.identifier_value == value,
        )
    ).scalar_one_or_none()


def _ensure_identifier(session, *, asset_id: str, tenant_id: str, kind: str, value: str) -> None:
    exists = session.execute(
        select(models.AssetIdentifier.id).where(
            models.AssetIdentifier.tenant_id == tenant_id,
            models.AssetIdentifier.identifier_type == kind,
            models.AssetIdentifier.identifier_value == value,
        )
    ).scalar_one_or_none()
    if exists is None:
        session.add(
            models.AssetIdentifier(
                asset_id=asset_id,
                tenant_id=tenant_id,
                identifier_type=kind,
                identifier_value=value,
            )
        )


def _pick_survivor(session, left_id: str, right_id: str) -> tuple[models.Asset, models.Asset]:
    """Prefer context, then age, then the left (IP) side."""
    left = session.get(models.Asset, left_id)
    right = session.get(models.Asset, right_id)
    if left is None:
        return right, right
    if right is None:
        return left, left
    def score(asset: models.Asset) -> tuple:
        context = sum(
            1
            for field in CONTEXT_FIELDS
            if getattr(asset, field, None) not in (None, "")
        )
        first = _aware(asset.first_seen) or datetime.max.replace(tzinfo=UTC)
        return (context, 0 if asset.status == "active" else -1, -first.timestamp())
    if score(right) > score(left):
        return right, left
    return left, right


def _repoint_findings(session, *, tenant_id: str, absorbed_id: str, survivor_id: str) -> None:
    from api.services.vulnerabilities import finding_key

    rows = session.execute(
        select(models.Vulnerability).where(
            models.Vulnerability.tenant_id == tenant_id,
            models.Vulnerability.asset_id == absorbed_id,
        )
    ).scalars().all()
    for row in rows:
        new_key = finding_key(
            asset_id=survivor_id, cve=row.cve, script_id=row.script_id, port=row.port
        )
        clash = session.execute(
            select(models.Vulnerability).where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.finding_key == new_key,
            )
        ).scalar_one_or_none()
        if clash is None:
            row.asset_id = survivor_id
            row.finding_key = new_key
            continue
        clash.observation_count = (clash.observation_count or 1) + (row.observation_count or 1)
        row_seen = _aware(row.last_seen_at)
        clash_seen = _aware(clash.last_seen_at)
        if row_seen and (clash_seen is None or row_seen > clash_seen):
            clash.last_seen_at = row.last_seen_at
            clash.last_seen_run_id = row.last_seen_run_id
        session.delete(row)


def _merge_assets(
    session,
    *,
    tenant_id: str,
    survivor: models.Asset,
    absorbed: models.Asset,
    now: datetime,
) -> None:
    if survivor.asset_id == absorbed.asset_id:
        return
    for field in CONTEXT_FIELDS:
        if getattr(survivor, field, None) in (None, "") and getattr(absorbed, field, None) not in (None, ""):
            setattr(survivor, field, getattr(absorbed, field))
    absorbed_first, survivor_first = _aware(absorbed.first_seen), _aware(survivor.first_seen)
    if absorbed_first and (survivor_first is None or absorbed_first < survivor_first):
        survivor.first_seen = absorbed.first_seen
    absorbed_last, survivor_last = _aware(absorbed.last_seen), _aware(survivor.last_seen)
    if absorbed_last and (survivor_last is None or absorbed_last > survivor_last):
        survivor.last_seen = absorbed.last_seen
    if survivor.status == "stale" and absorbed.status == "active":
        survivor.status = "active"

    identifiers = session.execute(
        select(models.AssetIdentifier).where(models.AssetIdentifier.asset_id == absorbed.asset_id)
    ).scalars().all()
    for ident in identifiers:
        taken = session.execute(
            select(models.AssetIdentifier).where(
                models.AssetIdentifier.tenant_id == tenant_id,
                models.AssetIdentifier.identifier_type == ident.identifier_type,
                models.AssetIdentifier.identifier_value == ident.identifier_value,
            )
        ).scalar_one_or_none()
        if taken is None:
            ident.asset_id = survivor.asset_id
        elif taken.asset_id != survivor.asset_id:
            ident.asset_id = survivor.asset_id
        else:
            session.delete(ident)

    _repoint_findings(session, tenant_id=tenant_id, absorbed_id=absorbed.asset_id, survivor_id=survivor.asset_id)
    for event in session.execute(
        select(models.AssetContextEvent).where(models.AssetContextEvent.asset_id == absorbed.asset_id)
    ).scalars():
        event.asset_id = survivor.asset_id
    for tag in session.execute(
        select(models.AssetTag).where(models.AssetTag.asset_id == absorbed.asset_id)
    ).scalars():
        clash = session.execute(
            select(models.AssetTag.id).where(
                models.AssetTag.asset_id == survivor.asset_id,
                models.AssetTag.key == tag.key,
            )
        ).scalar_one_or_none()
        if clash is None:
            tag.asset_id = survivor.asset_id
        else:
            session.delete(tag)
    session.flush()
    session.delete(absorbed)
    survivor.last_seen = now


def _apply_identity_correlations(
    session,
    *,
    tenant_id: str,
    run_id: str,
    run_dir: Path,
    now: datetime,
) -> tuple[int, int]:
    forward = forward_names_by_ip(
        runs_service._load_json(run_dir / "hostnames.json"),  # noqa: SLF001
        runs_service._load_json(run_dir / "dns_resolution.json"),  # noqa: SLF001
    )
    certs = cert_dns_by_ip(runs_service._load_json(run_dir / "tls_posture.json"))  # noqa: SLF001
    correlations = correlate_identities(forward=forward, certs_by_ip=certs)
    linked = 0
    merged = 0
    for link in correlations:
        survivor_id = _apply_one_correlation(session, tenant_id=tenant_id, link=link, now=now)
        if survivor_id and link.mergeable:
            merged += 1
        existing = session.execute(
            select(models.AssetIdentityLink).where(
                models.AssetIdentityLink.tenant_id == tenant_id,
                models.AssetIdentityLink.ip == link.ip,
                models.AssetIdentityLink.fqdn == link.fqdn,
            )
        ).scalar_one_or_none()
        sources = ",".join(link.sources)
        if existing is None:
            session.add(
                models.AssetIdentityLink(
                    tenant_id=tenant_id,
                    ip=link.ip,
                    fqdn=link.fqdn,
                    sources=sources,
                    confidence=link.confidence,
                    shared=link.shared,
                    merged=bool(survivor_id and link.mergeable),
                    survivor_id=survivor_id,
                    run_id=run_id,
                    updated_at=now,
                )
            )
        else:
            existing.sources = sources
            existing.confidence = link.confidence
            existing.shared = link.shared
            existing.merged = bool(survivor_id and link.mergeable) or existing.merged
            existing.survivor_id = survivor_id or existing.survivor_id
            existing.run_id = run_id
            existing.updated_at = now
        linked += 1
    return linked, merged


def _apply_one_correlation(
    session,
    *,
    tenant_id: str,
    link: IdentityCorrelation,
    now: datetime,
) -> str | None:
    if not link.mergeable:
        return None
    ip_asset = _identifier_asset_id(session, tenant_id, "ip", link.ip)
    fqdn_asset = _identifier_asset_id(session, tenant_id, "fqdn", link.fqdn)
    if ip_asset and fqdn_asset and ip_asset != fqdn_asset:
        survivor, absorbed = _pick_survivor(session, ip_asset, fqdn_asset)
        if survivor.status == "decommissioned" or absorbed.status == "decommissioned":
            return None
        _merge_assets(session, tenant_id=tenant_id, survivor=survivor, absorbed=absorbed, now=now)
        return survivor.asset_id
    target = ip_asset or fqdn_asset
    if target is None:
        return None
    asset = session.get(models.Asset, target)
    if asset is None or asset.status == "decommissioned":
        return None
    _ensure_identifier(session, asset_id=target, tenant_id=tenant_id, kind="ip", value=link.ip)
    _ensure_identifier(session, asset_id=target, tenant_id=tenant_id, kind="fqdn", value=link.fqdn)
    return target


def upsert_assets_from_run(settings: Settings, *, tenant_id: str, run_id: str) -> AssetUpsertStats:
    """Upsert one asset per host observed in ``run_id`` into the registry.

    One asset per *host record* in the run (not per identifier): when a host
    has both an IP and hostname(s), all of them attach to the same asset.
    After that, P4.2 may attach or merge an IP-only asset with a
    bare-FQDN asset when forward DNS *and* a certificate on that IP agree,
    and the IP is not shared. The evidence is written to
    ``asset_identity_links``; a wrong merge is worse than two rows.
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

        session.flush()
        linked, merged = _apply_identity_correlations(
            session, tenant_id=tenant_id, run_id=run_id, run_dir=run_dir, now=now
        )

    marked_stale = mark_stale_assets(settings, tenant_id=tenant_id)
    return AssetUpsertStats(
        hosts_seen=len(hosts),
        assets_created=created,
        assets_updated=updated,
        marked_stale=marked_stale,
        identities_linked=linked,
        identities_merged=merged,
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


ASSET_SORT_COLUMNS = {
    "last_seen": models.Asset.last_seen,
    "first_seen": models.Asset.first_seen,
    "status": models.Asset.status,
    "asset_criticality": models.Asset.asset_criticality,
    "asset_id": models.Asset.asset_id,
    "owner_email": models.Asset.owner_email,
    "business_service": models.Asset.business_service,
}


def list_assets(
    settings: Settings,
    tenant_id: str,
    *,
    status: str | None = None,
    unowned: bool = False,
    exposure: str | None = None,
    q: str | None = None,
    offset: int = 0,
    limit: int = 500,
    sort: str | None = None,
    order: str | None = None,
) -> tuple[list[dict], int]:
    """Return ``(page, total_after_filtering)``.

    Filtering, counting, and slicing all run in SQL (ROADMAP P3.2) — the
    identifier search is an EXISTS subquery rather than a post-filter over the
    fetched page, so `total` is honest and `limit` bounds work, not results.

    Identifiers and the open-finding rollup for the whole page are fetched in
    one ``IN`` query each rather than one query per asset (ROADMAP P3.8 / #136):
    the N+1 cost was invisible in wall-clock against a local socket but made
    the dashboard's ``limit=5000`` page issue 5002 statements and take ~1.1 s,
    and every one of those round-trips is paid again over a real network. See
    docs/scale-profile.md.
    """
    sort_column = ASSET_SORT_COLUMNS.get(sort or "", models.Asset.last_seen)
    direction = sort_column.asc() if (order or "").lower() == "asc" else sort_column.desc()

    with get_session(settings.postgres_url) as session:
        filters = [models.Asset.tenant_id == tenant_id]
        if status:
            filters.append(models.Asset.status == status)
        if unowned:
            filters.append(models.Asset.owner_email.is_(None))
            filters.append(models.Asset.status.in_(("active", "stale")))
        if exposure:
            if exposure not in EXPOSURE_LEVELS:
                raise ValueError(f"exposure must be one of {', '.join(EXPOSURE_LEVELS)}")
            filters.append(models.Asset.exposure_level == exposure)
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            ident_hit = (
                select(models.AssetIdentifier.id)
                .where(
                    models.AssetIdentifier.asset_id == models.Asset.asset_id,
                    func.lower(models.AssetIdentifier.identifier_value).like(needle),
                )
                .exists()
            )
            filters.append(
                or_(
                    ident_hit,
                    func.lower(models.Asset.owner_email).like(needle),
                    func.lower(models.Asset.business_service).like(needle),
                )
            )

        total = session.execute(
            select(func.count()).select_from(models.Asset).where(*filters)
        ).scalar_one()
        assets = session.execute(
            select(models.Asset)
            .where(*filters)
            # asset_id breaks ties so paging is stable when timestamps collide.
            .order_by(direction, models.Asset.asset_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()

        by_asset: dict[str, list[models.AssetIdentifier]] = {}
        if assets:
            page_ids = [asset.asset_id for asset in assets]
            for identifier in session.execute(
                select(models.AssetIdentifier).where(
                    models.AssetIdentifier.asset_id.in_(page_ids)
                )
            ).scalars():
                by_asset.setdefault(identifier.asset_id, []).append(identifier)

        risk_by_asset = _page_open_risk(session, [asset.asset_id for asset in assets])

        results: list[dict] = []
        for asset in assets:
            identifiers = by_asset.get(asset.asset_id, [])
            primary = next((i.identifier_value for i in identifiers if i.identifier_type == "ip"), None)
            risk = risk_by_asset.get(asset.asset_id, _EMPTY_PAGE_RISK)
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
                    "owner_email": asset.owner_email,
                    "business_service": asset.business_service,
                    "environment": asset.environment,
                    "exposure_level": asset.exposure_level,
                    "open_findings": risk["open_findings"],
                    "unassigned_findings": risk["unassigned_findings"],
                    "estate_risk": risk["estate_risk"],
                }
            )
        return results, total


_EMPTY_PAGE_RISK = {"open_findings": 0, "unassigned_findings": 0, "estate_risk": None}


def _page_open_risk(session, page_ids: list[str]) -> dict[str, dict]:
    """Open-finding rollup for one inventory page. One query, not N (#136)."""
    from api.services import nist_risk, vuln_states

    if not page_ids:
        return {}
    rows = session.execute(
        select(
            models.Vulnerability.asset_id,
            models.Vulnerability.risk_level,
            models.Vulnerability.assignee,
        ).where(
            models.Vulnerability.asset_id.in_(page_ids),
            models.Vulnerability.state.in_(tuple(vuln_states.ACTIVE)),
        )
    ).all()
    out: dict[str, dict] = {}
    for asset_id, risk_level, assignee in rows:
        bucket = out.setdefault(asset_id, {
            "open_findings": 0,
            "unassigned_findings": 0,
            "estate_risk": None,
        })
        bucket["open_findings"] += 1
        if not assignee:
            bucket["unassigned_findings"] += 1
        level = str(risk_level) if risk_level in nist_risk.LEVEL_RANK else None
        if level and nist_risk.LEVEL_RANK[level] > nist_risk.LEVEL_RANK.get(
            bucket["estate_risk"] or "", -1
        ):
            bucket["estate_risk"] = level
    return out


def summary(settings: Settings, tenant_id: str) -> dict:
    """Asset posture counts for the Risk Dashboard (#135). One pass."""
    by_status = {"active": 0, "stale": 0, "decommissioned": 0}
    by_criticality = {"unset": 0, "0": 0, "1": 0, "2": 0, "3": 0, "4": 0}
    total = 0
    unowned = 0
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(
                models.Asset.status,
                models.Asset.owner_email,
                models.Asset.asset_criticality,
            ).where(models.Asset.tenant_id == tenant_id)
        ).all()
    for status, owner_email, criticality in rows:
        total += 1
        status_key = str(status) if status in by_status else "active"
        by_status[status_key] = by_status.get(status_key, 0) + 1
        if criticality is None:
            by_criticality["unset"] += 1
        else:
            key = str(int(criticality))
            by_criticality[key] = by_criticality.get(key, 0) + 1
        if status in ("active", "stale") and not owner_email:
            unowned += 1
    return {
        "total": total,
        "unowned": unowned,
        "by_status": by_status,
        "by_criticality": by_criticality,
        "generated_at": datetime.now(UTC).isoformat(),
    }


def asset_exists(settings: Settings, tenant_id: str, asset_id: str) -> bool:
    """Tenant-scoped existence check — cheaper than ``get_asset`` (no risk rollup)."""
    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        return asset is not None and asset.tenant_id == tenant_id


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
        detail = {
            "asset_id": asset.asset_id,
            "tenant_id": asset.tenant_id,
            "status": asset.status,
            "first_seen": asset.first_seen,
            "last_seen": asset.last_seen,
            "owner_email": asset.owner_email,
            "business_unit": asset.business_unit,
            "asset_criticality": asset.asset_criticality,
            "business_service": asset.business_service,
            "environment": asset.environment,
            "data_classification": asset.data_classification,
            "exposure_level": asset.exposure_level,
            "context_source": asset.context_source,
            "identifiers": [
                {"identifier_type": i.identifier_type, "identifier_value": i.identifier_value}
                for i in identifiers
            ],
            "tags": {t.key: t.value for t in tags},
            "identity_links": _identity_links_for(session, tenant_id, identifiers),
        }
    return _with_risk(settings, tenant_id, asset_id, detail)


def _identity_links_for(session, tenant_id: str, identifiers) -> list[dict]:
    ips = [i.identifier_value for i in identifiers if i.identifier_type == "ip"]
    fqdns = [i.identifier_value for i in identifiers if i.identifier_type == "fqdn"]
    if not ips and not fqdns:
        return []
    clauses = []
    if ips:
        clauses.append(models.AssetIdentityLink.ip.in_(ips))
    if fqdns:
        clauses.append(models.AssetIdentityLink.fqdn.in_(fqdns))
    rows = session.execute(
        select(models.AssetIdentityLink).where(
            models.AssetIdentityLink.tenant_id == tenant_id,
            or_(*clauses),
        )
    ).scalars().all()
    return [
        {
            "ip": row.ip,
            "fqdn": row.fqdn,
            "sources": [s for s in row.sources.split(",") if s],
            "confidence": row.confidence,
            "shared": row.shared,
            "merged": row.merged,
        }
        for row in rows
    ]


def _with_risk(settings: Settings, tenant_id: str, asset_id: str, detail: dict) -> dict:
    from api.services import vulnerabilities as vulns_service

    detail["risk"] = vulns_service.summary(settings, tenant_id=tenant_id, asset_id=asset_id)
    return detail


def _asset_for_ip(session, tenant_id: str, host_ip: str) -> models.Asset | None:
    """Resolve by identifier, not by assuming ``asset_id == ip_identity_key``.

    After P4.2 a merged survivor may keep the FQDN-side id.
    """
    asset_id = _identifier_asset_id(session, tenant_id, "ip", host_ip)
    if asset_id is None:
        asset_id = ip_identity_key(tenant_id, host_ip)
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        return None
    return asset


def get_asset_criticality_by_ip(settings: Settings, tenant_id: str, host_ip: str) -> int | None:
    """tenant+IP -> operator-set ``asset_criticality``, or ``None``.

    Never raises — callers (risk scoring) treat any failure the same as
    "no override, fall back to the heuristic".
    """
    try:
        with get_session(settings.postgres_url) as session:
            asset = _asset_for_ip(session, tenant_id, host_ip)
            return None if asset is None else asset.asset_criticality
    except Exception:  # noqa: BLE001
        LOG.warning("asset_criticality lookup failed tenant=%s host=%s", tenant_id, host_ip)
        return None


def get_asset_exposure_by_ip(settings: Settings, tenant_id: str, host_ip: str) -> str | None:
    """Operator-set ``exposure_level``, or None. Never inferred from the IP."""
    try:
        with get_session(settings.postgres_url) as session:
            asset = _asset_for_ip(session, tenant_id, host_ip)
            return None if asset is None else asset.exposure_level
    except Exception:  # noqa: BLE001
        LOG.warning("exposure_level lookup failed tenant=%s host=%s", tenant_id, host_ip)
        return None


_MANUAL_STATUS = "decommissioned"


def _validate_context(updates: dict[str, Any]) -> None:
    if "asset_criticality" in updates and updates["asset_criticality"] is not None:
        val = updates["asset_criticality"]
        if not isinstance(val, int) or isinstance(val, bool) or not (0 <= val <= 4):
            raise ValueError("asset_criticality must be an integer 0-4")
    checks = (
        ("environment", ENVIRONMENTS),
        ("data_classification", DATA_CLASSIFICATIONS),
        ("exposure_level", EXPOSURE_LEVELS),
        ("context_source", CONTEXT_SOURCES),
    )
    for field, allowed in checks:
        value = updates.get(field)
        if value is None:
            continue
        if value not in allowed:
            raise ValueError(f"{field} must be one of {', '.join(allowed)}")


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def update_asset(
    settings: Settings,
    tenant_id: str,
    asset_id: str,
    updates: dict[str, Any],
    *,
    actor: str | None = None,
) -> dict | None:
    """Partial update of operator-settable Asset fields.

    Only keys present in ``updates`` are touched, so an explicit ``None``
    clears a field while an omitted key leaves it untouched. Context writes
    (#146) are audited in the same transaction. ``status`` may only be set to
    ``decommissioned`` — "active"/"stale" stay system-managed.

    A decommission (Phase 10.1 ``decommissioned_host`` event) is logged the
    run an asset actually transitions into that status — not on a repeat
    PATCH once it's already decommissioned.
    """
    _validate_context(updates)
    if "status" in updates and updates["status"] not in (None, _MANUAL_STATUS):
        raise ValueError(f"status may only be manually set to {_MANUAL_STATUS!r}")
    source = updates.get("context_source") or "operator"
    now = _now().replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        # Locked for the read-modify-write: two concurrent decommission PATCHes
        # would otherwise both read "active" and both count as the transition,
        # emitting the event twice for one logical change. (SQLite, the no-Postgres
        # fallback, has no row locks and no concurrent writer to need them.)
        asset = session.get(models.Asset, asset_id, with_for_update=True)
        if asset is None or asset.tenant_id != tenant_id:
            return None
        previous_status = asset.status
        for field in CONTEXT_FIELDS:
            if field not in updates:
                continue
            old = getattr(asset, field)
            new = updates[field]
            if isinstance(new, str):
                new = new.strip() or None
            if old == new:
                continue
            setattr(asset, field, new)
            session.add(
                models.AssetContextEvent(
                    asset_id=asset.asset_id,
                    tenant_id=asset.tenant_id,
                    occurred_at=now,
                    field=field,
                    old_value=_stringify(old),
                    new_value=_stringify(new),
                    actor=actor,
                    source=source,
                )
            )
        if "context_source" in updates or any(f in updates for f in CONTEXT_FIELDS):
            asset.context_source = source
        decommissioned = (
            updates.get("status") == _MANUAL_STATUS and previous_status != _MANUAL_STATUS
        )
        if decommissioned:
            asset.status = _MANUAL_STATUS
            LOG.info(
                "asset_event kind=decommissioned_host tenant_id=%s asset_id=%s previous_status=%s",
                tenant_id,
                asset_id,
                previous_status,
            )
    updated = get_asset(settings, tenant_id, asset_id)
    if decommissioned:
        # Published after the session closes, so a broker that hangs cannot
        # hold the row's transaction open — and after the read, so the event
        # can name the host the asset is known by.
        _publish_decommissioned(settings, tenant_id, asset_id, updated, previous_status)
    return updated


def _publish_decommissioned(
    settings: Settings,
    tenant_id: str,
    asset_id: str,
    asset: dict | None,
    previous_status: str | None,
) -> None:
    """Best-effort ``decommissioned_host`` publish (Phase 10.2). Never raises —
    the operator's PATCH succeeded either way, and the log line above stays the
    record of it."""
    if not settings.asset_events_enabled or not settings.nats_url:
        return
    identifiers = (asset or {}).get("identifiers") or []
    host = next(
        (i["identifier_value"] for i in identifiers if i.get("identifier_type") == "ip"),
        None,
    ) or (identifiers[0]["identifier_value"] if identifiers else None)
    try:
        asset_events.publish_asset_status_event(
            nats_url=settings.nats_url,
            tenant_id=tenant_id,
            kind="decommissioned_host",
            asset_id=asset_id,
            host=host,
            data={"previous_status": previous_status},
        )
    except Exception:  # noqa: BLE001
        LOG.exception("decommissioned_host publish failed tenant=%s asset=%s", tenant_id, asset_id)


def list_context_events(
    settings: Settings,
    tenant_id: str,
    asset_id: str,
    *,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[dict], int]:
    """Newest-first context audit trail for one asset."""
    with get_session(settings.postgres_url) as session:
        filters = [
            models.AssetContextEvent.asset_id == asset_id,
            models.AssetContextEvent.tenant_id == tenant_id,
        ]
        total = session.execute(
            select(func.count()).select_from(models.AssetContextEvent).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.AssetContextEvent)
            .where(*filters)
            .order_by(models.AssetContextEvent.occurred_at.desc(), models.AssetContextEvent.id.desc())
            .offset(offset)
            .limit(limit)
        ).scalars().all()
        return [
            {
                "id": row.id,
                "asset_id": row.asset_id,
                "tenant_id": row.tenant_id,
                "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
                "field": row.field,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "actor": row.actor,
                "source": row.source,
            }
            for row in rows
        ], total
