"""Read-only vendor remediation over accepted inventory and local feeds.

No inference, network calls or lifecycle changes. Matcher rows are revalidated
against current vendor records; bounded local citations replace arbitrary URLs.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import advisories, package_identity, patch_gap, rpm_identity, software_cve_match as matcher
from api.services.advisories import msrc, rpm
from api.services.advisories.coverage import snapshot_provider
from api.services.local_operator.gateway import GatewayError

MAX_ROWS = 100


def _utc(value):
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _iso(value):
    stamp = _utc(value)
    return stamp.isoformat().replace("+00:00", "Z") if stamp else None


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def _feed(row):
    if row.distro == "windows":
        data = msrc.get_dataset()
        installed = msrc.parse_build(row.installed_version)
        records = data.remediations_for(installed) if installed else ()
        fingerprint = _digest([(r.cve_id, r.kb, str(r.fixed_build), r.product) for r in records])
        return data, records, fingerprint
    data = snapshot_provider(advisories.get_provider(row.distro))
    if data is None:
        return None, (), ""
    records = data.advisories_for(release=row.distro_release or "", source_package=row.source_package)
    fingerprint = _digest([(r.advisory_id, r.cve_ids, r.release, r.source_package,
                            r.fixed_version, r.state, getattr(r, "architecture", None),
                            getattr(r, "product_id", None), getattr(r, "source_sha256", None),
                            getattr(r, "source_updated", None)) for r in records])
    return data, records, fingerprint


def _supported(row, records):
    if row.distro == "windows":
        installed = msrc.parse_build(row.installed_version)
        fixed = msrc.parse_build(row.fixed_version)
        if installed is None or fixed is None or installed.family != fixed.family:
            return False
        # A stored KB-only verdict needs current KB inventory before it can be
        # promoted here. Build comparisons use the existing MSRC grammar.
        expected = matcher.FIXED if installed.ubr >= fixed.ubr else matcher.VULNERABLE
        return row.status == expected and any(
            r.cve_id == row.cve_id and r.kb == row.advisory_id
            and str(r.fixed_build) == row.fixed_version for r in records)
    if row.distro in rpm_identity.RPM_DISTROS:
        # Native RPM selection rejects module/channel ambiguity and incomplete
        # provenance; matching one old row is insufficient after a feed import.
        from types import SimpleNamespace

        identity = package_identity.identify(
            name=row.installed_package, version=row.installed_version,
            architecture=(row.evidence or {}).get("architecture"), source="rpm",
            distro=package_identity.DistroContext(distro=row.distro, release=row.distro_release,
                                                  supported=True))
        if not identity.matchable:
            return False
        records, reason = rpm.select_records(identity, SimpleNamespace(advisories_for=lambda **_: records))
        if reason:
            return False
    for record in records:
        if (record.advisory_id != row.advisory_id or row.cve_id not in record.cve_ids
                or record.fixed_version != row.fixed_version):
            continue
        architecture = getattr(record, "architecture", None)
        if architecture and architecture != (row.evidence or {}).get("architecture"):
            continue
        product = getattr(record, "product_id", None)
        if product and product != (row.evidence or {}).get("product_id"):
            continue
        expected = (matcher.NOT_APPLICABLE if record.state == advisories.STATE_NOT_AFFECTED
                    else matcher.VULNERABLE if not record.fixed_version or record.state == advisories.STATE_OPEN
                    else None)
        if expected is not None:
            return row.status == expected
        flavor = patch_gap._flavor_for(row.purl)  # noqa: SLF001
        if not flavor or not row.installed_version:
            return False
        status, _ = matcher._compare_status(installed=row.installed_version,  # noqa: SLF001
                                           fixed=row.fixed_version, flavor=flavor)
        return status == row.status
    return False


def _classify(row, snapshot, *, now, feed):
    data, records, _ = feed
    if snapshot is None or row.snapshot_id != snapshot.snapshot_id:
        return "unknown", "inventory_snapshot_changed"
    observed = _utc(snapshot.collected_at)
    if observed is None or observed > now + timedelta(minutes=5):
        return "unknown", "inventory_time_unknown"
    if now - observed > timedelta(days=7):
        return "stale", "inventory_stale"
    if row.status == matcher.UNKNOWN:
        return "unknown", "insufficient_inventory_or_coverage"
    if data is None or not data.available():
        return "unknown", "no_advisory_data"
    label = data.source_label() or ""
    if not label or "seed" in label.lower():
        return "unknown", "unverified_or_seed_feed"
    feed_at = _utc(data.feed_date())
    if feed_at is None or feed_at > now + timedelta(days=1):
        return "unknown", "feed_time_unknown"
    if now - feed_at > timedelta(days=30):
        return "stale", "advisory_stale"
    row_feed_at = _utc(row.feed_date)
    if row_feed_at is None or row_feed_at > now + timedelta(days=1):
        return "unknown", "matched_advisory_time_unknown"
    if now - row_feed_at > timedelta(days=30):
        return "stale", "matched_advisory_stale"
    if not _supported(row, records):
        return "unknown", "advisory_changed_or_unsupported"
    if row.status == matcher.VULNERABLE:
        if any(getattr(record, "state", None) == advisories.STATE_OPEN
               and record.advisory_id == row.advisory_id and row.cve_id in record.cve_ids
               for record in records):
            return "no_fix", "vendor_has_no_fix"
        return ("fix_available", None) if row.fixed_version else ("no_fix", "vendor_has_no_fix")
    if row.status in {matcher.FIXED, matcher.NOT_APPLICABLE}:
        return row.status, None
    return "unknown", "unsupported_match_status"


def _source(row, snapshot, feed, status):
    payload = {key: getattr(row, key) for key in (
        "id", "device_id", "snapshot_id", "match_key", "cve_id", "status", "installed_package",
        "source_package", "installed_version", "fixed_version", "advisory_id", "provider",
        "distro", "distro_release", "purl", "feed_date")}
    payload["inventory_sha256"] = snapshot.payload_digest if snapshot else None
    payload["feed_sha256"] = feed[2]
    payload["feed_date_at_read"] = feed[0].feed_date() if feed[0] else None
    payload["feed_source_at_read"] = feed[0].source_label() if feed[0] else None
    payload["matched_at"] = _iso(row.matched_at)
    payload["status_at_read"] = status
    payload["installation_identity"] = (row.evidence or {}).get("installation_identity")
    payload["architecture"] = (row.evidence or {}).get("architecture")
    return {"source_id": str(row.id), "source_hash": _digest(payload),
            "snapshot_id": row.snapshot_id, "advisory_id": row.advisory_id,
            "provider": row.provider, "feed_date": row.feed_date,
            "observed_at": _iso(snapshot.collected_at) if snapshot else None, "status": status}


def _card(row, source, status, reason, architecture):
    return {"package": row.installed_package or row.source_package,
            "installed_version": row.installed_version,
            "target_version": row.fixed_version if status in {"fix_available", "fixed"} else None,
            "distro": row.distro, "distro_release": row.distro_release,
            "architecture": (row.evidence or {}).get("architecture") or architecture,
            "status": status, "cve_ids": [row.cve_id] if row.cve_id else [],
            "upgrade_command": None, "sources": [source],
            "verification": {"method": "endpoint_inventory", "requires_confirmation": True},
            "limitations": [reason] if reason else []}


def for_device(settings, principal, *, device_id, language="ru", limit=50, now=None):
    if language not in {"ru", "en"} or type(limit) is not int or not 1 <= limit <= MAX_ROWS:
        raise GatewayError("operator_invalid_query")
    now = _utc(now or datetime.now(UTC))
    with tenant_scope.tenant(principal.tenant_id), get_session(settings.postgres_url) as db:
        device = db.scalar(select(models.EndpointDevice).where(
            models.EndpointDevice.device_id == device_id, models.EndpointDevice.tenant_id == principal.tenant_id))
        if device is None:
            return None
        snapshot_id = device.software_snapshot_id or device.latest_snapshot_id
        snapshot = db.scalar(select(models.EndpointInventorySnapshot).where(
            models.EndpointInventorySnapshot.snapshot_id == snapshot_id,
            models.EndpointInventorySnapshot.device_id == device_id,
            models.EndpointInventorySnapshot.tenant_id == principal.tenant_id))
        rows = db.scalars(select(models.SoftwareCveMatch).where(
            models.SoftwareCveMatch.tenant_id == principal.tenant_id,
            models.SoftwareCveMatch.device_id == device_id).order_by(
                models.SoftwareCveMatch.id).limit(limit + 1)).all()
        architecture = device.os_arch
    return build_cards(rows[:limit], snapshot, device_id=device_id, snapshot_id=snapshot_id,
                       architecture=architecture, language=language, now=now, truncated=len(rows) > limit)


def build_cards(rows, snapshot, *, device_id, snapshot_id, architecture, language, now, truncated=False):
    feeds, items, grouped = {}, [], {}
    for row in rows:
        key = (row.distro, row.distro_release, row.source_package, row.installed_version)
        if key not in feeds:
            feeds[key] = _feed(row)
        feed = feeds[key]
        state, reason = _classify(row, snapshot, now=now, feed=feed)
        source = _source(row, snapshot, feed, state)
        # Do not combine different installation/OS/feed identities.
        group_key = (row.installed_package, row.installed_version, row.distro, row.distro_release,
                     row.purl, (row.evidence or {}).get("installation_identity"),
                     (row.evidence or {}).get("architecture") or architecture, row.snapshot_id, feed[2], state)
        if state == "fix_available" and row.distro != "windows":
            grouped.setdefault(group_key, []).append((row, source))
        else:
            items.append(_card(row, source, state, reason, architecture))
    for group in grouped.values():
        gaps, _ = patch_gap._build_gaps([row for row, _ in group])  # noqa: SLF001
        row, source = group[0]
        card = _card(row, source, "fix_available", None, architecture)
        card["sources"] = [source for _, source in group]
        if gaps and gaps[0]["target_version"]:
            card.update(target_version=gaps[0]["target_version"], cve_ids=gaps[0]["cve_ids"],
                        upgrade_command=gaps[0]["upgrade_command"])
        else:
            card.update(status="unknown", target_version=None, limitations=["unorderable_fixes"])
        items.append(card)
    states = {item["status"] for item in items}
    state = ("unknown" if not items else "incomplete" if truncated or "unknown" in states
             else "stale" if "stale" in states else "complete")
    return {"device_id": device_id, "snapshot_id": snapshot_id, "state": state,
            "quality_status": "deterministic", "language": language,
            "reason": "no_assessed_matches" if not items else "result_truncated" if truncated else None,
            "items": items, "truncated": truncated,
            "limits": {"feed_max_age_days": 30, "inventory_max_age_days": 7},
            "limitations": ["observed_inventory_only", "no_installation_or_lifecycle_change",
                            "no_backup_restart_or_rollback_plan_supplied"]}


def get_source(settings, principal, *, device_id, source_id, snapshot_id, source_hash):
    result = for_device(settings, principal, device_id=device_id, limit=MAX_ROWS)
    if result is None:
        return None
    for card in result["items"]:
        for source in card["sources"]:
            if source["source_id"] == source_id:
                if source["snapshot_id"] != snapshot_id or source["source_hash"] != source_hash:
                    raise GatewayError("operator_source_changed")
                return {**source, "card": {key: value for key, value in card.items() if key != "sources"}}
    return None
