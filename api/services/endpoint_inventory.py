"""Lariska endpoint-inventory ingestion (Agent_plan.md S1-S7).

Ingests device identity/OS metadata and installed-software snapshots from the
separate Lariska endpoint agent. Deliberately kept independent of the
network-scanner agent protocol (``api/services/jobs.py``, ``ingest.raw_results``)
per Agent_plan.md 3.1 — only ``api.auth.require_agent`` (tenant/agent identity)
is shared.

Only agent-hashed platform identifiers are ever stored (``EndpointIdentifier.
value_hash``) — the API never sees or computes a hash from a raw MAC/serial.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.schemas import EndpointInventorySnapshotRequest
from api.settings import Settings

_settings: Settings | None = None


class RateLimitError(Exception):
    """Too many inventory submissions for this agent in the current window."""


class PayloadTooLargeError(Exception):
    """Software/identifier/label count exceeds the configured limit."""


class ConflictError(Exception):
    """Same snapshot_id resubmitted with different content."""


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "endpoint_inventory.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _parse_dt(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.EndpointSoftwareChange).delete()
        session.query(models.EndpointSoftwareItem).delete()
        session.query(models.EndpointInventorySnapshot).delete()
        session.query(models.EndpointIdentifier).delete()
        session.query(models.EndpointDevice).delete()


def _comparison_key(item: Any) -> str:
    raw = "|".join(
        [
            (item.name or "").strip().lower(),
            (item.publisher or "").strip().lower(),
            (item.architecture or "").strip().lower(),
            item.source,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _canonical_digest(request: EndpointInventorySnapshotRequest) -> str:
    payload = request.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_bounds(settings: Settings, request: EndpointInventorySnapshotRequest) -> None:
    if len(request.software) > settings.endpoint_inventory_max_software_items:
        raise PayloadTooLargeError(
            f"software entry count {len(request.software)} exceeds limit "
            f"{settings.endpoint_inventory_max_software_items}"
        )
    if len(request.identifiers) > settings.endpoint_inventory_max_identifiers:
        raise PayloadTooLargeError(
            f"identifier count {len(request.identifiers)} exceeds limit "
            f"{settings.endpoint_inventory_max_identifiers}"
        )
    if len(request.labels) > settings.endpoint_inventory_max_labels:
        raise PayloadTooLargeError(
            f"label count {len(request.labels)} exceeds limit {settings.endpoint_inventory_max_labels}"
        )

    max_len = settings.endpoint_inventory_max_string_length
    for key, value in request.labels.items():
        if len(key) > max_len or len(value) > max_len:
            raise ValueError(f"label {key!r} exceeds max string length {max_len}")
    for warning in request.collector_warnings:
        if len(warning) > max_len:
            raise ValueError(f"collector_warnings entry exceeds max string length {max_len}")

    keys_seen: set[str] = set()
    for item in request.software:
        key = _comparison_key(item)
        if key in keys_seen:
            raise ValueError(
                f"duplicate software entry (name={item.name!r}, publisher={item.publisher!r}, "
                f"architecture={item.architecture!r}, source={item.source!r})"
            )
        keys_seen.add(key)

    collected_at = _parse_dt(request.collected_at)
    now = _now()
    if collected_at > now + timedelta(seconds=settings.endpoint_inventory_max_future_skew_seconds):
        raise ValueError("collected_at is too far in the future")
    if now - collected_at > timedelta(seconds=settings.endpoint_inventory_max_snapshot_age_seconds):
        raise ValueError("collected_at is older than the maximum accepted snapshot age")


def _check_rate_limit(session, settings: Settings, *, tenant_id: str, agent_id: str) -> None:
    cutoff = _now() - timedelta(hours=1)
    count = session.execute(
        select(models.EndpointInventorySnapshot.snapshot_id)
        .join(
            models.EndpointDevice,
            models.EndpointInventorySnapshot.device_id == models.EndpointDevice.device_id,
        )
        .where(
            models.EndpointDevice.tenant_id == tenant_id,
            models.EndpointDevice.agent_id == agent_id,
            models.EndpointInventorySnapshot.received_at >= cutoff,
        )
    ).all()
    if len(count) >= settings.endpoint_inventory_rate_limit_per_hour:
        raise RateLimitError(
            f"endpoint inventory submissions rate-limited: "
            f"{settings.endpoint_inventory_rate_limit_per_hour} per hour"
        )


def _reconcile_asset(session, *, tenant_id: str, device: models.EndpointDevice, hostname: str) -> None:
    """Priority order per Agent_plan.md §6. Only runs when the device has no
    asset link yet — an existing link (or an established conflict) is
    preserved across resubmits, never re-evaluated."""
    if device.asset_id is not None or device.reconciliation_status == "conflict":
        return

    fqdn = hostname.strip().lower()
    matched_asset_id = session.execute(
        select(models.AssetIdentifier.asset_id).where(
            models.AssetIdentifier.tenant_id == tenant_id,
            models.AssetIdentifier.identifier_type == "fqdn",
            models.AssetIdentifier.identifier_value == fqdn,
        )
    ).scalar_one_or_none()
    if matched_asset_id is not None:
        device.asset_id = matched_asset_id
        device.reconciliation_status = "linked"
        return

    now = _now()
    new_asset_id = f"ep_{uuid.uuid4().hex[:16]}"
    session.add(
        models.Asset(
            asset_id=new_asset_id,
            tenant_id=tenant_id,
            status="active",
            first_seen=now,
            last_seen=now,
        )
    )
    device.asset_id = new_asset_id
    device.reconciliation_status = "linked"


def _upsert_identifiers(
    session, *, tenant_id: str, device: models.EndpointDevice, identifiers: list[Any]
) -> None:
    now = _now()
    for identifier in identifiers:
        existing = session.execute(
            select(models.EndpointIdentifier).where(
                models.EndpointIdentifier.tenant_id == tenant_id,
                models.EndpointIdentifier.identifier_type == identifier.identifier_type,
                models.EndpointIdentifier.value_hash == identifier.value_hash,
            )
        ).scalar_one_or_none()
        if existing is None:
            session.add(
                models.EndpointIdentifier(
                    device_id=device.device_id,
                    tenant_id=tenant_id,
                    identifier_type=identifier.identifier_type,
                    value_hash=identifier.value_hash,
                    first_seen=now,
                    last_seen=now,
                )
            )
        elif existing.device_id == device.device_id:
            existing.last_seen = now
        else:
            # Strong identifier already claimed by a different device in this
            # tenant — never auto-merge; surface as a reviewable conflict.
            device.reconciliation_status = "conflict"


def ingest_snapshot(
    *, tenant_id: str, agent_id: str, request: EndpointInventorySnapshotRequest
) -> dict[str, Any]:
    settings = _require_settings()
    if request.agent_id != agent_id:
        raise ValueError("agent_id in body does not match the authenticated agent")

    _validate_bounds(settings, request)
    digest = _canonical_digest(request)
    collected_at = _parse_dt(request.collected_at)
    now = _now()

    with get_session(settings.postgres_url) as session:
        existing_snapshot = session.get(models.EndpointInventorySnapshot, request.snapshot_id)
        if existing_snapshot is not None:
            if existing_snapshot.tenant_id != tenant_id:
                raise ConflictError("snapshot_id already used by a different tenant")
            if existing_snapshot.payload_digest == digest:
                return {**dict(existing_snapshot.response), "_replay": True}
            raise ConflictError(
                f"snapshot_id {request.snapshot_id!r} already accepted with different content"
            )

        _check_rate_limit(session, settings, tenant_id=tenant_id, agent_id=agent_id)

        device = session.execute(
            select(models.EndpointDevice).where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.agent_id == agent_id,
            )
        ).scalar_one_or_none()
        is_first_snapshot = device is None or device.latest_snapshot_id is None
        if device is None:
            device = models.EndpointDevice(
                device_id=f"dev_{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                agent_id=agent_id,
                hostname=request.hostname,
                os_family=request.os_family,
                os_name=request.os_name,
                os_version=request.os_version,
                os_arch=request.os_arch,
                agent_version=request.agent_version,
                labels=dict(request.labels),
                first_seen=now,
                last_seen=now,
            )
            session.add(device)
        else:
            device.hostname = request.hostname
            device.os_family = request.os_family
            device.os_name = request.os_name
            device.os_version = request.os_version
            device.os_arch = request.os_arch
            device.agent_version = request.agent_version
            device.labels = dict(request.labels)
            device.last_seen = now
        session.flush()

        _upsert_identifiers(session, tenant_id=tenant_id, device=device, identifiers=request.identifiers)
        _reconcile_asset(session, tenant_id=tenant_id, device=device, hostname=request.hostname)

        previous_items: dict[str, str | None] = {}
        if not is_first_snapshot and device.latest_snapshot_id:
            previous_rows = session.execute(
                select(models.EndpointSoftwareItem).where(
                    models.EndpointSoftwareItem.snapshot_id == device.latest_snapshot_id
                )
            ).scalars().all()
            previous_items = {row.comparison_key: row.version for row in previous_rows}

        snapshot = models.EndpointInventorySnapshot(
            snapshot_id=request.snapshot_id,
            tenant_id=tenant_id,
            device_id=device.device_id,
            schema_version=request.schema_version,
            collected_at=collected_at,
            received_at=now,
            payload_digest=digest,
            software_count=len(request.software),
            collector_warnings={"warnings": list(request.collector_warnings)},
            response={},
        )
        session.add(snapshot)
        session.flush()

        current_items: dict[str, str | None] = {}
        for item in request.software:
            key = _comparison_key(item)
            current_items[key] = item.version
            session.add(
                models.EndpointSoftwareItem(
                    snapshot_id=snapshot.snapshot_id,
                    tenant_id=tenant_id,
                    device_id=device.device_id,
                    comparison_key=key,
                    name=item.name,
                    version=item.version,
                    publisher=item.publisher,
                    architecture=item.architecture,
                    source=item.source,
                    install_location=item.install_location,
                )
            )

        changes = {"installed": 0, "removed": 0, "updated": 0}
        if not is_first_snapshot:
            name_by_key = {_comparison_key(item): item.name for item in request.software}
            for key, new_version in current_items.items():
                if key not in previous_items:
                    changes["installed"] += 1
                    session.add(
                        models.EndpointSoftwareChange(
                            tenant_id=tenant_id,
                            device_id=device.device_id,
                            snapshot_id=snapshot.snapshot_id,
                            comparison_key=key,
                            event_type="installed",
                            old_version=None,
                            new_version=new_version,
                            display_name=name_by_key.get(key, ""),
                            observed_at=now,
                        )
                    )
                elif previous_items[key] != new_version:
                    changes["updated"] += 1
                    session.add(
                        models.EndpointSoftwareChange(
                            tenant_id=tenant_id,
                            device_id=device.device_id,
                            snapshot_id=snapshot.snapshot_id,
                            comparison_key=key,
                            event_type="updated",
                            old_version=previous_items[key],
                            new_version=new_version,
                            display_name=name_by_key.get(key, ""),
                            observed_at=now,
                        )
                    )
            for key, old_version in previous_items.items():
                if key not in current_items:
                    changes["removed"] += 1
                    session.add(
                        models.EndpointSoftwareChange(
                            tenant_id=tenant_id,
                            device_id=device.device_id,
                            snapshot_id=snapshot.snapshot_id,
                            comparison_key=key,
                            event_type="removed",
                            old_version=old_version,
                            new_version=None,
                            display_name="",
                            observed_at=now,
                        )
                    )

        device.last_inventory_at = now
        device.latest_snapshot_id = snapshot.snapshot_id

        if device.asset_id is not None:
            asset = session.get(models.Asset, device.asset_id)
            if asset is not None:
                asset.last_seen = now

        response = {
            "snapshot_id": snapshot.snapshot_id,
            "status": "accepted",
            "device_id": device.device_id,
            "asset_id": device.asset_id,
            "reconciliation_status": device.reconciliation_status,
            "software_count": snapshot.software_count,
            "changes": changes,
        }
        snapshot.response = response
        return {**response, "_replay": False}


def _device_to_dict(row: models.EndpointDevice) -> dict[str, Any]:
    return {
        "device_id": row.device_id,
        "tenant_id": row.tenant_id,
        "agent_id": row.agent_id,
        "asset_id": row.asset_id,
        "hostname": row.hostname,
        "os_family": row.os_family,
        "os_name": row.os_name,
        "os_version": row.os_version,
        "os_arch": row.os_arch,
        "agent_version": row.agent_version,
        "labels": dict(row.labels or {}),
        "reconciliation_status": row.reconciliation_status,
        "first_seen": _iso(row.first_seen),
        "last_seen": _iso(row.last_seen),
        "last_inventory_at": _iso(row.last_inventory_at),
        "latest_snapshot_id": row.latest_snapshot_id,
    }


def list_devices(tenant_id: str, *, asset_id: str | None = None) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.EndpointDevice).where(models.EndpointDevice.tenant_id == tenant_id)
        if asset_id:
            stmt = stmt.where(models.EndpointDevice.asset_id == asset_id)
        rows = session.execute(stmt).scalars().all()
    items = [_device_to_dict(row) for row in rows]
    items.sort(key=lambda d: str(d.get("last_seen") or ""), reverse=True)
    return items


def get_device(tenant_id: str, device_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.EndpointDevice, device_id)
        if row is None or row.tenant_id != tenant_id:
            return None
        return _device_to_dict(row)


def list_snapshots(tenant_id: str, device_id: str) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, device_id)
        if device is None or device.tenant_id != tenant_id:
            return []
        rows = session.execute(
            select(models.EndpointInventorySnapshot).where(
                models.EndpointInventorySnapshot.device_id == device_id
            )
        ).scalars().all()
    items = [
        {
            "snapshot_id": row.snapshot_id,
            "device_id": row.device_id,
            "schema_version": row.schema_version,
            "collected_at": _iso(row.collected_at),
            "received_at": _iso(row.received_at),
            "software_count": row.software_count,
            "collector_warnings": list((row.collector_warnings or {}).get("warnings", [])),
        }
        for row in rows
    ]
    items.sort(key=lambda s: str(s.get("received_at") or ""), reverse=True)
    return items


def list_changes(tenant_id: str, device_id: str) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, device_id)
        if device is None or device.tenant_id != tenant_id:
            return []
        rows = session.execute(
            select(models.EndpointSoftwareChange)
            .where(models.EndpointSoftwareChange.device_id == device_id)
            .order_by(models.EndpointSoftwareChange.observed_at.desc())
        ).scalars().all()
    return [
        {
            "device_id": row.device_id,
            "snapshot_id": row.snapshot_id,
            "event_type": row.event_type,
            "display_name": row.display_name,
            "old_version": row.old_version,
            "new_version": row.new_version,
            "observed_at": _iso(row.observed_at),
        }
        for row in rows
    ]


def list_software_for_asset(tenant_id: str, asset_id: str) -> list[dict[str, Any]]:
    """Latest snapshot's software for every device linked to ``asset_id``."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        devices = session.execute(
            select(models.EndpointDevice).where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.asset_id == asset_id,
            )
        ).scalars().all()
        items: list[dict[str, Any]] = []
        for device in devices:
            if not device.latest_snapshot_id:
                continue
            rows = session.execute(
                select(models.EndpointSoftwareItem).where(
                    models.EndpointSoftwareItem.snapshot_id == device.latest_snapshot_id
                )
            ).scalars().all()
            for row in rows:
                items.append(
                    {
                        "name": row.name,
                        "version": row.version,
                        "publisher": row.publisher,
                        "architecture": row.architecture,
                        "source": row.source,
                        "install_location": row.install_location,
                    }
                )
    return items
