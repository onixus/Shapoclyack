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
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, or_, select

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.schemas import EndpointInventorySnapshotRequest
from api.services import metrics as metrics_service
from api.services import quotas
from api.settings import Settings

_log = logging.getLogger("shapoclyack.endpoint-inventory")
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
    if getattr(item, "installation_identity", None):
        return item.installation_identity
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
    # Preserve deployed v1 digests after adding nullable v2 fields: an old
    # spooled snapshot must still replay against the exact original hash.
    if request.schema_version == 1:
        payload.pop("sources", None)
        for item in payload["software"]:
            for name in _IDENTITY_FIELDS:
                item.pop(name, None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_IDENTITY_FIELDS = (
    "product_identity",
    "installation_identity",
    "package_id",
    "scope",
    "install_instance_id",
)
_SOFTWARE_FIELDS = (
    "name",
    "version",
    "publisher",
    "architecture",
    "source",
    "install_location",
    *_IDENTITY_FIELDS,
)


def _software_payload(item: Any) -> dict[str, Any]:
    return {name: getattr(item, name, None) for name in _SOFTWARE_FIELDS}


def _has_v2_baseline(previous_rows, previous_states, previous_schema):
    # A downgraded receipt still carries the last v2 observations. Its wire
    # schema cannot make a later v1 receipt authoritative over that baseline.
    return (
        previous_schema == 2
        or any(getattr(row, "installation_identity", None) for row in previous_rows)
        or any(state.get("status") for state in previous_states)
    )


def _effective_inventory(request, previous_rows, previous_states, previous_schema):
    """Only a complete source replaces its last known inventory.

    Failed, partial, omitted and downgraded sources retain their last accepted
    observations. A source's last-complete timestamp is computed by the API,
    never taken on faith from the agent's claim.
    """
    if request.schema_version == 1 and not _has_v2_baseline(
        previous_rows, previous_states, previous_schema
    ):
        return list(request.software), []
    previous_by_source: dict[str, list[Any]] = {}
    for row in previous_rows:
        previous_by_source.setdefault(row.source, []).append(row)
    old_states = {state["source"]: state for state in previous_states}
    reported = {state.source: state.model_dump() for state in request.sources}
    observed: dict[str, list[Any]] = {}
    for item in request.software:
        observed.setdefault(item.source, []).append(item)
    effective = []
    states = []
    for source in sorted(set(previous_by_source) | set(old_states) | set(reported)):
        state = reported.get(source)
        if state is None:
            state = {
                "source": source,
                "status": "failed",
                "collected_at": request.collected_at,
                "collector_version": request.agent_version,
                "diagnostic_code": "schema_downgrade"
                if request.schema_version == 1
                else "source_not_reported",
            }
        state["last_complete_at"] = (
            state["collected_at"]
            if state["status"] == "complete"
            else old_states.get(source, {}).get("last_complete_at")
        )
        if (
            state["last_complete_at"] is None
            and source in previous_by_source
            and previous_schema == 1
        ):
            # A legacy full snapshot is authoritative, but has no per-source
            # timestamp. The caller supplies its snapshot's collection time.
            state["last_complete_at"] = old_states.get(source, {}).get(
                "legacy_collected_at"
            )
        effective.extend(
            observed.get(source, [])
            if state["status"] == "complete"
            else previous_by_source.get(source, [])
        )
        states.append(state)
    return effective, states


def _validate_bounds(
    settings: Settings, request: EndpointInventorySnapshotRequest
) -> None:
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
            raise ValueError(
                f"collector_warnings entry exceeds max string length {max_len}"
            )

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
    for state in request.sources:
        source_time = _parse_dt(state.collected_at)
        if source_time > collected_at:
            raise ValueError("source collected_at is later than snapshot collected_at")
    now = _now()
    if collected_at > now + timedelta(
        seconds=settings.endpoint_inventory_max_future_skew_seconds
    ):
        raise ValueError("collected_at is too far in the future")
    if now - collected_at > timedelta(
        seconds=settings.endpoint_inventory_max_snapshot_age_seconds
    ):
        raise ValueError("collected_at is older than the maximum accepted snapshot age")


def _check_rate_limit(
    session, settings: Settings, *, tenant_id: str, agent_id: str
) -> None:
    cutoff = _now() - timedelta(hours=1)
    count = session.execute(
        select(models.EndpointInventorySnapshot.snapshot_id)
        .join(
            models.EndpointDevice,
            models.EndpointInventorySnapshot.device_id
            == models.EndpointDevice.device_id,
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


def _reconcile_asset(
    session,
    *,
    tenant_id: str,
    device: models.EndpointDevice,
    hostname: str,
    settings: Settings,
) -> None:
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

    # A new asset is about to be registered, so the tenant's asset quota
    # applies here exactly as it does to a network scan (Track E). Read only
    # now, on the same session: most snapshots come from devices that are
    # already linked and returned above, and counting a tenant's assets on
    # every one of those would be a table scan per heartbeat.
    #
    # The snapshot itself is still accepted: the endpoint inventory is the
    # value the agent was installed for, and refusing it would lose software
    # and patch data over a *registry* limit. The device stays ``unlinked``
    # and links itself on a later submit once the quota is raised, because
    # reconciliation re-runs for any device without an asset.
    capacity = quotas.asset_capacity_in_session(session, settings, tenant_id)
    if capacity is not None and capacity <= 0:
        device.reconciliation_status = "unlinked"
        quotas.record_asset_refusal(tenant_id, 1)
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

    # ``snapshot_id`` is the collector's choice and the table's key, so whether
    # another tenant already used it is asked across tenants (#311), as in
    # ``agents.register_agent``; in the agent's own scope the row would be
    # invisible and the conflict a duplicate-key error at the insert.
    with tenant_scope.system("inventory ingest: is this snapshot id another tenant's"):
        with get_session(settings.postgres_url) as session:
            owner = session.execute(
                select(models.EndpointInventorySnapshot.tenant_id).where(
                    models.EndpointInventorySnapshot.snapshot_id == request.snapshot_id
                )
            ).scalar_one_or_none()
    if owner is not None and owner != tenant_id:
        raise ConflictError("snapshot_id already used by a different tenant")

    with get_session(settings.postgres_url) as session:
        existing_snapshot = session.get(
            models.EndpointInventorySnapshot, request.snapshot_id
        )
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
            select(models.EndpointDevice)
            .where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.agent_id == agent_id,
            )
            .with_for_update()
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
        old_os = (device.os_family, device.os_name, device.os_version, device.os_arch)
        if not is_first_snapshot:
            device.hostname = request.hostname
            device.os_family = request.os_family
            device.os_name = request.os_name
            device.os_version = request.os_version
            device.os_arch = request.os_arch
            device.agent_version = request.agent_version
            device.labels = dict(request.labels)
            device.last_seen = now
        session.flush()

        _upsert_identifiers(
            session, tenant_id=tenant_id, device=device, identifiers=request.identifiers
        )
        _reconcile_asset(
            session,
            tenant_id=tenant_id,
            device=device,
            hostname=request.hostname,
            settings=settings,
        )

        previous_rows: list[Any] = []
        previous_schema = None
        previous_snapshot = None
        previous_items: dict[str, str | None] = {}
        previous_name_by_key: dict[str, str] = {}
        if not is_first_snapshot and device.latest_snapshot_id:
            previous_rows = (
                session.execute(
                    select(models.EndpointSoftwareItem).where(
                        models.EndpointSoftwareItem.snapshot_id
                        == device.latest_snapshot_id
                    )
                )
                .scalars()
                .all()
            )
            previous_items = {row.comparison_key: row.version for row in previous_rows}
            previous_name_by_key = {
                row.comparison_key: row.name for row in previous_rows
            }

        if device.latest_snapshot_id:
            previous_snapshot = session.get(
                models.EndpointInventorySnapshot, device.latest_snapshot_id
            )
            previous_schema = (
                previous_snapshot.schema_version if previous_snapshot else None
            )
        if previous_snapshot is not None and collected_at < _parse_dt(
            _iso(previous_snapshot.collected_at)
        ):
            raise ValueError(
                "snapshot collected_at precedes the latest accepted inventory"
            )
        old_states = list(device.source_states or [])
        if not old_states and previous_snapshot is not None:
            old_states = [
                {
                    "source": row.source,
                    "legacy_collected_at": _iso(previous_snapshot.collected_at),
                }
                for row in previous_rows
            ]
        last_complete = {
            state["source"]: state.get("last_complete_at") for state in old_states
        }
        for state in request.sources:
            previous_complete = last_complete.get(state.source)
            if (
                state.status == "complete"
                and previous_complete
                and _parse_dt(state.collected_at) < _parse_dt(previous_complete)
            ):
                raise ValueError(
                    "source collected_at precedes its last complete inventory"
                )
        effective_items, source_states = _effective_inventory(
            request, previous_rows, old_states, previous_schema
        )
        if len(effective_items) > settings.endpoint_inventory_max_software_items:
            raise PayloadTooLargeError(
                "effective software entry count exceeds the configured limit"
            )

        snapshot = models.EndpointInventorySnapshot(
            snapshot_id=request.snapshot_id,
            tenant_id=tenant_id,
            device_id=device.device_id,
            schema_version=request.schema_version,
            collected_at=collected_at,
            received_at=now,
            payload_digest=digest,
            software_count=len(effective_items),
            source_states=source_states,
            collector_warnings={"warnings": list(request.collector_warnings)},
            response={},
        )
        session.add(snapshot)
        session.flush()

        current_items: dict[str, str | None] = {}
        for item in effective_items:
            key = _comparison_key(item)
            current_items[key] = item.version
            session.add(
                models.EndpointSoftwareItem(
                    snapshot_id=snapshot.snapshot_id,
                    tenant_id=tenant_id,
                    device_id=device.device_id,
                    comparison_key=key,
                    **_software_payload(item),
                )
            )

        changes = {"installed": 0, "removed": 0, "updated": 0}
        if not is_first_snapshot and previous_schema == request.schema_version:
            name_by_key = {_comparison_key(item): item.name for item in effective_items}
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
                            display_name=previous_name_by_key.get(key, ""),
                            observed_at=now,
                        )
                    )

        device.last_inventory_at = now
        previous_effective = sorted(
            (_comparison_key(item), json.dumps(_software_payload(item), sort_keys=True))
            for item in previous_rows
        )
        current_effective = sorted(
            (_comparison_key(item), json.dumps(_software_payload(item), sort_keys=True))
            for item in effective_items
        )
        inventory_changed = (
            (
                request.schema_version == 1
                and not _has_v2_baseline(previous_rows, old_states, previous_schema)
            )
            or previous_effective != current_effective
            or old_os
            != (device.os_family, device.os_name, device.os_version, device.os_arch)
        )
        # A successful collection is new assessment evidence even when its
        # packages are unchanged: vendor advisories may have changed since
        # the previous pass. Degraded-only receipts still avoid re-matching.
        needs_assessment = inventory_changed or any(
            state.status == "complete" for state in request.sources
        )
        if needs_assessment or not device.software_snapshot_id:
            device.software_snapshot_id = snapshot.snapshot_id
        device.source_states = source_states
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

    # The device's ``latest_snapshot_id`` has moved, which is what makes it due
    # for re-matching (api/services/software_match_worker.py). Re-matching here
    # would put a fleet-wide advisory walk on the agent's rate-limited ingest
    # path, so this only shortens the worker's wait; the queue itself is the
    # snapshot comparison, which survives a restart and this process not
    # holding the leader lock.
    try:
        from api.services import software_match_worker

        if needs_assessment:
            software_match_worker.notify()
    except Exception:  # noqa: BLE001 - a nudge is not worth failing a submission
        _log.warning("Could not notify the software match worker", exc_info=True)

    metrics_service.ENDPOINT_SOFTWARE_ITEMS.observe(len(request.software))
    for event_type, count in changes.items():
        if count:
            metrics_service.ENDPOINT_SOFTWARE_CHANGES_TOTAL.labels(event_type).inc(
                count
            )

    # Phase S8: publish accepted endpoint inventory summary to NATS (fail-soft)
    if settings.endpoint_nats_events_enabled and settings.nats_url:
        try:
            from api.services import nats_bus

            bus = nats_bus.get_bus(settings.nats_url)
            if bus is not None:
                bus.publish_endpoint_inventory(
                    {
                        "event_type": "endpoint_inventory_accepted",
                        "tenant_id": tenant_id,
                        "device_id": response["device_id"],
                        "asset_id": response["asset_id"],
                        "snapshot_id": response["snapshot_id"],
                        "payload_digest": digest,
                        "software_count": response["software_count"],
                        "changes_summary": changes,
                        "reconciliation_status": response["reconciliation_status"],
                        "collected_at": _iso(collected_at),
                        "received_at": _iso(now),
                    }
                )
        except Exception:  # noqa: BLE001
            _log.warning(
                "Failed to publish endpoint inventory NATS event for snapshot %s",
                request.snapshot_id,
                exc_info=True,
            )

    return {**response, "_replay": False}


def device_status(
    last_inventory_at: datetime | None, *, now: datetime | None = None
) -> str:
    """Derived endpoint staleness (S9, decision 7).

    Kept derived rather than a stored column so a threshold change takes effect
    immediately and can never disagree with ``last_inventory_at``. A device
    that has never submitted an accepted snapshot counts as stale.
    """
    settings = _require_settings()
    if last_inventory_at is None:
        return "stale"
    if last_inventory_at.tzinfo is None:
        last_inventory_at = last_inventory_at.replace(tzinfo=UTC)
    age = (now or _now()) - last_inventory_at
    return "stale" if age > timedelta(hours=settings.endpoint_stale_hours) else "active"


def _device_to_dict(row: models.EndpointDevice) -> dict[str, Any]:
    return {
        "status": device_status(row.last_inventory_at),
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
        "sources": list(row.source_states or []),
    }


def list_devices(
    tenant_id: str, *, asset_id: str | None = None, status: str | None = None
) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.EndpointDevice).where(
            models.EndpointDevice.tenant_id == tenant_id
        )
        if asset_id:
            stmt = stmt.where(models.EndpointDevice.asset_id == asset_id)
        rows = session.execute(stmt).scalars().all()
    items = [_device_to_dict(row) for row in rows]
    if status:
        # Derived, not a column — filter after mapping (see device_status).
        items = [d for d in items if d["status"] == status]
    items.sort(key=lambda d: str(d.get("last_seen") or ""), reverse=True)
    return items


def device_state_counts(
    session: Any, *, now: datetime, stale_hours: int
) -> dict[str, int]:
    """``{"active": n, "stale": m}`` over every tenant, in one aggregate (#334).

    What ``octo_endpoint_devices`` reports, read at scrape time. The rule is
    :func:`device_status` in SQL — never submitted, or last submitted more
    than ``stale_hours`` ago, is stale — counted by the database rather than
    by loading one timestamp per device, which is what :func:`device_counts`
    does for the System page.
    """
    last = models.EndpointDevice.last_inventory_at
    stale_before = now - timedelta(hours=stale_hours)
    total, stale = session.execute(
        select(
            func.count(),
            func.coalesce(
                func.sum(case((or_(last.is_(None), last < stale_before), 1), else_=0)),
                0,
            ),
        ).select_from(models.EndpointDevice)
    ).one()
    return {"active": int(total) - int(stale), "stale": int(stale)}


def device_counts(tenant_id: str | None = None) -> dict[str, int]:
    """Total / stale endpoint-device counts, optionally scoped to one tenant.

    Feeds the System page (S9 / §15).
    """
    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.EndpointDevice.last_inventory_at)
        if tenant_id:
            stmt = stmt.where(models.EndpointDevice.tenant_id == tenant_id)
        seen = session.execute(stmt).scalars().all()
    stale = sum(1 for last in seen if device_status(last, now=now) == "stale")
    return {"total": len(seen), "stale": stale, "active": len(seen) - stale}


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
        rows = (
            session.execute(
                select(models.EndpointInventorySnapshot).where(
                    models.EndpointInventorySnapshot.device_id == device_id
                )
            )
            .scalars()
            .all()
        )
    items = [
        {
            "snapshot_id": row.snapshot_id,
            "device_id": row.device_id,
            "schema_version": row.schema_version,
            "collected_at": _iso(row.collected_at),
            "received_at": _iso(row.received_at),
            "software_count": row.software_count,
            "collector_warnings": list(
                (row.collector_warnings or {}).get("warnings", [])
            ),
            "sources": list(row.source_states or []),
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
        rows = (
            session.execute(
                select(models.EndpointSoftwareChange)
                .where(models.EndpointSoftwareChange.device_id == device_id)
                .order_by(models.EndpointSoftwareChange.observed_at.desc())
            )
            .scalars()
            .all()
        )
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


_MAX_RECENT_CHANGES_LIMIT = 200


def list_recent_changes(
    tenant_id: str,
    *,
    limit: int = 50,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    """Cross-device software-change feed (installed/removed/updated), newest
    first, joined with the owning device's hostname/asset for display."""
    limit = max(1, min(limit, _MAX_RECENT_CHANGES_LIMIT))
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        query = (
            select(models.EndpointSoftwareChange, models.EndpointDevice)
            .join(
                models.EndpointDevice,
                models.EndpointDevice.device_id
                == models.EndpointSoftwareChange.device_id,
            )
            .where(models.EndpointSoftwareChange.tenant_id == tenant_id)
            .order_by(models.EndpointSoftwareChange.observed_at.desc())
            .limit(limit)
        )
        if event_type:
            query = query.where(models.EndpointSoftwareChange.event_type == event_type)
        rows = session.execute(query).all()
    return [
        {
            "device_id": change.device_id,
            "snapshot_id": change.snapshot_id,
            "event_type": change.event_type,
            "display_name": change.display_name,
            "old_version": change.old_version,
            "new_version": change.new_version,
            "observed_at": _iso(change.observed_at),
            "hostname": device.hostname,
            "asset_id": device.asset_id,
        }
        for change, device in rows
    ]


def list_software_for_asset(tenant_id: str, asset_id: str) -> list[dict[str, Any]]:
    """Latest snapshot's software for every device linked to ``asset_id``."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        devices = (
            session.execute(
                select(models.EndpointDevice).where(
                    models.EndpointDevice.tenant_id == tenant_id,
                    models.EndpointDevice.asset_id == asset_id,
                )
            )
            .scalars()
            .all()
        )
        items: list[dict[str, Any]] = []
        for device in devices:
            if not device.latest_snapshot_id:
                continue
            rows = (
                session.execute(
                    select(models.EndpointSoftwareItem).where(
                        models.EndpointSoftwareItem.snapshot_id
                        == device.latest_snapshot_id
                    )
                )
                .scalars()
                .all()
            )
            for row in rows:
                items.append(
                    {
                        **_software_payload(row),
                    }
                )
    return items
