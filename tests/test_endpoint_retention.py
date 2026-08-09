"""Endpoint-inventory retention sweep and server-side staleness (Agent_plan.md S9)."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import EndpointInventorySnapshotRequest, EndpointSoftwareItem
from api.services import endpoint_inventory, endpoint_retention
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **overrides)


@pytest.fixture()
def settings(tmp_path):
    s = _settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    endpoint_inventory.configure(s)
    endpoint_inventory.reset_for_tests()
    return s


def _request(**overrides: object) -> EndpointInventorySnapshotRequest:
    base = dict(
        schema_version=1,
        snapshot_id="snap_1",
        agent_id="agent-1",
        collected_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        hostname="host-1.example.internal",
        os_family="linux",
        os_name="Ubuntu",
        os_version="24.04",
        os_arch="x86_64",
        agent_version="1.0.0",
        labels={},
        identifiers=[],
        software=[
            EndpointSoftwareItem(name="curl", version="8.5.0", publisher="Canonical", source="dpkg"),
        ],
        collector_warnings=[],
    )
    base.update(overrides)
    return EndpointInventorySnapshotRequest(**base)


def _age_snapshot(settings: Settings, snapshot_id: str, *, days: int) -> None:
    """Backdate an accepted snapshot and its change events past retention."""
    when = datetime.now(UTC) - timedelta(days=days)
    with get_session(settings.postgres_url) as session:
        snapshot = session.get(models.EndpointInventorySnapshot, snapshot_id)
        snapshot.received_at = when
        snapshot.collected_at = when
        for change in session.query(models.EndpointSoftwareChange).filter_by(
            snapshot_id=snapshot_id
        ):
            change.observed_at = when


def _software_rows(settings: Settings, snapshot_id: str) -> int:
    with get_session(settings.postgres_url) as session:
        return (
            session.query(models.EndpointSoftwareItem).filter_by(snapshot_id=snapshot_id).count()
        )


def _ingest_two_snapshots(settings: Settings) -> tuple[str, str]:
    endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=_request())
    endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-1",
        request=_request(
            snapshot_id="snap_2",
            software=[
                EndpointSoftwareItem(name="curl", version="8.6.0", publisher="Canonical", source="dpkg"),
                EndpointSoftwareItem(name="vim", version="9.1", publisher="Debian", source="dpkg"),
            ],
        ),
    )
    return "snap_1", "snap_2"


def test_expired_snapshot_loses_software_rows_but_keeps_summary(settings):
    old_id, _current_id = _ingest_two_snapshots(settings)
    _age_snapshot(settings, old_id, days=200)

    totals = endpoint_retention.sweep_tenant(settings, "default")

    assert totals["software_items_deleted"] == 1
    assert totals["snapshots_pruned"] == 1
    assert _software_rows(settings, old_id) == 0
    summaries = {s["snapshot_id"] for s in endpoint_inventory.list_snapshots("default", _device_id(settings))}
    assert old_id in summaries  # summary row survives the prune


def _device_id(settings: Settings) -> str:
    devices = endpoint_inventory.list_devices("default")
    return devices[0]["device_id"]


def test_current_snapshot_is_never_pruned(settings):
    _old_id, current_id = _ingest_two_snapshots(settings)
    _age_snapshot(settings, current_id, days=200)

    totals = endpoint_retention.sweep_tenant(settings, "default")

    # The device's latest_snapshot_id backs the next submission's diff, so its
    # software rows stay regardless of age.
    assert _software_rows(settings, current_id) == 2
    assert totals["software_items_deleted"] == 0


def test_sweep_is_idempotent(settings):
    old_id, _ = _ingest_two_snapshots(settings)
    _age_snapshot(settings, old_id, days=200)

    first = endpoint_retention.sweep_tenant(settings, "default")
    second = endpoint_retention.sweep_tenant(settings, "default")

    assert first["software_items_deleted"] == 1
    assert second == {"software_items_deleted": 0, "changes_deleted": 0, "snapshots_pruned": 0}


def test_change_events_outlive_software_rows_then_expire(settings):
    old_id, _ = _ingest_two_snapshots(settings)
    _age_snapshot(settings, old_id, days=200)
    # snap_2 produced the change events; age those past the software-retention
    # window but inside the 365d change window.
    _age_snapshot(settings, "snap_2", days=200)

    endpoint_retention.sweep_tenant(settings, "default")
    changes = endpoint_inventory.list_changes("default", _device_id(settings))
    assert len(changes) == 2  # curl updated + vim installed

    _age_snapshot(settings, "snap_2", days=400)
    totals = endpoint_retention.sweep_tenant(settings, "default")
    assert totals["changes_deleted"] == 2
    assert endpoint_inventory.list_changes("default", _device_id(settings)) == []


def test_sweep_batches_without_losing_rows(settings, tmp_path):
    old_id, _ = _ingest_two_snapshots(settings)
    _age_snapshot(settings, old_id, days=200)
    batched = _settings(tmp_path, endpoint_retention_batch_size=1)

    totals = endpoint_retention.sweep_tenant(batched, "default")

    assert totals["software_items_deleted"] == 1
    assert _software_rows(settings, old_id) == 0


def test_sweep_is_tenant_scoped(settings):
    other = tenants_service.create_tenant(name="other")
    for snapshot_id in ("snap_other", "snap_other_2"):
        endpoint_inventory.ingest_snapshot(
            tenant_id=other["tenant_id"],
            agent_id="agent-other",
            request=_request(snapshot_id=snapshot_id, agent_id="agent-other"),
        )
    _age_snapshot(settings, "snap_other", days=200)
    _ingest_two_snapshots(settings)
    _age_snapshot(settings, "snap_1", days=200)

    totals = endpoint_retention.sweep_tenant(settings, "default")

    assert totals["software_items_deleted"] == 1
    # The other tenant's expired snapshot is untouched by a default-tenant sweep,
    # even though it is well past retention.
    assert _software_rows(settings, "snap_other") == 1

    everything = endpoint_retention.sweep(settings)
    assert everything["tenants"] >= 2
    assert everything["software_items_deleted"] == 1  # the other tenant's, this time
    assert _software_rows(settings, "snap_other") == 0


def test_retention_disabled_worker_does_not_start(tmp_path):
    disabled = _settings(tmp_path, endpoint_retention_enabled=False)
    assert endpoint_retention.start_worker(disabled) is None
    assert endpoint_retention.worker_stats() is None


def test_worker_lifecycle_sweeps_once_and_stops(settings):
    old_id, _ = _ingest_two_snapshots(settings)
    _age_snapshot(settings, old_id, days=200)
    settings.endpoint_retention_interval_seconds = 3600  # one sweep, then idle

    worker = endpoint_retention.start_worker(settings)
    try:
        assert worker is not None
        deadline = time.time() + 5
        while time.time() < deadline and (endpoint_retention.worker_stats() or {}).get("runs", 0) < 1:
            time.sleep(0.05)
        stats = endpoint_retention.worker_stats()
        assert stats["runs"] == 1
        assert stats["software_items_deleted"] == 1
        # start_worker is idempotent while one is already running.
        assert endpoint_retention.start_worker(settings) is worker
    finally:
        endpoint_retention.stop_worker()
    assert endpoint_retention.worker_stats() is None


def test_worker_run_once_accumulates_stats(settings):
    old_id, _ = _ingest_two_snapshots(settings)
    _age_snapshot(settings, old_id, days=200)
    worker = endpoint_retention.EndpointRetentionWorker(settings=settings, interval_seconds=3600)

    worker.run_once()

    stats = worker.stats
    assert stats["runs"] == 1
    assert stats["software_items_deleted"] == 1
    assert stats["errors"] == 0
    assert stats["last_run_at"] is not None


def test_device_status_derives_from_stale_hours(settings):
    endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=_request())
    device_id = _device_id(settings)
    assert endpoint_inventory.get_device("default", device_id)["status"] == "active"
    assert endpoint_inventory.device_counts()["stale"] == 0

    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, device_id)
        device.last_inventory_at = datetime.now(UTC) - timedelta(hours=49)

    assert endpoint_inventory.get_device("default", device_id)["status"] == "stale"
    assert endpoint_inventory.device_counts() == {"total": 1, "stale": 1, "active": 0}
    assert endpoint_inventory.list_devices("default", status="active") == []
    assert len(endpoint_inventory.list_devices("default", status="stale")) == 1


def test_device_status_threshold_is_configurable(settings, tmp_path):
    endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=_request())
    device_id = _device_id(settings)
    with get_session(settings.postgres_url) as session:
        session.get(models.EndpointDevice, device_id).last_inventory_at = datetime.now(
            UTC
        ) - timedelta(hours=49)

    endpoint_inventory.configure(_settings(tmp_path, endpoint_stale_hours=72))
    try:
        assert endpoint_inventory.get_device("default", device_id)["status"] == "active"
    finally:
        endpoint_inventory.configure(settings)
