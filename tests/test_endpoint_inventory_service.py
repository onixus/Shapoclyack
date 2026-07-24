"""Endpoint inventory ingestion service (Agent_plan.md S1-S7): bounds,
idempotency, software diff, and asset reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import EndpointIdentifierIn, EndpointInventorySnapshotRequest, EndpointSoftwareItem
from api.services import endpoint_inventory
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        postgres_url=POSTGRES_URL,
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


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


def test_ingest_first_snapshot_creates_device_and_asset(settings):
    result = endpoint_inventory.ingest_snapshot(
        tenant_id="default", agent_id="agent-1", request=_request()
    )
    assert result["status"] == "accepted"
    assert result["device_id"].startswith("dev_")
    assert result["asset_id"] is not None
    assert result["software_count"] == 1
    # First snapshot suppresses diff events entirely.
    assert result["changes"] == {"installed": 0, "removed": 0, "updated": 0}

    device = endpoint_inventory.get_device("default", result["device_id"])
    assert device["hostname"] == "host-1.example.internal"
    assert device["reconciliation_status"] == "linked"


def test_ingest_rejects_agent_id_mismatch(settings):
    with pytest.raises(ValueError, match="does not match"):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default", agent_id="agent-other", request=_request()
        )


def test_idempotent_replay_same_digest_returns_original(settings):
    req = _request()
    first = endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=req)
    second = endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=req)
    assert second["_replay"] is True
    assert second["device_id"] == first["device_id"]
    assert second["snapshot_id"] == first["snapshot_id"]


def test_same_snapshot_id_different_content_conflicts(settings):
    endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=_request())
    with pytest.raises(endpoint_inventory.ConflictError):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default",
            agent_id="agent-1",
            request=_request(hostname="renamed-host.example.internal"),
        )


def test_second_snapshot_computes_diff_events(settings):
    endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-1",
        request=_request(
            snapshot_id="snap_1",
            software=[
                EndpointSoftwareItem(name="curl", version="8.5.0", publisher="Canonical", source="dpkg"),
                EndpointSoftwareItem(name="vim", version="9.0", publisher="Debian", source="dpkg"),
            ],
        ),
    )
    result = endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-1",
        request=_request(
            snapshot_id="snap_2",
            software=[
                EndpointSoftwareItem(name="curl", version="8.6.0", publisher="Canonical", source="dpkg"),
                EndpointSoftwareItem(name="htop", version="3.3", publisher="Debian", source="dpkg"),
            ],
        ),
    )
    assert result["changes"] == {"installed": 1, "removed": 1, "updated": 1}

    device_id = result["device_id"]
    changes = {c["event_type"]: c for c in endpoint_inventory.list_changes("default", device_id)}
    assert changes["installed"]["display_name"] == "htop"
    assert changes["removed"]["old_version"] == "9.0"
    assert changes["updated"]["old_version"] == "8.5.0"
    assert changes["updated"]["new_version"] == "8.6.0"


def test_duplicate_software_entries_in_one_snapshot_rejected(settings):
    with pytest.raises(ValueError, match="duplicate software entry"):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default",
            agent_id="agent-1",
            request=_request(
                software=[
                    EndpointSoftwareItem(name="curl", version="1", publisher="Canonical", source="dpkg"),
                    EndpointSoftwareItem(name="curl", version="2", publisher="Canonical", source="dpkg"),
                ]
            ),
        )


def test_software_count_over_limit_raises_payload_too_large(tmp_path):
    s = _settings(tmp_path, endpoint_inventory_max_software_items=1)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    endpoint_inventory.configure(s)
    endpoint_inventory.reset_for_tests()
    with pytest.raises(endpoint_inventory.PayloadTooLargeError):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default",
            agent_id="agent-1",
            request=_request(
                software=[
                    EndpointSoftwareItem(name="curl", version="1", source="dpkg"),
                    EndpointSoftwareItem(name="vim", version="1", source="dpkg"),
                ]
            ),
        )


def test_future_collected_at_rejected(settings):
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    with pytest.raises(ValueError, match="future"):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default", agent_id="agent-1", request=_request(collected_at=future)
        )


def test_stale_collected_at_rejected(settings):
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    with pytest.raises(ValueError, match="maximum accepted snapshot age"):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default", agent_id="agent-1", request=_request(collected_at=old)
        )


def test_rate_limit_enforced(tmp_path):
    s = _settings(tmp_path, endpoint_inventory_rate_limit_per_hour=1)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    endpoint_inventory.configure(s)
    endpoint_inventory.reset_for_tests()
    endpoint_inventory.ingest_snapshot(
        tenant_id="default", agent_id="agent-1", request=_request(snapshot_id="snap_1")
    )
    with pytest.raises(endpoint_inventory.RateLimitError):
        endpoint_inventory.ingest_snapshot(
            tenant_id="default", agent_id="agent-1", request=_request(snapshot_id="snap_2")
        )


def test_reconciliation_links_to_existing_asset_by_fqdn(settings):
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id="ast_existing", tenant_id="default", status="active", first_seen=now, last_seen=now
            )
        )
        session.add(
            models.AssetIdentifier(
                asset_id="ast_existing",
                tenant_id="default",
                identifier_type="fqdn",
                identifier_value="host-1.example.internal",
            )
        )
    result = endpoint_inventory.ingest_snapshot(
        tenant_id="default", agent_id="agent-1", request=_request()
    )
    assert result["asset_id"] == "ast_existing"


def test_reconciliation_conflict_on_shared_identifier_does_not_merge(settings):
    ident = EndpointIdentifierIn(identifier_type="mac_hash", value_hash="deadbeef" * 4)
    first = endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-1",
        request=_request(identifiers=[ident]),
    )
    second = endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-2",
        request=_request(agent_id="agent-2", snapshot_id="snap_other", identifiers=[ident]),
    )
    assert second["reconciliation_status"] == "conflict"
    assert second["device_id"] != first["device_id"]
    assert second["asset_id"] is None


def test_tenant_isolation_devices_not_shared(settings):
    tenants_service.create_tenant(name="Other", tenant_id="ten_other")
    endpoint_inventory.ingest_snapshot(tenant_id="default", agent_id="agent-1", request=_request())
    endpoint_inventory.ingest_snapshot(
        tenant_id="ten_other", agent_id="agent-1", request=_request(snapshot_id="snap_other_tenant")
    )
    default_devices = endpoint_inventory.list_devices("default")
    other_devices = endpoint_inventory.list_devices("ten_other")
    assert len(default_devices) == 1
    assert len(other_devices) == 1
    assert default_devices[0]["device_id"] != other_devices[0]["device_id"]


def test_list_devices_filters_by_asset_id(settings):
    result = endpoint_inventory.ingest_snapshot(
        tenant_id="default", agent_id="agent-1", request=_request()
    )
    matching = endpoint_inventory.list_devices("default", asset_id=result["asset_id"])
    assert len(matching) == 1
    assert endpoint_inventory.list_devices("default", asset_id="ast_missing") == []


def test_list_software_for_asset_reflects_latest_snapshot(settings):
    endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-1",
        request=_request(
            snapshot_id="snap_1",
            software=[EndpointSoftwareItem(name="curl", version="8.5.0", source="dpkg")],
        ),
    )
    result = endpoint_inventory.ingest_snapshot(
        tenant_id="default",
        agent_id="agent-1",
        request=_request(
            snapshot_id="snap_2",
            software=[EndpointSoftwareItem(name="curl", version="8.6.0", source="dpkg")],
        ),
    )
    software = endpoint_inventory.list_software_for_asset("default", result["asset_id"])
    assert len(software) == 1
    assert software[0]["version"] == "8.6.0"
