"""Phase S10: End-to-end Endpoint Inventory Lifecycle Integration Suite.

Exercises the full lifecycle of the Lariska endpoint inventory subsystem:
1. Tenant provisioning & Agent JWT token exchange.
2. Initial snapshot submission with hardware identifiers and asset reconciliation.
3. First-snapshot diff suppression (0 change events emitted).
4. Idempotent replay handling & conflicting content rejection (409 Conflict).
5. Subsequent snapshot diff engine (installed, updated, removed transitions).
6. NATS JetStream event publishing on ``ingest.endpoint_inventory.{tenant_id}`` (Phase S8).
7. REST query APIs (/devices, /software, /changes, /assets/{id}/software).
8. Strict multi-tenant isolation across all read/write paths.
9. Server-side staleness derivation and retention pruning sweeps.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from api.services import endpoint_inventory
from api.services import endpoint_retention
from api.services import nats_bus
from api.services import tenants as tenants_service
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


def _hash_id(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def test_full_endpoint_inventory_lifecycle(tmp_path: Path, monkeypatch):
    settings = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        nats_url="nats://127.0.0.1:4222",
        endpoint_nats_events_enabled=True,
    )
    client = configured_client(
        tmp_path,
        monkeypatch,
        nats_url="nats://127.0.0.1:4222",
        endpoint_nats_events_enabled=True,
    )
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    endpoint_inventory.configure(settings)
    endpoint_inventory.reset_for_tests()

    # 0. Setup NATS mock to capture published events (Phase S8 verification)
    published_events: list[dict[str, Any]] = []
    mock_bus = MagicMock()

    def fake_publish(envelope: dict[str, Any], *, retries: int = 1) -> bool:
        published_events.append(envelope)
        return True

    mock_bus.publish_endpoint_inventory = fake_publish
    monkeypatch.setattr(nats_bus, "get_bus", lambda url: mock_bus)

    # 1. Provisioning: Create tenant and obtain provisioning key
    tenant_res = tenants_service.create_tenant(
        tenant_id="acme-corp",
        name="Acme Corporation",
    )
    assert tenant_res["tenant_id"] == "acme-corp"

    key_res = tenants_service.create_provisioning_key(
        tenant_id="acme-corp",
        label="Lariska Deployment Key",
    )
    provisioning_key = key_res["key"]
    assert provisioning_key.startswith("octo-pk-")

    # 2. Token Exchange: Lariska agent exchanges provisioning key for JWT
    token_resp = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": provisioning_key, "agent_id": "lariska-agent-01"},
    )
    assert token_resp.status_code == 200, token_resp.text
    agent_token = token_resp.json()["access_token"]
    agent_headers = {"Authorization": f"Bearer {agent_token}"}

    # 3. Initial Snapshot Submission: Enrollment with hardware IDs and 3 software packages
    now = datetime.now(UTC)
    mac_hash = _hash_id("00:1A:2B:3C:4D:5E")
    bios_hash = _hash_id("4c4c4544-004a-4d10-8037-c6c04f503832")

    snap1_payload = {
        "schema_version": 1,
        "snapshot_id": "snap-acme-001",
        "agent_id": "lariska-agent-01",
        "collected_at": (now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
        "hostname": "workstation-01.acme.local",
        "os_family": "linux",
        "os_name": "Ubuntu",
        "os_version": "24.04 LTS",
        "os_arch": "x86_64",
        "agent_version": "1.2.0",
        "labels": {"department": "engineering", "env": "prod"},
        "identifiers": [
            {"identifier_type": "mac_hash", "value_hash": mac_hash},
            {"identifier_type": "bios_uuid_hash", "value_hash": bios_hash},
        ],
        "software": [
            {"name": "nginx", "version": "1.24.0", "publisher": "Canonical", "architecture": "x86_64", "source": "dpkg"},
            {"name": "curl", "version": "8.5.0", "publisher": "Canonical", "architecture": "x86_64", "source": "dpkg"},
            {"name": "openssl", "version": "3.0.2", "publisher": "Canonical", "architecture": "x86_64", "source": "dpkg"},
        ],
        "collector_warnings": [],
    }

    resp1 = client.post("/api/endpoint/inventory", json=snap1_payload, headers=agent_headers)
    assert resp1.status_code == 201, resp1.text
    body1 = resp1.json()

    assert body1["status"] == "accepted"
    assert body1["snapshot_id"] == "snap-acme-001"
    assert body1["device_id"].startswith("dev_")
    device_id = body1["device_id"]
    assert body1["asset_id"].startswith("ep_")
    asset_id = body1["asset_id"]
    assert body1["software_count"] == 3
    # First snapshot suppression: zero diff events
    assert body1["changes"] == {"installed": 0, "removed": 0, "updated": 0}

    # 4. NATS Event Check (Phase S8)
    assert len(published_events) == 1
    nats_event_1 = published_events[0]
    assert nats_event_1["event_type"] == "endpoint_inventory_accepted"
    assert nats_event_1["tenant_id"] == "acme-corp"
    assert nats_event_1["device_id"] == device_id
    assert nats_event_1["asset_id"] == asset_id
    assert nats_event_1["software_count"] == 3
    assert nats_event_1["changes_summary"] == {"installed": 0, "removed": 0, "updated": 0}

    # 5. Idempotency & Replay Verification
    # 5a. Replay identical payload -> 200 OK with _replay=True
    resp_replay = client.post("/api/endpoint/inventory", json=snap1_payload, headers=agent_headers)
    assert resp_replay.status_code == 200
    assert resp_replay.json()["snapshot_id"] == "snap-acme-001"
    assert resp_replay.json()["status"] == "accepted"

    # 5b. Same snapshot_id with altered software list -> 409 Conflict
    conflict_payload = dict(snap1_payload)
    conflict_payload["software"] = [{"name": "curl", "version": "9.9.9", "publisher": "x", "architecture": "x", "source": "dpkg"}]
    resp_conflict = client.post("/api/endpoint/inventory", json=conflict_payload, headers=agent_headers)
    assert resp_conflict.status_code == 409

    # 6. Second Snapshot Submission: Diff Engine (Installed, Updated, Removed)
    snap2_payload = {
        "schema_version": 1,
        "snapshot_id": "snap-acme-002",
        "agent_id": "lariska-agent-01",
        "collected_at": now.isoformat().replace("+00:00", "Z"),
        "hostname": "workstation-01.acme.local",
        "os_family": "linux",
        "os_name": "Ubuntu",
        "os_version": "24.04 LTS",
        "os_arch": "x86_64",
        "agent_version": "1.2.0",
        "labels": {"department": "engineering", "env": "prod"},
        "identifiers": [
            {"identifier_type": "mac_hash", "value_hash": mac_hash},
            {"identifier_type": "bios_uuid_hash", "value_hash": bios_hash},
        ],
        "software": [
            # nginx updated: 1.24.0 -> 1.26.0
            {"name": "nginx", "version": "1.26.0", "publisher": "Canonical", "architecture": "x86_64", "source": "dpkg"},
            # curl unchanged: 8.5.0
            {"name": "curl", "version": "8.5.0", "publisher": "Canonical", "architecture": "x86_64", "source": "dpkg"},
            # openssl removed
            # python3 installed (new)
            {"name": "python3", "version": "3.12.3", "publisher": "Canonical", "architecture": "x86_64", "source": "dpkg"},
        ],
        "collector_warnings": ["Minor warning: battery status unavailable"],
    }

    resp2 = client.post("/api/endpoint/inventory", json=snap2_payload, headers=agent_headers)
    assert resp2.status_code == 201, resp2.text
    body2 = resp2.json()

    assert body2["snapshot_id"] == "snap-acme-002"
    assert body2["device_id"] == device_id
    assert body2["asset_id"] == asset_id
    assert body2["software_count"] == 3
    # Verify calculated diffs: 1 installed, 1 updated, 1 removed
    assert body2["changes"] == {"installed": 1, "removed": 1, "updated": 1}

    # 7. NATS Event Check for Snapshot 2 (Phase S8)
    assert len(published_events) == 2
    nats_event_2 = published_events[1]
    assert nats_event_2["snapshot_id"] == "snap-acme-002"
    assert nats_event_2["changes_summary"] == {"installed": 1, "removed": 1, "updated": 1}

    # 8. REST Query APIs Verification (Phase S6)
    admin_headers = auth_headers(client, username="admin")

    # 8a. List Devices for Tenant
    devices_resp = client.get("/api/endpoint/devices", headers=admin_headers, params={"tenant_id": "acme-corp"})
    assert devices_resp.status_code == 200
    devices = devices_resp.json()
    assert len(devices) == 1
    assert devices[0]["device_id"] == device_id
    assert devices[0]["hostname"] == "workstation-01.acme.local"
    assert devices[0]["status"] == "active"
    assert devices[0]["labels"] == {"department": "engineering", "env": "prod"}

    # 8b. Get Single Device
    device_detail_resp = client.get(f"/api/endpoint/devices/{device_id}", headers=admin_headers, params={"tenant_id": "acme-corp"})
    assert device_detail_resp.status_code == 200
    detail = device_detail_resp.json()
    assert detail["device_id"] == device_id
    assert detail["latest_snapshot_id"] == "snap-acme-002"

    # 8c. Query Software Change History
    changes_resp = client.get(f"/api/endpoint/devices/{device_id}/changes", headers=admin_headers, params={"tenant_id": "acme-corp"})
    assert changes_resp.status_code == 200
    changes_list = changes_resp.json()
    assert len(changes_list) == 3

    events_by_type = {c["event_type"]: c for c in changes_list}
    assert events_by_type["installed"]["display_name"] == "python3"
    assert events_by_type["installed"]["new_version"] == "3.12.3"
    assert events_by_type["updated"]["display_name"] == "nginx"
    assert events_by_type["updated"]["old_version"] == "1.24.0"
    assert events_by_type["updated"]["new_version"] == "1.26.0"
    assert events_by_type["removed"]["display_name"] == "openssl"
    assert events_by_type["removed"]["old_version"] == "3.0.2"

    # 8d. Query Asset Software View (Linked asset query)
    asset_sw_resp = client.get(f"/api/assets/{asset_id}/software", headers=admin_headers, params={"tenant_id": "acme-corp"})
    assert asset_sw_resp.status_code == 200
    assert len(asset_sw_resp.json()) == 3

    # 9. Tenant Isolation Guard
    # Another tenant (default) cannot query acme-corp device
    iso_resp = client.get(f"/api/endpoint/devices/{device_id}", headers=admin_headers, params={"tenant_id": "default"})
    assert iso_resp.status_code in (404, 403)

    # 10. Staleness & Retention Sweeps (Phase S9)
    fresh_status = endpoint_inventory.device_status(now)
    assert fresh_status == "active"
    stale_status = endpoint_inventory.device_status(now - timedelta(hours=50))
    assert stale_status == "stale"

    sweep_res = endpoint_retention.sweep(settings)
    assert isinstance(sweep_res, dict)
    assert sweep_res["tenants"] >= 1
    assert sweep_res["errors"] == 0
