"""API route tests for endpoint software advisories and patch gaps (Sprint 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from api.auth import Role, TokenUser, create_access_token
from api.db import models
from api.db.engine import get_session
from api.services import software_matcher
from api.settings import load_settings
from tests.conftest import TEST_JWT_SECRET, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path)
    return configured_client(tmp_path, monkeypatch, settings=settings)


@pytest.fixture
def viewer_headers():
    settings = load_settings()
    settings.jwt_secret = TEST_JWT_SECRET
    user = TokenUser(username="viewer", role=Role.viewer, tenant_id="default")
    token = create_access_token(settings, user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def operator_headers():
    settings = load_settings()
    settings.jwt_secret = TEST_JWT_SECRET
    user = TokenUser(username="operator", role=Role.operator, tenant_id="default")
    token = create_access_token(settings, user)
    return {"Authorization": f"Bearer {token}"}


def _seed_test_device(settings):
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.query(models.EndpointSoftwareAdvisory).delete()
        session.query(models.EndpointSoftwareItem).delete()
        session.query(models.EndpointInventorySnapshot).delete()
        session.query(models.EndpointDevice).delete()
        session.commit()

        device = models.EndpointDevice(
            device_id="dev-test-1",
            tenant_id="default",
            agent_id="agent-test-1",
            asset_id="asset-test-1",
            hostname="host-test-1",
            os_name="Debian GNU/Linux 11",
            agent_version="1.0.0",
            reconciliation_status="linked",
            first_seen=now,
            last_seen=now,
            last_inventory_at=now,
            latest_snapshot_id="snap-test-1",
        )
        snapshot = models.EndpointInventorySnapshot(
            snapshot_id="snap-test-1",
            tenant_id="default",
            device_id="dev-test-1",
            schema_version=1,
            collected_at=now,
            received_at=now,
            payload_digest="digest-test-1",
            software_count=1,
        )
        item = models.EndpointSoftwareItem(
            snapshot_id="snap-test-1",
            tenant_id="default",
            device_id="dev-test-1",
            comparison_key="k1",
            name="openssl",
            version="1.1.1k-1+deb11u1",
            publisher="Debian",
            source="deb",
        )
        session.add_all([device, snapshot, item])
        session.commit()


def test_device_advisories_and_patch_gap_routes(client, viewer_headers, operator_headers):
    settings = load_settings()
    _seed_test_device(settings)

    # 1. Force trigger match
    match_resp = client.post("/api/endpoint/devices/dev-test-1/match", headers=operator_headers)
    assert match_resp.status_code == 200
    advisories = match_resp.json()
    assert len(advisories) >= 1
    assert advisories[0]["cve"] == "CVE-2023-0286"

    # 2. Get device advisories
    get_resp = client.get("/api/endpoint/devices/dev-test-1/advisories", headers=viewer_headers)
    assert get_resp.status_code == 200
    assert len(get_resp.json()) >= 1

    # 3. Get tenant patch gap summary
    pg_resp = client.get("/api/endpoint/patch-gaps", headers=viewer_headers)
    assert pg_resp.status_code == 200
    pg_data = pg_resp.json()
    assert pg_data["total_advisories"] >= 1
    assert pg_data["vulnerable_package_count"] >= 1
    assert len(pg_data["remediations"]) >= 1

    # 4. Get device patch gap
    dpg_resp = client.get("/api/endpoint/devices/dev-test-1/patch-gap", headers=viewer_headers)
    assert dpg_resp.status_code == 200
    assert dpg_resp.json()["device_id"] == "dev-test-1"
