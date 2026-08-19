"""Route-level tests for the Phase 9.4 PATCH /assets/{asset_id} endpoint."""

from __future__ import annotations

from datetime import UTC, datetime


from api.auth import get_settings
from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from scanner.pipeline.asset_identity import ip_identity_key
from tests.conftest import api_client, login, requires_postgres

pytestmark = requires_postgres




def _seed_asset(host_ip: str, *, asset_criticality: int | None = None) -> str:
    settings = get_settings()
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    asset_id = ip_identity_key(tenant_id, host_ip)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        if session.get(models.Asset, asset_id) is None:
            session.add(
                models.Asset(
                    asset_id=asset_id,
                    tenant_id=tenant_id,
                    status="active",
                    first_seen=now,
                    last_seen=now,
                    asset_criticality=asset_criticality,
                )
            )
    return asset_id


def test_viewer_cannot_update_asset():
    asset_id = _seed_asset("10.0.9.1")
    client = api_client()
    token = login(client, "viewer")
    response = client.patch(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"asset_criticality": 3},
    )
    assert response.status_code == 403


def test_operator_can_update_asset():
    asset_id = _seed_asset("10.0.9.2")
    client = api_client()
    token = login(client, "operator")
    response = client.patch(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"asset_criticality": 3, "owner_email": "owner@example.com", "business_unit": "finance"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["asset_criticality"] == 3
    assert body["owner_email"] == "owner@example.com"
    assert body["business_unit"] == "finance"

    # A follow-up partial update must not clobber fields it didn't send.
    response2 = client.patch(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"business_unit": "engineering"},
    )
    assert response2.status_code == 200
    body2 = response2.json()
    assert body2["business_unit"] == "engineering"
    assert body2["owner_email"] == "owner@example.com"
    assert body2["asset_criticality"] == 3


def test_update_asset_out_of_range_criticality_is_422():
    asset_id = _seed_asset("10.0.9.3")
    client = api_client()
    token = login(client, "operator")
    response = client.patch(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"asset_criticality": 9},
    )
    assert response.status_code == 422


def test_operator_can_decommission_asset():
    asset_id = _seed_asset("10.0.9.4")
    client = api_client()
    token = login(client, "operator")
    response = client.patch(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "decommissioned"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "decommissioned"


def test_update_asset_rejects_non_decommissioned_status():
    asset_id = _seed_asset("10.0.9.5")
    client = api_client()
    token = login(client, "operator")
    response = client.patch(
        f"/api/assets/{asset_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "active"},
    )
    assert response.status_code == 422


def test_asset_summary_and_unowned_filter():
    """Risk Dashboard (#135): unowned is active/stale with no owner_email."""
    bare = _seed_asset("10.0.9.20")
    owned = _seed_asset("10.0.9.21", asset_criticality=4)
    client = api_client()
    operator = login(client, "operator")
    viewer = login(client, "viewer")
    assert (
        client.patch(
            f"/api/assets/{owned}",
            headers={"Authorization": f"Bearer {operator}"},
            json={"owner_email": "ada@example.com"},
        ).status_code
        == 200
    )

    summary = client.get("/api/assets/summary", headers={"Authorization": f"Bearer {viewer}"})
    assert summary.status_code == 200
    body = summary.json()
    assert body["total"] >= 2
    assert body["unowned"] >= 1
    assert body["by_criticality"]["4"] >= 1

    listed = client.get(
        "/api/assets",
        params={"unowned": True, "limit": 5000},
        headers={"Authorization": f"Bearer {viewer}"},
    )
    assert listed.status_code == 200
    ids = {row["asset_id"] for row in listed.json()["items"]}
    assert bare in ids
    assert owned not in ids


def test_update_asset_unknown_id_is_404():
    client = api_client()
    token = login(client, "operator")
    response = client.patch(
        "/api/assets/does-not-exist",
        headers={"Authorization": f"Bearer {token}"},
        json={"asset_criticality": 1},
    )
    assert response.status_code == 404
