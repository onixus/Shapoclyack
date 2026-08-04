"""Tenant-aware IAM (ROADMAP P0): memberships, server-derived tenant context,
and negative cross-tenant access on every scoped resource.

Before P0 the ``tenant_id`` query parameter was taken on trust, so any
authenticated viewer could read another tenant's data by typing a different
id. These tests pin the new contract: the parameter may only *select among*
the tenants a caller is entitled to.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.db import models
from api.db.engine import get_session
from api.settings import Settings
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        allow_scan_start=True,
        agent_token="test-agent-token",
        jwt_secret="test-secret",
        postgres_url=POSTGRES_URL,
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


@pytest.fixture()
def client(tmp_path, monkeypatch) -> TestClient:
    settings = _settings(tmp_path)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)

    from api.services import agents as agents_service
    from api.services import jobs as jobs_service
    from api.services import memberships as memberships_service
    from api.services import scan_schedules
    from api.services import tenants as tenants_service

    jobs_service._JOBS.clear()  # noqa: SLF001
    agents_service._agents.clear()  # noqa: SLF001
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    memberships_service.configure(settings)
    memberships_service.reset_for_tests()
    scan_schedules.configure(settings)
    scan_schedules.reset_for_tests()
    return TestClient(create_app())


def _token(client: TestClient, username: str) -> str:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": f"{username}-change-me"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def _headers(client: TestClient, username: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(client, username)}"}


def _make_tenant(client: TestClient, tenant_id: str) -> None:
    created = client.post(
        "/api/tenants",
        headers=_headers(client, "admin"),
        json={"name": tenant_id, "tenant_id": tenant_id},
    )
    assert created.status_code == 201


def _grant(client: TestClient, username: str, tenant_id: str, role: str = "operator") -> None:
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}",
        headers=_headers(client, "admin"),
        json={"role": role},
    )
    assert granted.status_code == 200


def _seed_asset(tmp_path: Path, *, tenant_id: str, asset_id: str, identifier: str) -> None:
    now = datetime.now(UTC)
    with get_session(_settings(tmp_path).postgres_url) as session:
        session.add(
            models.Asset(
                asset_id=asset_id,
                tenant_id=tenant_id,
                status="active",
                first_seen=now,
                last_seen=now,
            )
        )
        session.add(
            models.AssetIdentifier(
                asset_id=asset_id,
                tenant_id=tenant_id,
                identifier_type="ip",
                identifier_value=identifier,
            )
        )


def _cleanup_assets(tmp_path: Path) -> None:
    with get_session(_settings(tmp_path).postgres_url) as session:
        session.query(models.AssetIdentifier).delete()
        session.query(models.Asset).delete()


# --- membership administration -------------------------------------------------


def test_membership_grant_is_idempotent_and_revocable(client):
    _make_tenant(client, "ten_a")
    admin = _headers(client, "admin")

    _grant(client, "viewer", "ten_a", "viewer")
    _grant(client, "viewer", "ten_a", "operator")  # re-grant updates the role

    members = client.get("/api/tenants/ten_a/members", headers=admin)
    assert members.status_code == 200
    assert members.json() == [
        {
            "username": "viewer",
            "tenant_id": "ten_a",
            "role": "operator",
            "created_at": members.json()[0]["created_at"],
            "created_by": "admin",
        }
    ]

    assert client.delete("/api/tenants/ten_a/members/viewer", headers=admin).status_code == 204
    assert client.delete("/api/tenants/ten_a/members/viewer", headers=admin).status_code == 404
    assert client.get("/api/tenants/ten_a/members", headers=admin).json() == []


def test_membership_administration_is_admin_only(client):
    _make_tenant(client, "ten_a")
    operator = _headers(client, "operator")
    assert client.get("/api/tenants/ten_a/members", headers=operator).status_code == 403
    assert (
        client.put(
            "/api/tenants/ten_a/members/viewer", headers=operator, json={"role": "admin"}
        ).status_code
        == 403
    )


def test_grant_rejects_unknown_tenant_and_bad_role(client):
    admin = _headers(client, "admin")
    _make_tenant(client, "ten_a")
    assert (
        client.put(
            "/api/tenants/ten_missing/members/viewer", headers=admin, json={"role": "viewer"}
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/tenants/ten_a/members/viewer", headers=admin, json={"role": "superuser"}
        ).status_code
        == 422
    )


# --- tenant context resolution -------------------------------------------------


def test_me_reports_tenant_context(client):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "viewer", "ten_b", "viewer")

    me = client.get("/api/auth/me", headers=_headers(client, "viewer")).json()
    assert me["tenants"] == ["ten_b"]
    assert me["default_tenant"] == "ten_b"  # sole membership wins
    assert me["is_platform_admin"] is False

    admin_me = client.get("/api/auth/me", headers=_headers(client, "admin")).json()
    assert admin_me["is_platform_admin"] is True
    assert set(admin_me["tenants"]) >= {"default", "ten_a", "ten_b"}


def test_user_without_memberships_keeps_default_tenant(client):
    """Pre-P0 single-tenant installations must keep working untouched."""
    _make_tenant(client, "ten_a")
    viewer = _headers(client, "viewer")

    assert client.get("/api/assets", headers=viewer).status_code == 200
    assert client.get("/api/assets", headers=viewer, params={"tenant_id": "default"}).status_code == 200
    # …but that fallback is confined to `default`, not a free pass.
    assert client.get("/api/assets", headers=viewer, params={"tenant_id": "ten_a"}).status_code == 403


def test_tenant_list_is_scoped_to_memberships(client):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "operator", "ten_a")

    listed = client.get("/api/tenants", headers=_headers(client, "operator")).json()
    # An MSSP's customer list must not leak to an operator of one customer.
    assert [t["tenant_id"] for t in listed] == ["ten_a"]

    admin_listed = client.get("/api/tenants", headers=_headers(client, "admin")).json()
    assert {t["tenant_id"] for t in admin_listed} >= {"default", "ten_a", "ten_b"}


def test_membership_role_overrides_the_global_role(client):
    """A global viewer granted operator in one tenant may act there — and a
    global operator granted only viewer may not."""
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "viewer", "ten_a", "operator")
    _grant(client, "operator", "ten_b", "viewer")

    started = client.post(
        "/api/jobs",
        headers=_headers(client, "viewer"),
        params={"tenant_id": "ten_a"},
        json={"mode": "safe"},
    )
    assert started.status_code == 202
    assert started.json()["tenant_id"] == "ten_a"

    demoted = client.post(
        "/api/jobs",
        headers=_headers(client, "operator"),
        params={"tenant_id": "ten_b"},
        json={"mode": "safe"},
    )
    assert demoted.status_code == 403


# --- negative cross-tenant access ---------------------------------------------


def test_assets_are_not_readable_across_tenants(client, tmp_path):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "operator", "ten_a")
    _seed_asset(tmp_path, tenant_id="ten_b", asset_id="asset-b", identifier="10.9.9.9")
    operator = _headers(client, "operator")

    try:
        assert client.get("/api/assets", headers=operator, params={"tenant_id": "ten_b"}).status_code == 403
        # Even a direct id lookup: the resolved tenant is ten_a, so it is a miss.
        assert client.get("/api/assets/asset-b", headers=operator).status_code == 404
        assert client.get("/api/assets/asset-b/software", headers=operator).status_code == 404
        assert (
            client.patch(
                "/api/assets/asset-b", headers=operator, json={"business_unit": "hijacked"}
            ).status_code
            == 404
        )
    finally:
        _cleanup_assets(tmp_path)


def test_jobs_are_not_readable_or_startable_across_tenants(client):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "operator", "ten_a")
    admin = _headers(client, "admin")
    operator = _headers(client, "operator")

    other = client.post("/api/jobs", headers=admin, json={"mode": "safe", "tenant_id": "ten_b"})
    assert other.status_code == 202
    other_job_id = other.json()["job_id"]

    # A job in another tenant reads as missing, never as forbidden.
    assert client.get(f"/api/jobs/{other_job_id}", headers=operator).status_code == 404
    listed = client.get("/api/jobs", headers=operator).json()
    assert [j["tenant_id"] for j in listed["items"]] in ([], ["ten_a"])
    assert all(j["job_id"] != other_job_id for j in listed["items"])

    # The body cannot smuggle a foreign tenant past the resolved context.
    assert (
        client.post(
            "/api/jobs", headers=operator, json={"mode": "safe", "tenant_id": "ten_b"}
        ).status_code
        == 403
    )


def test_schedules_are_not_readable_or_mutable_across_tenants(client):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "operator", "ten_a", "admin")
    admin = _headers(client, "admin")
    operator = _headers(client, "operator")

    created = client.post(
        "/api/schedules",
        headers=admin,
        json={"name": "b-nightly", "tenant_id": "ten_b", "interval_seconds": 3600},
    )
    assert created.status_code == 201
    schedule_id = created.json()["schedule_id"]

    assert client.get(f"/api/schedules/{schedule_id}", headers=operator).status_code == 404
    assert (
        client.patch(
            f"/api/schedules/{schedule_id}", headers=operator, json={"enabled": False}
        ).status_code
        == 404
    )
    # Delete requires admin *in the tenant*; the operator holds that in ten_a
    # only, so a ten_b schedule is still out of reach.
    assert client.delete(f"/api/schedules/{schedule_id}", headers=operator).status_code == 404
    assert client.get(f"/api/schedules/{schedule_id}", headers=admin).status_code == 200


def test_agents_and_endpoint_devices_are_tenant_scoped(client):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    _grant(client, "operator", "ten_a")
    operator = _headers(client, "operator")

    from api.services import agents as agents_service

    agents_service.register_agent(
        agent_id="agent-b", hostname="b-worker", version="1", labels={}, tenant_id="ten_b"
    )

    listed = client.get("/api/agents", headers=operator).json()
    assert all(a["tenant_id"] == "ten_a" for a in listed["items"])
    assert client.get("/api/agents", headers=operator, params={"tenant_id": "ten_b"}).status_code == 403
    assert (
        client.get("/api/endpoint/devices", headers=operator, params={"tenant_id": "ten_b"}).status_code
        == 403
    )
    assert (
        client.get("/api/endpoint/changes", headers=operator, params={"tenant_id": "ten_b"}).status_code
        == 403
    )


def test_platform_admin_still_sees_every_tenant(client):
    _make_tenant(client, "ten_a")
    _make_tenant(client, "ten_b")
    admin = _headers(client, "admin")

    for tenant_id in ("ten_a", "ten_b"):
        assert (
            client.post(
                "/api/jobs", headers=admin, json={"mode": "safe", "tenant_id": tenant_id}
            ).status_code
            == 202
        )

    # Unscoped: the pre-P0 fleet-wide view is preserved for platform admins.
    every = client.get("/api/jobs", headers=admin).json()
    assert {j["tenant_id"] for j in every["items"]} >= {"ten_a", "ten_b"}

    # Scoped on request.
    scoped = client.get("/api/jobs", headers=admin, params={"tenant_id": "ten_a"}).json()
    assert {j["tenant_id"] for j in scoped["items"]} == {"ten_a"}


def test_revoking_a_membership_takes_effect_on_the_next_request(client):
    """Tenant context is resolved per request, not baked into the JWT, so a
    revoked membership must not survive in an already-issued token."""
    _make_tenant(client, "ten_a")
    _grant(client, "operator", "ten_a")
    operator = _headers(client, "operator")

    assert client.get("/api/assets", headers=operator, params={"tenant_id": "ten_a"}).status_code == 200
    assert (
        client.delete("/api/tenants/ten_a/members/operator", headers=_headers(client, "admin")).status_code
        == 204
    )
    assert client.get("/api/assets", headers=operator, params={"tenant_id": "ten_a"}).status_code == 403
