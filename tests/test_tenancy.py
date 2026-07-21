"""Phase 2 MSSP tenancy: provisioning keys, agent JWT, cross-tenant isolation."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        allow_scan_start=True,
        job_execution_mode="agent",
        agent_token="",  # JWT-only mode
        agent_stale_seconds=120,
        agent_jwt_expire_minutes=30,
        jwt_secret="test-secret",
        postgres_url=POSTGRES_URL,
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    settings = _settings(tmp_path, **overrides)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    jobs_service._JOBS.clear()  # noqa: SLF001
    agents_service._agents.clear()  # noqa: SLF001
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    return TestClient(create_app())


def _login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_create_tenant_and_provisioning_key_exchange(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = _login(client, "admin", "admin-change-me")

    created = client.post(
        "/api/tenants",
        headers={"Authorization": f"Bearer {admin}"},
        json={"name": "Acme MSSP", "tenant_id": "ten_acme"},
    )
    assert created.status_code == 201
    assert created.json()["tenant_id"] == "ten_acme"

    key = client.post(
        "/api/tenants/ten_acme/provisioning-keys",
        headers={"Authorization": f"Bearer {admin}"},
        json={"label": "edge-lab"},
    )
    assert key.status_code == 201
    plaintext = key.json()["key"]
    assert plaintext.startswith("octo-pk-")
    key_id = key.json()["key_id"]

    listed = client.get(
        "/api/tenants/ten_acme/provisioning-keys",
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert listed.status_code == 200
    assert listed.json()[0]["key"] is None  # plaintext only on create
    assert listed.json()[0]["key_id"] == key_id

    token = client.post("/api/auth/agent/token", json={"provisioning_key": plaintext})
    assert token.status_code == 200
    body = token.json()
    assert body["tenant_id"] == "ten_acme"
    assert body["key_id"] == key_id
    assert body["access_token"]

    reg = client.post(
        "/api/agent/register",
        headers={"Authorization": f"Bearer {body['access_token']}"},
        json={"hostname": "edge-1"},
    )
    assert reg.status_code == 200
    assert reg.json()["tenant_id"] == "ten_acme"


def test_cross_tenant_claim_denied(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, agent_token="legacy-shared")
    admin = _login(client, "admin", "admin-change-me")
    operator = _login(client, "operator", "operator-change-me")

    client.post(
        "/api/tenants",
        headers={"Authorization": f"Bearer {admin}"},
        json={"name": "A", "tenant_id": "ten_a"},
    )
    client.post(
        "/api/tenants",
        headers={"Authorization": f"Bearer {admin}"},
        json={"name": "B", "tenant_id": "ten_b"},
    )
    key_a = client.post(
        "/api/tenants/ten_a/provisioning-keys",
        headers={"Authorization": f"Bearer {admin}"},
        json={},
    ).json()["key"]
    key_b = client.post(
        "/api/tenants/ten_b/provisioning-keys",
        headers={"Authorization": f"Bearer {admin}"},
        json={},
    ).json()["key"]

    jwt_a = client.post("/api/auth/agent/token", json={"provisioning_key": key_a}).json()["access_token"]
    jwt_b = client.post("/api/auth/agent/token", json={"provisioning_key": key_b}).json()["access_token"]

    agent_a = client.post(
        "/api/agent/register",
        headers={"Authorization": f"Bearer {jwt_a}"},
        json={"hostname": "a"},
    ).json()["agent_id"]
    agent_b = client.post(
        "/api/agent/register",
        headers={"Authorization": f"Bearer {jwt_b}"},
        json={"hostname": "b"},
    ).json()["agent_id"]

    job = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {operator}"},
        json={"mode": "safe", "tenant_id": "ten_a"},
    )
    assert job.status_code == 202
    assert job.json()["tenant_id"] == "ten_a"
    job_id = job.json()["job_id"]

    # Tenant B agent must not claim tenant A job.
    denied = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_b}&job_id={job_id}",
        headers={"Authorization": f"Bearer {jwt_b}"},
    )
    assert denied.status_code == 204

    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_a}&job_id={job_id}",
        headers={"Authorization": f"Bearer {jwt_a}"},
    )
    assert claimed.status_code == 200
    assert claimed.json()["tenant_id"] == "ten_a"


def test_revoked_provisioning_key_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = _login(client, "admin", "admin-change-me")
    client.post(
        "/api/tenants",
        headers={"Authorization": f"Bearer {admin}"},
        json={"name": "X", "tenant_id": "ten_x"},
    )
    created = client.post(
        "/api/tenants/ten_x/provisioning-keys",
        headers={"Authorization": f"Bearer {admin}"},
        json={},
    ).json()
    client.post(
        f"/api/tenants/ten_x/provisioning-keys/{created['key_id']}/revoke",
        headers={"Authorization": f"Bearer {admin}"},
    )
    bad = client.post("/api/auth/agent/token", json={"provisioning_key": created["key"]})
    assert bad.status_code == 401


def test_operator_cannot_create_tenant(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    operator = _login(client, "operator", "operator-change-me")
    response = client.post(
        "/api/tenants",
        headers={"Authorization": f"Bearer {operator}"},
        json={"name": "Nope"},
    )
    assert response.status_code == 403
