from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    """Load a golden fixture, stamping ``collected_at`` to "now" — the fixture
    content is the shared schema-v1 contract; the timestamp only needs to
    satisfy the max-snapshot-age/future-skew bounds at request time."""
    body = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    if "collected_at" in body:
        body["collected_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return body


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    base = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        agent_token="test-agent-token",
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

    from api.services import endpoint_inventory as endpoint_inventory_service
    from api.services import tenants as tenants_service

    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    endpoint_inventory_service.configure(settings)
    endpoint_inventory_service.reset_for_tests()
    return TestClient(create_app())


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def _operator_token(client: TestClient) -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-change-me"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_valid_snapshot_returns_201(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = _load_fixture("endpoint_inventory_v1_valid.json")
    resp = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert resp.status_code == 201
    data = resp.json()
    assert data["snapshot_id"] == body["snapshot_id"]
    assert data["software_count"] == 2
    assert data["changes"] == {"installed": 0, "removed": 0, "updated": 0}


def test_replay_same_payload_returns_200(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = _load_fixture("endpoint_inventory_v1_valid.json")
    first = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert first.status_code == 201
    second = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert second.status_code == 200
    assert second.json()["snapshot_id"] == body["snapshot_id"]


def test_same_snapshot_id_different_content_returns_409(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = _load_fixture("endpoint_inventory_v1_valid.json")
    first = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert first.status_code == 201
    mutated = dict(body)
    mutated["hostname"] = "renamed.example.internal"
    second = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=mutated)
    assert second.status_code == 409


def test_unsupported_schema_version_returns_422(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = _load_fixture("endpoint_inventory_v1_invalid.json")
    resp = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert resp.status_code == 422


def test_oversized_software_list_returns_413(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, endpoint_inventory_max_software_items=1)
    body = _load_fixture("endpoint_inventory_v1_valid.json")
    resp = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert resp.status_code == 413


def test_missing_auth_returns_401(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = _load_fixture("endpoint_inventory_v1_valid.json")
    resp = client.post("/api/endpoint/inventory", json=body)
    assert resp.status_code == 401


def test_read_endpoints_require_viewer_role_and_are_tenant_scoped(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    body = _load_fixture("endpoint_inventory_v1_valid.json")
    submit = client.post("/api/endpoint/inventory", headers=_agent_headers(), json=body)
    assert submit.status_code == 201
    device_id = submit.json()["device_id"]
    asset_id = submit.json()["asset_id"]

    unauth = client.get("/api/endpoint/devices", params={"tenant_id": "default"})
    assert unauth.status_code == 401

    token = _operator_token(client)
    headers = {"Authorization": f"Bearer {token}"}

    listed = client.get("/api/endpoint/devices", headers=headers, params={"tenant_id": "default"})
    assert listed.status_code == 200
    assert any(d["device_id"] == device_id for d in listed.json())

    listed_other_tenant = client.get(
        "/api/endpoint/devices", headers=headers, params={"tenant_id": "ten_missing"}
    )
    assert listed_other_tenant.status_code == 200
    assert listed_other_tenant.json() == []

    detail = client.get(f"/api/endpoint/devices/{device_id}", headers=headers, params={"tenant_id": "default"})
    assert detail.status_code == 200
    assert detail.json()["hostname"] == body["hostname"]

    snapshots = client.get(
        f"/api/endpoint/devices/{device_id}/snapshots", headers=headers, params={"tenant_id": "default"}
    )
    assert snapshots.status_code == 200
    assert len(snapshots.json()) == 1

    software = client.get(
        f"/api/assets/{asset_id}/software", headers=headers, params={"tenant_id": "default"}
    )
    assert software.status_code == 200
    assert len(software.json()) == 2
