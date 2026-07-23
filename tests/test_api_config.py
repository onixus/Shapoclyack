"""Route-level tests for the editable configurator (GET/PUT /api/config)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.app import create_app
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _client() -> TestClient:
    return TestClient(create_app())


def _token(client: TestClient, username: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_get_config_shape():
    client = _client()
    headers = {"Authorization": f"Bearer {_token(client, 'viewer', 'viewer-change-me')}"}
    r = client.get("/api/config", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert "nuclei.enabled" in body["editable_paths"]
    assert "profiles.balanced.top_ports" in body["editable_paths"]
    assert isinstance(body["defaults"], dict)
    assert isinstance(body["effective"], dict)


def test_viewer_cannot_update():
    client = _client()
    headers = {"Authorization": f"Bearer {_token(client, 'viewer', 'viewer-change-me')}"}
    r = client.put("/api/config", headers=headers, json={"overrides": {"nuclei.enabled": True}})
    assert r.status_code == 403


def test_admin_update_and_reset():
    client = _client()
    headers = {"Authorization": f"Bearer {_token(client, 'admin', 'admin-change-me')}"}

    # Apply an override — effective flips, overrides records it.
    r = client.put("/api/config", headers=headers, json={"overrides": {"nuclei.enabled": True}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["effective"]["nuclei.enabled"] is True
    assert body["overrides"]["nuclei.enabled"] is True

    # Reset clears overrides; effective returns to the base default.
    r = client.put("/api/config", headers=headers, json={"overrides": {}})
    assert r.status_code == 200
    assert r.json()["overrides"] == {}


def test_admin_update_rejects_invalid():
    client = _client()
    headers = {"Authorization": f"Bearer {_token(client, 'admin', 'admin-change-me')}"}
    # Non-editable path.
    r = client.put("/api/config", headers=headers, json={"overrides": {"discovery.asn.enabled": True}})
    assert r.status_code == 422
    # Out-of-range value.
    r = client.put("/api/config", headers=headers, json={"overrides": {"profiles.safe.top_ports": 0}})
    assert r.status_code == 422
