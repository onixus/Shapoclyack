"""Route-level tests for the read-only GET /api/system status endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.app import create_app
from api.auth import get_settings
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _client() -> TestClient:
    return TestClient(create_app())


def _token(client: TestClient, username: str = "viewer", password: str = "viewer-change-me") -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_system_status_shape():
    client = _client()
    token = _token(client)
    response = client.get("/api/system", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()

    assert isinstance(body["app_version"], str) and body["app_version"]

    tool_names = {tool["name"] for tool in body["tools"]}
    assert tool_names == {"nmap", "naabu", "nuclei", "dnsx"}
    # Fail-soft: a tool absent from the CI runner reports version=None + an error
    # string rather than 500-ing the endpoint.
    for tool in body["tools"]:
        assert tool["version"] is not None or tool["error"] is not None

    enrichment_names = {db["name"] for db in body["enrichment"]}
    assert enrichment_names == {"epss", "kev", "geoip", "cvss4", "asn"}

    assert set(body["scan_config"]["stages"]) >= {"fingerprint", "tls_posture", "nuclei", "pdf_summary"}
    assert "balanced" in body["scan_config"]["profiles"]

    runtime = body["runtime"]
    assert isinstance(runtime["postgres_enabled"], bool)
    assert isinstance(runtime["job_execution_mode"], str)


def test_system_status_leaks_no_secrets():
    client = _client()
    token = _token(client)
    response = client.get("/api/system", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    raw = response.text

    settings = get_settings()
    # The runtime block reports only booleans/counts — never the actual URLs
    # (which embed the Postgres password) or the JWT secret.
    if settings.postgres_url:
        assert settings.postgres_url not in raw
    assert settings.jwt_secret not in raw


def test_system_status_requires_auth():
    client = _client()
    assert client.get("/api/system").status_code == 401


def test_system_status_reflects_config_overrides():
    """A saved override for an editable stage must show up in the Pipeline
    Stages panel, not just in GET /config -- system_status previously read
    only the base YAML file and silently ignored the overrides table."""
    client = _client()
    admin_token = _token(client, "admin", "admin-change-me")
    headers = {"Authorization": f"Bearer {admin_token}"}

    put_response = client.put(
        "/api/config",
        json={"overrides": {"fingerprint.enabled": True, "tls_posture.enabled": True}},
        headers=headers,
    )
    assert put_response.status_code == 200
    try:
        stages = client.get("/api/system", headers=headers).json()["scan_config"]["stages"]
        assert stages["fingerprint"] is True
        assert stages["tls_posture"] is True
        # Untouched stages are still read straight from the base file.
        assert stages["nuclei"] is False
    finally:
        client.put("/api/config", json={"overrides": {}}, headers=headers)
