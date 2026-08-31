"""Integration tests for service_tokens API routes (Sprint 1 IAM)."""

from __future__ import annotations

from pathlib import Path
import pytest

from api.auth import Role, TokenUser, create_access_token
from api.settings import load_settings
from tests.conftest import TEST_JWT_SECRET, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    settings = make_settings(tmp_path)
    return configured_client(tmp_path, monkeypatch, settings=settings)


@pytest.fixture
def admin_headers():
    settings = load_settings()
    settings.jwt_secret = TEST_JWT_SECRET
    user = TokenUser(username="admin", role=Role.admin)
    token = create_access_token(settings, user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def operator_headers():
    settings = load_settings()
    settings.jwt_secret = TEST_JWT_SECRET
    user = TokenUser(username="operator", role=Role.operator)
    token = create_access_token(settings, user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    settings = load_settings()
    settings.jwt_secret = TEST_JWT_SECRET
    user = TokenUser(username="viewer", role=Role.viewer)
    token = create_access_token(settings, user)
    return {"Authorization": f"Bearer {token}"}


def test_get_available_scopes(client, viewer_headers):
    resp = client.get("/api/service-tokens/scopes", headers=viewer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "scopes" in data
    assert "scans:read" in data["scopes"]
    assert "vulns:manage" in data["scopes"] or "vulns:write" in data["scopes"]


def test_service_token_crud_flow(client, operator_headers, viewer_headers, admin_headers):
    # 1. Viewer cannot create tokens
    resp = client.post(
        "/api/service-tokens",
        headers=viewer_headers,
        json={"name": "Viewer attempt", "role": "viewer"},
    )
    assert resp.status_code == 403

    # 2. Operator cannot create admin token
    resp = client.post(
        "/api/service-tokens",
        headers=operator_headers,
        json={"name": "Operator escalating", "role": "admin"},
    )
    assert resp.status_code == 403

    # 3. Operator creates valid operator token
    resp = client.post(
        "/api/service-tokens",
        headers=operator_headers,
        json={
            "name": "Pipeline Scraper",
            "role": "operator",
            "scopes": ["scans:read", "scans:write"],
            "expires_days": 60,
        },
    )
    assert resp.status_code == 201
    token_data = resp.json()
    assert "token" in token_data
    assert token_data["token"].startswith("shk_")
    token_str = token_data["token"]
    token_id = token_data["id"]

    # 4. List tokens
    resp = client.get("/api/service-tokens", headers=viewer_headers)
    assert resp.status_code == 200
    tokens = resp.json()
    assert any(t["id"] == token_id for t in tokens)

    # 5. Use the created service token to call an authenticated endpoint
    service_headers = {"Authorization": f"Bearer {token_str}"}
    scopes_resp = client.get("/api/service-tokens/scopes", headers=service_headers)
    assert scopes_resp.status_code == 200

    # 6. Revoke token
    del_resp = client.delete(f"/api/service-tokens/{token_id}", headers=operator_headers)
    assert del_resp.status_code == 200

    # 7. Revoked token fails authentication
    failed_resp = client.get("/api/service-tokens/scopes", headers=service_headers)
    assert failed_resp.status_code == 401

