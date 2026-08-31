"""Integration tests for OIDC API routes (Sprint 1 IAM)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings


@pytest.fixture
def oidc_settings(monkeypatch):
    monkeypatch.setenv("OCTO_OIDC_ENABLED", "true")
    monkeypatch.setenv("OCTO_OIDC_ISSUER_URL", "https://idp.example.com")
    monkeypatch.setenv("OCTO_OIDC_CLIENT_ID", "shapoclyack-client")
    monkeypatch.setenv("OCTO_OIDC_CLIENT_SECRET", "super-secret-oidc-key")
    monkeypatch.setenv("OCTO_OIDC_REDIRECT_URI", "https://app.example.com/api/auth/oidc/callback")


def test_oidc_config_endpoint(oidc_settings):
    app = create_app()
    client = TestClient(app)

    resp = client.get("/api/auth/oidc/config")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["issuer_url"] == "https://idp.example.com"
    assert data["client_id"] == "shapoclyack-client"


def test_oidc_login_endpoint(oidc_settings):
    app = create_app()
    client = TestClient(app)

    mock_doc = {
        "authorization_endpoint": "https://idp.example.com/protocol/openid-connect/auth",
        "token_endpoint": "https://idp.example.com/protocol/openid-connect/token",
    }

    with patch("api.services.oidc.fetch_discovery_document", return_value=mock_doc):
        resp = client.get("/api/auth/oidc/login?redirect_to=/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_url" in data
        assert "state" in data
        assert "https://idp.example.com/protocol/openid-connect/auth" in data["authorization_url"]


def test_oidc_callback_flow(oidc_settings):
    app = create_app()
    client = TestClient(app)

    mock_claims = {
        "sub": "oidc-user-12345",
        "email": "secops@example.com",
        "preferred_username": "secops_user",
        "roles": ["operator"],
    }

    state = "valid-test-state"
    with (
        patch("api.services.oidc.verify_state", return_value={"redirect_to": "/"}),
        patch("api.services.oidc.exchange_code", return_value=mock_claims),
    ):
        resp = client.get(f"/api/auth/oidc/callback?code=mock-auth-code&state={state}")
        assert resp.status_code == 200
        token_data = resp.json()
        assert "access_token" in token_data
        assert token_data["username"] == "secops_user"
        assert token_data["role"] == "operator"
