"""Operator settings integration: egress opt-in and honest public status."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth import get_settings
from api.routes.local_operator import operator_principal, router
from api.settings import InsecureConfigurationError, Settings, load_settings
from api.settings_cli import redacted_settings


@pytest.fixture
def clean_operator_env(monkeypatch):
    import os

    for key in os.environ:
        if key.startswith("OCTO_OPERATOR_") or key.startswith("OCTO_MCP_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("OCTO_ENV", "dev")
    return monkeypatch


def test_default_loader_never_enables_inference_or_mcp(clean_operator_env):
    settings = load_settings()
    assert not settings.operator_enabled
    assert not settings.operator_allow_external
    assert settings.operator_provider == "local"
    assert not settings.mcp_enabled


@pytest.mark.parametrize("name,value", [
    ("OCTO_OPERATOR_WORKER_LEASE_SECONDS", "120"),
    ("OCTO_OPERATOR_WORKER_POLL_SECONDS", "nan"),
    ("OCTO_OPERATOR_QUEUE_LIMIT", "101"),
])
def test_loader_refuses_unsafe_worker_limits(clean_operator_env, name, value):
    clean_operator_env.setenv("OCTO_OPERATOR_ENABLED", "true")
    clean_operator_env.setenv("OCTO_OPERATOR_WORKER_ENABLED", "true")
    clean_operator_env.setenv(name, value)
    with pytest.raises(InsecureConfigurationError, match="worker configuration"):
        load_settings()


def test_hosted_loader_needs_explicit_egress_permission(clean_operator_env):
    clean_operator_env.setenv("OCTO_OPERATOR_ENABLED", "true")
    clean_operator_env.setenv("OCTO_OPERATOR_PROVIDER", "openrouter")
    clean_operator_env.setenv("OCTO_OPERATOR_API_KEY", "provider-secret")
    with pytest.raises(InsecureConfigurationError):
        load_settings()
    clean_operator_env.setenv("OCTO_OPERATOR_ALLOW_EXTERNAL", "true")
    settings = load_settings()
    assert settings.operator_enabled
    assert settings.operator_provider == "openrouter"
    assert "provider-secret" not in json.dumps(redacted_settings(settings))
    assert "provider-secret" not in repr(settings)


def test_loader_binds_mcp_origins(clean_operator_env):
    clean_operator_env.setenv("OCTO_MCP_ENABLED", "true")
    clean_operator_env.setenv(
        "OCTO_MCP_ALLOWED_ORIGINS", "https://console.example, https://other.example"
    )
    settings = load_settings()
    assert settings.mcp_enabled
    assert settings.mcp_allowed_origins == [
        "https://console.example",
        "https://other.example",
    ]


def _client(settings):
    app = FastAPI()
    app.include_router(router, prefix="/api")
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[operator_principal] = lambda: SimpleNamespace(
        tenant_id="tenant-a"
    )
    return TestClient(app)


def test_status_does_not_claim_model_readiness_or_expose_credentials():
    settings = Settings(operator_enabled=True, operator_api_key="never-show-me")
    with _client(settings) as client:
        response = client.get("/api/operator/status")
    assert response.status_code == 200
    body = response.json()
    assert body["runtime_status"] == "not_checked"
    assert body["analysis_available"] is False
    assert body["durable_sessions_available"] is True
    assert body["quality_status"] == "quality_unverified"
    assert "never-show-me" not in response.text
    assert "base_url" not in body


def test_disabled_and_misconfigured_states_are_distinct():
    with _client(Settings()) as client:
        assert client.get("/api/operator/status").status_code == 404
    with _client(
        Settings(operator_enabled=True, operator_provider="unknown")
    ) as client:
        assert client.get("/api/operator/status").status_code == 503


def test_status_requires_authentication():
    app = FastAPI()
    app.include_router(router, prefix="/api")
    app.dependency_overrides[get_settings] = lambda: Settings(operator_enabled=True)
    with TestClient(app) as client:
        assert client.get("/api/operator/status").status_code in (401, 403)
