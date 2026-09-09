"""Security hardening and defensive middleware tests."""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.core import security
from api.settings import Settings
from tests.conftest import configured_client, requires_postgres


def test_security_headers_middleware():
    """Verify that all defensive security headers are injected."""
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-xss-protection") == "1; mode=block"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in (headers.get("permissions-policy") or "")
    assert headers.get("cross-origin-opener-policy") == "same-origin"
    assert "default-src 'self'" in (headers.get("content-security-policy") or "")


@requires_postgres
def test_hsts_header_follows_the_configured_flag(tmp_path, monkeypatch):
    """#224: the header existed in the middleware but nothing could turn it on —
    ``enable_hsts`` defaulted to False and the app constructed the middleware
    with no arguments, so it was never sent in any deployment."""
    client = configured_client(tmp_path, monkeypatch, hsts_enabled=True)
    headers = client.get("/api/health").headers
    assert headers.get("strict-transport-security") == "max-age=31536000; includeSubDomains"


@requires_postgres
def test_hsts_header_absent_when_disabled(tmp_path, monkeypatch):
    """Off in dev on purpose: a browser that picks up the header on
    http://localhost pins itself to HTTPS for a year."""
    client = configured_client(tmp_path, monkeypatch, hsts_enabled=False)
    assert "strict-transport-security" not in client.get("/api/health").headers


@requires_postgres
def test_interactive_schema_is_not_served_in_prod_configuration(tmp_path, monkeypatch):
    """#319: the app was built with FastAPI's defaults, so `/docs` and
    `/openapi.json` handed the full map of the API — every route, parameter and
    response field — to anyone who could reach an installation."""
    client = configured_client(tmp_path, monkeypatch, api_docs_enabled=False)

    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path


@requires_postgres
def test_interactive_schema_is_served_when_enabled(tmp_path, monkeypatch):
    """The default under `OCTO_ENV=dev`: turning it off must be a setting, not
    the removal of the feature."""
    client = configured_client(tmp_path, monkeypatch, api_docs_enabled=True)

    assert client.get("/docs").status_code == 200
    assert "/api/health" in client.get("/openapi.json").json()["paths"]


@requires_postgres
def test_metrics_require_the_configured_bearer_token(tmp_path, monkeypatch):
    """#319: with `OCTO_METRICS_TOKEN` set, the series — every route, the queue
    depth and login outcomes — stop being readable by an unauthenticated
    caller. A wrong token is refused the same way a missing one is."""
    client = configured_client(tmp_path, monkeypatch, metrics_token="metrics-secret")

    unauthenticated = client.get("/metrics")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers.get("www-authenticate") == "Bearer"
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": "metrics-secret"}).status_code == 401

    authorized = client.get("/metrics", headers={"Authorization": "Bearer metrics-secret"})
    assert authorized.status_code == 200
    assert "octo_http_requests_total" in authorized.text


@requires_postgres
def test_metrics_stay_open_without_a_token(tmp_path, monkeypatch):
    """Unset keeps the documented Prometheus shape: an upgrade must not break
    a ServiceMonitor that scrapes from inside the cluster."""
    client = configured_client(tmp_path, monkeypatch, metrics_token="")
    assert client.get("/metrics").status_code == 200


def test_jwt_algorithm_whitelist_enforcement():
    """Verify that insecure algorithms like 'none' are rejected."""
    claims = {"sub": "testuser", "role": "admin"}
    secret = "test-secret-12345678-abcdef-12345678"

    # Allowed algorithms work
    token = security.encode_jwt(claims, secret=secret, algorithm="HS256")
    decoded = security.decode_jwt(token, secret=secret, algorithm="HS256")
    assert decoded["sub"] == "testuser"

    # Insecure 'none' algorithm is rejected
    with pytest.raises(ValueError, match="Insecure or unsupported JWT algorithm"):
        security.encode_jwt(claims, secret="", algorithm="none")

    with pytest.raises(ValueError, match="Insecure or unsupported JWT algorithm"):
        security.decode_jwt(token, secret=secret, algorithm="none")

    with pytest.raises(ValueError, match="Insecure or unsupported JWT algorithm"):
        security.decode_jwt(token, secret=secret, algorithm="UNSUPPORTED_ALGO")


def test_artifact_path_traversal_prevention(tmp_path: Path):
    """Verify that path traversal attempts on run artifacts fail closed."""
    from api.services.runs import resolve_artifact

    run_dir = tmp_path / "runs" / "run-safe"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "safe.json").write_text("{}", encoding="utf-8")

    settings = Settings(output_dir=tmp_path)

    # Safe path resolves
    resolved = resolve_artifact(settings, "run-safe", "safe.json")
    assert resolved is not None
    assert resolved.name == "safe.json"

    # Directory traversal attempts return None
    assert resolve_artifact(settings, "run-safe", "../../../etc/passwd") is None
    assert resolve_artifact(settings, "run-safe", "..\\..\\windows\\system32") is None
    assert resolve_artifact(settings, "run-safe", "/etc/shadow") is None
    assert resolve_artifact(settings, "run-safe", "sub/../../secret.txt") is None
