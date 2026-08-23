"""Security hardening and defensive middleware tests."""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.core import security
from api.settings import Settings


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
