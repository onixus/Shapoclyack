"""Security controls that no single feature test owns.

The suite already covers tenant isolation (test_tenancy.py, test_tenant_iam.py)
and artifact path traversal (test_api_runs.py). What was missing is the layer
underneath those: whether a token has to be *genuine* to be honoured at all,
whether every protected route actually refuses an anonymous caller, and whether
the read-only surfaces leak the secrets they are documented not to expose.

These are negative tests by construction. Each one asserts that a specific
attack does not work, so a regression shows up as a test that stops failing the
attack — not as a feature that stops working.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from tests.conftest import (
    TEST_JWT_SECRET,
    api_client,
    auth_headers,
    bearer,
    configured_client,
    login,
    requires_postgres,
)

pytestmark = requires_postgres


def _forge(payload: dict, *, secret: str = TEST_JWT_SECRET, algorithm: str = "HS256") -> str:
    """Mint a token directly, bypassing the API, to test what the decoder accepts."""
    base = {
        "sub": "viewer",
        "role": "viewer",
        "typ": "user",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=30),
    }
    base.update(payload)
    return jwt.encode(base, secret, algorithm=algorithm)


# --------------------------------------------------------------------------
# Token integrity
# --------------------------------------------------------------------------


def test_tampered_signature_is_rejected(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    token = login(client, "viewer")
    header, payload, signature = token.split(".")
    # Flip one character of the signature; the header and claims stay valid, so
    # this passes any check that parses the token without verifying it.
    #
    # Flip the *first* character, not the last: base64url of a 32-byte HS256
    # signature is 43 characters, whose final character carries only 2
    # significant bits, so four different characters there decode to the same
    # signature bytes. Editing it produced a still-valid token roughly one run
    # in sixteen, and the assertion below failed with no tampering having
    # happened.
    flipped = "A" if signature[0] != "A" else "B"
    forged = f"{header}.{payload}.{flipped}{signature[1:]}"

    response = client.get("/api/auth/me", headers=bearer(forged))
    assert response.status_code == 401


def test_token_signed_with_another_secret_is_rejected(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    forged = _forge({"role": "admin"}, secret="not-the-configured-secret")

    response = client.get("/api/auth/me", headers=bearer(forged))
    assert response.status_code == 401


def test_role_cannot_be_escalated_by_editing_the_payload(tmp_path, monkeypatch):
    """The whole point of signing: an attacker holding a valid viewer token
    cannot promote themselves by rewriting the role claim."""
    client = configured_client(tmp_path, monkeypatch)
    viewer = login(client, "viewer")
    header, _payload, signature = viewer.split(".")
    admin_claims = _forge({"role": "admin"}).split(".")[1]
    forged = f"{header}.{admin_claims}.{signature}"

    response = client.get("/api/auth/me", headers=bearer(forged))
    assert response.status_code == 401


def test_expired_token_is_rejected(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    expired = _forge(
        {
            "iat": datetime.now(UTC) - timedelta(hours=2),
            "exp": datetime.now(UTC) - timedelta(hours=1),
        }
    )

    response = client.get("/api/auth/me", headers=bearer(expired))
    assert response.status_code == 401


def test_unsigned_alg_none_token_is_rejected(tmp_path, monkeypatch):
    """The classic JWT bypass: claim `alg: none` and send no signature. The
    decoder pins `algorithms=[settings.jwt_algorithm]`, so it must not be
    talked out of verifying."""
    client = configured_client(tmp_path, monkeypatch)
    unsigned = jwt.encode(
        {
            "sub": "admin",
            "role": "admin",
            "typ": "user",
            "exp": datetime.now(UTC) + timedelta(minutes=30),
        },
        key="",
        algorithm="none",
    )

    response = client.get("/api/auth/me", headers=bearer(unsigned))
    assert response.status_code == 401


def test_token_with_unknown_role_is_rejected(tmp_path, monkeypatch):
    """A correctly signed token is still not a licence to invent a role."""
    client = configured_client(tmp_path, monkeypatch)
    forged = _forge({"role": "superadmin"})

    response = client.get("/api/auth/me", headers=bearer(forged))
    assert response.status_code == 401


def test_token_without_subject_or_role_is_rejected(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    for missing in ({"sub": ""}, {"role": ""}):
        response = client.get("/api/auth/me", headers=bearer(_forge(missing)))
        assert response.status_code == 401, missing


@pytest.mark.parametrize("scheme", ["", "Basic ", "Token "])
def test_non_bearer_authorization_schemes_are_rejected(tmp_path, monkeypatch, scheme):
    client = configured_client(tmp_path, monkeypatch)
    token = login(client, "viewer")

    response = client.get("/api/auth/me", headers={"Authorization": f"{scheme}{token}"})
    assert response.status_code == 401


# --------------------------------------------------------------------------
# Token type confusion (user tokens vs. agent tokens)
# --------------------------------------------------------------------------


def test_agent_token_cannot_be_used_on_operator_apis(tmp_path, monkeypatch):
    """Agent JWTs are minted from a provisioning key, which an agent host holds
    on disk. They must not double as console credentials."""
    client = configured_client(tmp_path, monkeypatch)
    agent_token = _forge({"typ": "agent", "tenant_id": "default", "role": "admin"})

    response = client.get("/api/auth/me", headers=bearer(agent_token))
    assert response.status_code == 401


def test_user_token_cannot_claim_agent_endpoints(tmp_path, monkeypatch):
    """The mirror case: a console token, even an admin's, is not an agent."""
    client = configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", agent_token=""
    )
    admin = login(client, "admin")

    response = client.post(
        "/api/agent/heartbeat",
        headers=bearer(admin),
        json={"agent_id": "a1", "status": "idle"},
    )
    assert response.status_code in (401, 403)


def test_agent_token_without_tenant_is_rejected(tmp_path, monkeypatch):
    """tenant_id is what scopes every agent operation; a token missing it must
    not fall back to a default tenant."""
    client = configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", agent_token=""
    )
    # Built without the _forge default claims: the point is the *absence* of
    # tenant_id, which a merge over the defaults would quietly reintroduce.
    no_tenant = jwt.encode(
        {
            "sub": "agent-1",
            "typ": "agent",
            "exp": datetime.now(UTC) + timedelta(minutes=30),
        },
        TEST_JWT_SECRET,
        algorithm="HS256",
    )

    response = client.post(
        "/api/agent/heartbeat",
        headers=bearer(no_tenant),
        json={"agent_id": "agent-1", "status": "idle"},
    )
    assert response.status_code == 401


# --------------------------------------------------------------------------
# Anonymous access
# --------------------------------------------------------------------------


PROTECTED_ENDPOINTS = [
    ("GET", "/api/runs"),
    ("GET", "/api/jobs"),
    ("GET", "/api/assets"),
    ("GET", "/api/agents"),
    ("GET", "/api/schedules"),
    ("GET", "/api/config"),
    ("GET", "/api/system"),
    ("GET", "/api/auth/me"),
    ("POST", "/api/jobs"),
    ("POST", "/api/schedules"),
]


@pytest.mark.parametrize("method, path", PROTECTED_ENDPOINTS)
def test_protected_endpoints_reject_anonymous_callers(method, path):
    """Enumerated rather than spot-checked: a new route that forgets its
    dependency is the failure mode this catches."""
    client = api_client()
    response = client.request(method, path, json={} if method == "POST" else None)
    assert response.status_code == 401, f"{method} {path} answered {response.status_code}"


# --------------------------------------------------------------------------
# Authorization: roles
# --------------------------------------------------------------------------


VIEWER_FORBIDDEN = [
    ("POST", "/api/jobs", {"mode": "balanced"}),
    ("POST", "/api/schedules", {"name": "x", "interval_seconds": 3600}),
    ("PUT", "/api/config", {"overrides": {}}),
]


@pytest.mark.parametrize("method, path, body", VIEWER_FORBIDDEN)
def test_viewer_cannot_mutate(method, path, body):
    client = api_client()
    response = client.request(method, path, headers=auth_headers(client, "viewer"), json=body)
    assert response.status_code == 403, f"{method} {path} answered {response.status_code}"


def test_operator_cannot_reach_admin_only_surfaces():
    """Operator is the busiest role, so the admin boundary above it is the one
    most likely to erode."""
    client = api_client()
    headers = auth_headers(client, "operator")

    created = client.post("/api/tenants", headers=headers, json={"name": "acme"})
    assert created.status_code == 403

    updated = client.put("/api/config", headers=headers, json={"overrides": {}})
    assert updated.status_code == 403


# --------------------------------------------------------------------------
# Secret exposure
# --------------------------------------------------------------------------


SECRET_MARKERS = ["test-secret", "test-agent-token", "change-me", "octo-ci-secret"]


def test_system_status_exposes_no_secrets(tmp_path, monkeypatch):
    """docs say /api/system reports configuration *presence*, never values.
    Asserted over the whole serialized body so a newly added field is covered
    without anyone remembering to extend this test."""
    client = configured_client(tmp_path, monkeypatch)
    response = client.get("/api/system", headers=auth_headers(client, "admin"))
    assert response.status_code == 200

    body = response.text
    for marker in SECRET_MARKERS:
        assert marker not in body, f"/api/system leaked {marker!r}"
    for key in ("jwt_secret", "agent_token", "password", "postgres_url"):
        assert key not in body, f"/api/system exposed field {key!r}"


def test_configured_secret_reads_back_masked(tmp_path, monkeypatch):
    """The NVD API key is write-only by design: the UI shows a mask, and the
    plaintext must never come back out of the read endpoint."""
    from api.services.config_override import SECRET_MASK

    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")

    stored = client.put(
        "/api/config",
        headers=headers,
        json={"overrides": {"enrichment.cvss4.nvd_api_key": "super-secret-key"}},
    )
    assert stored.status_code == 200, stored.text

    read_back = client.get("/api/config", headers=headers)
    assert read_back.status_code == 200
    assert "super-secret-key" not in read_back.text
    assert SECRET_MASK in read_back.text


def test_login_does_not_reveal_whether_a_username_exists():
    """Identical status and body for an unknown user and a wrong password —
    otherwise the login form is a user-enumeration oracle."""
    client = api_client()

    unknown = client.post(
        "/api/auth/login", json={"username": "no-such-user", "password": "whatever"}
    )
    wrong_password = client.post(
        "/api/auth/login", json={"username": "viewer", "password": "wrong"}
    )

    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json() == wrong_password.json()


def test_token_response_carries_no_password_material():
    client = api_client()
    response = client.post(
        "/api/auth/login", json={"username": "viewer", "password": "viewer-change-me"}
    )
    assert response.status_code == 200
    assert "viewer-change-me" not in response.text
    for field in ("password", "password_hash", "hash"):
        assert field not in response.json()
