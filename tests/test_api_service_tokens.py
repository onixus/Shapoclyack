"""Service tokens end to end: issue, authenticate, scope, revoke, expire.

Postgres-gated like the rest of the API suite (the store is a table). What is
asserted here is the part that cannot be asserted from the scope algebra alone:
that a presented token really does authenticate, really is confined to its
tenant and role, and really stops working the moment it is revoked or expires.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import service_tokens
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    return client, settings, admin


def issue(client, admin, **body):
    payload = {"name": "ci", "scopes": ["runs:read"], "role": "viewer", **body}
    tenant_id = payload.pop("tenant_id", "default")
    response = client.post(
        f"/api/tenants/{tenant_id}/service-tokens", headers=admin, json=payload
    )
    assert response.status_code == 201, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# Issue
# --------------------------------------------------------------------------- #


def test_create_returns_the_plaintext_exactly_once(env):
    client, _settings, admin = env
    created = issue(client, admin)
    plaintext = created["token"]
    assert plaintext.startswith("octo_st_")
    assert created["token_prefix"] and plaintext.startswith(created["token_prefix"])

    listed = client.get("/api/tenants/default/service-tokens", headers=admin)
    assert listed.status_code == 200
    assert [item["token_id"] for item in listed.json()] == [created["token_id"]]
    assert all(item["token"] is None for item in listed.json())
    assert plaintext not in listed.text


def test_only_a_hash_of_the_secret_is_stored(env):
    client, settings, admin = env
    created = issue(client, admin)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ServiceToken, created["token_id"])
        assert row.token_hash.startswith("$2")
        assert created["token"] not in row.token_hash


def test_creation_is_admin_only(env):
    client, _settings, _admin = env
    for role in ("viewer", "operator"):
        response = client.post(
            "/api/tenants/default/service-tokens",
            headers=auth_headers(client, role),
            json={"name": "x", "scopes": ["runs:read"]},
        )
        assert response.status_code == 403


def test_creation_rejects_an_unknown_tenant_and_an_invalid_scope(env):
    client, _settings, admin = env
    missing = client.post(
        "/api/tenants/nope/service-tokens", headers=admin, json={"name": "x", "scopes": ["runs:read"]}
    )
    assert missing.status_code == 404
    bad = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "x", "scopes": ["runs:delete"]},
    )
    assert bad.status_code == 422


def test_expiry_is_bounded_by_the_configured_maximum(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, service_token_max_ttl_days=30)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    response = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "x", "scopes": ["runs:read"], "expires_in_days": 90},
    )
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def test_a_token_authenticates_on_the_same_bearer_header(env):
    client, _settings, admin = env
    token = issue(client, admin, scopes=["runs:read"])["token"]
    assert client.get("/api/runs", headers=bearer(token)).status_code == 200


def test_a_token_is_refused_outside_its_scopes(env):
    client, _settings, admin = env
    token = issue(client, admin, scopes=["assets:read"])["token"]
    denied = client.get("/api/runs", headers=bearer(token))
    assert denied.status_code == 403
    assert "runs:read" in denied.json()["detail"]


def test_a_read_scope_does_not_admit_a_write(env):
    client, _settings, admin = env
    approve_scan_scope(_settings)
    token = issue(client, admin, scopes=["jobs:read"], role="operator")["token"]
    response = client.post(
        "/api/jobs", headers=bearer(token), json={"targets": ["example.com"], "profile": "quick"}
    )
    assert response.status_code == 403


def test_a_token_never_exceeds_the_role_it_maps_to(env):
    client, _settings, admin = env
    token = issue(client, admin, scopes=["*"], role="viewer")["token"]
    # Scoped for everything, but a viewer cannot start work.
    response = client.post(
        "/api/jobs", headers=bearer(token), json={"targets": ["example.com"], "profile": "quick"}
    )
    assert response.status_code == 403


def test_identity_administration_is_closed_even_to_an_admin_token(env):
    client, _settings, admin = env
    token = issue(client, admin, scopes=["*"], role="admin")["token"]
    assert client.get("/api/users", headers=bearer(token)).status_code == 403
    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 403
    # Including minting another token, which would make revocation pointless.
    assert (
        client.post(
            "/api/tenants/default/service-tokens",
            headers=bearer(token),
            json={"name": "y", "scopes": ["*"]},
        ).status_code
        == 403
    )


def test_a_token_cannot_act_in_another_tenant(env):
    client, _settings, admin = env
    created = client.post("/api/tenants", headers=admin, json={"name": "Acme"})
    other = created.json()["tenant_id"]
    token = issue(client, admin, scopes=["assets:read"])["token"]
    response = client.get(f"/api/assets?tenant_id={other}", headers=bearer(token))
    assert response.status_code == 403


def test_an_unknown_or_tampered_token_is_refused(env):
    client, _settings, admin = env
    plaintext = issue(client, admin)["token"]
    tampered = plaintext[:-4] + ("aaaa" if not plaintext.endswith("aaaa") else "bbbb")
    assert client.get("/api/runs", headers=bearer(tampered)).status_code == 401
    assert (
        client.get("/api/runs", headers=bearer("octo_st_" + "0" * 16 + "_" + "z" * 40)).status_code
        == 401
    )


def test_last_used_at_is_recorded(env):
    client, settings, admin = env
    created = issue(client, admin)
    assert created["last_used_at"] is None
    client.get("/api/runs", headers=bearer(created["token"]))
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ServiceToken, created["token_id"])
        assert row.last_used_at is not None


# --------------------------------------------------------------------------- #
# Revocation and expiry
# --------------------------------------------------------------------------- #


def test_revocation_takes_effect_immediately(env):
    client, _settings, admin = env
    created = issue(client, admin)
    token = created["token"]
    assert client.get("/api/runs", headers=bearer(token)).status_code == 200

    revoked = client.post(
        f"/api/tenants/default/service-tokens/{created['token_id']}/revoke", headers=admin
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert client.get("/api/runs", headers=bearer(token)).status_code == 401


def test_revocation_is_idempotent_and_scoped_to_the_tenant(env):
    client, _settings, admin = env
    created = issue(client, admin)
    first = client.post(
        f"/api/tenants/default/service-tokens/{created['token_id']}/revoke", headers=admin
    ).json()
    second = client.post(
        f"/api/tenants/default/service-tokens/{created['token_id']}/revoke", headers=admin
    ).json()
    assert first["revoked_at"] == second["revoked_at"]

    other = client.post("/api/tenants", headers=admin, json={"name": "Acme"}).json()["tenant_id"]
    wrong_tenant = client.post(
        f"/api/tenants/{other}/service-tokens/{created['token_id']}/revoke", headers=admin
    )
    assert wrong_tenant.status_code == 404


def test_an_expired_token_stops_authenticating(env):
    client, settings, admin = env
    created = issue(client, admin)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ServiceToken, created["token_id"])
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)

    assert client.get("/api/runs", headers=bearer(created["token"])).status_code == 401
    listed = client.get("/api/tenants/default/service-tokens", headers=admin).json()
    assert listed[0]["status"] == "expired"


def test_a_token_whose_tenant_was_removed_stops_authenticating(env):
    client, settings, admin = env
    other = client.post("/api/tenants", headers=admin, json={"name": "Acme"}).json()["tenant_id"]
    created = issue(client, admin, tenant_id=other, scopes=["assets:read"])
    assert (
        client.get(f"/api/assets?tenant_id={other}", headers=bearer(created["token"])).status_code
        == 200
    )

    with get_session(settings.postgres_url) as session:
        tenant = session.get(models.Tenant, other)
        tenant.status = "disabled"
    assert client.get("/api/assets", headers=bearer(created["token"])).status_code == 401


# --------------------------------------------------------------------------- #
# Service layer
# --------------------------------------------------------------------------- #


def test_verify_returns_the_issued_role_and_scopes(env):
    client, settings, admin = env
    created = issue(client, admin, scopes=["runs:read", "assets:*"], role="operator")
    principal = service_tokens.verify_token(settings, created["token"])
    assert principal is not None
    assert principal.tenant_id == "default"
    assert principal.role == "operator"
    assert set(principal.scopes) == {"runs:read", "assets:*"}
    assert principal.username.startswith("service-token:")


def test_verify_finds_the_row_by_its_public_prefix(env):
    client, settings, admin = env
    created = issue(client, admin)
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.ServiceToken).where(
                models.ServiceToken.token_prefix == created["token_prefix"]
            )
        ).scalar_one()
        assert row.token_id == created["token_id"]
