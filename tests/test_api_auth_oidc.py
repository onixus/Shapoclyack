"""The SSO routes end to end: callback, linking, JIT provisioning, audit trail.

Postgres-gated (accounts and the auth trail are tables). The provider itself is
the in-process fake from tests/test_oidc.py, so what is exercised here is the
route's own behaviour: which callbacks yield a session, which account that
session belongs to, and what is written down about it.
"""

from __future__ import annotations

import pytest

from api.services import auth_audit
from api.services import oidc
from api.services import users as users_service
from tests.conftest import (
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)
from tests.test_oidc import (
    CLIENT_ID,
    ISSUER,
    FakeProvider,
    make_id_token,
)

pytestmark = requires_postgres


def sso_settings(tmp_path, **overrides):
    return make_settings(
        tmp_path,
        oidc_issuer=ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret="client-secret",
        oidc_redirect_uri="https://console.example/api/auth/oidc/callback",
        **overrides,
    )


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(oidc, "_http_get_json", fake.get_json)
    monkeypatch.setattr(oidc, "_http_post_form", fake.post_form)
    return fake


def start_login(client) -> str:
    """Begin a login and return the state the provider would send back."""
    response = client.get("/api/auth/oidc/login?redirect=false")
    assert response.status_code == 200, response.text
    return response.json()["state"]


def callback(client, provider, state, **claims):
    stored = next(iter(oidc._states.values()))  # noqa: SLF001 - the nonce is server-side
    provider.token_response = {"id_token": make_id_token(nonce=stored.nonce, **claims)}
    return client.get(f"/api/auth/oidc/callback?code=code-1&state={state}")


# --------------------------------------------------------------------------- #
# Feature reporting
# --------------------------------------------------------------------------- #


def test_sso_is_reported_off_and_the_routes_404_when_unconfigured(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    assert client.get("/api/auth/sso").json() == {
        "enabled": False,
        "login_url": "/api/auth/oidc/login",
    }
    assert client.get("/api/health").json()["sso"]["enabled"] is False
    assert client.get("/api/auth/oidc/login").status_code == 404


def test_sso_status_is_public_and_names_no_provider(tmp_path, monkeypatch, provider):
    client = configured_client(tmp_path, monkeypatch, settings=sso_settings(tmp_path))
    response = client.get("/api/auth/sso")
    assert response.status_code == 200
    assert response.json()["enabled"] is True
    assert ISSUER not in response.text


def test_login_redirects_to_the_provider(tmp_path, monkeypatch, provider):
    client = configured_client(tmp_path, monkeypatch, settings=sso_settings(tmp_path))
    response = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith(f"{ISSUER}/authorize?")
    assert "code_challenge_method=S256" in location


def test_login_refuses_to_carry_an_offsite_next(tmp_path, monkeypatch, provider):
    """An open redirect on an authentication endpoint is a phishing primitive."""
    client = configured_client(tmp_path, monkeypatch, settings=sso_settings(tmp_path))
    client.get("/api/auth/oidc/login?redirect=false&next=//evil.example")
    stored = next(iter(oidc._states.values()))  # noqa: SLF001
    assert stored.next_url == ""


# --------------------------------------------------------------------------- #
# Callback
# --------------------------------------------------------------------------- #


def test_callback_signs_in_a_linked_account(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    # An admin vouches for the address; only that makes the account linkable.
    assert (
        client.put(
            "/api/users/operator/email",
            headers=admin,
            json={"email": "op@example.com", "verified": True},
        ).status_code
        == 200
    )

    state = start_login(client)
    response = callback(client, provider, state, email="op@example.com", email_verified=True)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["username"] == "operator"
    assert body["role"] == "operator"

    # The session is the platform's ordinary one.
    me = client.get("/api/auth/me", headers=bearer(body["access_token"]))
    assert me.status_code == 200
    assert me.json()["username"] == "operator"


def test_a_linked_account_is_afterwards_matched_by_subject_not_email(
    tmp_path, monkeypatch, provider
):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    client.put(
        "/api/users/operator/email",
        headers=admin,
        json={"email": "op@example.com", "verified": True},
    )
    callback(client, provider, start_login(client), email="op@example.com", email_verified=True)

    # Same subject, new address at the provider: still the same account.
    second = callback(
        client, provider, start_login(client), email="renamed@example.com", email_verified=True
    )
    assert second.json()["username"] == "operator"


def test_an_unverified_email_is_never_auto_linked(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    client.put(
        "/api/users/operator/email",
        headers=admin,
        json={"email": "op@example.com", "verified": True},
    )
    response = callback(
        client, provider, start_login(client), email="op@example.com", email_verified=False
    )
    assert response.status_code == 403


def test_an_address_the_platform_has_not_verified_is_not_linked(
    tmp_path, monkeypatch, provider
):
    """The provider asserting ``email_verified`` is not enough on its own: the
    local account must already carry the address, marked verified by an admin."""
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    client.put(
        "/api/users/operator/email",
        headers=admin,
        json={"email": "op@example.com", "verified": False},
    )
    response = callback(
        client, provider, start_login(client), email="op@example.com", email_verified=True
    )
    assert response.status_code == 403


def test_a_disabled_account_cannot_be_reached_through_sso(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    client.put(
        "/api/users/operator/email",
        headers=admin,
        json={"email": "op@example.com", "verified": True},
    )
    callback(client, provider, start_login(client), email="op@example.com", email_verified=True)
    client.put("/api/users/operator/disabled", headers=admin, json={"disabled": True})

    response = callback(
        client, provider, start_login(client), email="op@example.com", email_verified=True
    )
    assert response.status_code == 403


# --------------------------------------------------------------------------- #
# Just-in-time provisioning
# --------------------------------------------------------------------------- #


def test_jit_is_off_by_default(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(
        client,
        provider,
        start_login(client),
        preferred_username="newcomer",
        email="new@example.com",
        email_verified=True,
    )
    assert response.status_code == 403
    assert users_service.get_user("newcomer") is None


def test_jit_provisions_at_the_default_role(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(
        client,
        provider,
        start_login(client),
        preferred_username="newcomer",
        email="new@example.com",
        email_verified=True,
    )
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "viewer"

    created = users_service.get_user("newcomer")
    assert created["role"] == "viewer"
    # Provider-only: there is no password to guess or reset.
    assert created["has_password"] is False
    assert created["sso_linked"] is True


def test_jit_maps_a_group_claim_to_a_role(tmp_path, monkeypatch, provider):
    settings = sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_role_claim="groups",
        oidc_role_map={"vm-ops": "operator"},
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(
        client,
        provider,
        start_login(client),
        preferred_username="pipeline",
        groups=["vm-ops"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["role"] == "operator"


def test_jit_grants_membership_in_the_claimed_tenant(tmp_path, monkeypatch, provider):
    settings = sso_settings(
        tmp_path, oidc_jit_provisioning=True, oidc_tenant_claim="tenant"
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    tenant_id = client.post("/api/tenants", headers=admin, json={"name": "Acme"}).json()[
        "tenant_id"
    ]
    response = callback(
        client,
        provider,
        start_login(client),
        preferred_username="acme-user",
        tenant=tenant_id,
    )
    assert response.status_code == 200, response.text
    me = client.get("/api/auth/me", headers=bearer(response.json()["access_token"]))
    assert me.json()["tenants"] == [tenant_id]


def test_jit_never_provisions_over_an_existing_local_account(
    tmp_path, monkeypatch, provider
):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(
        client, provider, start_login(client), preferred_username="admin", email_verified=False
    )
    assert response.status_code == 403
    # The local admin still authenticates with its own password.
    assert auth_headers(client, "admin")


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


def test_a_replayed_state_is_refused(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    state = start_login(client)
    stored = next(iter(oidc._states.values()))  # noqa: SLF001
    provider.token_response = {"id_token": make_id_token(nonce=stored.nonce, sub="s")}

    assert client.get(f"/api/auth/oidc/callback?code=c&state={state}").status_code == 200
    replay = client.get(f"/api/auth/oidc/callback?code=c&state={state}")
    assert replay.status_code == 401


def test_a_token_with_the_wrong_audience_is_refused(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(client, provider, start_login(client), audience="another-client")
    assert response.status_code == 401


def test_an_expired_token_is_refused(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(client, provider, start_login(client), expires_in=-3600)
    assert response.status_code == 401


def test_a_replayed_nonce_from_another_request_is_refused(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    state = start_login(client)
    # A token minted for some *other* authorization request.
    provider.token_response = {"id_token": make_id_token(nonce="nonce-from-elsewhere")}
    assert client.get(f"/api/auth/oidc/callback?code=c&state={state}").status_code == 401


def test_a_refusal_never_quotes_the_provider_or_the_token(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = callback(client, provider, start_login(client), audience="another-client")
    assert settings.oidc_client_secret not in response.text
    assert "aud" not in response.json()["detail"]


def test_a_callback_without_a_code_is_a_400(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    assert client.get("/api/auth/oidc/callback").status_code == 400


# --------------------------------------------------------------------------- #
# Audit trail
# --------------------------------------------------------------------------- #


def test_every_outcome_reaches_the_auth_trail(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")

    callback(client, provider, start_login(client), preferred_username="newcomer")
    callback(client, provider, start_login(client), preferred_username="newcomer")

    events = client.get("/api/auth/events?limit=100", headers=admin).json()["items"]
    reasons = [event["reason"] for event in events if event["username"] == "newcomer"]
    assert auth_audit.REASON_SSO_PROVISIONED in reasons
    assert auth_audit.REASON_SSO_SIGNIN in reasons


def test_a_refused_identity_is_recorded_as_denied(tmp_path, monkeypatch, provider):
    settings = sso_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    callback(client, provider, start_login(client), preferred_username="stranger")

    events = client.get("/api/auth/events?outcome=denied&limit=50", headers=admin).json()["items"]
    assert any(
        event["reason"] == auth_audit.REASON_SSO_NOT_PROVISIONED
        and event["username"] == "stranger"
        for event in events
    )


# --------------------------------------------------------------------------- #
# Post-login redirect
# --------------------------------------------------------------------------- #


def test_the_console_redirect_carries_the_token_in_the_fragment(
    tmp_path, monkeypatch, provider
):
    settings = sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_post_login_redirect="https://console.example/login",
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    state = start_login(client)
    stored = next(iter(oidc._states.values()))  # noqa: SLF001
    provider.token_response = {"id_token": make_id_token(nonce=stored.nonce)}
    response = client.get(
        f"/api/auth/oidc/callback?code=c&state={state}", follow_redirects=False
    )
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("https://console.example/login#access_token=")
    # A fragment, not a query string: browsers never send it to a server and
    # access logs never record it.
    assert "?access_token=" not in location
