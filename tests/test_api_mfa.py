"""The second factor, end to end: enrol, challenge, step up, reset (#315).

The defect these guard is one sentence long: a local console account — the one
that mints service tokens, approves scanning scopes and deploys agents — was
protected by a password and nothing else. Every test below fails against the
pre-#315 API, most of them because the endpoint did not exist and the rest
because the policy did not.

Time is controlled rather than waited on: ``api.services.mfa._now`` is the one
clock the service reads, so a test can hand it a moment, compute the code that
belongs to it, and then move on to the next thirty-second step without sleeping
through one.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from api.core import totp
from tests.conftest import (
    TEST_USERS,
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


class Clock:
    """The service's ``_now``, under the test's control.

    Naive UTC, like every timestamp in this schema, and the same value the
    codes are computed from — so ``clock.code(secret)`` is by construction the
    code the server expects at that instant.
    """

    def __init__(self) -> None:
        self.now = datetime(2026, 9, 10, 12, 0, 0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)

    def code(self, secret: str, *, offset_steps: int = 0) -> str:
        return totp.code_at(secret, self.now + timedelta(seconds=offset_steps * totp.STEP_SECONDS))

    def next_code(self, secret: str) -> str:
        """The code for the following step, having spent the current one.

        Enrolment consumes a step, and so does every verification: the window
        accepts the next one, and using it is what a person with a phone
        actually does thirty seconds later.
        """
        self.advance(totp.STEP_SECONDS)
        return self.code(secret)


@pytest.fixture
def clock(monkeypatch) -> Clock:
    instance = Clock()
    monkeypatch.setattr("api.services.mfa._now", instance)
    return instance


def enrol(client, headers, clock: Clock) -> tuple[str, list[str]]:
    """Take one account through setup + confirm. Returns (secret, recovery codes)."""
    setup = client.post("/api/auth/mfa/totp/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/")

    confirm = client.post(
        "/api/auth/mfa/totp/confirm", headers=headers, json={"code": clock.code(secret)}
    )
    assert confirm.status_code == 200, confirm.text
    codes = confirm.json()["recovery_codes"]
    assert len(codes) == 10
    return secret, codes


def password_login(client, username: str = "admin") -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": TEST_USERS[username]}
    )
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# Enrolment and the two-leg login
# --------------------------------------------------------------------------- #


def test_login_returns_a_challenge_and_the_code_completes_it(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)

    challenge = password_login(client)
    # The password alone buys no session at all — that is the whole point.
    assert challenge["mfa_required"] is True
    assert challenge["access_token"] is None
    assert challenge["mfa_token"]

    verified = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": challenge["mfa_token"], "code": clock.next_code(secret)},
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["role"] == "admin"
    session = bearer(verified.json()["access_token"])
    assert client.get("/api/users", headers=session).status_code == 200


def test_the_challenge_token_opens_nothing_but_the_verify_endpoint(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    enrol(client, headers, clock)

    challenge = password_login(client)["mfa_token"]
    # Presented as a session token it is refused: ``typ`` is not "user", and
    # the decoder allowlists that value rather than denylisting the others.
    assert client.get("/api/users", headers=bearer(challenge)).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(challenge)).status_code == 401


def test_a_code_cannot_be_used_twice(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)

    code = clock.next_code(secret)
    first = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": password_login(client)["mfa_token"], "code": code},
    )
    assert first.status_code == 200

    replay = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": password_login(client)["mfa_token"], "code": code},
    )
    assert replay.status_code == 401


def test_a_recovery_code_works_once_and_is_then_spent(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    _, codes = enrol(client, headers, clock)

    used = codes[0]
    first = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": password_login(client)["mfa_token"], "recovery_code": used},
    )
    assert first.status_code == 200
    session = bearer(first.json()["access_token"])
    assert client.get("/api/auth/mfa", headers=session).json()["recovery_codes_remaining"] == 9

    again = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": password_login(client)["mfa_token"], "recovery_code": used},
    )
    assert again.status_code == 401
    # A different, unspent code still works, so the refusal above was about
    # that one code and not about recovery codes having stopped working.
    other = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": password_login(client)["mfa_token"], "recovery_code": codes[1]},
    )
    assert other.status_code == 200


def test_the_stored_secret_is_encrypted_when_a_master_key_is_configured(
    tmp_path, monkeypatch, clock
):
    monkeypatch.setenv("OCTO_MASTER_KEY", "0" * 43 + "=")
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    secret, _ = enrol(client, auth_headers(client, "admin"), clock)

    from api.db import models
    from api.db.engine import get_session

    with get_session(settings.postgres_url) as session:
        stored = session.get(models.User, "admin").mfa_secret
    assert stored is not None
    assert secret not in stored
    assert stored.startswith("v1:")


# --------------------------------------------------------------------------- #
# Disable and admin reset
# --------------------------------------------------------------------------- #


def test_disable_needs_the_password_and_a_live_factor(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)

    wrong_password = client.post(
        "/api/auth/mfa/disable",
        headers=headers,
        json={"password": "not-the-password", "code": clock.next_code(secret)},
    )
    assert wrong_password.status_code == 401

    no_code = client.post(
        "/api/auth/mfa/disable", headers=headers, json={"password": TEST_USERS["admin"]}
    )
    assert no_code.status_code == 422

    done = client.post(
        "/api/auth/mfa/disable",
        headers=headers,
        json={"password": TEST_USERS["admin"], "code": clock.next_code(secret)},
    )
    assert done.status_code == 200, done.text
    assert done.json()["enabled"] is False
    # And the account is back to a one-leg login.
    assert password_login(client)["access_token"]


def test_admin_reset_clears_the_factor_and_ends_the_sessions(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")
    enrol(client, operator, clock)
    admin = auth_headers(client, "admin")

    # The operator's own session is live right up to the reset.
    assert client.get("/api/auth/me", headers=operator).status_code == 200
    reset = client.post("/api/users/operator/mfa/reset", headers=admin)
    assert reset.status_code == 200, reset.text
    assert reset.json()["enabled"] is False
    assert client.get("/api/auth/me", headers=operator).status_code == 401

    events = client.get("/api/audit", headers=admin, params={"action": "user.mfa_reset"})
    assert events.status_code == 200
    assert [item["resource_id"] for item in events.json()["items"]] == ["operator"]


def test_reset_is_platform_admin_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    response = client.post(
        "/api/users/admin/mfa/reset", headers=auth_headers(client, "operator")
    )
    assert response.status_code == 403


# --------------------------------------------------------------------------- #
# Policy: a role that must carry a factor
# --------------------------------------------------------------------------- #


def test_a_required_role_without_a_factor_gets_a_session_that_can_only_enrol(
    tmp_path, monkeypatch, clock
):
    client = configured_client(tmp_path, monkeypatch, mfa_required_roles=["admin"])
    session = password_login(client)
    assert session["mfa_required"] is True
    headers = bearer(session["access_token"])

    # Everything but enrolment, logout and the principal is refused...
    assert client.get("/api/users", headers=headers).status_code == 403
    assert client.get("/api/runs", headers=headers).status_code == 403
    # ...and the way out is open.
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["mfa_pending"] is True
    assert client.get("/api/auth/mfa", headers=headers).status_code == 200

    secret, _ = enrol(client, headers, clock)
    # Enrolled: the next login is a two-leg one, and its session is unrestricted.
    challenge = password_login(client)
    verified = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": challenge["mfa_token"], "code": clock.next_code(secret)},
    )
    assert verified.status_code == 200
    unrestricted = bearer(verified.json()["access_token"])
    assert client.get("/api/users", headers=unrestricted).status_code == 200


def test_a_role_not_named_by_the_policy_is_untouched(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, mfa_required_roles=["admin"])
    session = password_login(client, "operator")
    assert session["mfa_required"] is False
    assert client.get("/api/runs", headers=bearer(session["access_token"])).status_code == 200


# --------------------------------------------------------------------------- #
# Step-up
# --------------------------------------------------------------------------- #


def test_minting_a_credential_needs_a_recent_verification(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch, mfa_stepup_minutes=15)
    headers = auth_headers(client, "admin")
    secret, _ = enrol(client, headers, clock)

    # The session that enrolled is a plain password session: it has never
    # presented a code, so it may not mint a provisioning key.
    stale = client.post("/api/tenants/default/provisioning-keys", headers=headers, json={"label": "x"})
    assert stale.status_code == 403
    assert "multi-factor" in stale.json()["detail"]

    verified = client.post(
        "/api/auth/mfa/verify",
        headers=headers,
        json={"code": clock.next_code(secret)},
    )
    assert verified.status_code == 200, verified.text
    fresh = bearer(verified.json()["access_token"])
    assert (
        client.post(
            "/api/tenants/default/provisioning-keys", headers=fresh, json={"label": "x"}
        ).status_code
        == 201
    )


def test_step_up_does_not_apply_to_an_account_without_a_factor(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    response = client.post(
        "/api/tenants/default/provisioning-keys",
        headers=auth_headers(client, "admin"),
        json={"label": "x"},
    )
    assert response.status_code == 201


# --------------------------------------------------------------------------- #
# Break-glass local login
# --------------------------------------------------------------------------- #


def _sso_settings(tmp_path, **overrides):
    return make_settings(
        tmp_path,
        oidc_issuer="https://idp.example",
        oidc_client_id="console",
        oidc_client_secret="shh",
        **overrides,
    )


def test_break_glass_login_is_allowed_named_and_recorded(tmp_path, monkeypatch):
    settings = _sso_settings(tmp_path, local_login="break-glass", break_glass_users=["admin"])
    client = configured_client(tmp_path, monkeypatch, settings=settings)

    allowed = password_login(client)
    assert allowed["access_token"]
    admin = bearer(allowed["access_token"])

    events = client.get(
        "/api/audit", headers=admin, params={"action": "auth.break_glass_login"}
    )
    assert [item["resource_id"] for item in events.json()["items"]] == ["admin"]

    auth_events = client.get("/api/auth/events", headers=admin)
    assert any(item["reason"] == "break_glass_login" for item in auth_events.json()["items"])


def test_a_non_break_glass_account_cannot_use_its_password(tmp_path, monkeypatch):
    settings = _sso_settings(tmp_path, local_login="break-glass", break_glass_users=["admin"])
    client = configured_client(tmp_path, monkeypatch, settings=settings)

    refused = client.post(
        "/api/auth/login", json={"username": "operator", "password": TEST_USERS["operator"]}
    )
    # The same 401 a wrong password gets: the break-glass list is exactly the
    # shortlist worth attacking, and this endpoint is unauthenticated.
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Invalid credentials"

    events = client.get("/api/auth/events", headers=auth_headers(client, "admin"))
    assert any(
        item["reason"] == "local_login_not_break_glass" for item in events.json()["items"]
    )


def test_local_login_can_be_turned_off_entirely(tmp_path, monkeypatch):
    settings = _sso_settings(tmp_path, local_login="disabled")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    refused = client.post(
        "/api/auth/login", json={"username": "admin", "password": TEST_USERS["admin"]}
    )
    assert refused.status_code == 401
    # The mode itself is public — the login form has to know not to offer a
    # password box — while naming no account.
    assert client.get("/api/auth/sso").json()["local_login"] == "disabled"


def test_the_policy_does_nothing_without_an_identity_provider(tmp_path, monkeypatch):
    # Same OCTO_LOCAL_LOGIN, no OIDC: an installation with neither SSO nor
    # password login is one nobody can reach, so the policy stays inert.
    client = configured_client(
        tmp_path, monkeypatch, local_login="disabled", break_glass_users=[]
    )
    assert password_login(client)["access_token"]
    assert client.get("/api/auth/sso").json()["local_login"] == "enabled"
