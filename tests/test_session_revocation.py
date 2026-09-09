"""Console sessions can be ended before the token expires (#314).

The defect these guard is one sentence long: a console JWT was believed for its
whole eight-hour life, so disabling, deleting or demoting an account changed
nothing for the token already in that person's browser. Every test below fails
against the pre-#314 decoder — the account-state ones because nothing was ever
looked up, the logout ones because the endpoints did not exist, and the
rotation ones because there was exactly one signing key.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from api.core.security import jwt_kid
from tests.conftest import (
    TEST_JWT_SECRET,
    TEST_USERS,
    auth_headers,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

# A second and a third key, so "accepted from the rotation window" and "accepted
# from anywhere" are different assertions.
RETIRED_SECRET = "retired-test-secret-0123456789abcdef"
STRANGER_SECRET = "not-this-installations-key-0123456789"
STRONG = "correct-horse-battery"


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    return client, settings, auth_headers(client, "admin")


def forge(
    *,
    secret: str = TEST_JWT_SECRET,
    kid: str | None = None,
    username: str = "viewer",
    role: str = "viewer",
    **claims,
) -> str:
    """Mint a console token directly, to test what the decoder accepts."""
    payload = {
        "sub": username,
        "role": role,
        "typ": "user",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=30),
    }
    payload.update(claims)
    headers = {"kid": kid} if kid is not None else None
    return jwt.encode(payload, secret, algorithm="HS256", headers=headers)


# --------------------------------------------------------------------------- #
# Account state reaches the token that was already issued
# --------------------------------------------------------------------------- #


def test_disabling_an_account_refuses_its_live_token(env):
    """The EPIC's acceptance criterion: a disabled user loses access at once."""
    client, _settings, admin = env
    token = login(client, "operator")
    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 200

    disabled = client.put(
        "/api/users/operator/disabled", headers=admin, json={"disabled": True}
    )
    assert disabled.status_code == 200

    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_deleting_an_account_refuses_its_live_token(env):
    client, _settings, admin = env
    token = login(client, "operator")

    assert client.delete("/api/users/operator", headers=admin).status_code == 204

    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_demotion_refuses_the_token_issued_at_the_old_role(env):
    client, _settings, admin = env
    token = login(client, "operator")

    demoted = client.put("/api/users/operator/role", headers=admin, json={"role": "viewer"})
    assert demoted.status_code == 200

    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401
    # And the next login is a viewer, from the table rather than from a claim.
    assert client.post(
        "/api/auth/login", json={"username": "operator", "password": TEST_USERS["operator"]}
    ).json()["role"] == "viewer"


def test_admin_password_reset_refuses_the_live_token(env):
    client, _settings, admin = env
    token = login(client, "operator")

    reset = client.put(
        "/api/users/operator/password", headers=admin, json={"password": STRONG}
    )
    assert reset.status_code == 200

    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_changing_your_own_password_ends_your_own_session(env):
    """Documented behaviour, not an accident: the console lands on the login form."""
    client, _settings, _admin = env
    token = login(client, "operator")

    changed = client.post(
        "/api/auth/password",
        headers=bearer(token),
        json={"current_password": TEST_USERS["operator"], "new_password": STRONG},
    )
    assert changed.status_code == 204

    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401
    assert login(client, "operator", STRONG)


def test_a_token_whose_role_claim_disagrees_with_the_table_uses_the_table(env):
    """Signed with the real key, but claiming a role the account does not have.

    Only reachable by someone holding the signing key, which is why it is not
    an escalation on its own — but the row is the authority, so it is also not
    a promotion.
    """
    client, settings, _admin = env
    forged = forge(username="viewer", role="admin", ver=0, jti="claims-admin")

    response = client.get("/api/auth/me", headers=bearer(forged))
    assert response.status_code == 200
    assert response.json()["role"] == "viewer"
    assert settings.jwt_secret == TEST_JWT_SECRET  # the token was honestly signed


# --------------------------------------------------------------------------- #
# Logout and revoke-all
# --------------------------------------------------------------------------- #


def test_logout_ends_that_session_and_leaves_the_other_one(env):
    client, _settings, _admin = env
    laptop = login(client, "operator")
    phone = login(client, "operator")

    assert client.post("/api/auth/logout", headers=bearer(laptop)).status_code == 204

    assert client.get("/api/auth/me", headers=bearer(laptop)).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(phone)).status_code == 200


def test_logout_is_idempotent_for_the_token_it_already_refused(env):
    client, _settings, _admin = env
    token = login(client, "operator")

    assert client.post("/api/auth/logout", headers=bearer(token)).status_code == 204
    # The second attempt is refused as an invalid session, not as a server
    # error: the denylist row is the reason the request no longer authenticates.
    assert client.post("/api/auth/logout", headers=bearer(token)).status_code == 401


def test_the_denylist_sweeps_rows_whose_token_has_already_expired(env):
    """The table is bounded by live logouts, not by history."""
    from api.services import sessions as sessions_service

    client, settings, _admin = env
    token = login(client, "operator")
    # A row for a token that expired an hour ago: nothing left to refuse.
    sessions_service.revoke_token(
        settings,
        jti="expired-yesterday",
        username="operator",
        expires_at=datetime.now(UTC) - timedelta(hours=1),
    )
    assert sessions_service.count_revoked(settings, "operator") == 1

    assert client.post("/api/auth/logout", headers=bearer(token)).status_code == 204

    # One row, not two: the write swept the dead one on its way in.
    assert sessions_service.count_revoked(settings, "operator") == 1


def test_revoke_all_ends_every_session_of_the_caller(env):
    client, _settings, _admin = env
    laptop = login(client, "operator")
    phone = login(client, "operator")

    assert client.post("/api/auth/sessions/revoke-all", headers=bearer(laptop)).status_code == 204

    assert client.get("/api/auth/me", headers=bearer(laptop)).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(phone)).status_code == 401
    # A fresh login is minted at the new generation and works.
    assert client.get("/api/auth/me", headers=bearer(login(client, "operator"))).status_code == 200


def test_admin_revokes_another_accounts_sessions(env):
    client, _settings, admin = env
    laptop = login(client, "operator")
    phone = login(client, "operator")

    revoked = client.post("/api/users/operator/sessions/revoke-all", headers=admin)
    assert revoked.status_code == 204

    assert client.get("/api/auth/me", headers=bearer(laptop)).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(phone)).status_code == 401


def test_admin_revoke_all_needs_admin_and_an_existing_account(env):
    client, _settings, admin = env
    operator = auth_headers(client, "operator")

    assert client.post("/api/users/viewer/sessions/revoke-all", headers=operator).status_code == 403
    assert client.post("/api/users/nobody/sessions/revoke-all", headers=admin).status_code == 404


def test_a_service_token_is_not_a_session(env):
    """Service tokens are credentials, revoked as credentials (Track E).

    They never reach the session endpoints even when their scope list asks to:
    ``auth`` is in ``FORBIDDEN_RESOURCES``, so the scope layer refuses first.
    Asserted here so that adding session endpoints under ``/api/auth`` has not
    quietly opened a door for a credential that is revoked somewhere else.
    """
    client, _settings, admin = env
    created = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["runs:read", "auth:write"], "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    token = created.json()["token"]

    assert client.post("/api/auth/logout", headers=bearer(token)).status_code == 403
    assert client.post("/api/auth/sessions/revoke-all", headers=bearer(token)).status_code == 403
    # …and it still authenticates, because nothing here revoked it.
    assert client.get("/api/runs", headers=bearer(token)).status_code == 200


# --------------------------------------------------------------------------- #
# Token generation
# --------------------------------------------------------------------------- #


def test_a_token_minted_before_the_upgrade_is_still_accepted(env):
    """No ``ver``, no ``jti`` — every session live at the moment of the upgrade.

    Migration 0038 backfills every account at generation 0, so these keep
    working until they expire rather than the deploy signing the console out.
    """
    client, _settings, _admin = env
    legacy = forge(username="operator", role="operator")

    assert client.get("/api/auth/me", headers=bearer(legacy)).status_code == 200
    # They cannot be logged out one at a time, which the endpoint says rather
    # than answering 204 and doing nothing.
    assert client.post("/api/auth/logout", headers=bearer(legacy)).status_code == 400
    # "Everywhere" does work on them, because a generation bump needs no jti.
    assert client.post("/api/auth/sessions/revoke-all", headers=bearer(legacy)).status_code == 204
    assert client.get("/api/auth/me", headers=bearer(legacy)).status_code == 401
    # A pre-#314 token claims no generation at all, so once the account has
    # moved past 0 it can never match again — one bump ends every legacy
    # session of that account for good, which is the upgrade path an operator
    # who does not want to wait eight hours takes.
    assert client.get("/api/auth/me", headers=bearer(legacy)).status_code == 401


def test_a_stale_version_claim_is_refused(env):
    client, _settings, _admin = env
    ahead = forge(username="operator", role="operator", ver=7, jti="from-the-future")

    assert client.get("/api/auth/me", headers=bearer(ahead)).status_code == 401


# --------------------------------------------------------------------------- #
# Signing-key rotation
# --------------------------------------------------------------------------- #


def test_login_stamps_the_signing_keys_kid(env):
    client, _settings, _admin = env
    token = login(client, "operator")

    header = jwt.get_unverified_header(token)
    assert header["kid"] == jwt_kid(TEST_JWT_SECRET)
    claims = jwt.decode(token, TEST_JWT_SECRET, algorithms=["HS256"])
    assert claims["jti"] and claims["ver"] == 0


def test_a_token_signed_with_a_retired_key_is_accepted(tmp_path, monkeypatch):
    """The point of the rotation window: yesterday's sessions survive the deploy."""
    client = configured_client(
        tmp_path,
        monkeypatch,
        jwt_secret=TEST_JWT_SECRET,
        jwt_secret_previous=[RETIRED_SECRET],
    )
    retired = forge(
        secret=RETIRED_SECRET,
        kid=jwt_kid(RETIRED_SECRET),
        username="operator",
        role="operator",
        ver=0,
        jti="signed-yesterday",
    )

    assert client.get("/api/auth/me", headers=bearer(retired)).status_code == 200


def test_a_token_signed_with_a_key_that_was_never_ours_is_refused(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        jwt_secret=TEST_JWT_SECRET,
        jwt_secret_previous=[RETIRED_SECRET],
    )
    stranger = forge(secret=STRANGER_SECRET, username="operator", role="operator", ver=0)

    assert client.get("/api/auth/me", headers=bearer(stranger)).status_code == 401


def test_the_kid_selects_the_key_and_is_not_a_hint_to_ignore(tmp_path, monkeypatch):
    """A token naming one key of the window but signed with another is forged."""
    client = configured_client(
        tmp_path,
        monkeypatch,
        jwt_secret=TEST_JWT_SECRET,
        jwt_secret_previous=[RETIRED_SECRET],
    )
    mislabelled = forge(
        secret=RETIRED_SECRET,
        kid=jwt_kid(TEST_JWT_SECRET),
        username="operator",
        role="operator",
        ver=0,
    )

    assert client.get("/api/auth/me", headers=bearer(mislabelled)).status_code == 401


def test_an_agent_token_signed_with_a_retired_key_still_verifies(tmp_path, monkeypatch):
    """One rotation covers both audiences while the agent key is derived (#312)."""
    from api.core.security import derive_agent_jwt_secret

    client = configured_client(
        tmp_path,
        monkeypatch,
        job_execution_mode="agent",
        agent_token="",
        jwt_secret=TEST_JWT_SECRET,
        jwt_secret_previous=[RETIRED_SECRET],
    )
    retired_agent_key = derive_agent_jwt_secret(RETIRED_SECRET)
    token = jwt.encode(
        {
            "sub": "agent-1",
            "typ": "agent",
            "tenant_id": "default",
            "agent_id": "agent-1",
            "exp": datetime.now(UTC) + timedelta(minutes=30),
        },
        retired_agent_key,
        algorithm="HS256",
        headers={"kid": jwt_kid(retired_agent_key)},
    )

    response = client.post("/api/agent/jobs/claim?agent_id=agent-1", headers=bearer(token))
    # Any answer but 401: what is under test is that the signature verified.
    assert response.status_code != 401, response.text
