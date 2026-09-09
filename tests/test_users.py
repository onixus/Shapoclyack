"""Postgres-backed console accounts (#156).

The property that matters most here is negative: a password that is not a
bcrypt hash must never authenticate. Before this change ``authenticate_user``
compared plaintext whenever the stored value did not start with ``$2``, so the
test that a plaintext row is rejected is the regression guard for the whole
issue.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from tests.conftest import (
    TEST_USERS,
    auth_headers,
    configured_client,
    make_settings,
    reset_service_state,
    requires_postgres,
)

pytestmark = requires_postgres

STRONG = "correct-horse-battery"
OTHER_STRONG = "another-long-password"


def _admin(client):
    return auth_headers(client, "admin", TEST_USERS["admin"])


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


def test_plaintext_stored_password_never_authenticates(tmp_path, monkeypatch) -> None:
    """The #156 regression guard: pre-change, this login succeeded."""
    from api.db import models
    from api.db.engine import get_session
    from api.services import users as users_service

    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    users_service.configure(settings)

    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, "operator")
        row.password_hash = "plaintext-password"

    response = client.post(
        "/api/auth/login", json={"username": "operator", "password": "plaintext-password"}
    )
    assert response.status_code == 401


def test_disabled_user_cannot_log_in(tmp_path, monkeypatch) -> None:
    from api.services import users as users_service

    client = configured_client(tmp_path, monkeypatch)
    users_service.set_disabled("operator", True)

    response = client.post(
        "/api/auth/login", json={"username": "operator", "password": TEST_USERS["operator"]}
    )
    assert response.status_code == 401

    users_service.set_disabled("operator", False)
    assert (
        client.post(
            "/api/auth/login", json={"username": "operator", "password": TEST_USERS["operator"]}
        ).status_code
        == 200
    )


def test_account_without_a_password_cannot_log_in(tmp_path, monkeypatch) -> None:
    """Migration 0013 backfills orphan memberships as accounts with no password."""
    from api.db import models
    from api.db.engine import get_session
    from api.services import users as users_service

    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    users_service.configure(settings)

    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.User(
                username="ghost",
                password_hash="",
                role="viewer",
                created_at=now,
                updated_at=now,
                created_by="migration:0013_users",
            )
        )

    # An empty password never reaches the service — LoginRequest rejects it at
    # the schema — so the case that matters is a non-empty guess.
    response = client.post("/api/auth/login", json={"username": "ghost", "password": "anything"})

    assert response.status_code == 401


def test_unknown_user_and_wrong_password_are_indistinguishable(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)

    missing = client.post("/api/auth/login", json={"username": "nobody", "password": STRONG})
    wrong = client.post("/api/auth/login", json={"username": "admin", "password": STRONG})

    assert missing.status_code == wrong.status_code == 401
    assert missing.json() == wrong.json()


# --------------------------------------------------------------------------
# Admin CRUD
# --------------------------------------------------------------------------


def test_create_list_and_login_as_new_user(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)

    created = client.post(
        "/api/users",
        json={"username": "alice", "password": STRONG, "role": "operator"},
        headers=_admin(client),
    )
    assert created.status_code == 201
    body = created.json()
    assert body["username"] == "alice"
    assert body["role"] == "operator"
    assert body["disabled"] is False

    listed = client.get("/api/users", headers=_admin(client))
    assert listed.status_code == 200
    assert "alice" in [u["username"] for u in listed.json()]

    token = client.post("/api/auth/login", json={"username": "alice", "password": STRONG})
    assert token.status_code == 200
    assert token.json()["role"] == "operator"


def test_create_user_stores_the_email_it_was_given_unverified(tmp_path, monkeypatch) -> None:
    """The address was silently dropped before: ``CreateUserRequest`` had no field.

    Unverified whatever the caller says, because ``verified`` is what makes an
    account linkable to an SSO identity by address.
    """
    client = configured_client(tmp_path, monkeypatch)

    created = client.post(
        "/api/users",
        json={
            "username": "alice",
            "password": STRONG,
            "role": "viewer",
            "email": " Alice@Example.COM ",
        },
        headers=_admin(client),
    )

    assert created.status_code == 201, created.text
    assert created.json()["email"] == "alice@example.com"
    assert created.json()["email_verified"] is False
    listed = {u["username"]: u for u in client.get("/api/users", headers=_admin(client)).json()}
    assert listed["alice"]["email"] == "alice@example.com"


def test_create_user_with_a_taken_email_leaves_no_account_behind(tmp_path, monkeypatch) -> None:
    """The address is written in the account's own transaction, so the refusal
    that a second request would have raised cannot leave a half-created user."""
    client = configured_client(tmp_path, monkeypatch)
    headers = _admin(client)
    client.put(
        "/api/users/operator/email",
        json={"email": "shared@example.com", "verified": True},
        headers=headers,
    )

    refused = client.post(
        "/api/users",
        json={
            "username": "alice",
            "password": STRONG,
            "role": "viewer",
            "email": "shared@example.com",
        },
        headers=headers,
    )

    assert refused.status_code == 422
    assert "already used" in refused.json()["detail"]
    assert "alice" not in [u["username"] for u in client.get("/api/users", headers=headers).json()]


def test_user_responses_carry_tenant_memberships(tmp_path, monkeypatch) -> None:
    """Sorted membership ids, and the platform-admin flag that explains an empty list."""
    client = configured_client(tmp_path, monkeypatch)
    headers = _admin(client)
    client.post(
        "/api/users",
        json={"username": "alice", "password": STRONG, "role": "viewer"},
        headers=headers,
    )
    acme = client.post("/api/tenants", json={"name": "Acme"}, headers=headers).json()["tenant_id"]
    client.put(f"/api/tenants/{acme}/members/alice", json={"role": "operator"}, headers=headers)
    client.put("/api/tenants/default/members/alice", json={"role": "viewer"}, headers=headers)

    listed = {u["username"]: u for u in client.get("/api/users", headers=headers).json()}

    assert listed["alice"]["tenants"] == sorted([acme, "default"])
    assert listed["alice"]["is_platform_admin"] is False
    # A platform admin has no grant row and needs none: the global admin role
    # bypasses the membership table, so an empty list is not "no access".
    assert listed["admin"]["tenants"] == []
    assert listed["admin"]["is_platform_admin"] is True

    single = client.put("/api/users/alice/role", json={"role": "operator"}, headers=headers)
    assert single.json()["tenants"] == sorted([acme, "default"])


def test_the_users_list_takes_one_membership_query_whatever_its_length(
    tmp_path, monkeypatch
) -> None:
    """No N+1: the memberships of the whole page come back in a single SELECT."""
    from sqlalchemy import event

    from api.db.engine import get_engine
    from api.services import users as users_service

    client = configured_client(tmp_path, monkeypatch)
    headers = _admin(client)
    for name in ("alice", "bob", "carol"):
        client.post(
            "/api/users",
            json={"username": name, "password": STRONG, "role": "viewer"},
            headers=headers,
        )
        client.put(f"/api/tenants/default/members/{name}", json={"role": "viewer"}, headers=headers)

    engine = get_engine(users_service._require_settings().postgres_url)
    seen: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        if "user_tenants" in statement:
            seen.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        users_service.list_users()
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert len(seen) == 1, seen


def test_no_response_ever_carries_password_material(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    client.post(
        "/api/users",
        json={"username": "alice", "password": STRONG, "role": "viewer"},
        headers=_admin(client),
    )

    listed = client.get("/api/users", headers=_admin(client))

    raw = json.dumps(listed.json())
    assert STRONG not in raw
    assert "$2" not in raw
    assert "password_hash" not in raw


def test_duplicate_username_is_rejected(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    payload = {"username": "alice", "password": STRONG, "role": "viewer"}
    client.post("/api/users", json=payload, headers=_admin(client))

    again = client.post("/api/users", json=payload, headers=_admin(client))

    assert again.status_code == 422


def test_short_password_is_rejected(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)

    response = client.post(
        "/api/users",
        json={"username": "alice", "password": "short", "role": "viewer"},
        headers=_admin(client),
    )

    assert response.status_code == 422


def test_non_admin_cannot_manage_users(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator", TEST_USERS["operator"])

    assert client.get("/api/users", headers=operator).status_code == 403
    assert (
        client.post(
            "/api/users",
            json={"username": "alice", "password": STRONG, "role": "admin"},
            headers=operator,
        ).status_code
        == 403
    )


def test_admin_reset_password_then_login(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)

    response = client.put(
        "/api/users/operator/password", json={"password": OTHER_STRONG}, headers=_admin(client)
    )

    assert response.status_code == 200
    assert (
        client.post(
            "/api/auth/login", json={"username": "operator", "password": OTHER_STRONG}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/auth/login", json={"username": "operator", "password": TEST_USERS["operator"]}
        ).status_code
        == 401
    )


def test_role_change_takes_effect_on_next_login(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)

    client.put("/api/users/viewer/role", json={"role": "operator"}, headers=_admin(client))

    token = client.post(
        "/api/auth/login", json={"username": "viewer", "password": TEST_USERS["viewer"]}
    )
    assert token.json()["role"] == "operator"


def test_delete_user_removes_it(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    client.post(
        "/api/users",
        json={"username": "alice", "password": STRONG, "role": "viewer"},
        headers=_admin(client),
    )

    assert client.delete("/api/users/alice", headers=_admin(client)).status_code == 204
    assert client.delete("/api/users/alice", headers=_admin(client)).status_code == 404


def test_deleting_a_user_cascades_their_memberships(tmp_path, monkeypatch) -> None:
    """FK from migration 0013: no grant may outlive the account it was made for."""
    from api.services import memberships as memberships_service

    client = configured_client(tmp_path, monkeypatch)
    client.post(
        "/api/users",
        json={"username": "alice", "password": STRONG, "role": "viewer"},
        headers=_admin(client),
    )
    client.put(
        "/api/tenants/default/members/alice", json={"role": "operator"}, headers=_admin(client)
    )
    assert memberships_service.list_memberships(tenant_id="default")

    client.delete("/api/users/alice", headers=_admin(client))

    remaining = [m["username"] for m in memberships_service.list_memberships(tenant_id="default")]
    assert "alice" not in remaining


# --------------------------------------------------------------------------
# Lockout guards
# --------------------------------------------------------------------------


def test_last_admin_cannot_be_disabled_demoted_or_deleted(tmp_path, monkeypatch) -> None:
    """An install whose only admin is gone can be recovered only by hand."""
    client = configured_client(tmp_path, monkeypatch)
    headers = _admin(client)

    assert (
        client.put("/api/users/admin/disabled", json={"disabled": True}, headers=headers).status_code
        == 409
    )
    assert (
        client.put("/api/users/admin/role", json={"role": "viewer"}, headers=headers).status_code
        == 409
    )
    assert client.delete("/api/users/admin", headers=headers).status_code == 409


def test_last_admin_guard_lifts_once_another_admin_exists(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    headers = _admin(client)
    client.post(
        "/api/users",
        json={"username": "root2", "password": STRONG, "role": "admin"},
        headers=headers,
    )

    response = client.put("/api/users/admin/role", json={"role": "viewer"}, headers=headers)

    assert response.status_code == 200


def test_cannot_delete_the_account_you_are_signed_in_as(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    headers = _admin(client)
    client.post(
        "/api/users",
        json={"username": "root2", "password": STRONG, "role": "admin"},
        headers=headers,
    )

    assert client.delete("/api/users/admin", headers=headers).status_code == 409


# --------------------------------------------------------------------------
# Self-service password change
# --------------------------------------------------------------------------


def test_user_changes_own_password(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "viewer", TEST_USERS["viewer"])

    response = client.post(
        "/api/auth/password",
        json={"current_password": TEST_USERS["viewer"], "new_password": OTHER_STRONG},
        headers=headers,
    )

    assert response.status_code == 204
    assert (
        client.post(
            "/api/auth/login", json={"username": "viewer", "password": OTHER_STRONG}
        ).status_code
        == 200
    )


def test_own_password_change_requires_the_current_one(tmp_path, monkeypatch) -> None:
    """A valid token is not proof of knowing the password — it may be stolen."""
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "viewer", TEST_USERS["viewer"])

    response = client.post(
        "/api/auth/password",
        json={"current_password": "not-the-password", "new_password": OTHER_STRONG},
        headers=headers,
    )

    assert response.status_code == 401
    assert (
        client.post(
            "/api/auth/login", json={"username": "viewer", "password": TEST_USERS["viewer"]}
        ).status_code
        == 200
    )


def test_password_change_needs_no_admin_role(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "viewer", TEST_USERS["viewer"])

    response = client.post(
        "/api/auth/password",
        json={"current_password": TEST_USERS["viewer"], "new_password": OTHER_STRONG},
        headers=headers,
    )

    assert response.status_code == 204


# --------------------------------------------------------------------------
# Bootstrap / one-time import
# --------------------------------------------------------------------------


def test_env_users_are_imported_once_and_plaintext_is_hashed(tmp_path, monkeypatch) -> None:
    from api.services import users as users_service

    settings = make_settings(
        tmp_path,
        env="prod",
        users=[{"username": "ops", "password": STRONG, "role": "admin"}],
    )
    reset_service_state(settings)

    users_service.bootstrap(settings)

    assert users_service.authenticate("ops", STRONG) is not None
    assert users_service.get_user("ops")["created_by"] == "import:OCTO_API_USERS"

    # A later edit to the variable is ignored: the table is the source of truth
    # from the first import on, so two stores cannot drift apart.
    settings.users = [{"username": "ops2", "password": STRONG, "role": "admin"}]
    users_service.bootstrap(settings)
    assert users_service.get_user("ops2") is None


def test_import_carries_an_existing_bcrypt_hash_across(tmp_path, monkeypatch) -> None:
    from api.auth import hash_password
    from api.services import users as users_service

    hashed = hash_password(STRONG)
    settings = make_settings(
        tmp_path, env="prod", users=[{"username": "ops", "password": hashed, "role": "admin"}]
    )
    reset_service_state(settings)

    users_service.bootstrap(settings)

    assert users_service.authenticate("ops", STRONG) is not None


def test_built_in_demo_accounts_are_never_imported_in_prod(tmp_path, monkeypatch) -> None:
    """Importing them would re-open, through the table, what #155 closed in env."""
    from api.settings import DEFAULT_USERS, InsecureConfigurationError
    from api.services import users as users_service

    settings = make_settings(tmp_path, env="prod", users=list(DEFAULT_USERS))
    reset_service_state(settings)

    with pytest.raises(InsecureConfigurationError, match="no console account"):
        users_service.bootstrap(settings)

    assert users_service.list_users() == []


def test_prod_without_any_account_refuses_to_start(tmp_path, monkeypatch) -> None:
    from api.settings import InsecureConfigurationError
    from api.services import users as users_service

    settings = make_settings(tmp_path, env="prod", users=[])
    reset_service_state(settings)

    with pytest.raises(InsecureConfigurationError, match="no console account"):
        users_service.bootstrap(settings)


def test_dev_seeds_the_demo_accounts(tmp_path, monkeypatch) -> None:
    from api.services import users as users_service

    settings = make_settings(tmp_path, env="dev")
    reset_service_state(settings)

    users_service.bootstrap(settings)

    assert users_service.authenticate("admin", TEST_USERS["admin"]) is not None


def test_bootstrap_is_a_no_op_once_an_account_exists(tmp_path, monkeypatch) -> None:
    """Restarts must not resurrect demo accounts an operator deleted."""
    from api.services import users as users_service

    settings = make_settings(tmp_path, env="dev")
    reset_service_state(settings)
    users_service.bootstrap(settings)
    users_service.delete_user("viewer")

    users_service.bootstrap(settings)

    assert users_service.get_user("viewer") is None


def test_concurrent_seeding_does_not_raise(tmp_path, monkeypatch) -> None:
    """Two writers seeding at once is a no-op for the loser, not a crash (#257).

    ``_seed_dev_users`` checked for the row and then inserted it, with nothing
    in between. Replicas run the startup bootstrap simultaneously, so the
    second writer's insert hit the ``username`` primary key and took the whole
    transaction — and the API start — down with it. In the suite the second
    writer was a deployment worker left over from an earlier test, which is why
    this surfaced as an unrelated file failing roughly one run in five.
    """
    import threading

    from api.services import users as users_service

    settings = make_settings(tmp_path, env="dev")
    reset_service_state(settings)

    barrier = threading.Barrier(4)
    errors: list[BaseException] = []

    def seed() -> None:
        barrier.wait()
        try:
            users_service._seed_dev_users(settings)
        except BaseException as exc:  # noqa: BLE001 - the assertion is "nothing raised"
            errors.append(exc)

    threads = [threading.Thread(target=seed) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, f"seeding raced with itself: {errors!r}"
    # Seeded once, not four times: the losers must not have written duplicates
    # under different casing or a second row per account.
    assert users_service.authenticate("admin", TEST_USERS["admin"]) is not None
    assert len(users_service.list_users()) == len(TEST_USERS)
