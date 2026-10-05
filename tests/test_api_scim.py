"""SCIM 2.0 provisioning end to end: the credential, the binding, the effects (#316).

The protocol subset is what directory clients send; the tests that matter most
are the ones about *who may change what* — a token held to one tenant reaching
another, a provisioning token minting an admin, a person's lock undone by a
push — because a SCIM endpoint that gets those wrong is a remote account
administration API with a long-lived bearer token in front of it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import oidc
from api.services import users as users_service
from tests.conftest import (
    POSTGRES_URL,
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)
from tests.test_api_auth_oidc import callback, sso_settings, start_login
from tests.test_oidc import FakeProvider

pytestmark = requires_postgres


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(oidc, "_http_get_json", fake.get_json)
    monkeypatch.setattr(oidc, "_http_post_form", fake.post_form)
    return fake


SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


def _tenant(client, admin, name: str) -> str:
    response = client.post("/api/tenants", headers=admin, json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()["tenant_id"]


def _scim_token(client, admin, **body) -> str:
    body.setdefault("name", "directory")
    response = client.post("/api/auth/scim-tokens", headers=admin, json=body)
    assert response.status_code == 201, response.text
    assert response.json()["token"].startswith("octo_scim_")
    return response.json()["token"]


def _create_user(client, token, username, **extra):
    return client.post(
        "/scim/v2/Users",
        headers=bearer(token),
        json={"schemas": [SCIM_USER], "userName": username, **extra},
    )


def _create_group(client, token, name, members=()):
    return client.post(
        "/scim/v2/Groups",
        headers=bearer(token),
        json={"displayName": name, "members": [{"value": member} for member in members]},
    )


def _patch(client, token, path, *operations):
    return client.patch(
        path, headers=bearer(token), json={"schemas": [PATCH], "Operations": list(operations)}
    )


def _memberships(username: str) -> dict[str, tuple[str, str]]:
    with get_session(POSTGRES_URL) as session:
        rows = (
            session.execute(select(models.UserTenant).where(models.UserTenant.username == username))
            .scalars()
            .all()
        )
        return {row.tenant_id: (row.role, row.source) for row in rows}


def _account(username: str) -> models.User:
    with get_session(POSTGRES_URL) as session:
        row = session.get(models.User, username)
        session.expunge(row)
        return row


def _setup(tmp_path, monkeypatch, **overrides):
    settings = make_settings(
        tmp_path, oidc_role_map={"vm-ops": "operator", "vm-admins": "admin"}, **overrides
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    beta = _tenant(client, admin, "Beta")
    settings.idp_group_map = {
        "acme-ops": [{"tenant_id": acme, "role": "operator"}],
        "acme-view": [{"tenant_id": acme, "role": "viewer"}],
        "beta-ops": [{"tenant_id": beta, "role": "operator"}],
    }
    return settings, client, admin, acme, beta


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


def test_only_a_scim_token_reaches_scim_and_it_reaches_nothing_else(tmp_path, monkeypatch):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    service = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["*"], "role": "admin"},
    ).json()["token"]

    assert client.get("/scim/v2/Users", headers=bearer(token)).status_code == 200
    # A person's session and a tenant's integration are not provisioning.
    assert client.get("/scim/v2/Users", headers=admin).status_code == 401
    assert client.get("/scim/v2/Users", headers=bearer(service)).status_code == 401
    assert client.get("/scim/v2/Users").status_code == 401
    # And the provisioning token is nobody's session.
    assert client.get("/api/users", headers=bearer(token)).status_code == 401
    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_issuing_a_scim_token_is_platform_admin_work(tmp_path, monkeypatch):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")
    assert (
        client.post(
            "/api/auth/scim-tokens", headers=operator, json={"name": "x", "all_tenants": True}
        ).status_code
        == 403
    )
    # Bound to nothing, to both, or an admin grant on a tenant-bound token.
    for body in (
        {"name": "x"},
        {"name": "x", "all_tenants": True, "tenant_ids": [acme]},
        {"name": "x", "tenant_ids": [acme], "grant_platform_admin": True},
    ):
        assert client.post("/api/auth/scim-tokens", headers=admin, json=body).status_code == 422
    assert (
        client.post(
            "/api/auth/scim-tokens", headers=admin, json={"name": "x", "tenant_ids": ["nope"]}
        ).status_code
        == 404
    )

    token = _scim_token(client, admin, tenant_ids=[acme])
    listed = client.get("/api/auth/scim-tokens", headers=admin).json()
    assert listed[0]["tenant_ids"] == [acme]
    assert "token" not in listed[0] or listed[0]["token"] is None
    token_id = listed[0]["token_id"]
    assert client.post(f"/api/auth/scim-tokens/{token_id}/revoke", headers=admin).status_code == 200
    assert client.get("/scim/v2/Users", headers=bearer(token)).status_code == 401
    created = client.get("/api/audit?action=scim_token.create", headers=admin).json()["items"]
    assert created[0]["actor"] == "admin"


def test_discovery_documents(tmp_path, monkeypatch):
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    config = client.get("/scim/v2/ServiceProviderConfig", headers=bearer(token))
    assert config.status_code == 200
    assert config.headers["content-type"].startswith("application/scim+json")
    assert config.json()["patch"]["supported"] is True
    types = client.get("/scim/v2/ResourceTypes", headers=bearer(token)).json()
    assert {item["id"] for item in types["Resources"]} == {"User", "Group"}
    schemas = client.get("/scim/v2/Schemas", headers=bearer(token)).json()
    assert {item["name"] for item in schemas["Resources"]} == {"User", "Group"}


# --------------------------------------------------------------------------- #
# Users and groups through an installation-wide token
# --------------------------------------------------------------------------- #


def test_a_user_is_provisioned_granted_by_group_and_deactivated(tmp_path, monkeypatch):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)

    created = client.post(
        "/scim/v2/Users",
        headers={**bearer(token), "Content-Type": "application/scim+json"},
        content=json.dumps(
            {
                "schemas": [SCIM_USER],
                "userName": "erin",
                "emails": [{"value": "Erin@Example.com", "primary": True}],
            }
        ),
    )
    assert created.status_code == 201, created.text
    assert created.json()["id"] == "erin"
    account = _account("erin")
    assert account.password_hash == ""
    assert account.email == "erin@example.com"
    assert account.email_verified is False
    # No group yet, so no access: without this the account would fall back to
    # the default tenant with the default role, which no mapping granted.
    assert account.disabled_source == "idp"
    assert created.json()["active"] is True
    assert _create_user(client, token, "erin").status_code == 409

    found = client.get('/scim/v2/Users?filter=userName eq "erin"', headers=bearer(token)).json()
    assert found["totalResults"] == 1
    assert (
        client.get('/scim/v2/Users?filter=emails eq "x"', headers=bearer(token)).status_code == 400
    )

    group = _create_group(client, token, "acme-ops", members=["erin"])
    assert group.status_code == 201, group.text
    assert _memberships("erin") == {acme: ("operator", "idp")}
    assert _account("erin").disabled_at is None

    # Entra sends booleans as strings.
    assert (
        _patch(
            client,
            token,
            "/scim/v2/Users/erin",
            {"op": "Replace", "path": "active", "value": "False"},
        ).status_code
        == 200
    )
    account = _account("erin")
    assert account.disabled_source == "scim"
    assert client.get("/scim/v2/Users/erin", headers=bearer(token)).json()["active"] is False
    # Okta's shape for the same thing, and back.
    assert (
        _patch(
            client, token, "/scim/v2/Users/erin", {"op": "replace", "value": {"active": True}}
        ).status_code
        == 200
    )
    assert _account("erin").disabled_at is None

    # DELETE deactivates; the account and its history stay.
    assert client.delete("/scim/v2/Users/erin", headers=bearer(token)).status_code == 204
    assert _account("erin").disabled_source == "scim"

    trail = client.get("/api/audit?resource_id=erin", headers=admin).json()["items"]
    actions = {row["action"] for row in trail}
    assert {"user.create", "membership.grant", "user.disable"} <= actions
    assert all(row["actor"] == "scim-token:directory" for row in trail)
    assert all(row["actor_type"] == "service_token" for row in trail)


def test_leaving_a_group_ends_the_membership_and_the_sessions(tmp_path, monkeypatch, provider):
    settings = sso_settings(
        tmp_path, oidc_role_claim="groups", oidc_role_map={"vm-ops": "operator"}
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}
    token = _scim_token(client, admin, all_tenants=True)

    assert _create_user(client, token, "erin", externalId="idp-erin").status_code == 201
    group_id = _create_group(client, token, "acme-ops", members=["erin"]).json()["id"]

    # The SCIM account signs in through SSO: linked by the subject the
    # provisioning client sent as externalId, JIT off.
    login = callback(
        client, provider, start_login(client), preferred_username="erin", sub="idp-erin"
    )
    assert login.status_code == 200, login.text
    session_token = login.json()["access_token"]
    assert client.get("/api/auth/me", headers=bearer(session_token)).json()["tenants"] == [acme]

    removed = _patch(
        client,
        token,
        f"/scim/v2/Groups/{group_id}",
        {"op": "remove", "path": 'members[value eq "erin"]'},
    )
    assert removed.status_code == 200, removed.text
    assert _memberships("erin") == {}
    assert _account("erin").disabled_source == "idp"
    assert client.get("/api/auth/me", headers=bearer(session_token)).status_code == 401


def test_a_scim_token_cannot_make_an_admin_unless_issued_to(tmp_path, monkeypatch):
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    plain = _scim_token(client, admin, all_tenants=True, name="plain")
    assert _create_user(client, plain, "erin").status_code == 201
    # A group mapped to admin is not the plain token's to hold: holding it
    # would be choosing who the next admin-capable push promotes.
    assert _create_group(client, plain, "vm-admins", members=["erin"]).status_code == 403
    assert _account("erin").role == "viewer"

    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True, name="strong")
    assert _create_user(client, strong, "fred").status_code == 201
    group_id = _create_group(client, strong, "vm-admins", members=["fred"]).json()["id"]
    assert _account("fred").role == "admin"
    # And the plain token may not take the admin away again either.
    assert client.delete("/scim/v2/Users/fred", headers=bearer(plain)).status_code == 403
    assert _account("fred").disabled_at is None
    assert client.delete(f"/scim/v2/Groups/{group_id}", headers=bearer(plain)).status_code == 404
    assert _account("fred").role == "admin"


def test_a_plain_token_cannot_plant_a_member_in_the_admin_group(tmp_path, monkeypatch):
    """Two tokens, neither enough alone (review of #316).

    The plain token's change used to be stored and ignored; the next resync of
    the account by an admin-capable token — about anything at all — then read
    the planted membership and promoted it.
    """
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    plain = _scim_token(client, admin, all_tenants=True, name="plain")
    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True, name="strong")
    assert _create_user(client, strong, "fred").status_code == 201
    group_id = _create_group(client, strong, "vm-admins", members=["fred"]).json()["id"]
    assert _create_user(client, plain, "erin").status_code == 201

    planted = _patch(
        client,
        plain,
        f"/scim/v2/Groups/{group_id}",
        {"op": "add", "path": "members", "value": [{"value": "erin"}]},
    )
    assert planted.status_code == 404
    # An unrelated push about erin by the admin-capable directory.
    assert _create_group(client, strong, "acme-view", members=["erin"]).status_code == 201
    assert _account("erin").role == "viewer"


def test_a_group_mapped_to_admin_after_it_was_pushed_grants_no_admin(tmp_path, monkeypatch):
    """A group grants no more than the token that created it could.

    Pushed unmapped by the plain token, mapped to admin by an operator later:
    the admin-capable token's next resync of a member must not promote them.
    """
    settings, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    plain = _scim_token(client, admin, all_tenants=True, name="plain")
    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True, name="strong")
    assert _create_user(client, plain, "erin").status_code == 201
    assert _create_group(client, plain, "vm-root", members=["erin"]).status_code == 201
    settings.oidc_role_map["vm-root"] = "admin"

    assert _create_group(client, strong, "acme-view", members=["erin"]).status_code == 201
    assert _account("erin").role == "viewer"


def test_local_and_break_glass_accounts_are_not_scim_s(tmp_path, monkeypatch):
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch, break_glass_users=["operator"])
    token = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True)
    # Visible — a client checks the name before it creates — but not writable.
    assert client.get("/scim/v2/Users/viewer", headers=bearer(token)).status_code == 200
    for username in ("viewer", "operator", "admin"):
        response = _patch(
            client,
            token,
            f"/scim/v2/Users/{username}",
            {"op": "replace", "path": "active", "value": False},
        )
        assert response.status_code == 403, (username, response.text)
        assert response.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
        assert _account(username).disabled_at is None


def test_a_person_s_disable_is_not_undone_by_scim(tmp_path, monkeypatch):
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    assert _create_user(client, token, "erin").status_code == 201
    assert _create_group(client, token, "acme-ops", members=["erin"]).status_code == 201
    assert (
        client.put("/api/users/erin/disabled", headers=admin, json={"disabled": True}).status_code
        == 200
    )

    refused = _patch(
        client, token, "/scim/v2/Users/erin", {"op": "replace", "path": "active", "value": True}
    )
    assert refused.status_code == 403
    assert _account("erin").disabled_at is not None


# --------------------------------------------------------------------------- #
# A token held to some tenants
# --------------------------------------------------------------------------- #


def test_a_tenant_bound_token_stays_inside_its_tenants(tmp_path, monkeypatch):
    _, client, admin, acme, beta = _setup(tmp_path, monkeypatch)
    everywhere = _scim_token(client, admin, all_tenants=True, name="hq")
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")

    # An account the HQ directory placed in beta only: invisible to acme's.
    assert _create_user(client, everywhere, "bob").status_code == 201
    assert _create_group(client, everywhere, "beta-ops", members=["bob"]).status_code == 201
    assert client.get("/scim/v2/Users/bob", headers=bearer(scoped)).status_code == 404
    assert client.get("/scim/v2/Users", headers=bearer(scoped)).json()["totalResults"] == 0
    assert client.delete("/scim/v2/Users/bob", headers=bearer(scoped)).status_code == 404
    # Nor its group, nor a group mapped outside acme or to a global role.
    assert client.get("/scim/v2/Groups", headers=bearer(scoped)).json()["totalResults"] == 0
    assert _create_group(client, scoped, "beta-ops-2").status_code == 201  # unmapped: its own
    settings_map_outside = _create_group(client, scoped, "vm-ops")
    assert settings_map_outside.status_code == 403

    # Inside acme it provisions and grants as usual.
    assert _create_user(client, scoped, "carol").status_code == 201
    assert _create_group(client, scoped, "acme-ops", members=["carol"]).status_code == 201
    assert _memberships("carol") == {acme: ("operator", "idp")}
    assert _account("carol").disabled_at is None

    # bob joins acme through the HQ directory: now acme's token sees him, may
    # change his acme membership, but may not deactivate an account that also
    # belongs to beta.
    group_id = client.get(
        '/scim/v2/Groups?filter=displayName eq "acme-ops"', headers=bearer(everywhere)
    ).json()["Resources"][0]["id"]
    assert (
        _patch(
            client,
            everywhere,
            f"/scim/v2/Groups/{group_id}",
            {"op": "add", "path": "members", "value": [{"value": "bob"}]},
        ).status_code
        == 200
    )
    assert client.get("/scim/v2/Users/bob", headers=bearer(scoped)).status_code == 200
    assert client.delete("/scim/v2/Users/bob", headers=bearer(scoped)).status_code == 403
    assert _account("bob").disabled_at is None
    removed = _patch(
        client,
        scoped,
        f"/scim/v2/Groups/{group_id}",
        {"op": "remove", "path": 'members[value eq "bob"]'},
    )
    assert removed.status_code == 200, removed.text
    assert _memberships("bob") == {beta: ("operator", "idp")}

    # And the global role is out of its reach altogether.
    assert _account("carol").role == "viewer"


def test_a_tenant_bound_push_leaves_the_idp_s_grants_elsewhere_alone(tmp_path, monkeypatch):
    """The resync a tenant-bound token triggers is held to its tenants too.

    carol holds an IdP grant in beta that no SCIM group of hers explains — an
    SSO login granted it. Recomputing her access from her SCIM groups alone,
    across every tenant, would remove it; acme's directory has no say there.
    """
    _, client, admin, acme, beta = _setup(tmp_path, monkeypatch)
    scoped = _scim_token(client, admin, tenant_ids=[acme])
    assert _create_user(client, scoped, "carol").status_code == 201
    with get_session(POSTGRES_URL) as session:
        session.add(
            models.UserTenant(
                username="carol",
                tenant_id=beta,
                role="viewer",
                created_at=datetime.now(UTC),
                created_by="oidc:test",
                source="idp",
            )
        )
    assert _create_group(client, scoped, "acme-ops", members=["carol"]).status_code == 201
    assert _memberships("carol") == {acme: ("operator", "idp"), beta: ("viewer", "idp")}


def test_renaming_a_group_out_of_scope_is_refused(tmp_path, monkeypatch):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    scoped = _scim_token(client, admin, tenant_ids=[acme])
    group_id = _create_group(client, scoped, "acme-view").json()["id"]
    response = _patch(
        client,
        scoped,
        f"/scim/v2/Groups/{group_id}",
        {"op": "replace", "path": "displayName", "value": "beta-ops"},
    )
    assert response.status_code == 403
    assert (
        client.get(f"/scim/v2/Groups/{group_id}", headers=bearer(scoped)).json()["displayName"]
        == "acme-view"
    )


def test_deleting_a_group_takes_its_grants_with_it(tmp_path, monkeypatch):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    assert _create_user(client, token, "erin").status_code == 201
    group_id = _create_group(client, token, "acme-ops", members=["erin"]).json()["id"]
    assert _memberships("erin") == {acme: ("operator", "idp")}
    assert client.delete(f"/scim/v2/Groups/{group_id}", headers=bearer(token)).status_code == 204
    assert _memberships("erin") == {}
    deleted = client.get("/api/audit?action=scim_group.delete", headers=admin).json()["items"]
    assert deleted[0]["before"]["members"] == ["erin"]


def test_erasure_takes_the_scim_group_memberships(tmp_path, monkeypatch):
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    assert _create_user(client, token, "erin").status_code == 201
    group_id = _create_group(client, token, "acme-ops", members=["erin"]).json()["id"]
    assert client.post("/api/users/erin/erase", headers=admin).status_code == 200
    assert client.get(f"/scim/v2/Groups/{group_id}", headers=bearer(token)).json()["members"] == []
    assert client.get("/scim/v2/Users/erin", headers=bearer(token)).status_code == 404


def test_a_person_s_disable_over_scim_s_own_is_the_person_s(tmp_path, monkeypatch):
    """An administrator disabling an account SCIM already deactivated makes
    the lock theirs: the directory's ``active: true`` no longer lifts it."""
    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    assert _create_user(client, token, "erin").status_code == 201
    assert _create_group(client, token, "acme-ops", members=["erin"]).status_code == 201
    assert client.delete("/scim/v2/Users/erin", headers=bearer(token)).status_code == 204
    assert _account("erin").disabled_source == "scim"
    assert (
        client.put("/api/users/erin/disabled", headers=admin, json={"disabled": True}).status_code
        == 200
    )
    assert _account("erin").disabled_source is None

    refused = _patch(
        client, token, "/scim/v2/Users/erin", {"op": "replace", "path": "active", "value": True}
    )
    assert refused.status_code == 403
    assert _account("erin").disabled_at is not None


def test_a_concurrent_create_of_one_username_is_a_conflict(tmp_path, monkeypatch):
    """Two creates of one ``userName`` racing past the existence check: the
    loser is a ``409 uniqueness``, which a directory retries as a lookup, not
    a ``500``."""
    from api.services import scim as scim_service

    _, client, admin, _, _ = _setup(tmp_path, monkeypatch)
    token = _scim_token(client, admin, all_tenants=True)
    real_set_email = scim_service._set_email

    def _the_other_request_commits_first(session, row, email):
        with get_session(POSTGRES_URL) as other:
            other.add(
                models.User(
                    username=row.username,
                    password_hash="",
                    role="viewer",
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                    created_by="scim:other",
                )
            )
        return real_set_email(session, row, email)

    monkeypatch.setattr(scim_service, "_set_email", _the_other_request_commits_first)
    response = _create_user(client, token, "erin")
    assert response.status_code == 409, response.text
    assert response.json()["scimType"] == "uniqueness"


# --------------------------------------------------------------------------- #
# What a token held to some tenants may not do (review of #316)
# --------------------------------------------------------------------------- #


def test_a_group_grants_no_more_than_the_tenants_of_the_token_that_created_it(
    tmp_path, monkeypatch
):
    """acme's directory pushes a group under a name nobody has mapped yet; the
    operator later maps that name to beta. The group must not start granting
    beta — through any token's resync of its members."""
    settings, client, admin, acme, beta = _setup(tmp_path, monkeypatch)
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    everywhere = _scim_token(client, admin, all_tenants=True, name="hq")
    assert _create_user(client, scoped, "mallory").status_code == 201
    assert _create_group(client, scoped, "acme-ops", members=["mallory"]).status_code == 201
    assert _create_group(client, scoped, "beta-admins", members=["mallory"]).status_code == 201

    settings.idp_group_map["beta-admins"] = [{"tenant_id": beta, "role": "admin"}]
    assert _create_group(client, everywhere, "acme-view", members=["mallory"]).status_code == 201
    assert _memberships("mallory") == {acme: ("operator", "idp")}


def test_a_tenant_bound_token_cannot_deactivate_a_platform_admin_in_its_tenant(
    tmp_path, monkeypatch
):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True, name="hq")
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    assert _create_user(client, strong, "boss").status_code == 201
    assert _create_group(client, strong, "vm-admins", members=["boss"]).status_code == 201
    assert _create_group(client, strong, "acme-ops", members=["boss"]).status_code == 201
    # Every membership boss holds is in acme, and still: a platform admin.
    assert set(_memberships("boss")) == {acme}
    assert client.get("/scim/v2/Users/boss", headers=bearer(scoped)).status_code == 200
    assert client.delete("/scim/v2/Users/boss", headers=bearer(scoped)).status_code == 403
    assert _account("boss").disabled_at is None


def test_a_tenant_bound_token_cannot_put_another_tenant_s_account_in_its_group(
    tmp_path, monkeypatch
):
    _, client, admin, acme, beta = _setup(tmp_path, monkeypatch)
    everywhere = _scim_token(client, admin, all_tenants=True, name="hq")
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    assert _create_user(client, everywhere, "bob").status_code == 201
    assert _create_group(client, everywhere, "beta-ops", members=["bob"]).status_code == 201

    created = _create_group(client, scoped, "acme-ops", members=["bob"])
    assert created.status_code == 400, created.text
    group_id = _create_group(client, scoped, "acme-ops").json()["id"]
    added = _patch(
        client,
        scoped,
        f"/scim/v2/Groups/{group_id}",
        {"op": "add", "path": "members", "value": [{"value": "bob"}]},
    )
    assert added.status_code == 400, added.text
    assert _memberships("bob") == {beta: ("operator", "idp")}


def test_a_tenant_bound_token_cannot_remove_a_member_it_cannot_see(tmp_path, monkeypatch):
    """bob sits in an acme-mapped group whose role acme does not have, so the
    group grants him nothing in acme and acme's directory cannot see him."""
    settings, client, admin, acme, beta = _setup(tmp_path, monkeypatch)
    settings.idp_group_map["acme-odd"] = [{"tenant_id": acme, "role": "no-such-role"}]
    everywhere = _scim_token(client, admin, all_tenants=True, name="hq")
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    assert _create_user(client, everywhere, "bob").status_code == 201
    assert _create_group(client, everywhere, "beta-ops", members=["bob"]).status_code == 201
    group_id = _create_group(client, everywhere, "acme-odd", members=["bob"]).json()["id"]
    assert client.get("/scim/v2/Users/bob", headers=bearer(scoped)).status_code == 404

    removed = _patch(
        client,
        scoped,
        f"/scim/v2/Groups/{group_id}",
        {"op": "remove", "path": 'members[value eq "bob"]'},
    )
    assert removed.status_code == 400, removed.text
    members = client.get(f"/scim/v2/Groups/{group_id}", headers=bearer(everywhere)).json()
    assert [member["value"] for member in members["members"]] == ["bob"]


def test_a_tenant_bound_token_does_not_own_an_account_in_no_tenant(
    tmp_path, monkeypatch, provider
):
    """An account in no membership is inside every binding (the empty set is a
    subset of anything). Owning it on that strength let one tenant's directory
    create ``ciso`` deactivated and lock the real one out of SSO for good."""
    settings = sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_role_claim="groups",
        oidc_role_map={"vm-ops": "operator"},
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    scoped = _scim_token(client, admin, tenant_ids=[acme])

    assert _create_user(client, scoped, "ciso", active=False).status_code == 403
    assert users_service.get_user("ciso") is None
    login = callback(
        client, provider, start_login(client), preferred_username="ciso", sub="idp-ciso",
        groups=["vm-ops"],
    )
    assert login.status_code == 200, login.text


def test_a_placeholder_of_a_tenant_bound_token_does_not_capture_a_login(
    tmp_path, monkeypatch, provider
):
    """An account a tenant-bound token created and never granted anything is
    not linked to the identity it names: the login goes on as if it were not
    there, rather than into an account that directory alone controls."""
    settings = sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_role_claim="groups",
        oidc_role_map={"vm-ops": "operator"},
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    scoped = _scim_token(client, admin, tenant_ids=[acme])
    assert _create_user(client, scoped, "holder", externalId="idp-ciso").status_code == 201
    # In no group: disabled as the IdP's, so it is not the default tenant's.
    assert _account("holder").disabled_source == "idp"

    login = callback(
        client, provider, start_login(client), preferred_username="ciso", sub="idp-ciso",
        groups=["vm-ops"],
    )
    assert login.status_code == 200, login.text
    assert login.json()["username"] == "ciso"
    assert _account("holder").oidc_subject is None


# --------------------------------------------------------------------------- #
# Linking a SCIM account at its first SSO login (review of #316)
# --------------------------------------------------------------------------- #


def _sso_with_scim(tmp_path, monkeypatch, **overrides):
    settings = sso_settings(
        tmp_path,
        oidc_role_claim="groups",
        oidc_role_map={"vm-admins": "admin", "vm-ops": "operator"},
        **overrides,
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True)
    return settings, client, admin, strong


def test_an_unverified_address_does_not_link_a_scim_account(tmp_path, monkeypatch, provider):
    """The username of a login can come from an ``email`` claim nobody
    verified (no ``preferred_username``, or ``OCTO_OIDC_USERNAME_CLAIM=email``).
    Linking by it handed a SCIM-provisioned platform admin to whoever typed
    that address into their IdP profile."""
    _, client, _, strong = _sso_with_scim(tmp_path, monkeypatch)
    assert (
        _create_user(
            client, strong, "root@corp.example", emails=[{"value": "root@corp.example"}]
        ).status_code
        == 201
    )
    assert (
        _create_group(client, strong, "vm-admins", members=["root@corp.example"]).status_code
        == 201
    )
    assert _account("root@corp.example").role == "admin"

    response = callback(
        client,
        provider,
        start_login(client),
        sub="attacker-sub",
        email="root@corp.example",
        email_verified=False,
    )
    assert response.status_code == 403, response.text
    assert _account("root@corp.example").oidc_subject is None


def test_a_scim_account_is_not_linked_by_username_alone(tmp_path, monkeypatch, provider):
    _, client, _, strong = _sso_with_scim(tmp_path, monkeypatch)
    assert _create_user(client, strong, "erin", externalId="idp-erin").status_code == 201
    assert _create_group(client, strong, "vm-ops", members=["erin"]).status_code == 201
    response = callback(
        client, provider, start_login(client), preferred_username="erin", sub="someone-else"
    )
    assert response.status_code == 403, response.text
    assert _account("erin").oidc_subject is None


def test_a_scim_account_links_by_its_external_id(tmp_path, monkeypatch, provider):
    """``externalId`` is the directory's key for the person; where it carries
    the IdP subject it links whatever the login's username claim says."""
    _, client, _, strong = _sso_with_scim(tmp_path, monkeypatch)
    created = _create_user(client, strong, "erin", externalId="idp-erin")
    assert created.json()["externalId"] == "idp-erin"
    assert _create_group(client, strong, "vm-ops", members=["erin"]).status_code == 201
    response = callback(
        client, provider, start_login(client), preferred_username="e.smith", sub="idp-erin"
    )
    assert response.status_code == 200, response.text
    assert response.json()["username"] == "erin"
    assert _account("erin").oidc_subject == "idp-erin"
    # Another account cannot claim the same key.
    clash = _create_user(client, strong, "erin2", externalId="idp-erin")
    assert clash.status_code == 409


def test_a_scim_account_links_by_a_verified_address(tmp_path, monkeypatch, provider):
    _, client, _, strong = _sso_with_scim(tmp_path, monkeypatch)
    assert (
        _create_user(client, strong, "erin", emails=[{"value": "erin@corp.example"}]).status_code
        == 201
    )
    assert _create_group(client, strong, "vm-ops", members=["erin"]).status_code == 201
    response = callback(
        client,
        provider,
        start_login(client),
        preferred_username="e.smith",
        sub="idp-erin",
        email="erin@corp.example",
        email_verified=True,
    )
    assert response.status_code == 200, response.text
    assert response.json()["username"] == "erin"


def test_a_scim_account_given_a_password_is_no_longer_linked_by_scim(
    tmp_path, monkeypatch, provider
):
    _, client, _, strong = _sso_with_scim(tmp_path, monkeypatch)
    assert _create_user(client, strong, "erin", externalId="idp-erin").status_code == 201
    assert _create_group(client, strong, "vm-ops", members=["erin"]).status_code == 201
    with get_session(POSTGRES_URL) as session:
        session.get(models.User, "erin").password_hash = "$2b$12$not-a-real-hash"
    response = callback(client, provider, start_login(client), sub="idp-erin")
    assert response.status_code == 403, response.text
    assert _account("erin").oidc_subject is None


def test_only_an_account_scim_created_is_linked_by_scim_s_identifiers(
    tmp_path, monkeypatch, provider
):
    """An account without a password that something else made, carrying an
    unverified address, is not SCIM's to hand to a login."""
    _, client, _, _ = _sso_with_scim(tmp_path, monkeypatch)
    now = datetime.now(UTC)
    with get_session(POSTGRES_URL) as session:
        session.add(
            models.User(
                username="ops-bot",
                password_hash="",
                role="operator",
                created_at=now,
                updated_at=now,
                created_by="admin",
                email="ops@corp.example",
                email_verified=False,
                scim_external_id="idp-ops",
            )
        )
        session.flush()
        session.add(
            models.UserTenant(
                username="ops-bot", tenant_id="default", role="viewer", created_at=now
            )
        )
    response = callback(
        client,
        provider,
        start_login(client),
        sub="idp-ops",
        email="ops@corp.example",
        email_verified=True,
    )
    assert response.status_code == 403, response.text
    assert _account("ops-bot").oidc_subject is None


def test_an_erased_scim_account_is_never_linked(tmp_path, monkeypatch, provider):
    _, client, admin, strong = _sso_with_scim(tmp_path, monkeypatch)
    assert _create_user(client, strong, "erin", externalId="idp-erin").status_code == 201
    assert _create_group(client, strong, "vm-ops", members=["erin"]).status_code == 201
    assert client.post("/api/users/erin/erase", headers=admin).status_code == 200
    assert _account("erin").scim_external_id is None
    # Even with the identifiers left behind, a tombstone links nothing.
    with get_session(POSTGRES_URL) as session:
        row = session.get(models.User, "erin")
        row.scim_external_id = "idp-erin"
        row.email = "erin@corp.example"
        row.disabled_at = None
        row.disabled_source = None
    response = callback(
        client,
        provider,
        start_login(client),
        sub="idp-erin",
        email="erin@corp.example",
        email_verified=True,
    )
    assert response.status_code == 403, response.text
    assert _account("erin").oidc_subject is None


def test_a_tenant_bound_token_edits_its_new_account_but_cannot_lock_it(tmp_path, monkeypatch):
    """Directories send attributes in a ``PATCH`` right after the create; that
    is the creator's to make on an account it has granted nothing yet. A
    deactivation is not, and neither is any change to another tenant's
    account it can see."""
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    everywhere = _scim_token(client, admin, all_tenants=True, name="hq")
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    assert _create_user(client, scoped, "carol").status_code == 201
    edited = _patch(
        client,
        scoped,
        "/scim/v2/Users/carol",
        {"op": "replace", "path": "externalId", "value": "idp-carol"},
        {"op": "replace", "path": "emails", "value": [{"value": "carol@acme.example"}]},
    )
    assert edited.status_code == 200, edited.text
    assert _account("carol").scim_external_id == "idp-carol"
    locked = _patch(
        client, scoped, "/scim/v2/Users/carol", {"op": "replace", "path": "active", "value": False}
    )
    assert locked.status_code == 403

    # bob: HQ's, in acme and beta. Visible to acme's token, not its to re-key.
    assert _create_user(client, everywhere, "bob", externalId="idp-bob").status_code == 201
    assert _create_group(client, everywhere, "acme-ops", members=["bob"]).status_code == 201
    assert _create_group(client, everywhere, "beta-ops", members=["bob"]).status_code == 201
    rekeyed = _patch(
        client,
        scoped,
        "/scim/v2/Users/bob",
        {"op": "replace", "path": "externalId", "value": "idp-mallory"},
    )
    assert rekeyed.status_code == 403
    assert _account("bob").scim_external_id == "idp-bob"


# --------------------------------------------------------------------------- #
# Link keys, global roles and revoked tokens (second review of #316)
# --------------------------------------------------------------------------- #


def test_a_tenant_bound_token_cannot_rekey_an_account_another_token_created(
    tmp_path, monkeypatch, provider
):
    """``externalId`` and the address decide whose first SSO login lands in an
    unlinked account. HQ's ``ciso`` holds memberships in acme only, so acme's
    token "owned" it — and could point it at an identity of its choosing, and
    with it the global role HQ's directory gave it."""
    settings, client, admin, strong = _sso_with_scim(tmp_path, monkeypatch)
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    assert _create_user(client, strong, "ciso", externalId="idp-ciso").status_code == 201
    assert _create_group(client, strong, "acme-ops", members=["ciso"]).status_code == 201
    assert _create_group(client, strong, "vm-ops", members=["ciso"]).status_code == 201
    assert set(_memberships("ciso")) == {acme}
    assert _account("ciso").role == "operator"

    for operation in (
        {"op": "replace", "path": "externalId", "value": "idp-mallory"},
        {"op": "replace", "path": "emails", "value": [{"value": "mallory@acme.example"}]},
    ):
        response = _patch(client, scoped, "/scim/v2/Users/ciso", operation)
        assert response.status_code == 403, response.text
    put = client.put(
        "/scim/v2/Users/ciso",
        headers=bearer(scoped),
        json={"schemas": [SCIM_USER], "userName": "ciso", "externalId": "idp-mallory"},
    )
    assert put.status_code == 403, put.text
    # Nor may it lock an account carrying a global role above viewer.
    assert client.delete("/scim/v2/Users/ciso", headers=bearer(scoped)).status_code == 403
    account = _account("ciso")
    assert account.scim_external_id == "idp-ciso"
    assert account.email is None
    assert account.disabled_at is None

    response = callback(
        client, provider, start_login(client), preferred_username="m", sub="idp-mallory"
    )
    assert response.status_code == 403, response.text
    assert _account("ciso").oidc_subject is None


def test_only_the_creator_or_an_admin_capable_token_rekeys_an_unlinked_account(
    tmp_path, monkeypatch
):
    _, client, admin, acme, _ = _setup(tmp_path, monkeypatch)
    plain = _scim_token(client, admin, all_tenants=True, name="hq")
    other = _scim_token(client, admin, all_tenants=True, name="hr")
    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True, name="iam")
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    assert _create_user(client, plain, "erin", externalId="idp-erin").status_code == 201
    assert _create_group(client, plain, "acme-view", members=["erin"]).status_code == 201

    def rekey(token, value):
        return _patch(
            client, token, "/scim/v2/Users/erin",
            {"op": "replace", "path": "externalId", "value": value},
        )

    assert rekey(scoped, "idp-x").status_code == 403
    assert rekey(other, "idp-x").status_code == 403
    assert rekey(plain, "idp-erin-2").status_code == 200
    assert rekey(strong, "idp-erin-3").status_code == 200
    assert _account("erin").scim_external_id == "idp-erin-3"
    # Once somebody has signed in to it, the stored subject is the identity
    # and the keys are attributes the account's owners may change.
    with get_session(POSTGRES_URL) as session:
        linked = session.get(models.User, "erin")
        linked.oidc_issuer, linked.oidc_subject = "https://idp.example", "idp-erin-3"
    assert rekey(scoped, "idp-erin-4").status_code == 200
    # Lifecycle is not a link key: the tenant's token still deactivates an
    # account wholly inside its tenant.
    assert client.delete("/scim/v2/Users/erin", headers=bearer(scoped)).status_code == 204


def test_revoking_a_scim_token_neither_strips_nor_extends_what_its_groups_grant(
    tmp_path, monkeypatch
):
    """Its groups are the directory's data, not the credential: revoking the
    credential stops further changes through it, and an unrelated push by
    another token must not read the revoked token's groups as granting
    nothing (a mass revocation) — nor as granting more than its binding."""
    settings, client, admin, acme, beta = _setup(tmp_path, monkeypatch)
    scoped = _scim_token(client, admin, tenant_ids=[acme], name="acme-directory")
    everywhere = _scim_token(client, admin, all_tenants=True, name="hq")
    token_id = next(
        row["token_id"]
        for row in client.get("/api/auth/scim-tokens", headers=admin).json()
        if row["name"] == "acme-directory"
    )
    assert _create_user(client, everywhere, "frank").status_code == 201
    group = _create_group(client, scoped, "acme-ops", members=[])
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    assert _create_group(client, scoped, "beta-later", members=[]).status_code == 201
    assert (
        _patch(
            client, everywhere, f"/scim/v2/Groups/{group_id}",
            {"op": "add", "path": "members", "value": [{"value": "frank"}]},
        ).status_code
        == 200
    )
    assert _memberships("frank") == {acme: ("operator", "idp")}

    revoked = client.post(f"/api/auth/scim-tokens/{token_id}/revoke", headers=admin)
    assert revoked.status_code == 200, revoked.text
    assert client.get("/scim/v2/Users", headers=bearer(scoped)).status_code == 401

    # An unrelated push by another token resyncs frank.
    settings.idp_group_map["beta-later"] = [{"tenant_id": beta, "role": "admin"}]
    assert _create_group(client, everywhere, "beta-ops", members=["frank"]).status_code == 201
    assert _memberships("frank") == {
        acme: ("operator", "idp"),
        beta: ("operator", "idp"),
    }
    # The way out is removing the group, by a token that may.
    assert client.delete(f"/scim/v2/Groups/{group_id}", headers=bearer(everywhere)).status_code == 204
    assert _memberships("frank") == {beta: ("operator", "idp")}
