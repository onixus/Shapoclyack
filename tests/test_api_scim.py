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

    assert _create_user(client, token, "erin").status_code == 201
    group_id = _create_group(client, token, "acme-ops", members=["erin"]).json()["id"]

    # The SCIM account signs in through SSO: linked by the username the
    # provisioning client asserted, JIT off.
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
    assert _create_group(client, plain, "vm-admins", members=["erin"]).status_code == 201
    # Mapped to admin, and ignored: the next best mapping is none, so the
    # default role — and the account stays without access.
    assert _account("erin").role == "viewer"

    strong = _scim_token(client, admin, all_tenants=True, grant_platform_admin=True, name="strong")
    assert _create_user(client, strong, "fred").status_code == 201
    group_id = client.get(
        '/scim/v2/Groups?filter=displayName eq "vm-admins"', headers=bearer(strong)
    ).json()["Resources"][0]["id"]
    assert (
        _patch(
            client,
            strong,
            f"/scim/v2/Groups/{group_id}",
            {"op": "add", "path": "members", "value": [{"value": "fred"}]},
        ).status_code
        == 200
    )
    assert _account("fred").role == "admin"
    # And the plain token may not take the admin away again either.
    assert client.delete("/scim/v2/Users/fred", headers=bearer(plain)).status_code == 403
    assert _account("fred").disabled_at is None


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
