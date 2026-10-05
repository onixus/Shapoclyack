"""IdP-authoritative SSO logins: role, memberships and access follow the groups (#316).

Before this, the identity provider decided an account's role and tenant once,
at just-in-time provisioning. Every test here drives a real callback through
the in-process provider of tests/test_oidc.py and then reads what the database
and the audit trail say — the resync is a side effect of signing in, so that is
where it has to be observed.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from api.db import models
from api.db.engine import get_session
from api.services import oidc
from api.services import users as users_service
from tests.conftest import POSTGRES_URL, auth_headers, bearer, configured_client, requires_postgres
from tests.test_api_auth_oidc import callback, sso_settings, start_login
from tests.test_oidc import FakeProvider

pytestmark = requires_postgres


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(oidc, "_http_get_json", fake.get_json)
    monkeypatch.setattr(oidc, "_http_post_form", fake.post_form)
    return fake


ROLE_MAP = {"vm-admins": "admin", "vm-ops": "operator"}


def _authoritative(tmp_path, **overrides):
    return sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_role_claim="groups",
        oidc_role_map=dict(ROLE_MAP),
        idp_authoritative=True,
        **overrides,
    )


def _tenant(client, admin, name: str) -> str:
    response = client.post("/api/tenants", headers=admin, json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()["tenant_id"]


def _login(client, provider, *, username="dana", sub="idp-dana", groups=(), **claims):
    return callback(
        client,
        provider,
        start_login(client),
        preferred_username=username,
        sub=sub,
        groups=list(groups),
        **claims,
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


def _audit(client, admin, **query) -> list[dict]:
    params = "&".join(f"{key}={value}" for key, value in query.items())
    response = client.get(f"/api/audit?{params}", headers=admin)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_a_login_without_the_group_loses_the_membership_and_its_sessions(
    tmp_path, monkeypatch, provider
):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}

    first = _login(client, provider, groups=["vm-ops", "acme-ops"])
    assert first.status_code == 200, first.text
    assert first.json()["role"] == "operator"
    assert _memberships("dana") == {acme: ("operator", "idp")}
    old_token = first.json()["access_token"]
    assert client.get("/api/auth/me", headers=bearer(old_token)).status_code == 200

    # Taken out of acme-ops at the IdP.
    second = _login(client, provider, groups=["vm-ops"])
    assert second.status_code == 200, second.text
    assert _memberships("dana") == {}
    # The session issued while the membership existed is over (#314): a token
    # that still carried it would make the removal take effect at its expiry.
    assert client.get("/api/auth/me", headers=bearer(old_token)).status_code == 401
    assert (
        client.get("/api/auth/me", headers=bearer(second.json()["access_token"])).status_code == 200
    )

    revoked = _audit(client, admin, action="membership.revoke", resource_id="dana")
    assert len(revoked) == 1
    assert revoked[0]["tenant_id"] == acme
    assert revoked[0]["before"] == {"role": "operator", "source": "idp"}
    assert revoked[0]["actor"].startswith("oidc:")


def test_the_global_role_follows_the_groups_both_ways(tmp_path, monkeypatch, provider):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")

    assert _login(client, provider, groups=["vm-admins"]).json()["role"] == "admin"
    demoted = _login(client, provider, groups=["vm-ops"])
    assert demoted.status_code == 200
    assert demoted.json()["role"] == "operator"
    assert _account("dana").role == "operator"

    changes = _audit(client, admin, action="user.role_change", resource_id="dana")
    assert [(row["before"]["role"], row["after"]["role"]) for row in changes] == [
        ("admin", "operator")
    ]


def test_an_account_in_no_mapped_group_is_disabled_and_comes_back_with_one(
    tmp_path, monkeypatch, provider
):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")

    first = _login(client, provider, groups=["vm-ops"])
    assert first.status_code == 200
    old_token = first.json()["access_token"]

    refused = _login(client, provider, groups=["marketing"])
    assert refused.status_code == 403
    account = _account("dana")
    # Committed although the login that caused it was refused.
    assert account.disabled_at is not None
    assert account.disabled_source == "idp"
    assert client.get("/api/auth/me", headers=bearer(old_token)).status_code == 401
    disables = _audit(client, admin, action="user.disable", resource_id="dana")
    assert disables[0]["after"]["disabled"] is True
    assert disables[0]["after"]["source"] == "idp"

    # Back in a mapped group: the IdP undoes its own disable.
    again = _login(client, provider, groups=["vm-ops"])
    assert again.status_code == 200, again.text
    assert _account("dana").disabled_at is None


def test_a_person_s_disable_is_not_undone_by_the_next_login(tmp_path, monkeypatch, provider):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    assert _login(client, provider, groups=["vm-ops"]).status_code == 200

    assert (
        client.put("/api/users/dana/disabled", headers=admin, json={"disabled": True}).status_code
        == 200
    )
    refused = _login(client, provider, groups=["vm-ops"])
    assert refused.status_code == 403
    assert _account("dana").disabled_at is not None
    assert _account("dana").disabled_source is None


def test_locally_granted_memberships_survive_switching_authoritative_mode_on(
    tmp_path, monkeypatch, provider
):
    """The post-upgrade state: an installation that has been granting SSO users
    access by hand turns the mode on. Nothing a person granted may go."""
    settings = sso_settings(tmp_path, oidc_jit_provisioning=True, oidc_role_claim="groups")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    beta = _tenant(client, admin, "Beta")

    # Provisioned before the switch, then granted beta by an administrator.
    assert _login(client, provider, groups=["vm-ops"]).status_code == 200
    assert (
        client.put(
            f"/api/tenants/{beta}/members/dana", headers=admin, json={"role": "operator"}
        ).status_code
        == 200
    )
    # This release's JIT marks its own grant as the IdP's...
    assert _memberships("dana")["default"] == ("viewer", "idp")
    # ...but the previous release wrote it with no source column at all: the
    # server default is what an upgraded database holds for such a row.
    with get_session(POSTGRES_URL) as session:
        session.execute(
            text("DELETE FROM user_tenants WHERE username = 'dana' AND tenant_id = 'default'")
        )
        session.execute(
            text(
                "INSERT INTO user_tenants (username, tenant_id, role, created_at) "
                "VALUES ('dana', 'default', 'viewer', now())"
            )
        )
    assert _memberships("dana") == {
        beta: ("operator", "local"),
        "default": ("viewer", "local"),
    }

    settings.idp_authoritative = True
    settings.oidc_role_map = dict(ROLE_MAP)
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "viewer"}]}

    assert _login(client, provider, groups=["vm-ops", "acme-ops"]).status_code == 200
    assert _memberships("dana") == {
        acme: ("viewer", "idp"),
        beta: ("operator", "local"),
        "default": ("viewer", "local"),
    }

    # Out of every mapped group: the account is disabled, and the local grants
    # are still there for the day it is re-enabled — disabled, not wiped.
    assert _login(client, provider, groups=[]).status_code == 403
    assert _memberships("dana") == {
        beta: ("operator", "local"),
        "default": ("viewer", "local"),
    }


def test_a_person_regranting_an_idp_membership_takes_it_over(tmp_path, monkeypatch, provider):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "viewer"}]}

    assert _login(client, provider, groups=["vm-ops", "acme-ops"]).status_code == 200
    assert (
        client.put(
            f"/api/tenants/{acme}/members/dana", headers=admin, json={"role": "operator"}
        ).status_code
        == 200
    )
    assert _memberships("dana") == {acme: ("operator", "local")}
    assert _login(client, provider, groups=["vm-ops"]).status_code == 200
    assert _memberships("dana") == {acme: ("operator", "local")}


def test_the_break_glass_account_is_never_resynced(tmp_path, monkeypatch, provider):
    settings = _authoritative(tmp_path, break_glass_users=["operator"])
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    assert (
        client.put(
            "/api/users/operator/email",
            headers=admin,
            json={"email": "op@example.com", "verified": True},
        ).status_code
        == 200
    )

    # In no mapped group at all: anyone else would be disabled here.
    response = _login(
        client,
        provider,
        username="operator",
        sub="idp-op",
        groups=[],
        email="op@example.com",
        email_verified=True,
    )
    assert response.status_code == 200, response.text
    account = _account("operator")
    assert account.disabled_at is None
    assert account.role == "operator"
    assert _audit(client, admin, resource_id="operator", action="user.disable") == []


def test_jit_in_authoritative_mode_creates_no_account_for_an_unmapped_identity(
    tmp_path, monkeypatch, provider
):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    assert _login(client, provider, groups=["marketing"]).status_code == 403
    assert users_service.get_user("dana") is None


def test_with_the_mode_off_a_login_changes_nothing(tmp_path, monkeypatch, provider):
    settings = sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_role_claim="groups",
        oidc_role_map=dict(ROLE_MAP),
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    assert _login(client, provider, groups=["vm-admins"]).json()["role"] == "admin"
    # The pre-#316 behaviour: the role was decided at provisioning.
    assert _login(client, provider, groups=[]).json()["role"] == "admin"


def test_the_mode_with_nothing_mapped_stays_off(tmp_path, monkeypatch, provider):
    settings = sso_settings(
        tmp_path, oidc_jit_provisioning=True, oidc_role_claim="groups", idp_authoritative=True
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    assert _login(client, provider, groups=[]).status_code == 200
    assert _login(client, provider, groups=[]).status_code == 200
    assert _account("dana").disabled_at is None
