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

    # Taken out of acme-ops at the IdP. Still in vm-ops, but that places her
    # in no tenant: the login is refused rather than let into `default`.
    second = _login(client, provider, groups=["vm-ops"])
    assert second.status_code == 403, second.text
    assert _memberships("dana") == {}
    # The session issued while the membership existed is over (#314): a token
    # that still carried it would make the removal take effect at its expiry.
    assert client.get("/api/auth/me", headers=bearer(old_token)).status_code == 401

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
    # JIT's tenant-claim grant is not the resync's (it never reads the claim)...
    assert _memberships("dana")["default"] == ("viewer", "local")
    # ...and the previous release wrote it with no source column at all: the
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


def test_a_member_cannot_take_over_their_own_idp_membership(tmp_path, monkeypatch, provider):
    """Review of #316: a tenant admin by IdP group re-granted herself the same
    role, the row became ``local``, and taking her out of the group at the IdP
    no longer removed it — the one thing the mode exists for, undone by the
    person it is meant to cut off."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-admins": [{"tenant_id": acme, "role": "admin"}]}

    first = _login(client, provider, groups=["vm-ops", "acme-admins"])
    assert first.status_code == 200, first.text
    assert _memberships("dana") == {acme: ("admin", "idp")}
    pin = client.put(
        f"/api/tenants/{acme}/members/dana",
        headers=bearer(first.json()["access_token"]),
        json={"role": "admin"},
    )
    assert pin.status_code == 403, pin.text
    assert _memberships("dana") == {acme: ("admin", "idp")}

    # In no tenant any more: refused, not let into `default`.
    assert _login(client, provider, groups=["vm-ops"]).status_code == 403
    assert _memberships("dana") == {}


def test_taking_over_an_idp_membership_shows_in_the_trail(tmp_path, monkeypatch, provider):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}
    assert _login(client, provider, groups=["vm-ops", "acme-ops"]).status_code == 200

    # The same role: without the source in the document this row read as a
    # no-op, and the takeover was invisible.
    assert (
        client.put(
            f"/api/tenants/{acme}/members/dana", headers=admin, json={"role": "operator"}
        ).status_code
        == 200
    )
    grants = _audit(client, admin, action="membership.grant", resource_id="dana", actor="admin")
    assert grants[0]["before"] == {"role": "operator", "source": "idp"}
    assert grants[0]["after"] == {"role": "operator", "source": "local"}


def _overage_login(client, provider, **claims):
    return callback(
        client, provider, start_login(client), preferred_username="dana", sub="idp-dana", **claims
    )


@pytest.mark.parametrize(
    "claims",
    [
        # Entra ID over its group limit: the claim is replaced by a pointer.
        {"_claim_names": {"groups": "src1"}, "_claim_sources": {"src1": {"endpoint": "x"}}},
        {"hasgroups": True},
        # A pointer next to a list is still a pointer: the list is not all of them.
        {"groups": [], "_claim_names": {"groups": "src1"}},
        # Not sent at all.
        {},
    ],
    ids=["claim-names", "hasgroups", "pointer-and-list", "absent"],
)
def test_a_token_that_does_not_list_the_groups_changes_nothing(
    tmp_path, monkeypatch, provider, claims
):
    """No groups claim is "the groups are not here", not "in no group": acting
    on it disabled every Entra user over the group limit at each login."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}
    assert _login(client, provider, groups=["vm-ops", "acme-ops"]).status_code == 200

    response = _overage_login(client, provider, **claims)
    assert response.status_code == 200, response.text
    assert _memberships("dana") == {acme: ("operator", "idp")}
    account = _account("dana")
    assert account.disabled_at is None
    assert account.role == "operator"


def test_jit_does_not_provision_from_a_token_that_does_not_list_the_groups(
    tmp_path, monkeypatch, provider
):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    response = _overage_login(client, provider, hasgroups=True)
    assert response.status_code == 403
    assert users_service.get_user("dana") is None


def test_a_group_mapped_to_a_role_the_tenant_no_longer_has_revokes_nothing(
    tmp_path, monkeypatch, provider
):
    """A map entry naming a role the tenant does not have — the role renamed
    while the map did not name it, and the map left on the old name: the
    mapping is wrong, not the person's groups, and the resync must not act on
    the membership it may have granted."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    defined = client.post(
        f"/api/tenants/{acme}/roles",
        headers=admin,
        json={"role_id": "analyst", "rank": 1, "permissions": ["audit.read"]},
    )
    assert defined.status_code == 201, defined.text
    settings.idp_group_map = {"acme-analysts": [{"tenant_id": acme, "role": "analyst"}]}
    assert _login(client, provider, groups=["vm-ops", "acme-analysts"]).status_code == 200
    assert _memberships("dana") == {acme: ("analyst", "idp")}

    mapped, settings.idp_group_map = settings.idp_group_map, {}
    renamed = client.patch(
        f"/api/tenants/{acme}/roles/analyst", headers=admin, json={"role_id": "soc-analyst"}
    )
    assert renamed.status_code == 200, renamed.text
    settings.idp_group_map = mapped
    # Another tenant's entry naming the new name explains nothing here.
    settings.idp_group_map["other-soc"] = [{"tenant_id": "default", "role": "soc-analyst"}]
    assert _memberships("dana") == {acme: ("soc-analyst", "idp")}
    assert _login(client, provider, groups=["vm-ops", "acme-analysts"]).status_code == 200
    assert _memberships("dana") == {acme: ("soc-analyst", "idp")}


def test_a_scope_that_may_not_grant_admin_does_not_demote_one(tmp_path, monkeypatch):
    """The reconcile contract itself, below the callers that today never ask
    it to: a role change from ``admin`` is an admin-capable scope's only."""
    from api.services import idp_sync

    settings = _authoritative(tmp_path)
    configured_client(tmp_path, monkeypatch, settings=settings)
    with get_session(POSTGRES_URL) as session:
        row = session.get(models.User, "admin")
        row.password_hash = ""
        result = idp_sync.reconcile(
            session,
            settings,
            row,
            ["vm-ops"],
            scope=idp_sync.SyncScope(allow_admin=False),
            audit=None,
        )
        assert result.role is None
        assert row.role == "admin"
        session.rollback()


def _analyst_role(client, admin, tenant_id: str) -> None:
    defined = client.post(
        f"/api/tenants/{tenant_id}/roles",
        headers=admin,
        json={"role_id": "analyst", "rank": 1, "permissions": ["audit.read"]},
    )
    assert defined.status_code == 201, defined.text


def test_a_broken_mapping_does_not_keep_a_grant_another_group_gave(
    tmp_path, monkeypatch, provider
):
    """One entry of the map naming a role the tenant does not have froze every
    IdP membership the person held there — including one a healthy group gave.
    Taken out of that group, they kept it: removal stopped revoking."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    _analyst_role(client, admin, acme)
    settings.idp_group_map = {
        "acme-admins": [{"tenant_id": acme, "role": "admin"}],
        "acme-analysts": [{"tenant_id": acme, "role": "analyst"}],
    }
    assert _login(client, provider, groups=["vm-ops", "acme-admins", "acme-analysts"]).status_code == 200
    assert _memberships("dana") == {acme: ("admin", "idp")}

    # The operator's typo (or a role gone from under the map).
    settings.idp_group_map["acme-analysts"] = [{"tenant_id": acme, "role": "analyts"}]
    first = _login(client, provider, groups=["vm-ops", "acme-admins", "acme-analysts"])
    assert first.status_code == 200, first.text
    assert _memberships("dana") == {acme: ("admin", "idp")}

    # Out of acme-admins at the IdP: the admin grant goes, broken map or not
    # (and with it her last tenant, so the login is refused).
    second = _login(client, provider, groups=["vm-ops", "acme-analysts"])
    assert second.status_code == 403, second.text
    assert _memberships("dana") == {}


def test_a_broken_mapping_lowers_a_grant_to_what_the_healthy_groups_give(
    tmp_path, monkeypatch, provider
):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {
        "acme-admins": [{"tenant_id": acme, "role": "admin"}],
        "acme-view": [{"tenant_id": acme, "role": "viewer"}],
        "acme-odd": [{"tenant_id": acme, "role": "no-such-role"}],
    }
    assert _login(client, provider, groups=["vm-ops", "acme-admins", "acme-odd"]).status_code == 200
    assert _memberships("dana") == {acme: ("admin", "idp")}
    assert _login(client, provider, groups=["vm-ops", "acme-view", "acme-odd"]).status_code == 200
    assert _memberships("dana") == {acme: ("viewer", "idp")}


def test_the_mode_without_a_groups_claim_configured_stays_off(tmp_path, monkeypatch, provider):
    """No ``OCTO_OIDC_ROLE_CLAIM`` means no login lists any group; read as "in
    no mapped group" it would disable every SSO account at its next login."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    assert _login(client, provider, groups=["vm-ops"]).status_code == 200
    settings.oidc_role_claim = ""
    again = _login(client, provider, groups=["vm-ops"])
    assert again.status_code == 200, again.text
    assert _account("dana").disabled_at is None


@pytest.mark.parametrize("required", [False, True])
def test_a_token_without_the_groups_claim_is_counted_and_optionally_read_as_none(
    tmp_path, monkeypatch, provider, required
):
    """Okta leaves an empty groups claim out of the token. By default that is
    "not listed" (the resync is skipped, and counted); an installation whose
    IdP always sends the claim says so, and then its absence is "no groups"."""
    from api.services import metrics as metrics_service

    settings = _authoritative(tmp_path, idp_groups_claim_required=required)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}
    assert _login(client, provider, groups=["vm-ops", "acme-ops"]).status_code == 200

    def skipped() -> float:
        return metrics_service.REGISTRY.get_sample_value("octo_idp_resync_skipped_total") or 0.0

    before = skipped()
    response = _overage_login(client, provider)
    if required:
        assert response.status_code == 403, response.text
        assert _memberships("dana") == {}
        assert _account("dana").disabled_source == "idp"
        assert skipped() == before
    else:
        assert response.status_code == 200, response.text
        assert _memberships("dana") == {acme: ("operator", "idp")}
        assert skipped() == before + 1

    # Entra ID's overage is "not listed" either way.
    before = skipped()
    _overage_login(client, provider, hasgroups=True)
    assert skipped() == before + 1


def test_losing_the_last_tenant_does_not_fall_back_to_the_default_one(
    tmp_path, monkeypatch, provider
):
    """Review of #316 (CR-507): an account with no membership acts in `default`
    with its global role. Taken out of her last tenant group but still in a
    group mapped to a global role, dana went from 403 on `default` to 200
    there — a removal at the IdP that widened her access."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}

    first = _login(client, provider, groups=["vm-ops", "acme-ops"])
    assert first.status_code == 200, first.text
    old = bearer(first.json()["access_token"])
    assert client.get("/api/assets", headers=old, params={"tenant_id": "default"}).status_code == 403

    refused = _login(client, provider, groups=["vm-ops"])
    assert refused.status_code == 403, refused.text
    account = _account("dana")
    assert account.disabled_source == "idp"
    assert account.role == "operator"
    assert client.get("/api/assets", headers=old, params={"tenant_id": "default"}).status_code == 401
    disables = _audit(client, admin, action="user.disable", resource_id="dana")
    assert disables[0]["after"]["reason"] == "in no tenant"

    # A group that places her again undoes the IdP's own disable.
    back = _login(client, provider, groups=["vm-ops", "acme-ops"])
    assert back.status_code == 200, back.text
    assert _account("dana").disabled_at is None
    assert _memberships("dana") == {acme: ("operator", "idp")}


def test_jit_provisions_no_account_a_group_places_in_no_tenant(tmp_path, monkeypatch, provider):
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {"acme-ops": [{"tenant_id": acme, "role": "operator"}]}

    assert _login(client, provider, groups=["vm-ops"]).status_code == 403
    assert users_service.get_user("dana") is None
    # A platform admin is confined by no tenant, so the role alone lets one in.
    admin_login = _login(client, provider, username="ada", sub="idp-ada", groups=["vm-admins"])
    assert admin_login.status_code == 200, admin_login.text


def test_an_installation_that_maps_default_keeps_people_there(tmp_path, monkeypatch, provider):
    """The fallback is refused, not the tenant: mapping `default` explicitly
    is how an installation that places people in tenants keeps one there."""
    settings = _authoritative(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    settings.idp_group_map = {
        "acme-ops": [{"tenant_id": acme, "role": "operator"}],
        "staff": [{"tenant_id": "default", "role": "viewer"}],
    }
    response = _login(client, provider, groups=["vm-ops", "staff"])
    assert response.status_code == 200, response.text
    assert _memberships("dana") == {"default": ("viewer", "idp")}


def test_a_jit_tenant_claim_grant_survives_switching_authoritative_on(
    tmp_path, monkeypatch, provider
):
    """Review of #316 (CR-507): JIT's tenant-claim membership was written as
    the IdP's, and the resync — which never reads the claim — revoked it at
    the first login after the switch, landing ivy in `default`."""
    settings = sso_settings(
        tmp_path,
        oidc_jit_provisioning=True,
        oidc_role_claim="groups",
        oidc_role_map={"vm-ops": "operator"},
        oidc_tenant_claim="tenant",
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    acme = _tenant(client, admin, "Acme")
    login = dict(username="ivy", sub="idp-ivy", groups=["vm-ops"], tenant=acme)
    assert _login(client, provider, **login).status_code == 200
    assert _memberships("ivy") == {acme: ("operator", "local")}

    settings.idp_authoritative = True
    response = _login(client, provider, **login)
    assert response.status_code == 200, response.text
    assert _memberships("ivy") == {acme: ("operator", "local")}
    token = bearer(response.json()["access_token"])
    assert client.get("/api/assets", headers=token, params={"tenant_id": acme}).status_code == 200
    assert client.get("/api/assets", headers=token, params={"tenant_id": "default"}).status_code == 403
