"""MFA policy and step-up by what an account may do in a tenant (#504).

The defect: ``OCTO_MFA_REQUIRED_ROLES=admin`` was compared with ``users.role``
alone, while since #318 the authority to run a tenant comes from a
*membership*. A global ``viewer`` holding ``admin`` — or ``scope-approver``, or
a tenant-defined role with ``tenant.member.manage`` — in some tenant signed in
with a password and nothing else, and then handed out that tenant's roles
without a step-up, because the membership and role routes did not ask for one.

Every test below fails against the API before #504: the requirement tests
because the policy never looked at a membership, the step-up tests because the
routes answered a plain password session with 200.

Time is controlled rather than waited on, as in ``tests/test_api_mfa.py``; the
clock starts from the real present so no test carries a calendar date.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import insert

from api.core import totp
from api.db import models
from api.db.engine import get_session
from tests.conftest import (
    POSTGRES_URL,
    TEST_USERS,
    auth_headers,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


class Clock:
    """``api.services.mfa._now``, under the test's control. Naive UTC."""

    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)

    def next_code(self, secret: str) -> str:
        self.advance(totp.STEP_SECONDS)
        return totp.code_at(secret, self.now)


@pytest.fixture
def clock(monkeypatch) -> Clock:
    instance = Clock()
    monkeypatch.setattr("api.services.mfa._now", instance)
    return instance


# --- helpers ------------------------------------------------------------------


def _setup(tmp_path, monkeypatch, **overrides):
    """A client with **no** MFA policy yet, and the settings object it runs on.

    Every test builds its tenants, accounts and memberships first and turns the
    policy on afterwards (:func:`_policy`) — which is also how it happens in
    production: a redeploy over a database that already has them. Configuring
    the policy up front would confine the platform admin the fixtures act as.
    """
    settings = make_settings(tmp_path, **overrides)
    return configured_client(tmp_path, monkeypatch, settings=settings), settings


def _policy(settings, **fields) -> None:
    for name, value in fields.items():
        assert hasattr(settings, name), f"unknown Settings field: {name}"
        setattr(settings, name, value)


def _password(username: str) -> str:
    return TEST_USERS.get(username) or f"{username}-password-1234"


def _admin(client) -> dict[str, str]:
    return auth_headers(client, "admin")


def _tenant(client, tenant_id: str) -> None:
    created = client.post(
        "/api/tenants", headers=_admin(client), json={"name": tenant_id, "tenant_id": tenant_id}
    )
    assert created.status_code == 201, created.text


def _user(client, username: str, role: str = "viewer") -> None:
    created = client.post(
        "/api/users",
        headers=_admin(client),
        json={"username": username, "password": _password(username), "role": role},
    )
    assert created.status_code == 201, created.text


def _grant(client, tenant_id: str, username: str, role: str, admin=None) -> None:
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}",
        headers=admin or _admin(client),
        json={"role": role},
    )
    assert granted.status_code == 200, granted.text


def _login(client, username: str) -> dict:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": _password(username)}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _enrol(client, headers, clock: Clock, username: str) -> str:
    setup = client.post("/api/auth/mfa/totp/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    confirm = client.post(
        "/api/auth/mfa/totp/confirm",
        headers=headers,
        json={"code": totp.code_at(secret, clock.now), "password": _password(username)},
    )
    assert confirm.status_code == 200, confirm.text
    return secret


def _signed_in_with_code(client, username: str, clock: Clock, secret: str) -> dict[str, str]:
    challenge = _login(client, username)
    assert challenge["mfa_token"], challenge
    verified = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": challenge["mfa_token"], "code": clock.next_code(secret)},
    )
    assert verified.status_code == 200, verified.text
    return bearer(verified.json()["access_token"])


def _admin_with_mfa(client, clock: Clock) -> dict[str, str]:
    """The platform admin, enrolled and freshly verified: what acts once a policy is on."""
    secret = _enrol(client, _admin(client), clock, "admin")
    return _signed_in_with_code(client, "admin", clock, secret)


def _confined(client, headers) -> bool:
    """Whether this session is held to the MFA routes."""
    response = client.get("/api/runs", headers=headers)
    if response.status_code == 403:
        detail = response.json()["detail"]
        assert "multi-factor" in detail or "security key" in detail, detail
        return True
    assert response.status_code == 200, response.text
    return False


# --- The requirement follows tenant authority -----------------------------------


def test_a_tenant_admin_with_a_global_viewer_role_is_held_to_mfa_for_admins(
    tmp_path, monkeypatch
):
    """The scenario of the issue: "MFA for admins" covers the admin of a tenant."""
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "boss")
    assert session["mfa_required"] is True
    headers = bearer(session["access_token"])
    assert _confined(client, headers)
    # Not only in the tenant it administers: a session is one session, and a
    # password that reached it reached every tenant the account is in.
    assert client.get("/api/runs?tenant_id=acme", headers=headers).status_code == 403

    me = client.get("/api/auth/me", headers=headers).json()
    assert me["role"] == "viewer"
    assert me["mfa_required"] is True
    assert me["mfa_pending"] is True

    status = client.get("/api/auth/mfa", headers=headers).json()
    assert status["required"] is True
    assert {
        (reason["tenant_id"], reason["role"]) for reason in status["required_because"]
    } == {("acme", "admin")}


@pytest.mark.parametrize("role", ["scope-approver", "risk-approver", "token-admin"])
def test_the_approval_and_credential_roles_are_held_to_mfa_for_admins(
    tmp_path, monkeypatch, role
):
    """Rank 1, so no rank comparison catches them — the permission does."""
    client, settings = _setup(tmp_path, monkeypatch)
    _user(client, "specialist")
    _grant(client, "default", "specialist", role)
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "specialist")
    assert session["mfa_required"] is True
    assert _confined(client, bearer(session["access_token"]))


@pytest.mark.parametrize("role", ["viewer", "auditor", "scan-operator"])
def test_a_membership_with_no_administrative_permission_is_not_held(
    tmp_path, monkeypatch, role
):
    """The requirement is about power over the tenant, not about having a membership."""
    client, settings = _setup(tmp_path, monkeypatch)
    _user(client, "reader")
    _grant(client, "default", "reader", role)
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "reader")
    assert session["mfa_required"] is False
    headers = bearer(session["access_token"])
    assert not _confined(client, headers)
    assert client.get("/api/auth/mfa", headers=headers).json()["required_because"] == []


def test_a_rank_3_tenant_role_is_held_by_the_permissions_it_carries(tmp_path, monkeypatch):
    """A role the tenant wrote itself is covered by what it may do, not by its name.

    ``OCTO_MFA_REQUIRED_PERMISSIONS`` names the authority and no role list is
    set at all, so nothing but the tenant role's own ``role_permissions`` rows
    can be what puts the requirement there.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    defined = client.post(
        "/api/tenants/acme/roles",
        headers=_admin(client),
        json={
            "role_id": "people-lead",
            "rank": 3,
            "permissions": ["tenant.member.read", "tenant.member.manage", "audit.read"],
        },
    )
    assert defined.status_code == 201, defined.text
    _user(client, "lead")
    _grant(client, "acme", "lead", "people-lead")
    _user(client, "bystander")
    _grant(client, "acme", "bystander", "viewer")
    _policy(settings, mfa_required_permissions=["tenant.member.manage"])

    lead = _login(client, "lead")
    assert lead["mfa_required"] is True
    assert _confined(client, bearer(lead["access_token"]))
    reasons = client.get("/api/auth/mfa", headers=bearer(lead["access_token"])).json()[
        "required_because"
    ]
    assert reasons == [
        {
            "tenant_id": "acme",
            "role": "people-lead",
            "permissions": ["tenant.member.manage"],
            "phishing_resistant": False,
        }
    ]

    assert _login(client, "bystander")["mfa_required"] is False
    # The global admin holds every permission, so a permission-only policy
    # reaches it as well: it is the platform's admin in every tenant.
    assert _login(client, "admin")["mfa_required"] is True


def test_the_role_list_keeps_meaning_the_global_role(tmp_path, monkeypatch):
    """``OCTO_MFA_REQUIRED_ROLES`` works exactly as before, with the permission policy off.

    The role list means ``users.role`` and nothing else, so
    ``OCTO_MFA_REQUIRED_PERMISSIONS=none`` is a true way back to the old
    behaviour for an installation that has to stage the change: the tenant
    admin is covered by its permissions, not by its role's name.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    _policy(settings, mfa_required_roles=["admin"], mfa_required_permissions=[])

    assert _login(client, "admin")["mfa_required"] is True
    assert _login(client, "boss")["mfa_required"] is False
    assert _login(client, "operator")["mfa_required"] is False

    _policy(settings, mfa_required_roles=["admin", "viewer"])
    # A listed global role still covers its holder, memberships or not.
    assert _login(client, "boss")["mfa_required"] is True


def test_an_explicit_empty_permission_list_turns_the_permission_policy_off(
    tmp_path, monkeypatch
):
    """``OCTO_MFA_REQUIRED_PERMISSIONS=none``: only role names count."""
    client, settings = _setup(tmp_path, monkeypatch)
    _user(client, "approver")
    _grant(client, "default", "approver", "scope-approver")
    _policy(settings, mfa_required_roles=["admin"], mfa_required_permissions=[])
    assert _login(client, "approver")["mfa_required"] is False


def _tenant_role(client, tenant_id: str, role_id: str, rank: int, permissions: list[str]) -> None:
    defined = client.post(
        f"/api/tenants/{tenant_id}/roles",
        headers=_admin(client),
        json={"role_id": role_id, "rank": rank, "permissions": permissions},
    )
    assert defined.status_code == 201, defined.text


def test_a_rank_3_tenant_role_is_held_by_its_rank_under_the_derived_default(
    tmp_path, monkeypatch
):
    """The tenant-admin rank is authority whatever permissions the role lists.

    Rank 3 alone passes every ``require_tenant(Role.admin)`` gate — the SSH
    push, webhooks, notification channels, SLA policies — so a tenant role
    written as ``rank: 3, permissions: []`` administers the tenant as surely as
    the built-in ``admin`` does. "MFA for admins" has to cover it. An explicit
    permission list is the operator saying exactly what it means, and the rank
    does not widen it.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _tenant_role(client, "acme", "deployer", 3, [])
    _user(client, "dep")
    _grant(client, "acme", "dep", "deployer")
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "dep")
    assert session["mfa_required"] is True
    headers = bearer(session["access_token"])
    assert _confined(client, headers)
    assert client.get("/api/auth/mfa", headers=headers).json()["required_because"] == [
        {"tenant_id": "acme", "role": "deployer", "permissions": [], "phishing_resistant": False}
    ]

    _policy(settings, mfa_required_permissions=["scan_scope.approve"])
    assert _login(client, "dep")["mfa_required"] is False

    _policy(
        settings,
        mfa_required_roles=[],
        mfa_required_permissions=None,
        mfa_phishing_resistant_roles=["admin"],
    )
    assert client.get("/api/auth/me", headers=headers).json()["phishing_resistant_required"] is True


def test_the_endpoint_agent_authority_is_held_to_mfa_for_admins(tmp_path, monkeypatch):
    """``endpoint_agent.manage`` replaces the binary every endpoint runs.

    A rank-1 tenant role carrying only that permission is outside every rank
    rule, so the permission itself has to be in the derived set.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _tenant_role(client, "acme", "agent-release", 1, ["endpoint_agent.manage"])
    _user(client, "rel")
    _grant(client, "acme", "rel", "agent-release")
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "rel")
    assert session["mfa_required"] is True
    assert _confined(client, bearer(session["access_token"]))


def test_the_authority_counts_in_whichever_tenant_holds_it(tmp_path, monkeypatch):
    """Not the first membership: a viewer in ``aaa`` who administers ``zzz``.

    Memberships are read in tenant order, so a requirement taken from the first
    one alone would look at ``aaa`` and let the password through.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "aaa")
    _tenant(client, "zzz")
    _user(client, "split")
    _grant(client, "aaa", "split", "viewer")
    _grant(client, "zzz", "split", "admin")
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "split")
    assert session["mfa_required"] is True
    headers = bearer(session["access_token"])
    assert client.get("/api/runs?tenant_id=aaa", headers=headers).status_code == 403
    reasons = client.get("/api/auth/mfa", headers=headers).json()["required_because"]
    assert [(reason["tenant_id"], reason["role"]) for reason in reasons] == [("zzz", "admin")]


def test_the_requirement_is_read_once_per_request(tmp_path, monkeypatch):
    """The confinement check and the route answer from one membership read.

    ``/api/auth/me`` and ``/api/auth/mfa`` both decide the requirement after
    ``get_current_user`` already has for the same request; the second read is
    the same answer at the same moment, so it is taken from the request.
    """
    from api.services import rbac as rbac_service

    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    _policy(settings, mfa_required_roles=["admin"])
    headers = bearer(_login(client, "boss")["access_token"])

    reads: list[str] = []
    real = rbac_service.held_by

    def counted(username, *, global_role):
        reads.append(username)
        return real(username, global_role=global_role)

    monkeypatch.setattr(rbac_service, "held_by", counted)
    assert client.get("/api/auth/me", headers=headers).json()["mfa_pending"] is True
    assert reads == ["boss"]
    reads.clear()
    assert client.get("/api/auth/mfa", headers=headers).json()["required"] is True
    assert reads == ["boss"]
    reads.clear()
    # A global role the list names decides "must enrol" without the memberships.
    _policy(settings, mfa_required_roles=["admin", "viewer"])
    assert _confined(client, headers)
    assert reads == []


# --- Sessions that are already open -----------------------------------------------


def test_a_grant_reaches_a_session_opened_before_it(tmp_path, monkeypatch, clock):
    """Decided per request: the promotion confines the very next call, no re-login.

    The other choice — wait for the session to end — would hand a freshly
    promoted account up to ``OCTO_JWT_EXPIRE_MINUTES`` of tenant
    administration on a password alone, which is the window this issue is about.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _user(client, "climber")
    _grant(client, "default", "climber", "viewer")
    admin = _admin_with_mfa(client, clock)
    _policy(settings, mfa_required_roles=["admin"])

    session = _login(client, "climber")
    assert session["mfa_required"] is False
    headers = bearer(session["access_token"])
    assert not _confined(client, headers)

    _grant(client, "default", "climber", "admin", admin=admin)
    assert _confined(client, headers)
    me = client.get("/api/auth/me", headers=headers).json()
    assert me["mfa_pending"] is True
    assert me["mfa_required"] is True

    # And back: the requirement is the authority, so taking it away lifts it.
    _grant(client, "default", "climber", "viewer", admin=admin)
    assert not _confined(client, headers)


def test_a_role_edit_reaches_its_holders(tmp_path, monkeypatch, clock):
    """Widening a tenant role puts every holder under the policy from their next request."""
    client, settings = _setup(tmp_path, monkeypatch)
    created = client.post(
        "/api/tenants/default/roles",
        headers=_admin(client),
        json={"role_id": "helpdesk", "rank": 1, "permissions": ["tenant.member.read"]},
    )
    assert created.status_code == 201, created.text
    _user(client, "desk")
    _grant(client, "default", "desk", "helpdesk")
    admin = _admin_with_mfa(client, clock)
    _policy(settings, mfa_required_permissions=["tenant.member.manage"])

    headers = bearer(_login(client, "desk")["access_token"])
    assert not _confined(client, headers)

    widened = client.patch(
        "/api/tenants/default/roles/helpdesk",
        headers=admin,
        json={"permissions": ["tenant.member.read", "tenant.member.manage"]},
    )
    assert widened.status_code == 200, widened.text
    assert _confined(client, headers)


# --- After an upgrade: rows an earlier release wrote ----------------------------------


def test_memberships_and_tenant_roles_written_before_the_upgrade_are_covered(
    tmp_path, monkeypatch
):
    """The policy reads what is already in the database, not only what the API writes now.

    The rows below are written with plain SQL, the way migrations 0049/0070 and
    an earlier release's grant left them: a membership naming the built-in
    ``admin``, one naming a tenant role and its ``role_permissions``, and one
    naming a tenant role whose row is gone. Turning the policy on (a redeploy)
    must cover the first two on their open sessions, and must not invent an
    authority for the third — an unresolvable role confers nothing, so it
    requires nothing.
    """
    client, settings = _setup(tmp_path, monkeypatch)
    _tenant(client, "legacy")
    for name in ("old-admin", "old-custom", "old-orphan"):
        _user(client, name)
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(POSTGRES_URL) as session:
        session.execute(
            insert(models.RoleDefinition).values(
                role_id="key-keeper",
                tenant_id="legacy",
                description="written by an earlier release",
                builtin=False,
                rank=1,
                created_at=now,
            )
        )
        session.execute(
            insert(models.RolePermission).values(
                role_id="key-keeper",
                tenant_id="legacy",
                permission_key="tenant.credential.manage",
            )
        )
        session.execute(
            insert(models.UserTenant),
            [
                {"username": "old-admin", "tenant_id": "legacy", "role": "admin", "created_at": now},
                {
                    "username": "old-custom",
                    "tenant_id": "legacy",
                    "role": "key-keeper",
                    "created_at": now,
                },
                {
                    "username": "old-orphan",
                    "tenant_id": "legacy",
                    "role": "deleted-role",
                    "created_at": now,
                },
            ],
        )
    sessions = {
        name: bearer(login(client, name, _password(name)))
        for name in ("old-admin", "old-custom", "old-orphan")
    }
    assert not any(_confined(client, headers) for headers in sessions.values())

    _policy(settings, mfa_required_roles=["admin"])

    assert _confined(client, sessions["old-admin"])
    assert _confined(client, sessions["old-custom"])
    assert not _confined(client, sessions["old-orphan"])


# --- Phishing-resistant counterpart -----------------------------------------------------

_RELYING_PARTY = {
    "webauthn_rp_id": "console.example.test",
    "webauthn_origins": ["https://console.example.test"],
}


def test_the_key_policy_follows_tenant_authority_too(tmp_path, monkeypatch, clock):
    """``OCTO_MFA_PHISHING_RESISTANT_ROLES=admin`` covers a tenant admin's code session."""
    client, settings = _setup(tmp_path, monkeypatch, **_RELYING_PARTY)
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    _policy(settings, mfa_phishing_resistant_roles=["admin"])

    first = bearer(_login(client, "boss")["access_token"])
    # Implicitly MFA-required, so the first session is told to enrol at all.
    assert client.get("/api/auth/me", headers=first).json()["mfa_pending"] is True
    secret = _enrol(client, first, clock, "boss")

    coded = _signed_in_with_code(client, "boss", clock, secret)
    refused = client.get("/api/runs", headers=coded)
    assert refused.status_code == 403
    assert "security key" in refused.json()["detail"]
    me = client.get("/api/auth/me", headers=coded).json()
    assert me["phishing_resistant_required"] is True
    assert me["phishing_resistant_pending"] is True
    status = client.get("/api/auth/mfa", headers=coded).json()
    assert status["phishing_resistant_required"] is True
    assert status["stepup_phishing_resistant"] is True


def test_the_key_policy_by_permission(tmp_path, monkeypatch, clock):
    """``OCTO_MFA_PHISHING_RESISTANT_PERMISSIONS`` alone, on a rank-1 approver."""
    client, settings = _setup(tmp_path, monkeypatch, **_RELYING_PARTY)
    _user(client, "approver")
    _grant(client, "default", "approver", "scope-approver")
    _user(client, "reader")
    _grant(client, "default", "reader", "auditor")
    _policy(settings, mfa_phishing_resistant_permissions=["scan_scope.approve"])

    first = bearer(_login(client, "approver")["access_token"])
    assert client.get("/api/auth/me", headers=first).json()["mfa_pending"] is True
    secret = _enrol(client, first, clock, "approver")
    coded = _signed_in_with_code(client, "approver", clock, secret)
    assert client.get("/api/auth/me", headers=coded).json()["phishing_resistant_pending"] is True

    reader = bearer(_login(client, "reader")["access_token"])
    assert not _confined(client, reader)


def test_a_relayed_code_cannot_strip_a_tenant_admins_keys(tmp_path, monkeypatch, clock):
    """The key policy's side door, for an admin by membership.

    Turning MFA off removes every key, so where policy wants a key of an
    account that holds one, disable must be proved with it (#315). That check
    asked the global role: a tenant admin with a global ``viewer`` role could
    be phished for a password and a code, and the relayed session could clear
    the keys and enrol the attacker's.
    """
    from tests.soft_authenticator import SoftAuthenticator
    from tests.test_api_webauthn import ORIGIN, RP_ID, _register

    client, settings = _setup(
        tmp_path, monkeypatch, webauthn_rp_id=RP_ID, webauthn_origins=[ORIGIN]
    )
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    first = bearer(_login(client, "boss")["access_token"])
    secret = _enrol(client, first, clock, "boss")
    stepped_up = client.post(
        "/api/auth/mfa/verify", headers=first, json={"code": clock.next_code(secret)}
    )
    assert stepped_up.status_code == 200, stepped_up.text
    _register(client, bearer(stepped_up.json()["access_token"]), SoftAuthenticator(ORIGIN))
    _policy(settings, mfa_phishing_resistant_roles=["admin"])

    phished = _signed_in_with_code(client, "boss", clock, secret)
    refused = client.post(
        "/api/auth/mfa/disable",
        headers=phished,
        json={"password": _password("boss"), "code": clock.next_code(secret)},
    )
    assert refused.status_code == 403, refused.text
    assert "needs a recent multi-factor verification" in refused.json()["detail"]
    assert client.get("/api/auth/mfa", headers=phished).json()["webauthn_credentials"] == 1


def test_a_relayed_code_cannot_add_a_key_next_to_a_tenant_admins_own(
    tmp_path, monkeypatch, clock
):
    """The other half of the side door: enrolling the phisher's key.

    Under a key policy a session proved with a code may register a key only
    while the account has none. A tenant admin who already holds one must
    prove the new key with it — asked of what the account holds in its
    tenants, not of the global ``viewer`` role.
    """
    from tests.soft_authenticator import SoftAuthenticator
    from tests.test_api_webauthn import ORIGIN, RP_ID, _register

    client, settings = _setup(
        tmp_path, monkeypatch, webauthn_rp_id=RP_ID, webauthn_origins=[ORIGIN]
    )
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    first = bearer(_login(client, "boss")["access_token"])
    secret = _enrol(client, first, clock, "boss")
    stepped_up = client.post(
        "/api/auth/mfa/verify", headers=first, json={"code": clock.next_code(secret)}
    )
    assert stepped_up.status_code == 200, stepped_up.text
    _register(client, bearer(stepped_up.json()["access_token"]), SoftAuthenticator(ORIGIN))
    _policy(settings, mfa_phishing_resistant_roles=["admin"])

    phished = _signed_in_with_code(client, "boss", clock, secret)
    refused = client.post("/api/auth/mfa/webauthn/register/options", headers=phished)
    assert refused.status_code == 403, refused.text
    assert "one you already hold" in refused.json()["detail"]
    assert client.get("/api/auth/mfa", headers=phished).json()["webauthn_credentials"] == 1


# --- Step-up on the routes that hand out tenant authority ---------------------------------


def _tenant_admin_with_mfa(client, clock: Clock) -> tuple[dict[str, str], dict[str, str]]:
    """A global viewer administering ``acme``: (password-only session, fresh step-up)."""
    _tenant(client, "acme")
    _user(client, "boss")
    _grant(client, "acme", "boss", "admin")
    first = bearer(_login(client, "boss")["access_token"])
    secret = _enrol(client, first, clock, "boss")
    # The session that enrolled has never presented a code at a sign-in or a
    # step-up: what a stolen password plus an open tab would be holding.
    fresh = _signed_in_with_code(client, "boss", clock, secret)
    return first, fresh


def _refused_for_step_up(response) -> None:
    assert response.status_code == 403, response.text
    assert "recent multi-factor verification" in response.json()["detail"]


def test_granting_changing_and_revoking_a_membership_needs_a_step_up(
    tmp_path, monkeypatch, clock
):
    client = configured_client(tmp_path, monkeypatch)
    stale, fresh = _tenant_admin_with_mfa(client, clock)
    _user(client, "colleague")

    for role in ("viewer", "scope-approver"):
        _refused_for_step_up(
            client.put("/api/tenants/acme/members/colleague", headers=stale, json={"role": role})
        )
    granted = client.put(
        "/api/tenants/acme/members/colleague", headers=fresh, json={"role": "viewer"}
    )
    assert granted.status_code == 200, granted.text
    _refused_for_step_up(
        client.put("/api/tenants/acme/members/colleague", headers=stale, json={"role": "admin"})
    )
    _refused_for_step_up(client.delete("/api/tenants/acme/members/colleague", headers=stale))

    members = client.get("/api/tenants/acme/members", headers=fresh).json()
    assert {m["username"]: m["role"] for m in members}["colleague"] == "viewer"

    assert client.delete("/api/tenants/acme/members/colleague", headers=fresh).status_code == 204


def test_tenant_role_crud_needs_a_step_up(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch)
    stale, fresh = _tenant_admin_with_mfa(client, clock)
    body = {"role_id": "soc-lead", "rank": 2, "permissions": ["audit.read", "scan.cancel"]}

    _refused_for_step_up(client.post("/api/tenants/acme/roles", headers=stale, json=body))
    assert client.post("/api/tenants/acme/roles", headers=fresh, json=body).status_code == 201

    _refused_for_step_up(
        client.patch(
            "/api/tenants/acme/roles/soc-lead", headers=stale, json={"permissions": ["audit.read"]}
        )
    )
    _refused_for_step_up(client.delete("/api/tenants/acme/roles/soc-lead", headers=stale))

    # Deleting with reassignment regrants every holder: the same step-up.
    _user(client, "lead")
    assert (
        client.put(
            "/api/tenants/acme/members/lead", headers=fresh, json={"role": "soc-lead"}
        ).status_code
        == 200
    )
    _refused_for_step_up(
        client.delete("/api/tenants/acme/roles/soc-lead?reassign_to=admin", headers=stale)
    )
    roles = {r["role_id"] for r in client.get("/api/rbac/roles?tenant_id=acme", headers=fresh).json()}
    assert "soc-lead" in roles

    moved = client.delete("/api/tenants/acme/roles/soc-lead?reassign_to=viewer", headers=fresh)
    assert moved.status_code == 200, moved.text
    assert moved.json()["memberships_reassigned"] == 1


def test_a_step_up_goes_stale_on_the_membership_routes(tmp_path, monkeypatch, clock):
    client = configured_client(tmp_path, monkeypatch, mfa_stepup_minutes=15)
    _, fresh = _tenant_admin_with_mfa(client, clock)
    _user(client, "colleague")
    clock.advance(16 * 60)
    _refused_for_step_up(
        client.put("/api/tenants/acme/members/colleague", headers=fresh, json={"role": "viewer"})
    )


def test_service_tokens_are_still_refused_by_the_scope_layer(tmp_path, monkeypatch):
    """Step-up lets a service token through by design; ``tenants`` is out of its scope.

    An admin-role, all-scopes token for the tenant is the strongest a tenant
    can mint. It must still reach none of the routes that grant authority.
    """
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "acme")
    minted = client.post(
        "/api/tenants/acme/service-tokens",
        headers=_admin(client),
        json={"name": "integration", "scopes": ["*"], "role": "admin"},
    )
    assert minted.status_code == 201, minted.text
    token = bearer(minted.json()["token"])
    _user(client, "colleague")

    attempts = [
        client.put("/api/tenants/acme/members/colleague", headers=token, json={"role": "admin"}),
        client.delete("/api/tenants/acme/members/colleague", headers=token),
        client.post(
            "/api/tenants/acme/roles",
            headers=token,
            json={"role_id": "token-made", "rank": 1, "permissions": ["audit.read"]},
        ),
        client.patch("/api/tenants/acme/roles/token-made", headers=token, json={"rank": 1}),
        client.delete("/api/tenants/acme/roles/token-made", headers=token),
    ]
    assert [response.status_code for response in attempts] == [403] * len(attempts)
    members = client.get("/api/tenants/acme/members", headers=_admin(client)).json()
    assert "colleague" not in {m["username"] for m in members}


def _platform_admin_sessions(client, clock: Clock) -> tuple[dict[str, str], dict[str, str]]:
    """The platform admin, enrolled: (session never stepped up, fresh step-up)."""
    stale = _admin(client)
    secret = _enrol(client, stale, clock, "admin")
    return stale, _signed_in_with_code(client, "admin", clock, secret)


def test_the_endpoint_agent_build_and_policy_need_a_step_up(tmp_path, monkeypatch, clock):
    """Replacing what every endpoint runs costs what minting a credential does."""
    from api.services import endpoint_agent_mgmt

    client, _ = _setup(tmp_path, monkeypatch)
    endpoint_agent_mgmt.reset_for_tests()
    stale, fresh = _platform_admin_sessions(client, clock)
    upload = {
        "data": {"version": "9.9.9", "platform": "x86_64-pc-windows-msvc"},
        "files": {"binary": ("a.exe", b"MZ-step-up", "application/octet-stream")},
    }
    policy = {"settings": {"log_level": "debug"}}
    try:
        _refused_for_step_up(client.post("/api/endpoint/agent/releases", headers=stale, **upload))
        _refused_for_step_up(client.put("/api/endpoint/agent/policy", headers=stale, json=policy))
        _refused_for_step_up(
            client.put("/api/endpoint/agent/policy/lariska-01", headers=stale, json=policy)
        )
        _refused_for_step_up(client.delete("/api/endpoint/agent/policy", headers=stale))
        _refused_for_step_up(client.delete("/api/endpoint/agent/policy/lariska-01", headers=stale))
        _refused_for_step_up(
            client.delete(
                "/api/endpoint/agent/releases/9.9.9/x86_64-pc-windows-msvc", headers=stale
            )
        )

        stored = client.post("/api/endpoint/agent/releases", headers=fresh, **upload)
        assert stored.status_code == 201, stored.text
        assert (
            client.put("/api/endpoint/agent/policy", headers=fresh, json=policy).status_code
            == 200
        )
        assert client.delete("/api/endpoint/agent/policy", headers=fresh).status_code == 204
        removed = client.delete(
            "/api/endpoint/agent/releases/9.9.9/x86_64-pc-windows-msvc", headers=fresh
        )
        assert removed.status_code == 204
    finally:
        endpoint_agent_mgmt.reset_for_tests()


def test_deciding_a_risk_acceptance_needs_a_step_up(tmp_path, monkeypatch, clock):
    """Approving, rejecting and revoking an acceptance: the paired approval of scan-scope.

    The step-up is a dependency, so it answers before the finding is looked
    up; the fresh session gets past it to the route's own 404.
    """
    client, _ = _setup(tmp_path, monkeypatch)
    stale, fresh = _platform_admin_sessions(client, clock)
    calls = (
        ("post", "/api/vulnerabilities/no-such-finding/exception/approve", {"note": "ok"}),
        ("post", "/api/vulnerabilities/no-such-finding/exception/reject", {"note": "no"}),
        ("delete", "/api/vulnerabilities/no-such-finding/exception", None),
    )
    for method, path, body in calls:
        kwargs = {"json": body} if body is not None else {}
        _refused_for_step_up(getattr(client, method)(path, headers=stale, **kwargs))
        assert getattr(client, method)(path, headers=fresh, **kwargs).status_code == 404


def test_disabling_deleting_and_signing_out_an_account_need_a_step_up(
    tmp_path, monkeypatch, clock
):
    """The account-administration step-ups had a gap: these three end other admins' access.

    Disabling or deleting the other admins, or signing them out, is how an
    open tab keeps an installation to itself — the reason membership revoke
    takes a step-up (#504) applies here word for word.
    """
    client, _ = _setup(tmp_path, monkeypatch)
    _user(client, "leaver")
    stale, fresh = _platform_admin_sessions(client, clock)

    _refused_for_step_up(
        client.put("/api/users/leaver/disabled", headers=stale, json={"disabled": True})
    )
    _refused_for_step_up(client.post("/api/users/leaver/sessions/revoke-all", headers=stale))
    _refused_for_step_up(client.delete("/api/users/leaver", headers=stale))

    assert (
        client.put("/api/users/leaver/disabled", headers=fresh, json={"disabled": True}).status_code
        == 200
    )
    assert client.post("/api/users/leaver/sessions/revoke-all", headers=fresh).status_code == 204
    assert client.delete("/api/users/leaver", headers=fresh).status_code == 204


def test_the_ssh_push_needs_a_step_up(tmp_path, monkeypatch, clock):
    """The push mints a key on the target, so it costs what the key mint costs.

    The step-up answers before the deployment policy or the target is
    consulted; nothing is sent anywhere.
    """
    client, _ = _setup(tmp_path, monkeypatch)
    stale, _ = _platform_admin_sessions(client, clock)
    push = {
        "host": "192.168.10.50",
        "port": 22,
        "username": "root",
        "password": "not-sent",
        "agent_id": "agent-remote-50",
        "expected_host_key": "SHA256:" + "A" * 43,
    }
    _refused_for_step_up(client.post("/api/agent/deploy/ssh", headers=stale, json=push))


# --- Minting a provisioning key is a named permission, not a rank ----------------------


def test_the_console_key_mint_asks_for_the_credential_permission(tmp_path, monkeypatch):
    """``POST /api/agent/deployment-command`` mints what ``POST …/provisioning-keys`` does.

    Its twin has asked for ``tenant.credential.manage`` since #318; this one
    asked for rank 3. So ``token-admin`` — whose whole role is that permission —
    was refused by the console's own button, and a tenant role at rank 3 that
    carries no credential authority minted keys. Same credential, same gate.
    The SSH push mints one as well, and keeps the admin rank on top: it also
    hands the platform a root login on the target.
    """
    client, _ = _setup(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _tenant_role(client, "acme", "deployer", 3, [])
    _user(client, "dep")
    _grant(client, "acme", "dep", "deployer")
    _user(client, "keys")
    _grant(client, "acme", "keys", "token-admin")
    rank_only = bearer(_login(client, "dep")["access_token"])
    token_admin = bearer(_login(client, "keys")["access_token"])

    refused = client.post(
        "/api/agent/deployment-command?tenant_id=acme", headers=rank_only, json={"label": "x"}
    )
    assert refused.status_code == 403, refused.text
    assert "tenant.credential.manage" in refused.json()["detail"]
    minted = client.post(
        "/api/agent/deployment-command?tenant_id=acme", headers=token_admin, json={"label": "y"}
    )
    assert minted.status_code == 201, minted.text

    push = {
        "host": "192.168.10.50",
        "port": 22,
        "username": "root",
        "password": "not-sent",
        "agent_id": "agent-remote-50",
        "expected_host_key": "SHA256:" + "A" * 43,
    }
    pushed = client.post("/api/agent/deploy/ssh?tenant_id=acme", headers=rank_only, json=push)
    assert pushed.status_code == 403, pushed.text
    assert "tenant.credential.manage" in pushed.json()["detail"]
    pushed = client.post("/api/agent/deploy/ssh?tenant_id=acme", headers=token_admin, json=push)
    assert pushed.status_code == 403, pushed.text
    assert "Role 'admin'" in pushed.json()["detail"]


# --- Configuration -----------------------------------------------------------------------


def test_the_permission_variables_parse_unset_none_and_typos(monkeypatch, caplog):
    """Unset derives, ``none`` is empty, an unknown key is dropped loudly."""
    from api.settings import _mfa_permissions

    monkeypatch.delenv("OCTO_MFA_REQUIRED_PERMISSIONS", raising=False)
    assert _mfa_permissions("OCTO_MFA_REQUIRED_PERMISSIONS") is None
    monkeypatch.setenv("OCTO_MFA_REQUIRED_PERMISSIONS", " ")
    assert _mfa_permissions("OCTO_MFA_REQUIRED_PERMISSIONS") is None
    monkeypatch.setenv("OCTO_MFA_REQUIRED_PERMISSIONS", "None")
    assert _mfa_permissions("OCTO_MFA_REQUIRED_PERMISSIONS") == []
    monkeypatch.setenv(
        "OCTO_MFA_REQUIRED_PERMISSIONS", "tenant.member.manage, Audit.Read,tenant.membr.manage"
    )
    assert _mfa_permissions("OCTO_MFA_REQUIRED_PERMISSIONS") == [
        "tenant.member.manage",
        "audit.read",
    ]
    assert "tenant.membr.manage" in caplog.text


def test_a_permission_variable_of_only_typos_refuses_to_start(monkeypatch):
    """Every key unknown is not ``none``: the operator asked for a policy.

    Dropping the typos would leave ``[]``, which is the explicit off switch —
    the derived default suppressed, tenant admins back outside the policy, and
    nothing but a warning to say so.
    """
    from api.settings import _mfa_permissions

    monkeypatch.setenv("OCTO_MFA_REQUIRED_PERMISSIONS", "tenant.members.manage, audit.reed")
    with pytest.raises(ValueError, match="OCTO_MFA_REQUIRED_PERMISSIONS"):
        _mfa_permissions("OCTO_MFA_REQUIRED_PERMISSIONS")


def test_the_derived_default_follows_the_admin_role_only(tmp_path):
    from api.core import permissions as permission_catalog
    from api.services import mfa as mfa_service

    settings = make_settings(tmp_path)
    assert not mfa_service.policy_configured(settings)
    settings.mfa_required_roles = ["operator"]
    assert mfa_service.required_permissions(settings) == frozenset()
    settings.mfa_required_roles = ["admin"]
    assert (
        mfa_service.required_permissions(settings)
        == permission_catalog.TENANT_AUTHORITY_PERMISSIONS
    )
    assert mfa_service.phishing_resistant_permissions(settings) == frozenset()
    settings.mfa_required_permissions = []
    assert mfa_service.required_permissions(settings) == frozenset()
    settings.mfa_phishing_resistant_roles = ["admin"]
    assert mfa_service.phishing_resistant_policy(settings)


def test_a_key_policy_by_permission_needs_a_relying_party_in_prod(tmp_path):
    from api.settings import ENV_PROD, InsecureConfigurationError, _validate_production

    settings = make_settings(
        tmp_path,
        env=ENV_PROD,
        mfa_phishing_resistant_permissions=["tenant.member.manage"],
        public_base_url="",
    )
    with pytest.raises(InsecureConfigurationError) as raised:
        _validate_production(settings, postgres_url_env="OCTO_POSTGRES_URL")
    assert "OCTO_MFA_PHISHING_RESISTANT_PERMISSIONS" in str(raised.value)
