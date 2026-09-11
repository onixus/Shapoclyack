"""Named permissions, the separation-of-duties roles, and tenant self-service (#318).

Before this the platform had three ranked roles, so "read the audit trail"
implied "mint credentials", "approve a scanning scope" implied "run scans", and
every tenant-administration route was the global admin's alone. Each test below
pins one of those separations; every one of them fails on the pre-#318 code,
which is what makes them worth having.
"""

from __future__ import annotations

import re
import typing
from pathlib import Path
from unittest.mock import patch

from api.core import permissions as permission_catalog
from api.db import models
from api.db.engine import get_session
from api.schemas import GlobalRoleName, JobInfo, TenantRoleName
from tests.conftest import (
    approve_scan_scope_via_api,
    auth_headers,
    configured_client,
    login,
    requires_postgres,
)

pytestmark = requires_postgres

_SCOPE = {
    "entries": [
        {"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"},
        {"effect": "allow", "kind": "domain", "value": "*"},
    ]
}


def _admin(client) -> dict[str, str]:
    return auth_headers(client, "admin")


def _account(client, username: str, tenant_id: str, role: str) -> dict[str, str]:
    """An account whose *global* role is viewer, holding ``role`` in one tenant.

    The global role stays the lowest on purpose: it is the only way to prove
    that the authority under test comes from the membership and not from the
    account, which is the shape an installation actually grants these roles in.
    """
    password = f"{username}-password-1234"
    created = client.post(
        "/api/users",
        headers=_admin(client),
        json={"username": username, "password": password, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}",
        headers=_admin(client),
        json={"role": role},
    )
    assert granted.status_code == 200, granted.text
    return {"Authorization": f"Bearer {login(client, username, password)}"}


def _global_account(
    client, username: str, tenant_id: str, role: str, *, global_role: str
) -> dict[str, str]:
    """Like :func:`_account`, but with a global role above ``viewer``.

    Only for the routes that are still gated on the *global* role — the
    cross-tenant listings, which resolve their own tenant set — where a global
    viewer is refused before the membership under test is looked at.
    """
    password = f"{username}-password-1234"
    created = client.post(
        "/api/users",
        headers=_admin(client),
        json={"username": username, "password": password, "role": global_role},
    )
    assert created.status_code == 201, created.text
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}",
        headers=_admin(client),
        json={"role": role},
    )
    assert granted.status_code == 200, granted.text
    return {"Authorization": f"Bearer {login(client, username, password)}"}


def _tenant(client, tenant_id: str) -> None:
    created = client.post(
        "/api/tenants",
        headers=_admin(client),
        json={"name": tenant_id, "tenant_id": tenant_id},
    )
    assert created.status_code == 201, created.text
    approve_scan_scope_via_api(client, tenant_id, _admin(client))


def test_the_seeded_catalogue_matches_the_compiled_role_table(tmp_path, monkeypatch):
    """Migration 0049's seed and api/core/permissions.py must not drift.

    The seed is a frozen copy — a migration that imports application code is a
    migration whose meaning changes after it has run — so this is the check
    that keeps the copy honest. It is also the only thing that would catch a
    permission added to the code and never published to the catalogue the
    console renders.
    """
    client = configured_client(tmp_path, monkeypatch)

    catalogue = client.get("/api/rbac/permissions", headers=auth_headers(client, "viewer"))
    assert catalogue.status_code == 200, catalogue.text
    assert {item["permission_key"]: item["description"] for item in catalogue.json()} == (
        permission_catalog.PERMISSIONS
    )

    roles = client.get("/api/rbac/roles", headers=_admin(client))
    assert roles.status_code == 200, roles.text
    seeded = {role["role_id"]: role for role in roles.json()}
    assert set(seeded) == set(permission_catalog.BUILTIN_ROLES)
    for name, definition in permission_catalog.BUILTIN_ROLES.items():
        assert set(seeded[name]["permissions"]) == set(definition.permissions), name
        assert seeded[name]["rank"] == definition.rank, name
        assert seeded[name]["builtin"] is True
        # "" in the table, absent on the wire: a built-in role is every
        # tenant's, and a consumer comparing this to its own tenant id should
        # not have to know the sentinel.
        assert seeded[name]["tenant_id"] is None


def test_the_grantable_roles_are_the_ones_the_schema_accepts():
    """``GrantMembershipRequest.role`` is a hand-written Literal; keep it in step."""
    assert set(typing.get_args(TenantRoleName)) == set(permission_catalog.TENANT_ROLES)
    # The platform admin is authority, not a grant: offering it as a tenant
    # role would let a tenant admin promote somebody to the whole installation.
    assert permission_catalog.ROLE_PLATFORM_ADMIN not in permission_catalog.TENANT_ROLES


def test_the_risk_approver_role_exists_for_the_approval_workflow():
    """#348 needs the role and the permission to exist; the workflow is its own.

    Asserted here rather than left implicit because this is the whole of what
    #318 owes #348, and a role defined with no route behind it is exactly the
    kind of thing a later cleanup deletes as dead.
    """
    held = permission_catalog.permissions_for(permission_catalog.ROLE_RISK_APPROVER)
    assert held == {permission_catalog.VULNERABILITY_EXCEPTION_APPROVE}
    # Rank 1: approving an accepted risk must not carry the ability to change
    # the finding it is about.
    assert permission_catalog.rank_for(permission_catalog.ROLE_RISK_APPROVER) == 1


def test_an_auditor_reads_the_trail_and_the_config_and_writes_nothing(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    auditor = _account(client, "reviewer", "default", "auditor")

    assert client.get("/api/audit", headers=auditor).status_code == 200
    assert client.get("/api/config", headers=auditor).status_code == 200
    assert client.get("/api/tenants/default/scan-scope", headers=auditor).status_code == 200

    # ...and every write, whichever door it knocks on.
    assert client.put(
        "/api/config", headers=auditor, json={"overrides": {"nuclei.enabled": True}}
    ).status_code == 403
    assert client.post(
        "/api/jobs", headers=auditor, json={"mode": "balanced"}
    ).status_code == 403
    assert client.put(
        "/api/tenants/default/scan-scope", headers=auditor, json=_SCOPE
    ).status_code == 403
    assert client.put(
        "/api/tenants/default/members/operator", headers=auditor, json={"role": "admin"}
    ).status_code == 403
    assert client.post(
        "/api/tenants/default/provisioning-keys", headers=auditor, json={"label": "nope"}
    ).status_code == 403


def test_approving_a_scope_and_running_a_scan_are_two_different_roles(tmp_path, monkeypatch):
    """The separation this issue is named for.

    Pre-#318 both were ``admin``/``operator`` on the rank ladder, so the
    installation could not express "you decide what we may scan" without also
    granting "you run the scans" — or the reverse.
    """
    client = configured_client(tmp_path, monkeypatch)
    approver = _account(client, "scope-boss", "default", "scope-approver")
    runner = _account(client, "scan-hand", "default", "scan-operator")

    assert client.put(
        "/api/tenants/default/scan-scope", headers=approver, json=_SCOPE
    ).status_code == 200
    # The approver cannot use the scope it just widened.
    assert client.post(
        "/api/jobs", headers=approver, json={"mode": "balanced"}
    ).status_code == 403

    # The operator cannot widen the scope it works inside.
    assert client.put(
        "/api/tenants/default/scan-scope", headers=runner, json=_SCOPE
    ).status_code == 403
    fake = JobInfo(
        job_id="job_rbac_1",
        status="queued",
        run_id=None,
        mode="balanced",
        command=["python", "-m", "scanner.main"],
        started_at=None,
        finished_at=None,
        exit_code=None,
        error=None,
        requested_by="scan-hand",
    )
    with patch("api.routes.jobs.jobs_service.start_scan", return_value=fake):
        started = client.post(
            "/api/jobs",
            headers=runner,
            json={"mode": "balanced", "delta": False, "skip_nse": True, "notify": False},
        )
    assert started.status_code == 202, started.text


def test_a_tenant_admin_administers_its_own_tenant_and_no_other(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _tenant(client, "globex")
    acme_admin = _account(client, "acme-boss", "acme", "admin")

    # Self-service: members and credentials of their own tenant.
    assert client.get("/api/tenants/acme/members", headers=acme_admin).status_code == 200
    assert client.put(
        "/api/tenants/acme/members/viewer", headers=acme_admin, json={"role": "auditor"}
    ).status_code == 200
    minted = client.post(
        "/api/tenants/acme/provisioning-keys", headers=acme_admin, json={"label": "rotation"}
    )
    assert minted.status_code == 201, minted.text
    assert client.get("/api/tenants/acme/quota", headers=acme_admin).status_code == 200

    # ...and nothing that decides what their tenant is allowed to be.
    assert client.put(
        "/api/tenants/acme/quota", headers=acme_admin, json={"max_assets": 100000}
    ).status_code == 403
    assert client.put(
        "/api/tenants/acme/scan-scope", headers=acme_admin, json=_SCOPE
    ).status_code == 403
    assert client.post(
        "/api/tenants", headers=acme_admin, json={"name": "mine", "tenant_id": "mine"}
    ).status_code == 403

    # ...and no way up: the global role is the platform's, and a tenant admin
    # who could set it would be one request away from administering every
    # customer on the installation.
    assert client.put(
        "/api/users/viewer/role", headers=acme_admin, json={"role": "admin"}
    ).status_code == 403
    assert client.post(
        "/api/users",
        headers=acme_admin,
        json={"username": "sneaked-in", "password": "sneaked-password-1", "role": "admin"},
    ).status_code == 403

    # ...and nothing at all in a tenant they hold no membership in. The path is
    # the tenant here, so this is the check that a tenant admin cannot walk the
    # customer list by editing the URL.
    assert client.get("/api/tenants/globex/members", headers=acme_admin).status_code == 403
    assert client.post(
        "/api/tenants/globex/provisioning-keys", headers=acme_admin, json={"label": "no"}
    ).status_code == 403


def test_a_token_admin_manages_credentials_and_not_members(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    token_admin = _account(client, "keymaster", "default", "token-admin")

    minted = client.post(
        "/api/tenants/default/provisioning-keys", headers=token_admin, json={"label": "ci"}
    )
    assert minted.status_code == 201, minted.text
    assert client.get(
        "/api/tenants/default/provisioning-keys", headers=token_admin
    ).status_code == 200
    assert client.put(
        "/api/tenants/default/members/viewer", headers=token_admin, json={"role": "admin"}
    ).status_code == 403
    assert client.get("/api/audit", headers=token_admin).status_code == 403


def test_a_viewer_reads_neither_the_configuration_nor_the_fleet_counters(tmp_path, monkeypatch):
    """Two cross-tenant leaks the lowest role used to have (#318).

    ``GET /api/config`` is the installation's scanning posture, and
    ``inventory`` in ``GET /api/system`` counts every tenant and agent on the
    installation — on an MSSP deployment, one customer's viewer being told how
    many other customers there are.
    """
    client = configured_client(tmp_path, monkeypatch)
    viewer = auth_headers(client, "viewer")

    assert client.get("/api/config", headers=viewer).status_code == 403

    seen_by_viewer = client.get("/api/system", headers=viewer)
    assert seen_by_viewer.status_code == 200
    # Nulls, not a refusal: the page keeps working, and the shape is the one
    # every client already handles for "the counts are unavailable".
    assert seen_by_viewer.json()["inventory"] == {
        "tenants": None,
        "agents_total": None,
        "agents_online": None,
    }

    seen_by_admin = client.get("/api/system", headers=_admin(client)).json()["inventory"]
    assert seen_by_admin["tenants"] is not None and seen_by_admin["tenants"] >= 1


def test_a_suspended_tenant_stops_its_people_not_only_its_agents(tmp_path, monkeypatch):
    """``status`` reached the machines and nothing else before #318.

    Suspending a tenant refused its provisioning-key exchange, so no *new*
    agent could join — while every person in the tenant kept reading and
    scanning exactly as before. The platform admin stays exempt, because
    somebody has to be able to look at, and lift, the suspension.
    """
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "paused")
    member = _account(client, "paused-user", "paused", "operator")
    assert client.get("/api/assets?tenant_id=paused", headers=member).status_code == 200

    # No route sets this yet — suspension is #325 — so the state is written
    # where the enforcement will read it from.
    from api.auth import get_settings

    settings = get_settings()
    with get_session(settings.postgres_url) as session:
        session.get(models.Tenant, "paused").status = "suspended"

    refused = client.get("/api/assets?tenant_id=paused", headers=member)
    assert refused.status_code == 403
    assert "suspended" in refused.json()["detail"]
    # The platform admin still reaches it.
    assert client.get("/api/assets?tenant_id=paused", headers=_admin(client)).status_code == 200


def test_a_role_grant_is_recorded_in_the_audit_trail(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _account(client, "newcomer", "default", "auditor")

    trail = client.get(
        "/api/audit?action=membership.grant&resource_id=newcomer", headers=_admin(client)
    )
    assert trail.status_code == 200, trail.text
    rows = trail.json()["items"]
    assert len(rows) == 1
    assert rows[0]["after"] == {"role": "auditor"}
    # New membership, so there is no "before" — the same distinction #327 drew
    # between a grant and a re-grant, now carrying the new role names.
    assert rows[0]["before"] is None


def test_a_token_admin_cannot_mint_a_credential_stronger_than_itself(tmp_path, monkeypatch):
    """The ceiling on issuance. Without it, #318 *added* an escalation.

    ``token-admin`` is rank 1 — it passes no write gate in the API — and holds
    ``tenant.credential.manage`` so a customer can rotate its own integration
    credentials. Before this check it could mint a service token with
    ``role: admin`` and then use that token to start scans, write assets and
    file reports: one request from "manages credentials" to "operates the
    tenant", which is the whole of what the role table is for.
    """
    client = configured_client(tmp_path, monkeypatch)
    token_admin = _account(client, "keymaster", "default", "token-admin")

    for role in ("admin", "operator"):
        refused = client.post(
            "/api/tenants/default/service-tokens",
            headers=token_admin,
            json={"name": f"escalate-{role}", "scopes": ["jobs:write"], "role": role},
        )
        assert refused.status_code == 403, refused.text
        assert "stronger" in refused.json()["detail"]

    # What it *is* for still works, and the credential it gets is no wider than
    # the hand that issued it.
    minted = client.post(
        "/api/tenants/default/service-tokens",
        headers=token_admin,
        json={"name": "ci-read", "scopes": ["runs:read"], "role": "viewer"},
    )
    assert minted.status_code == 201, minted.text
    issued = {"Authorization": f"Bearer {minted.json()['token']}"}
    assert client.post("/api/jobs", headers=issued, json={"mode": "balanced"}).status_code == 403

    # The tenant's own admin is rank 3 and keeps the whole ladder.
    tenant_admin = _account(client, "tenant-boss", "default", "admin")
    allowed = client.post(
        "/api/tenants/default/service-tokens",
        headers=tenant_admin,
        json={"name": "integration", "scopes": ["*"], "role": "admin"},
    )
    assert allowed.status_code == 201, allowed.text


def test_me_answers_for_the_tenant_the_console_is_acting_in(tmp_path, monkeypatch):
    """``/auth/me`` gates the console, and the console is not always in its default.

    Every request carries the tenant selected in the switcher (the axios
    interceptor in ``web-next/src/lib/api.ts``), so answering only for
    ``default_tenant`` gated each page on the wrong tenant: it hid a panel the
    API would have served, and offered one the API refuses.
    """
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _tenant(client, "globex")
    account = _account(client, "two-hats", "acme", "auditor")
    granted = client.put(
        "/api/tenants/globex/members/two-hats", headers=_admin(client), json={"role": "viewer"}
    )
    assert granted.status_code == 200, granted.text

    # The default tenant: an auditor, who may read the configuration.
    default_view = client.get("/api/auth/me", headers=account)
    assert default_view.status_code == 200, default_view.text
    assert default_view.json()["scoped_tenant"] == "acme"
    assert default_view.json()["tenant_role"] == "auditor"
    assert permission_catalog.CONFIG_READ in default_view.json()["permissions"]
    assert client.get("/api/config?tenant_id=acme", headers=account).status_code == 200

    # The switcher moves to globex, where the same account is a plain viewer.
    # The panel the console would render off the default answer 403s there.
    scoped = client.get("/api/auth/me?tenant_id=globex", headers=account)
    assert scoped.status_code == 200, scoped.text
    assert scoped.json()["scoped_tenant"] == "globex"
    assert scoped.json()["tenant_role"] == "viewer"
    assert permission_catalog.CONFIG_READ not in scoped.json()["permissions"]
    assert client.get("/api/config?tenant_id=globex", headers=account).status_code == 403

    # And a tenant this account holds nothing in is refused rather than
    # answered with the default tenant's authority.
    _tenant(client, "initech")
    assert client.get("/api/auth/me?tenant_id=initech", headers=account).status_code == 403


def test_a_suspended_tenant_leaves_the_listings_that_describe_it(tmp_path, monkeypatch):
    """"Every tenant-scoped request refused" has to include the tenant lists.

    ``GET /api/tenants`` feeds the console's switcher — offering a tenant whose
    every page then 403s — and ``GET /api/tenants/posture`` answered with the
    suspended tenant's *risk metrics*, which is the disclosure the suspension
    is supposed to stop. Both resolve their tenant set themselves, so neither
    passed through the ``require_active`` gate.
    """
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "paused")
    # Its own account with a *global* operator role, rather than the
    # membership-only ones ``_account`` builds: both listings hang off
    # ``require_role``, which reads the global role, so a global viewer never
    # reaches them at all. Its own rather than the seeded ``operator`` because
    # this test suspends the only tenant the account belongs to, and the
    # database outlives the test.
    member = _global_account(client, "paused-op", "paused", "operator", global_role="operator")

    listed = client.get("/api/tenants", headers=member)
    assert listed.status_code == 200, listed.text
    assert "paused" in {t["tenant_id"] for t in listed.json()}

    from api.auth import get_settings

    settings = get_settings()
    with get_session(settings.postgres_url) as session:
        session.get(models.Tenant, "paused").status = "suspended"

    # The list still parses — the status is in the schema, which is the other
    # half of this: a word the API cannot serialise turns the switcher into a
    # 500 rather than into a refusal.
    listed = client.get("/api/tenants", headers=member)
    assert listed.status_code == 200, listed.text
    assert "paused" not in {t["tenant_id"] for t in listed.json()}
    posture = client.get("/api/tenants/posture", headers=member)
    assert posture.status_code == 200, posture.text
    assert "paused" not in {row["tenant_id"] for row in posture.json()}

    # The platform admin keeps both, since it is who lifts the suspension.
    seen = client.get("/api/tenants", headers=_admin(client))
    assert seen.status_code == 200, seen.text
    rows = {t["tenant_id"]: t["status"] for t in seen.json()}
    assert rows["paused"] == "suspended"
    assert "paused" in {
        row["tenant_id"] for row in client.get("/api/tenants/posture", headers=_admin(client)).json()
    }


def test_the_global_roles_are_the_ones_the_user_schema_accepts():
    """``users.role`` had two truths: the constant and a hand-written Literal.

    ``GLOBAL_ROLES`` was documented as "assignable in ``users.role``" and read
    by nobody, while the validation lived in a Literal spelled out five times
    in ``api/schemas.py``. Whoever added a fourth global role would have found
    one of them and not the other. This is the same guard
    :func:`test_the_grantable_roles_are_the_ones_the_schema_accepts` puts on
    the tenant roles.
    """
    assert set(typing.get_args(GlobalRoleName)) == set(permission_catalog.GLOBAL_ROLES)
    # And the global names stay a subset of the tenant ones: a membership may
    # name every global role, not the other way round.
    assert set(permission_catalog.GLOBAL_ROLES) <= set(permission_catalog.TENANT_ROLES)


_AUTHZ_TS = Path(__file__).resolve().parents[1] / "web-next/src/lib/authz.ts"
_TS_RANK = re.compile(r'^\s*"?([a-z-]+)"?:\s*(\d+),\s*$', re.MULTILINE)


def test_the_consoles_rank_table_is_the_one_the_api_gates_on():
    """``ROLE_RANK`` in the console is a hand copy of this module's ``rank``.

    It cannot be anything else: the catalogue that would serve it,
    ``GET /api/rbac/roles``, is gated on ``tenant.member.read``, which only the
    tenant ``admin`` and the platform admin hold — so the very principals whose
    menu the rank decides (a ``scan-operator``, a ``viewer``) can never read
    it, and the console would fall back to a built-in copy anyway. What the
    copy can have is this: a ninth role added here and forgotten there scores
    :func:`api.core.permissions.rank_for`'s unknown-role 1 in the console,
    which hides every scanning page from a rank-2 role the API serves — the
    exact defect #318 closed, reopened by an addition. This is the same guard
    :func:`test_the_global_roles_are_the_ones_the_user_schema_accepts` puts on
    the global names, pointed at the other language.
    """
    source = _AUTHZ_TS.read_text(encoding="utf-8")
    body = source.split("const ROLE_RANK: Record<string, number> = {", 1)[1].split("};", 1)[0]
    console = {name: int(rank) for name, rank in _TS_RANK.findall(body)}
    assert console == {
        name: role.rank for name, role in permission_catalog.BUILTIN_ROLES.items()
    }


def _record_statements(settings):
    """Record every statement the API's engine executes. Returns (log, stop)."""
    from sqlalchemy import event

    from api.db.engine import get_engine

    engine = get_engine(settings.postgres_url)
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _record)
    return statements, lambda: event.remove(engine, "before_cursor_execute", _record)


def test_a_tenant_scoped_listing_reads_the_tenant_status_with_the_membership(
    tmp_path, monkeypatch
):
    """The suspension check costs no round trip of its own (#318 debt).

    ``require_active`` was a second ``SELECT`` on the tenants table on **every**
    tenant-scoped request, fired after ``resolve_tenant`` had already opened a
    transaction to read the membership — two round trips to answer "which
    tenant, which role, is it still active". On the hot listings (findings,
    assets) that doubled the authorisation cost of the request. The status now
    comes back with the membership, so this asserts the shape of what the
    request spends: exactly one statement against ``tenants``, the one joined
    onto ``user_tenants``.

    Counting statements rather than timing anything: a latency assertion in a
    test suite is a flake, and the defect was a shape, not a speed.
    """
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "acme")
    member = _account(client, "lister", "acme", "scan-operator")

    from api.auth import get_settings

    settings = get_settings()
    statements, stop = _record_statements(settings)
    try:
        listed = client.get("/api/assets?tenant_id=acme", headers=member)
        assert listed.status_code == 200, listed.text
    finally:
        stop()

    reads = [
        text
        for text in statements
        if "FROM user_tenants" in text or "FROM tenants" in text
    ]
    assert len(reads) == 1, "\n---\n".join(reads)
    # ...and it is one statement answering both questions, not a membership
    # lookup followed by a status lookup.
    assert "user_tenants" in reads[0] and "tenants.status" in reads[0], reads[0]

    # The suspension is still enforced per request rather than cached: flipping
    # the status refuses the very next call, with no TTL to wait out.
    with get_session(settings.postgres_url) as session:
        session.get(models.Tenant, "acme").status = "suspended"
    refused = client.get("/api/assets?tenant_id=acme", headers=member)
    assert refused.status_code == 403, refused.text
    assert "suspended" in refused.json()["detail"]
