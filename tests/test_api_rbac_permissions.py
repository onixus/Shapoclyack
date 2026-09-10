"""Named permissions, the separation-of-duties roles, and tenant self-service (#318).

Before this the platform had three ranked roles, so "read the audit trail"
implied "mint credentials", "approve a scanning scope" implied "run scans", and
every tenant-administration route was the global admin's alone. Each test below
pins one of those separations; every one of them fails on the pre-#318 code,
which is what makes them worth having.
"""

from __future__ import annotations

import typing
from unittest.mock import patch

from api.core import permissions as permission_catalog
from api.db import models
from api.db.engine import get_session
from api.schemas import JobInfo, TenantRoleName
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
