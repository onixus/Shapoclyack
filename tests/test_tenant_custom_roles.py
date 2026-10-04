"""Roles a tenant defines for itself (#318, the remainder).

The built-in table answers "what may a scope-approver do" for every tenant at
once; this is the other half — a tenant writing ``soc-lead`` as a name, a rank
and an explicit permission set, and granting it. Every test below pins one way
that can go wrong: a role that grants more than its author holds, a role that
reaches the platform, a role that leaks into the next tenant, a role whose
deletion quietly takes somebody's access with it, and a role name that the
rest of the API ranks as if it were a built-in one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.core import permissions as permission_catalog
from api.db import migrate, models
from api.db.engine import get_session
from tests.conftest import (
    POSTGRES_URL,
    approve_scan_scope_via_api,
    auth_headers,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


def _admin(client) -> dict[str, str]:
    return auth_headers(client, "admin")


def _tenant(client, tenant_id: str) -> None:
    created = client.post(
        "/api/tenants",
        headers=_admin(client),
        json={"name": tenant_id, "tenant_id": tenant_id},
    )
    assert created.status_code == 201, created.text
    approve_scan_scope_via_api(client, tenant_id, _admin(client))


def _user(client, username: str) -> str:
    password = f"{username}-password-1234"
    created = client.post(
        "/api/users",
        headers=_admin(client),
        json={"username": username, "password": password, "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    return password


def _member(client, username: str, tenant_id: str, role: str) -> dict[str, str]:
    """A global viewer holding ``role`` in one tenant, granted by the platform admin."""
    password = _user(client, username)
    granted = client.put(
        f"/api/tenants/{tenant_id}/members/{username}",
        headers=_admin(client),
        json={"role": role},
    )
    assert granted.status_code == 200, granted.text
    return {"Authorization": f"Bearer {login(client, username, password)}"}


def _define(client, tenant_id: str, headers, **body):
    return client.post(f"/api/tenants/{tenant_id}/roles", headers=headers, json=body)


def _me(client, headers, tenant_id: str = "default") -> dict:
    response = client.get(f"/api/auth/me?tenant_id={tenant_id}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


# --- What a tenant role grants ------------------------------------------------


def test_a_tenant_role_grants_exactly_its_permissions_and_rank(tmp_path, monkeypatch):
    """A defined role is enforced as defined — not as the viewer it used to score.

    Before this every non-built-in name resolved to rank 1 and nothing, and a
    membership naming one answered ``GET …/members`` with a 500: the response
    model was a ``Literal`` of the eight built-in names.
    """
    client = configured_client(tmp_path, monkeypatch)
    defined = _define(
        client,
        "default",
        _admin(client),
        role_id="SOC-Lead",
        description="Runs scans and reads the trail",
        rank=2,
        permissions=["audit.read", "scan.cancel"],
    )
    assert defined.status_code == 201, defined.text
    role = defined.json()
    assert role["role_id"] == "soc-lead"  # stored lowercase, like the built-ins
    assert role["tenant_id"] == "default"
    assert role["builtin"] is False
    assert role["rank"] == 2
    assert role["permissions"] == ["audit.read", "scan.cancel"]

    lead = _member(client, "lead", "default", "soc-lead")

    # Rank 2: the operator gate lets it in...
    assert client.get("/api/jobs", headers=lead).status_code == 200
    # ...a named permission it holds, too...
    assert client.get("/api/audit", headers=lead).status_code == 200
    # ...and one it was not given stays shut, although an operator-ranked
    # built-in would not have it either: the set is explicit, not inherited.
    assert client.get("/api/config", headers=lead).status_code == 403
    assert client.get("/api/tenants/default/members", headers=lead).status_code == 403

    me = _me(client, lead)
    assert me["tenant_role"] == "soc-lead"
    assert me["tenant_rank"] == 2
    assert me["permissions"] == ["audit.read", "scan.cancel"]

    members = client.get("/api/tenants/default/members", headers=_admin(client))
    assert members.status_code == 200, members.text
    assert {m["username"]: m["role"] for m in members.json()}["lead"] == "soc-lead"

    catalogue = client.get("/api/rbac/roles", headers=_admin(client)).json()
    assert {r["role_id"]: r["member_count"] for r in catalogue}["soc-lead"] == 1


def test_a_definition_no_tenant_role_may_have_is_refused_for_everyone(tmp_path, monkeypatch):
    """422 whoever asks — the platform admin included — and 409 for a taken name."""
    client = configured_client(tmp_path, monkeypatch)
    admin = _admin(client)

    unknown = _define(client, "default", admin, role_id="typo", permissions=["audit.raed"])
    assert unknown.status_code == 422
    assert "audit.raed" in unknown.json()["detail"]

    # The platform's own authority cannot be written into a tenant's role, or
    # a tenant admin granted it would be editing every tenant's scanner config.
    for key in ("config.write", "platform.quota.manage", "platform.tenant.lifecycle"):
        platform = _define(client, "default", admin, role_id="reacher", permissions=[key])
        assert platform.status_code == 422, key
        assert "platform" in platform.json()["detail"]

    # The separation of duties holds for a defined role as for the built-ins:
    # an approver who can write, or who can grant memberships, is not one.
    writes = _define(
        client, "default", admin, role_id="approver-op", rank=2, permissions=["scan_scope.approve"]
    )
    assert writes.status_code == 422
    delegates = _define(
        client,
        "default",
        admin,
        role_id="approver-hr",
        permissions=["vulnerability.exception.approve", "tenant.member.manage"],
    )
    assert delegates.status_code == 422

    assert _define(client, "default", admin, role_id="admin").status_code == 409
    assert _define(client, "default", admin, role_id="platform-admin").status_code == 409
    assert _define(client, "default", admin, role_id="bad name!").status_code == 422
    assert _define(client, "default", admin, role_id="soc", rank=4).status_code == 422
    assert _define(client, "default", admin, role_id="soc").status_code == 201
    assert _define(client, "default", admin, role_id="SOC").status_code == 409


# --- The ceiling ----------------------------------------------------------------


def test_a_member_manager_cannot_hand_out_more_than_it_holds(tmp_path, monkeypatch):
    """The escalation custom roles would open without a ceiling.

    Before this, ``tenant.member.manage`` was only ever held by a rank-3
    ``admin``, so "may grant memberships" could not mean "may make myself
    admin". A tenant role can hold it at rank 1 — and without the ceiling its
    holder could grant itself ``admin``, define a role with ``audit.read`` it
    does not have, or revoke the admins above it.
    """
    client = configured_client(tmp_path, monkeypatch)
    hr_role = _define(
        client,
        "default",
        _admin(client),
        role_id="people-ops",
        permissions=["tenant.member.read", "tenant.member.manage", "scan_scope.read"],
    )
    assert hr_role.status_code == 201, hr_role.text
    hr = _member(client, "hr", "default", "people-ops")
    boss = "boss"
    _member(client, boss, "default", "admin")
    _user(client, "newbie")

    # Defining: above its rank, or with a permission it lacks.
    assert _define(client, "default", hr, role_id="writer", rank=2).status_code == 403
    above = _define(client, "default", hr, role_id="reader", permissions=["audit.read"])
    assert above.status_code == 403
    assert "audit.read" in above.json()["detail"]

    # Granting: a built-in above it — to itself or anybody.
    for target in ("hr", "newbie"):
        for role in ("admin", "operator", "auditor"):
            refused = client.put(
                f"/api/tenants/default/members/{target}", headers=hr, json={"role": role}
            )
            assert refused.status_code == 403, (target, role, refused.text)
    assert _me(client, hr)["tenant_role"] == "people-ops"

    # Demoting or revoking somebody above it.
    assert client.put(
        f"/api/tenants/default/members/{boss}", headers=hr, json={"role": "viewer"}
    ).status_code == 403
    assert client.delete(f"/api/tenants/default/members/{boss}", headers=hr).status_code == 403

    # Within its ceiling it works: a viewer, its own role, and the approval
    # roles a member manager staffs without holding (as the tenant admin
    # always has) — scope-approver needs the scan_scope.read it does hold.
    for role in ("viewer", "people-ops", "scope-approver"):
        allowed = client.put(
            "/api/tenants/default/members/newbie", headers=hr, json={"role": role}
        )
        assert allowed.status_code == 200, (role, allowed.text)
    assert client.delete("/api/tenants/default/members/newbie", headers=hr).status_code == 204


def test_a_tenant_admin_keeps_granting_every_built_in_role(tmp_path, monkeypatch):
    """The ceiling must not take away what the tenant admin could already do.

    ``scope-approver`` and ``risk-approver`` carry approvals the tenant admin
    does not hold, and it has staffed them since #318 began.
    """
    client = configured_client(tmp_path, monkeypatch)
    tenant_admin = _member(client, "tenant-boss", "default", "admin")
    _user(client, "colleague")
    for role in permission_catalog.TENANT_ROLES:
        granted = client.put(
            "/api/tenants/default/members/colleague", headers=tenant_admin, json={"role": role}
        )
        assert granted.status_code == 200, (role, granted.text)


def test_a_role_above_the_editor_can_be_neither_edited_nor_deleted(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    assert _define(
        client, "default", _admin(client), role_id="analyst", rank=2, permissions=["audit.read"]
    ).status_code == 201
    assert _define(
        client,
        "default",
        _admin(client),
        role_id="people-ops",
        permissions=["tenant.member.read", "tenant.member.manage"],
    ).status_code == 201
    hr = _member(client, "hr", "default", "people-ops")

    assert client.patch(
        "/api/tenants/default/roles/analyst", headers=hr, json={"permissions": []}
    ).status_code == 403
    assert client.delete("/api/tenants/default/roles/analyst", headers=hr).status_code == 403
    # Nor can it widen its own role: that is defining one above itself.
    assert client.patch(
        "/api/tenants/default/roles/people-ops",
        headers=hr,
        json={"permissions": ["tenant.member.read", "tenant.member.manage", "audit.read"]},
    ).status_code == 403


def test_a_tenant_role_holding_credentials_mints_up_to_its_own_rank(tmp_path, monkeypatch):
    """The issuance ceiling reads the resolved rank, not the role's name.

    Looked up by name, a tenant role is "unknown" and scored 1 — a rank-2
    ``tenant.credential.manage`` holder refused an operator token it is
    entitled to — and an admin-ranked one could never be told apart from it.
    """
    client = configured_client(tmp_path, monkeypatch)
    assert _define(
        client,
        "default",
        _admin(client),
        role_id="integrator",
        rank=2,
        # An operator token carries config.read and scan.cancel, and the
        # ceiling compares permissions as well as rank.
        permissions=["tenant.credential.manage", "config.read", "scan.cancel"],
    ).status_code == 201
    integrator = _member(client, "integrator", "default", "integrator")

    operator = client.post(
        "/api/tenants/default/service-tokens",
        headers=integrator,
        json={"name": "ci", "scopes": ["jobs:write"], "role": "operator"},
    )
    assert operator.status_code == 201, operator.text
    admin = client.post(
        "/api/tenants/default/service-tokens",
        headers=integrator,
        json={"name": "too-much", "scopes": ["*"], "role": "admin"},
    )
    assert admin.status_code == 403, admin.text


# --- Isolation --------------------------------------------------------------


def test_a_tenant_role_is_invisible_and_ungrantable_in_another_tenant(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _tenant(client, "acme")
    _tenant(client, "globex")
    assert _define(
        client, "acme", _admin(client), role_id="night-shift", rank=2, permissions=["scan.cancel"]
    ).status_code == 201

    globex_admin = _member(client, "globex-admin", "globex", "admin")
    roles = client.get("/api/rbac/roles?tenant_id=globex", headers=globex_admin)
    assert roles.status_code == 200, roles.text
    assert "night-shift" not in {role["role_id"] for role in roles.json()}

    # The same name in the other tenant is no role at all — not even for the
    # platform admin, who acts in both.
    _user(client, "drifter")
    for headers in (globex_admin, _admin(client)):
        foreign = client.put(
            "/api/tenants/globex/members/drifter", headers=headers, json={"role": "night-shift"}
        )
        assert foreign.status_code == 422, foreign.text

    # Nor can globex's admin reach acme's role through globex's path...
    assert client.patch(
        "/api/tenants/globex/roles/night-shift", headers=globex_admin, json={"rank": 1}
    ).status_code == 404
    assert client.delete(
        "/api/tenants/globex/roles/night-shift", headers=globex_admin
    ).status_code == 404
    # ...or through acme's.
    assert client.patch(
        "/api/tenants/acme/roles/night-shift", headers=globex_admin, json={"rank": 1}
    ).status_code == 403

    # And a membership row naming another tenant's role (written by hand, or
    # left by a rollout) resolves to nothing rather than to acme's definition.
    with get_session(make_settings(tmp_path).postgres_url) as session:
        session.query(models.UserTenant).filter(
            models.UserTenant.username == "globex-admin"
        ).update({"role": "night-shift"})
    me = _me(client, globex_admin, "globex")
    assert me["tenant_rank"] == 1
    assert me["permissions"] == []


# --- Rename and delete --------------------------------------------------------


def test_deleting_a_held_role_is_refused_unless_its_holders_are_reassigned(
    tmp_path, monkeypatch
):
    """No member loses access as a side effect of a role going away."""
    client = configured_client(tmp_path, monkeypatch)
    admin = _admin(client)
    assert _define(
        client, "default", admin, role_id="analyst", rank=2, permissions=["audit.read"]
    ).status_code == 201
    analyst = _member(client, "analyst-1", "default", "analyst")
    _member(client, "analyst-2", "default", "analyst")

    refused = client.delete("/api/tenants/default/roles/analyst", headers=admin)
    assert refused.status_code == 409
    assert "2 member" in refused.json()["detail"]
    # Still there, still working.
    assert client.get("/api/audit", headers=analyst).status_code == 200

    assert client.delete(
        "/api/tenants/default/roles/analyst?reassign_to=analyst", headers=admin
    ).status_code == 422
    assert client.delete(
        "/api/tenants/default/roles/analyst?reassign_to=nobody", headers=admin
    ).status_code == 422

    moved = client.delete("/api/tenants/default/roles/analyst?reassign_to=auditor", headers=admin)
    assert moved.status_code == 200, moved.text
    assert moved.json() == {
        "role_id": "analyst",
        "reassigned_to": "auditor",
        "memberships_reassigned": 2,
    }
    members = {
        m["username"]: m["role"]
        for m in client.get("/api/tenants/default/members", headers=admin).json()
    }
    assert members["analyst-1"] == members["analyst-2"] == "auditor"
    assert "analyst" not in {
        role["role_id"] for role in client.get("/api/rbac/roles", headers=admin).json()
    }

    # Each holder's move is a membership change of its own in the trail.
    grants = client.get(
        "/api/audit?action=membership.grant&resource_id=analyst-1", headers=admin
    ).json()["items"]
    assert grants[0]["before"] == {"role": "analyst"}
    assert grants[0]["after"]["role"] == "auditor"
    deleted = client.get("/api/audit?action=role.delete", headers=admin).json()["items"]
    assert len(deleted) == 1
    assert deleted[0]["before"]["permissions"] == ["audit.read"]

    # An unheld role just goes.
    assert _define(client, "default", admin, role_id="spare").status_code == 201
    assert client.delete("/api/tenants/default/roles/spare", headers=admin).status_code == 200
    # And a built-in is nobody's to delete.
    assert client.delete("/api/tenants/default/roles/auditor", headers=admin).status_code == 404


def test_renaming_a_role_carries_its_holders_and_an_edit_reaches_them(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = _admin(client)
    assert _define(
        client, "default", admin, role_id="analyst", permissions=["audit.read"]
    ).status_code == 201
    analyst = _member(client, "analyst-1", "default", "analyst")

    renamed = client.patch(
        "/api/tenants/default/roles/analyst",
        headers=admin,
        json={"role_id": "threat-analyst", "description": "Reads the trail"},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["role_id"] == "threat-analyst"
    assert renamed.json()["member_count"] == 1
    assert renamed.json()["updated_by"] == "admin"

    # Same access under the new name, on the session it already had.
    me = _me(client, analyst)
    assert me["tenant_role"] == "threat-analyst"
    assert me["permissions"] == ["audit.read"]
    assert client.get("/api/audit", headers=analyst).status_code == 200
    # The old name is gone, so it can neither be granted nor collide.
    _user(client, "late")
    assert client.put(
        "/api/tenants/default/members/late", headers=admin, json={"role": "analyst"}
    ).status_code == 422
    assert client.patch(
        "/api/tenants/default/roles/threat-analyst", headers=admin, json={"role_id": "auditor"}
    ).status_code == 409

    # Narrowing the definition reaches the holder on the next request.
    assert client.patch(
        "/api/tenants/default/roles/threat-analyst", headers=admin, json={"permissions": []}
    ).status_code == 200
    assert client.get("/api/audit", headers=analyst).status_code == 403

    updates = client.get("/api/audit?action=role.update", headers=admin).json()["items"]
    assert len(updates) == 2
    rename = next(row for row in updates if row["before"]["role_id"] == "analyst")
    assert rename["after"]["role_id"] == "threat-analyst"
    assert rename["after"]["memberships_renamed"] == 1


# --- Resolution, and the state an upgrade leaves ------------------------------


def test_a_membership_written_before_the_upgrade_means_what_it_meant(tmp_path, monkeypatch):
    """Rows the previous release wrote, read by this one.

    Built-in names resolve from the compiled table exactly as before; a name
    the table does not know — a newer replica's, a deleted role's, the
    platform admin's written into a membership by hand — still resolves to
    the lowest authority, and the member list still renders it.
    """
    client = configured_client(tmp_path, monkeypatch)
    for username in ("legacy-op", "legacy-auditor", "ghost", "forged"):
        _user(client, username)
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(make_settings(tmp_path).postgres_url) as session:
        for username, role in (
            ("legacy-op", "operator"),
            ("legacy-auditor", "auditor"),
            ("ghost", "role-from-the-future"),
            ("forged", "platform-admin"),
        ):
            session.add(
                models.UserTenant(
                    username=username, tenant_id="default", role=role, created_at=now
                )
            )

    def headers(username: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {login(client, username, f'{username}-password-1234')}"}

    op = _me(client, headers("legacy-op"))
    assert (op["tenant_role"], op["tenant_rank"]) == ("operator", 2)
    assert set(op["permissions"]) == set(permission_catalog.BUILTIN_ROLES["operator"].permissions)
    assert client.get("/api/jobs", headers=headers("legacy-op")).status_code == 200
    assert client.get("/api/audit", headers=headers("legacy-auditor")).status_code == 200

    for username in ("ghost", "forged"):
        me = _me(client, headers(username))
        assert me["tenant_rank"] == 1, username
        assert me["permissions"] == [], username
        assert client.get("/api/jobs", headers=headers(username)).status_code == 403

    members = client.get("/api/tenants/default/members", headers=_admin(client))
    assert members.status_code == 200, members.text


def test_a_tampered_role_row_cannot_reach_the_platform(tmp_path, monkeypatch):
    """Resolution cuts to what a tenant role may hold, whatever the rows say."""
    from api.services import rbac as rbac_service

    configured_client(tmp_path, monkeypatch)
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(make_settings(tmp_path).postgres_url) as session:
        session.add(
            models.RoleDefinition(
                role_id="sneaky", tenant_id="default", builtin=False, rank=3, created_at=now
            )
        )
        session.flush()
        for key in ("config.write", "platform.quota.manage", "audit.read"):
            session.add(
                models.RolePermission(role_id="sneaky", tenant_id="default", permission_key=key)
            )
    resolved = rbac_service.resolve("default", "sneaky")
    assert resolved.permissions == frozenset({"audit.read"})
    assert rbac_service.resolve("other-tenant", "sneaky").permissions == frozenset()


def test_the_ceiling_and_the_separation_rules():
    """The two rules every write goes through, on their own."""
    held = permission_catalog.Authority(
        rank=1, permissions=frozenset({"tenant.member.manage", "scan_scope.read"})
    )
    assert permission_catalog.exceeds_authority(1, frozenset(), held) is None
    assert permission_catalog.exceeds_authority(2, frozenset(), held)
    assert permission_catalog.exceeds_authority(1, frozenset({"audit.read"}), held)
    # The approvals are delegable by a member manager...
    assert (
        permission_catalog.exceeds_authority(
            1, frozenset({"scan_scope.read", "scan_scope.approve"}), held
        )
        is None
    )
    # ...and by nobody else.
    no_manage = permission_catalog.Authority(rank=3, permissions=frozenset({"audit.read"}))
    assert permission_catalog.exceeds_authority(
        1, frozenset({"scan_scope.approve"}), no_manage
    )
    platform = permission_catalog.Authority(rank=1, permissions=frozenset(), is_platform_admin=True)
    assert permission_catalog.exceeds_authority(3, frozenset({"config.write"}), platform) is None

    assert permission_catalog.separation_of_duties_conflict(1, frozenset({"audit.read"})) is None
    assert permission_catalog.separation_of_duties_conflict(
        2, frozenset({"vulnerability.exception.approve"})
    )
    # Every built-in tenant role already has the shape a defined one is held to.
    for name in permission_catalog.TENANT_ROLES:
        role = permission_catalog.BUILTIN_ROLES[name]
        assert permission_catalog.separation_of_duties_conflict(role.rank, role.permissions) is None
    assert not {"config.write"} & permission_catalog.TENANT_GRANTABLE_PERMISSIONS
    assert not any(
        key.startswith("platform.") for key in permission_catalog.TENANT_GRANTABLE_PERMISSIONS
    )


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"mig0070_{uuid.uuid4().hex[:10]}"
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    try:
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def test_migration_0070_keeps_existing_memberships_and_round_trips(fresh_database):
    """0068 → 0070 over memberships the previous release wrote, then down and up."""
    url = fresh_database
    migrate._upgrade("0068_compliance_frameworks")  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, status, created_at) "
                    "VALUES ('acme', 'acme', 'active', now())"
                )
            )
            for username, role in (("op", "operator"), ("aud", "scope-approver")):
                conn.execute(
                    text(
                        "INSERT INTO users (username, password_hash, role, created_at, "
                        "updated_at) VALUES (:u, '', 'viewer', now(), now())"
                    ),
                    {"u": username},
                )
                conn.execute(
                    text(
                        "INSERT INTO user_tenants (username, tenant_id, role, created_at) "
                        "VALUES (:u, 'acme', :r, now())"
                    ),
                    {"u": username, "r": role},
                )

        migrate._upgrade("0070_tenant_custom_roles")  # noqa: SLF001
        with engine.begin() as conn:
            rows = dict(
                conn.execute(text("SELECT username, role FROM user_tenants")).all()
            )
            assert rows == {"op": "operator", "aud": "scope-approver"}
            # Every seeded built-in satisfies the new checks...
            assert conn.execute(
                text("SELECT count(*) FROM roles WHERE builtin AND tenant_id = ''")
            ).scalar_one() == len(permission_catalog.BUILTIN_ROLES)
            # ...and the checks refuse what the service never writes.
            for statement in (
                "INSERT INTO roles (role_id, tenant_id, builtin, rank, created_at) "
                "VALUES ('x', 'acme', false, 4, now())",
                "INSERT INTO roles (role_id, tenant_id, builtin, rank, created_at) "
                "VALUES ('x', '', false, 1, now())",
                "INSERT INTO roles (role_id, tenant_id, builtin, rank, created_at) "
                "VALUES ('x', 'acme', true, 1, now())",
            ):
                with pytest.raises(Exception, match="ck_roles_"):
                    with conn.begin_nested():
                        conn.execute(text(statement))
            conn.execute(
                text(
                    "INSERT INTO roles (role_id, tenant_id, builtin, rank, created_at) "
                    "VALUES ('analyst', 'acme', false, 2, now())"
                )
            )

        migrate._downgrade("0068_compliance_frameworks")  # noqa: SLF001
        migrate._upgrade("0070_tenant_custom_roles")  # noqa: SLF001
        with engine.begin() as conn:
            assert conn.execute(
                text("SELECT rank FROM roles WHERE role_id = 'analyst' AND tenant_id = 'acme'")
            ).scalar_one() == 2
    finally:
        engine.dispose()
