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

import threading
import time
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select, text
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

    # Within its ceiling it works: a viewer and its own role. Not the approval
    # roles, though it holds scope-approver's scan_scope.read: staffing an
    # approval without holding it is the admin rank's (see the test below).
    assert client.put(
        "/api/tenants/default/members/newbie", headers=hr, json={"role": "scope-approver"}
    ).status_code == 403
    for role in ("viewer", "people-ops"):
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


def test_a_member_manager_below_admin_cannot_staff_an_approval(tmp_path, monkeypatch):
    """The separation of duties, defeated from the side that grants (#501 review).

    The approvals may be handed out without being held — that is how the
    tenant ``admin`` staffs ``scope-approver`` — but only from the admin
    rank. Below it, ``tenant.member.manage`` would turn a role the tenant
    admin set up as "personnel" into an approval desk: an ``ops-lead`` at rank
    2 defines an approver role, grants it to a second account of their own,
    approves a wider scope with it and runs the scans in it from the first.
    """
    client = configured_client(tmp_path, monkeypatch)
    admin = _admin(client)
    assert _define(
        client,
        "default",
        admin,
        role_id="ops-lead",
        rank=2,
        permissions=["tenant.member.manage", "tenant.member.read", "config.read", "scan.cancel"],
    ).status_code == 201
    lead = _member(client, "lead", "default", "ops-lead")
    alt_password = _user(client, "lead-alt")
    alt = {"Authorization": f"Bearer {login(client, 'lead-alt', alt_password)}"}

    # A role of its own carrying the approval...
    approver = _define(
        client, "default", lead, role_id="approver2", permissions=["scan_scope.approve"]
    )
    assert approver.status_code == 403, approver.text
    assert "scan_scope.approve" in approver.json()["detail"]
    # ...or the built-in one, to the second account.
    for role in ("scope-approver", "risk-approver"):
        granted = client.put(
            "/api/tenants/default/members/lead-alt", headers=lead, json={"role": role}
        )
        assert granted.status_code == 403, (role, granted.text)
    widened = client.put(
        "/api/tenants/default/scan-scope",
        headers=alt,
        json={"entries": [{"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"}]},
    )
    assert widened.status_code == 403, widened.text
    assert "approver2" not in {
        role["role_id"] for role in client.get("/api/rbac/roles", headers=admin).json()
    }


def test_a_personnel_role_cannot_join_the_two_approvals_for_itself(tmp_path, monkeypatch):
    """The other half: a rank-1 ``people-ops`` writes ``approve-all`` and takes it.

    The built-ins keep the scope approval and the risk approval in two roles;
    a role holding both, granted by its own author, would be one person
    signing for what to scan and for what to leave unfixed.
    """
    client = configured_client(tmp_path, monkeypatch)
    assert _define(
        client,
        "default",
        _admin(client),
        role_id="people-ops",
        permissions=["tenant.member.read", "tenant.member.manage"],
    ).status_code == 201
    hr = _member(client, "hr", "default", "people-ops")

    both = _define(
        client,
        "default",
        hr,
        role_id="approve-all",
        permissions=["scan_scope.approve", "vulnerability.exception.approve"],
    )
    assert both.status_code == 403, both.text
    assert client.put(
        "/api/tenants/default/members/hr", headers=hr, json={"role": "risk-approver"}
    ).status_code == 403
    assert _me(client, hr)["tenant_role"] == "people-ops"


def test_a_tenant_defined_admin_rank_still_staffs_the_approvals(tmp_path, monkeypatch):
    """The exception is the admin rank's, not the built-in name's."""
    client = configured_client(tmp_path, monkeypatch)
    assert _define(
        client,
        "default",
        _admin(client),
        role_id="tenant-owner",
        rank=3,
        permissions=["tenant.member.read", "tenant.member.manage", "scan_scope.read"],
    ).status_code == 201
    owner = _member(client, "owner", "default", "tenant-owner")
    _user(client, "colleague")
    for role in ("scope-approver", "risk-approver"):
        granted = client.put(
            "/api/tenants/default/members/colleague", headers=owner, json={"role": role}
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


def test_a_role_the_idp_group_map_names_is_neither_renamed_nor_deleted(tmp_path, monkeypatch):
    """``OCTO_IDP_GROUP_MAP`` names tenant roles by name (#316). Renaming one
    under it, or deleting it, left the map pointing at nothing — a tenant
    administrator's way to make the IdP resync stop acting on that tenant."""
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = _admin(client)
    for role_id in ("analyst", "spare"):
        assert _define(
            client, "default", admin, role_id=role_id, permissions=["audit.read"]
        ).status_code == 201
    settings.idp_group_map = {"soc": [{"tenant_id": "default", "role": "analyst"}]}

    renamed = client.patch(
        "/api/tenants/default/roles/analyst", headers=admin, json={"role_id": "soc-analyst"}
    )
    assert renamed.status_code == 409, renamed.text
    assert "OCTO_IDP_GROUP_MAP" in renamed.json()["detail"]
    deleted = client.delete("/api/tenants/default/roles/analyst", headers=admin)
    assert deleted.status_code == 409, deleted.text
    # An edit that keeps the name is not a rename.
    assert client.patch(
        "/api/tenants/default/roles/analyst", headers=admin, json={"description": "SOC"}
    ).status_code == 200
    assert client.patch(
        "/api/tenants/default/roles/analyst", headers=admin, json={"role_id": "analyst"}
    ).status_code == 200
    # The same name in another tenant's entry is not this tenant's role.
    settings.idp_group_map["other"] = [{"tenant_id": "elsewhere", "role": "spare"}]
    assert client.delete("/api/tenants/default/roles/spare", headers=admin).status_code == 200


def test_deleting_a_role_cannot_reassign_its_holders_above_the_caller(tmp_path, monkeypatch):
    """``reassign_to`` is a grant, and is held to the same ceiling.

    Without it a ``people-ops`` holder would define a throwaway role within
    its reach, grant it to an accomplice, and delete it "reassigning" to
    ``admin`` — every holder regranted a role nobody let it grant.
    """
    client = configured_client(tmp_path, monkeypatch)
    assert _define(
        client,
        "default",
        _admin(client),
        role_id="people-ops",
        permissions=["tenant.member.read", "tenant.member.manage"],
    ).status_code == 201
    hr = _member(client, "hr", "default", "people-ops")
    assert _define(client, "default", hr, role_id="temp").status_code == 201
    _user(client, "accomplice")
    assert client.put(
        "/api/tenants/default/members/accomplice", headers=hr, json={"role": "temp"}
    ).status_code == 200

    for target in ("admin", "operator", "auditor"):
        refused = client.delete(
            f"/api/tenants/default/roles/temp?reassign_to={target}", headers=hr
        )
        assert refused.status_code == 403, (target, refused.text)
        assert "cannot reassign" in refused.json()["detail"]
    members = {
        m["username"]: m["role"]
        for m in client.get("/api/tenants/default/members", headers=_admin(client)).json()
    }
    assert members["accomplice"] == "temp"

    # The control: within its reach the same call goes through.
    moved = client.delete("/api/tenants/default/roles/temp?reassign_to=viewer", headers=hr)
    assert moved.status_code == 200, moved.text


def test_renaming_onto_another_tenant_role_is_a_conflict_not_a_crash(tmp_path, monkeypatch):
    """409 for a name the tenant already uses — not the primary key's 500.

    A built-in name is refused earlier, by the name check itself, so only a
    rename onto the tenant's *own* role reaches this one.
    """
    client = configured_client(tmp_path, monkeypatch)
    admin = _admin(client)
    assert _define(
        client, "default", admin, role_id="analyst", permissions=["audit.read"]
    ).status_code == 201
    assert _define(
        client, "default", admin, role_id="reviewer", permissions=["scan_scope.read"]
    ).status_code == 201
    _member(client, "analyst-1", "default", "analyst")

    taken = client.patch(
        "/api/tenants/default/roles/analyst", headers=admin, json={"role_id": "Reviewer"}
    )
    assert taken.status_code == 409, taken.text
    roles = {
        role["role_id"]: role
        for role in client.get("/api/rbac/roles", headers=admin).json()
        if not role["builtin"]
    }
    assert roles["analyst"]["permissions"] == ["audit.read"]
    assert roles["analyst"]["member_count"] == 1
    assert roles["reviewer"]["permissions"] == ["scan_scope.read"]


def _waiting_on_a_lock(settings) -> int:
    with get_session(settings.postgres_url) as session:
        return int(
            session.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
        )


def test_a_grant_in_flight_holds_off_the_delete_of_its_role(tmp_path, monkeypatch):
    """A grant and a delete of the same role, interleaved on two connections.

    The grant has read the role and not yet committed its membership; the
    delete counts holders and sees none. Unless the grant's ``FOR SHARE``
    makes the delete's ``FOR UPDATE`` wait for that commit, the delete goes
    ahead and the grant commits a membership naming a role that no longer
    exists. Driven by a barrier inside the grant and the database's own lock
    table, not by sleeps.
    """
    from api.services import memberships as memberships_service
    from api.services import rbac as rbac_service

    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    assert _define(
        client, "default", _admin(client), role_id="analyst", permissions=["audit.read"]
    ).status_code == 201
    _user(client, "newcomer")

    read_the_role = threading.Event()
    release = threading.Event()
    real_refuse_above = memberships_service._refuse_above  # noqa: SLF001

    def _check_then_hold(granted_by, role, what):
        real_refuse_above(granted_by, role, what)
        if role.name == "analyst" and threading.current_thread().name == "grant":
            read_the_role.set()
            assert release.wait(30), "the test never released the grant"

    monkeypatch.setattr(memberships_service, "_refuse_above", _check_then_hold)
    outcome: dict[str, object] = {}

    def _grant() -> None:
        try:
            outcome["grant"] = memberships_service.grant(
                username="newcomer", tenant_id="default", role="analyst", granted_by=None
            )
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            outcome["grant"] = exc

    def _delete() -> None:
        try:
            outcome["delete"] = rbac_service.delete_role(
                tenant_id="default",
                role_id="analyst",
                actor=permission_catalog.Authority(
                    rank=3, permissions=frozenset(), is_platform_admin=True
                ),
            )
        except Exception as exc:  # noqa: BLE001 - reported by the assertions below
            outcome["delete"] = exc

    granting = threading.Thread(target=_grant, name="grant")
    deleting = threading.Thread(target=_delete, name="delete")
    granting.start()
    try:
        assert read_the_role.wait(30), "the grant never reached its check"
        deleting.start()
        # Either the delete is now waiting on the grant's lock, or it did not
        # wait and has already finished — which is the defect, and is what
        # the assertions below report.
        deadline = time.monotonic() + 30
        while deleting.is_alive() and _waiting_on_a_lock(settings) == 0:
            assert time.monotonic() < deadline, "the delete neither waited nor finished"
            time.sleep(0.02)
    finally:
        release.set()
        granting.join(30)
        if deleting.ident is not None:
            deleting.join(30)

    assert isinstance(outcome["grant"], dict), outcome["grant"]
    assert isinstance(outcome["delete"], rbac_service.RoleInUse), outcome["delete"]
    with get_session(settings.postgres_url) as session:
        membership = session.execute(
            select(models.UserTenant).where(models.UserTenant.username == "newcomer")
        ).scalar_one()
        assert membership.role == "analyst"
        assert session.get(models.RoleDefinition, ("analyst", "default")) is not None


# --- The other rank gates a tenant role reaches -------------------------------


def test_a_tenant_role_is_ranked_at_the_restricted_artifacts(tmp_path, monkeypatch):
    """Ownership artifacts and screenshots are operator-only by rank, which a
    tenant role carries.

    Compared by name, ``soc-lead`` is no operator and is refused the run's
    ownership data the API's own rank says it may read.
    """
    from tests.test_api_restricted_artifacts import _seed_run

    client = configured_client(tmp_path, monkeypatch)
    run_dir = _seed_run(tmp_path / "output")
    (run_dir / "screenshots").mkdir()
    (run_dir / "screenshots" / "login.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    admin = _admin(client)
    assert _define(client, "default", admin, role_id="soc-lead", rank=2).status_code == 201
    assert _define(client, "default", admin, role_id="reader").status_code == 201
    lead = _member(client, "lead", "default", "soc-lead")
    reader = _member(client, "reader-1", "default", "reader")

    for rel in ("ownership.json", "ownership_findings.txt"):
        assert client.get(
            f"/api/runs/run-own/artifacts/{rel}", headers=lead
        ).status_code == 200, rel
        assert client.get(
            f"/api/runs/run-own/download/{rel}", headers=lead
        ).status_code == 200, rel
        assert client.get(
            f"/api/runs/run-own/artifacts/{rel}", headers=reader
        ).status_code == 404, rel
        assert client.get(
            f"/api/runs/run-own/download/{rel}", headers=reader
        ).status_code == 404, rel

    # Screenshots are operator-only the same way.
    shot = "/api/runs/run-own/download/screenshots/login.png"
    assert client.get(shot, headers=lead).status_code == 200
    assert client.get(shot, headers=reader).status_code == 404

    # The org profile carries the same ownership block, behind the same rank.
    profile = client.get("/api/runs/run-own/org-profile", headers=lead)
    assert profile.status_code == 200, profile.text
    assert profile.json()["ownership"]["domains"]["example.com"]["org_name"] == (
        "Example Holding LLC"
    )
    withheld = client.get("/api/runs/run-own/org-profile", headers=reader)
    assert withheld.status_code == 404 or withheld.json()["ownership"] is None, withheld.text


def test_a_tenant_role_is_ranked_at_the_bulk_verbs(tmp_path, monkeypatch):
    """The per-verb floor of ``/api/vulnerabilities/bulk`` is a rank as well."""
    from tests.test_api_vulnerabilities import _seed

    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    admin = _admin(client)
    assert _define(client, "default", admin, role_id="soc-lead", rank=2).status_code == 201
    assert _define(client, "default", admin, role_id="soc-head", rank=3).status_code == 201
    assert _define(client, "default", admin, role_id="reader").status_code == 201
    lead = _member(client, "lead", "default", "soc-lead")
    head = _member(client, "head", "default", "soc-head")
    reader = _member(client, "reader-1", "default", "reader")
    listed = client.get("/api/vulnerabilities", headers=admin).json()["items"]
    ids = [item["vuln_id"] for item in listed]

    def bulk(headers, action, payload):
        return client.post(
            "/api/vulnerabilities/bulk",
            headers=headers,
            json={"action": action, "vuln_ids": ids, "payload": payload},
        )

    assign = {"assignee": "ada"}
    assigned = bulk(lead, "assign", assign)
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["succeeded"] == len(ids)
    assert bulk(reader, "assign", assign).status_code == 403
    # The admin-ranked verbs: refused at rank 2, past the gate at rank 3.
    false_positive = {"reason": "a scanner artefact"}
    assert bulk(lead, "false_positive", false_positive).status_code == 403
    assert bulk(head, "false_positive", false_positive).status_code == 200


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
    # The approvals are delegable by a member manager at the admin rank...
    approval = frozenset({"scan_scope.read", "scan_scope.approve"})
    admin_rank = permission_catalog.Authority(
        rank=3, permissions=frozenset({"tenant.member.manage", "scan_scope.read"})
    )
    assert permission_catalog.exceeds_authority(1, approval, admin_rank) is None
    # ...and by nobody else: not one below it...
    assert permission_catalog.exceeds_authority(1, approval, held)
    operator_rank = permission_catalog.Authority(
        rank=2, permissions=frozenset({"tenant.member.manage", "scan_scope.read"})
    )
    assert permission_catalog.exceeds_authority(1, approval, operator_rank)
    # ...nor an admin rank that does not manage members.
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
