"""What each role may do, written down once (#318).

Before this the platform had exactly three roles, ranked — ``viewer`` <
``operator`` < ``admin`` — and every check was a comparison against that rank
(:func:`api.auth.require_role`). Two consequences an enterprise review will not
accept: there was no way to give somebody read access to the audit trail
without giving them the ability to mint credentials, and there was no way to
separate *approving* what a tenant may scan from *running* the scans, because
both landed on the same rank.

So the authority a role carries is a **set of named permissions**, and the rank
survives alongside it as what it always was: the coarse read/write gate the
existing routes are written against. Both are declared here, in one table per
role, which is the point — a role whose rank and permission set were declared
in different files is a role two people can change in half.

**The rank is still load-bearing, so read the numbers carefully.** The
separation-of-duties roles are all rank 1 (viewer-level *writes*) plus one
permission: a ``scope-approver`` who were rank 2 would pass every
``require_role(Role.operator)`` gate in the API and could start the scans it is
their job to only approve, which is the defect this file exists to remove.
``scan-operator`` is the one new role at rank 2, because it *is* an operator —
it is named separately so an installation can grant "runs scans" without the
word "operator" being the only thing it can say.

**Built-in roles are compiled in, not read from the database.** Migration 0049
seeds the same table into ``permissions``/``roles``/``role_permissions`` so the
catalogue is discoverable over the API and a custom role has something to
inherit from, but enforcement resolves a built-in role from this dict — a
request that had to query for its own authority would be a request that fails
open when the database is slow, and an upgrade would be able to lock everybody
out by seeding badly. ``tests/test_api_rbac_permissions.py`` asserts the seed
and this dict still agree.

**Global role vs tenant role.** ``users.role`` still holds one of
:data:`GLOBAL_ROLES` — the three original names — and the global ``admin`` is
the platform admin, whose authority is :data:`PLATFORM_ADMIN_PERMISSIONS` (all
of them). The new roles are *tenant* roles: they are granted on a membership
(``PUT /api/tenants/{tenant_id}/members/{username}``) and their authority stops
at that tenant's edge. A platform-wide auditor is therefore an ``auditor``
membership in each tenant, deliberately: "read every customer's audit trail" is
a decision that should be visible as a list of grants.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Permissions -----------------------------------------------------------
# ``resource.action``, like the audit trail's action names. Every key below is
# checked somewhere; the one exception is documented on itself.

#: Read the administrative audit trail of a tenant (``GET /api/audit/events``).
AUDIT_READ = "audit.read"
#: Read the installation's editable scanner configuration (``GET /api/config``).
CONFIG_READ = "config.read"
#: Replace it (``PUT /api/config``). Installation-wide, hence platform-only.
CONFIG_WRITE = "config.write"
#: See a tenant's approved scanning scope and the domains promoted under it.
SCAN_SCOPE_READ = "scan_scope.read"
#: Decide what a tenant may point the platform at (``PUT …/scan-scope``). The
#: separation this issue is named for: never held by a role that can also run
#: scans, so widening the scope and using it are two people.
SCAN_SCOPE_APPROVE = "scan_scope.approve"
#: Stop a scan this tenant is running (``POST /api/jobs/{id}/cancel``) — both
#: refusing to hand out a queued job and asking the agent running one to put it
#: down (#360). Named rather than ranked because stopping somebody else's scan
#: mid-flight is an authority an installation may want to hand out on its own,
#: to an on-call who is not otherwise an operator.
SCAN_CANCEL = "scan.cancel"
#: List a tenant's members and their roles.
TENANT_MEMBER_READ = "tenant.member.read"
#: Grant and revoke them — tenant self-service, no longer platform admin only.
TENANT_MEMBER_MANAGE = "tenant.member.manage"
#: Mint, list and revoke a tenant's own agent provisioning keys and service
#: tokens. What ``token-admin`` exists for, and what lets a tenant admin
#: rotate their own key instead of filing a ticket with the platform.
TENANT_CREDENTIAL_MANAGE = "tenant.credential.manage"
#: Read what the tenant was sold (``GET …/quota``).
TENANT_QUOTA_READ = "tenant.quota.read"
#: Change it. Platform-only on purpose: a tenant admin who could raise their
#: own quota is the control removing itself.
PLATFORM_QUOTA_MANAGE = "platform.quota.manage"
#: Create tenants (``POST /api/tenants``).
PLATFORM_TENANT_MANAGE = "platform.tenant.manage"
#: See installation-wide counters that span tenants — the tenant and agent
#: totals in ``GET /api/system``, which told a single-tenant viewer how many
#: other customers this installation has.
PLATFORM_FLEET_READ = "platform.fleet.read"
#: Approve or reject a requested risk acceptance on a finding
#: (``POST /api/vulnerabilities/{id}/exception/{approve,reject}``, #348).
#: Holding it is necessary and not sufficient: the service refuses the person
#: who filed the request by name, which is what separates the duties for a
#: platform admin, who holds every permission in this file.
VULNERABILITY_EXCEPTION_APPROVE = "vulnerability.exception.approve"

#: Every permission with the sentence the catalogue endpoint and migration 0049
#: publish for it. The dict is the closed set: a permission not in here cannot
#: be granted, and :func:`api.auth.require_permission` asserts against it, so a
#: typo at a call site is caught on import rather than at the first request.
PERMISSIONS: dict[str, str] = {
    AUDIT_READ: "Read the administrative audit trail",
    CONFIG_READ: "Read the editable scanner configuration",
    CONFIG_WRITE: "Change the installation-wide scanner configuration",
    SCAN_SCOPE_READ: "Read the tenant's approved scanning scope",
    SCAN_SCOPE_APPROVE: "Approve what the tenant may scan",
    SCAN_CANCEL: "Stop a queued or running scan",
    TENANT_MEMBER_READ: "List the tenant's members",
    TENANT_MEMBER_MANAGE: "Grant and revoke the tenant's members",
    TENANT_CREDENTIAL_MANAGE: "Manage the tenant's provisioning keys and service tokens",
    TENANT_QUOTA_READ: "Read the tenant's quota",
    PLATFORM_QUOTA_MANAGE: "Set any tenant's quota",
    PLATFORM_TENANT_MANAGE: "Create tenants",
    PLATFORM_FLEET_READ: "Read installation-wide counters across tenants",
    VULNERABILITY_EXCEPTION_APPROVE: "Approve an accepted risk on a finding",
}


# --- Roles -----------------------------------------------------------------

ROLE_VIEWER = "viewer"
ROLE_OPERATOR = "operator"
ROLE_ADMIN = "admin"
ROLE_AUDITOR = "auditor"
ROLE_SCAN_OPERATOR = "scan-operator"
ROLE_SCOPE_APPROVER = "scope-approver"
ROLE_TOKEN_ADMIN = "token-admin"
ROLE_RISK_APPROVER = "risk-approver"
#: Not a role anybody is granted: the authority of the global ``admin``, kept
#: as a row here so the platform admin's permissions are declared in the same
#: table as everyone else's rather than being "whatever the code forgot to
#: check". :func:`api.services.memberships.grant` refuses it as a tenant role.
ROLE_PLATFORM_ADMIN = "platform-admin"


@dataclass(frozen=True)
class RoleDefinition:
    """One role: its rank for the legacy gates, and what it may do."""

    name: str
    #: 1 = read-only, 2 = operator-level writes, 3 = administers the tenant.
    #: Consumed by :data:`api.auth.ROLE_RANK`; see the module docstring for why
    #: the specialist roles sit at 1.
    rank: int
    description: str
    permissions: frozenset[str]


def _role(name: str, rank: int, description: str, *permissions: str) -> RoleDefinition:
    unknown = set(permissions) - set(PERMISSIONS)
    assert not unknown, f"role {name} names unknown permissions: {sorted(unknown)}"
    return RoleDefinition(
        name=name, rank=rank, description=description, permissions=frozenset(permissions)
    )


#: The tenant-administrator set, shared by the ``admin`` membership role and
#: (by inclusion) the platform admin. Everything about running one customer,
#: and nothing that decides what a customer is allowed: the scope approval and
#: the quota stay outside, which is what makes tenant self-service safe to
#: hand over.
_TENANT_ADMIN_PERMISSIONS = (
    AUDIT_READ,
    CONFIG_READ,
    SCAN_SCOPE_READ,
    SCAN_CANCEL,
    TENANT_MEMBER_READ,
    TENANT_MEMBER_MANAGE,
    TENANT_CREDENTIAL_MANAGE,
    TENANT_QUOTA_READ,
)

BUILTIN_ROLES: dict[str, RoleDefinition] = {
    ROLE_VIEWER: _role(
        ROLE_VIEWER,
        1,
        "Reads the tenant's findings and assets",
    ),
    ROLE_OPERATOR: _role(
        ROLE_OPERATOR,
        2,
        "Runs scans and works the findings",
        CONFIG_READ,
        SCAN_CANCEL,
    ),
    ROLE_ADMIN: _role(
        ROLE_ADMIN,
        3,
        "Administers this tenant: members, credentials, audit trail",
        *_TENANT_ADMIN_PERMISSIONS,
    ),
    ROLE_AUDITOR: _role(
        ROLE_AUDITOR,
        # Rank 1, so every write gate in the API refuses it. An auditor who
        # could change the thing they are reviewing is not an auditor.
        1,
        "Reads the audit trail and the configuration, writes nothing",
        AUDIT_READ,
        CONFIG_READ,
        SCAN_SCOPE_READ,
        TENANT_QUOTA_READ,
    ),
    ROLE_SCAN_OPERATOR: _role(
        ROLE_SCAN_OPERATOR,
        2,
        "Runs scans within the approved scope, and cannot widen it",
        CONFIG_READ,
        SCAN_CANCEL,
    ),
    ROLE_SCOPE_APPROVER: _role(
        ROLE_SCOPE_APPROVER,
        1,
        "Approves what the tenant may scan, and runs nothing",
        SCAN_SCOPE_READ,
        SCAN_SCOPE_APPROVE,
    ),
    ROLE_TOKEN_ADMIN: _role(
        ROLE_TOKEN_ADMIN,
        1,
        "Manages the tenant's provisioning keys and service tokens",
        TENANT_CREDENTIAL_MANAGE,
    ),
    ROLE_RISK_APPROVER: _role(
        ROLE_RISK_APPROVER,
        1,
        "Approves and rejects requested risk acceptances (#348)",
        VULNERABILITY_EXCEPTION_APPROVE,
    ),
    ROLE_PLATFORM_ADMIN: _role(
        ROLE_PLATFORM_ADMIN,
        3,
        "Administers the installation and every tenant in it",
        *PERMISSIONS,
    ),
}

#: Assignable in ``users.role``. Unchanged by this issue: the three original
#: names, of which ``admin`` means platform admin.
GLOBAL_ROLES: tuple[str, ...] = (ROLE_VIEWER, ROLE_OPERATOR, ROLE_ADMIN)

#: Assignable on a membership — everything above except the platform admin,
#: which is a property of the account and not a grant inside one tenant.
TENANT_ROLES: tuple[str, ...] = tuple(
    name for name in BUILTIN_ROLES if name != ROLE_PLATFORM_ADMIN
)

#: What the global ``admin`` carries in whichever tenant it is acting in.
PLATFORM_ADMIN_PERMISSIONS: frozenset[str] = BUILTIN_ROLES[ROLE_PLATFORM_ADMIN].permissions

#: ``role -> rank`` for every built-in role, including the platform admin, so
#: :func:`api.auth.require_role` cannot ``KeyError`` on a role a membership
#: legitimately holds.
ROLE_RANKS: dict[str, int] = {name: role.rank for name, role in BUILTIN_ROLES.items()}


def permissions_for(role: str, *, is_platform_admin: bool = False) -> frozenset[str]:
    """What this role may do. An unknown role gets nothing, never everything.

    ``is_platform_admin`` wins over ``role``: the global admin acts in every
    tenant, and the membership row it may also happen to have there cannot
    lower that (which is the pre-existing rule in
    :func:`api.services.memberships.resolve_tenant`, expressed here in
    permissions).
    """
    if is_platform_admin:
        return PLATFORM_ADMIN_PERMISSIONS
    definition = BUILTIN_ROLES.get(role)
    return definition.permissions if definition is not None else frozenset()


def rank_for(role: str) -> int:
    """The legacy read/write rank of ``role``; 1 (read-only) when unknown."""
    return ROLE_RANKS.get(role, 1)
