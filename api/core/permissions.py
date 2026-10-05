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

**Tenant-defined roles are the exception, and are bounded by this file.** A
tenant can write its own role into those tables (:mod:`api.services.rbac`),
and that one is read back from them — but only ever as a subset of
:data:`TENANT_GRANTABLE_PERMISSIONS`, under the separation-of-duties rule and
the hand-out ceiling declared below (:func:`separation_of_duties_conflict`,
:func:`exceeds_authority`), and resolving to nothing when its row is missing.

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
#: Queue a scan ahead of the tenant's other scans: start one, or move a queued
#: one, with a ``priority`` above the default 0 (#365). Lowering a scan of
#: one's own to make room needs only the operator rank, and so does starting
#: one at or below 0. Its own permission because "jump the queue" is a
#: decision about everybody else's scans, and an operator who could set it on
#: every scan would make the ordering meaningless; the tenant ``admin`` holds
#: it, and a custom role can be given it on its own.
SCAN_PRIORITY_RAISE = "scan.priority.raise"
#: List a tenant's members and their roles.
TENANT_MEMBER_READ = "tenant.member.read"
#: Grant and revoke them — tenant self-service, no longer platform admin only.
TENANT_MEMBER_MANAGE = "tenant.member.manage"
#: Mint, list and revoke a tenant's own agent provisioning keys and service
#: tokens. What ``token-admin`` exists for, and what lets a tenant admin
#: rotate their own key instead of filing a ticket with the platform.
TENANT_CREDENTIAL_MANAGE = "tenant.credential.manage"
#: Create and delete a tenant's agent groups, and decide which agents are in
#: them (#361). Membership is what a job's ``agent_group`` is matched against
#: on claim, so this is the authority to change which worker may execute which
#: customer's scan — a tenant-administration decision, never the agent's own.
AGENT_GROUP_MANAGE = "agent.group.manage"
#: Set how hard this tenant may be scanned (``PUT …/scan-policy``, #362): the
#: rate ceilings pushed to the agent, the ports its scans must never touch, and
#: whether it may run anything but the ``safe`` speed profile. A tenant
#: administration decision rather than a scope approval — it narrows what the
#: platform does to a network it is already approved for — so the tenant's own
#: ``admin`` holds it. Reading it needs only ``scan_scope.read``: whoever may
#: see what a tenant is allowed to scan may see how hard.
SCAN_POLICY_MANAGE = "scan_policy.manage"
#: Decide what the tenant's endpoint agents run and how (``PUT
#: …/endpoint/agent/policy``, #358): their collection intervals and log level,
#: and which of the installation's builds they should upgrade to. The version
#: half is the authority to move every endpoint in the tenant to another
#: binary, which is why it is an administrator's and not an operator's, and
#: why the policy cannot carry the agent's ``server_url`` at all — an agent
#: that can be told where to report is an agent that can be told to report
#: somewhere else. It also lists the builds, and stops there: what those
#: builds *are* is :data:`PLATFORM_ENDPOINT_AGENT_RELEASE`'s.
ENDPOINT_AGENT_MANAGE = "endpoint_agent.manage"
#: Upload and delete endpoint-agent builds (``POST/DELETE
#: …/endpoint/agent/releases``, #510). Platform-only because the builds are:
#: one row per ``(version, platform)`` for the whole installation, so an
#: upload is a binary every tenant's endpoints run once their own policy names
#: that version, and a delete is every tenant's upgrade stopped. Held by a
#: tenant's admin, it was one customer replacing the code another customer's
#: workstations execute.
PLATFORM_ENDPOINT_AGENT_RELEASE = "platform.endpoint_agent_release.manage"
#: Read what the tenant was sold (``GET …/quota``).
TENANT_QUOTA_READ = "tenant.quota.read"
#: Change it. Platform-only on purpose: a tenant admin who could raise their
#: own quota is the control removing itself.
PLATFORM_QUOTA_MANAGE = "platform.quota.manage"
#: Create tenants (``POST /api/tenants``).
PLATFORM_TENANT_MANAGE = "platform.tenant.manage"
#: Suspend and resume a tenant, and request, cancel, approve and retry its
#: deletion (``/api/tenants/{tenant_id}/suspend`` and ``…/deletion``, #325).
#: Its own permission rather than ``platform.tenant.manage``: creating a
#: customer and destroying one are different acts, and an installation that
#: hands out the first to an onboarding role should not have handed out the
#: second with it. Platform-only — a tenant admin who could suspend their own
#: tenant could lock its other admins out, and one who could delete it would
#: be deciding what the platform keeps.
PLATFORM_TENANT_LIFECYCLE = "platform.tenant.lifecycle"
#: See installation-wide counters that span tenants — the tenant and agent
#: totals in ``GET /api/system``, which told a single-tenant viewer how many
#: other customers this installation has.
PLATFORM_FLEET_READ = "platform.fleet.read"
#: Read how long this tenant's data is kept, and whether it is on legal hold
#: (``GET /api/tenants/{tenant_id}/retention``, #332). The tenant's admin and
#: auditor hold it: "how long do you keep our scan evidence" is a question a
#: customer's DPO asks, and the answer is not a platform secret.
TENANT_RETENTION_READ = "tenant.retention.read"
#: Set the tenant's own retention windows (``PUT …/retention``, #332) — only
#: within the bounds the platform configured (``OCTO_RETENTION_BOUNDS``), which
#: is what lets the tenant's own ``admin`` hold it: the audit floor is not a
#: number this permission can reach below.
TENANT_RETENTION_MANAGE = "tenant.retention.manage"
#: Place and release a legal hold (``PUT/DELETE …/legal-hold``, #332).
#: Platform-only, for the reason the quota is: a tenant admin who could release
#: their own hold could let evidence age out mid-litigation, and one who could
#: place it could keep data past what the platform agreed to store.
PLATFORM_LEGAL_HOLD_MANAGE = "platform.legal_hold.manage"
#: Approve or reject a requested risk acceptance on a finding
#: (``POST /api/vulnerabilities/{id}/exception/{approve,reject}``, #348).
#: Holding it is necessary and not sufficient: the service refuses the person
#: who filed the request by name, which is what separates the duties for a
#: platform admin, who holds every permission in this file.
VULNERABILITY_EXCEPTION_APPROVE = "vulnerability.exception.approve"
#: Import a CMDB or directory export into the asset registry (``POST
#: /api/assets/import``, #350). Not the operator's ``PATCH`` at scale: an
#: import *registers* assets, which spends the tenant's purchased asset quota,
#: and rewrites the context of every asset in the file in one request — the
#: tenant's system of record speaking, which is a tenant administrator's
#: decision. An installation that wants a dedicated CMDB integration grants it
#: through a service token issued with the ``admin`` role for that tenant.
#: The route asks for the permission alone, not a rank: a tenant custom role
#: granted it imports at whatever rank it has. Deliberate — a "CMDB sync" role
#: is the use — and documented, since whoever grants it grants quota spend.
ASSET_IMPORT = "asset.import"

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
    SCAN_PRIORITY_RAISE: "Queue a scan ahead of the tenant's other scans",
    TENANT_MEMBER_READ: "List the tenant's members",
    TENANT_MEMBER_MANAGE: "Grant and revoke the tenant's members",
    TENANT_CREDENTIAL_MANAGE: "Manage the tenant's provisioning keys and service tokens",
    AGENT_GROUP_MANAGE: "Manage the tenant's agent groups and their members",
    SCAN_POLICY_MANAGE: "Set how hard this tenant may be scanned",
    ENDPOINT_AGENT_MANAGE: "Manage the tenant's endpoint agents and choose their build",
    PLATFORM_ENDPOINT_AGENT_RELEASE: "Upload and delete the installation's endpoint agent builds",
    TENANT_QUOTA_READ: "Read the tenant's quota",
    PLATFORM_QUOTA_MANAGE: "Set any tenant's quota",
    PLATFORM_TENANT_MANAGE: "Create tenants",
    PLATFORM_TENANT_LIFECYCLE: "Suspend, resume and delete tenants",
    PLATFORM_FLEET_READ: "Read installation-wide counters across tenants",
    VULNERABILITY_EXCEPTION_APPROVE: "Approve an accepted risk on a finding",
    TENANT_RETENTION_READ: "Read the tenant's data retention policy and legal hold",
    TENANT_RETENTION_MANAGE: "Set the tenant's retention windows within the platform bounds",
    PLATFORM_LEGAL_HOLD_MANAGE: "Place and release a legal hold on any tenant",
    ASSET_IMPORT: "Import a CMDB or directory export into the asset registry",
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
    SCAN_PRIORITY_RAISE,
    TENANT_MEMBER_READ,
    TENANT_MEMBER_MANAGE,
    TENANT_CREDENTIAL_MANAGE,
    AGENT_GROUP_MANAGE,
    SCAN_POLICY_MANAGE,
    ENDPOINT_AGENT_MANAGE,
    TENANT_QUOTA_READ,
    TENANT_RETENTION_READ,
    TENANT_RETENTION_MANAGE,
    ASSET_IMPORT,
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
        TENANT_RETENTION_READ,
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


#: Every permission some tenant role carries — the only ones a tenant-defined
#: role may name (#318). Derived rather than listed, so it is exactly "what a
#: membership can already reach": ``config.write`` and the ``platform.*``
#: authorities are held by the platform admin alone and are outside it, which
#: is what stops a tenant from writing a role that would reach the
#: installation. A permission added to the catalogue joins this set the day a
#: built-in tenant role is given it, and not before.
TENANT_GRANTABLE_PERMISSIONS: frozenset[str] = frozenset(
    key for name in TENANT_ROLES for key in BUILTIN_ROLES[name].permissions
)

#: The two *approval* authorities. They are the separation of duties itself:
#: whoever approves must not be whoever acts, so a role carrying either one
#: is held to read rank and may not also grant memberships (see
#: :func:`separation_of_duties_conflict`). They are also the two permissions a
#: tenant ``admin`` hands out without holding — it grants ``scope-approver``
#: and ``risk-approver`` to colleagues, and cannot approve anything itself —
#: which is why :func:`exceeds_authority` lets a member manager at the admin
#: rank delegate them, and nobody below it.
APPROVAL_PERMISSIONS: frozenset[str] = frozenset(
    {SCAN_SCOPE_APPROVE, VULNERABILITY_EXCEPTION_APPROVE}
)

#: The named authorities that decide *who else* may act in a tenant, what it
#: may be pointed at, or what runs on its endpoints: granting memberships and
#: writing roles, minting its provisioning keys and service tokens, the two
#: approvals, and choosing the endpoint agent build every endpoint installs.
#: What ``OCTO_MFA_REQUIRED_PERMISSIONS`` defaults to when
#: ``OCTO_MFA_REQUIRED_ROLES`` names ``admin`` (#504): "MFA for
#: administrators" has to mean whoever holds these in any tenant, not whoever
#: has the word ``admin`` in ``users.role``. Every role holding one — the
#: tenant ``admin``, ``token-admin``, ``scope-approver``, ``risk-approver``, a
#: tenant-defined role carrying any of them — is one a stolen password would
#: turn into somebody else's access.
#:
#: Not the whole of a tenant administrator's power, and not meant to be: the
#: routes still gated on the admin *rank* (webhooks, notification channels,
#: SLA policies, the SSH push's target) are reached by rank 3 whatever the
#: role lists, so the derived default covers rank 3 by itself as well
#: (:func:`api.services.mfa.requirement`). Every route that issues a tenant
#: credential asks for ``tenant.credential.manage`` by name.
TENANT_AUTHORITY_PERMISSIONS: frozenset[str] = frozenset(
    {
        TENANT_MEMBER_MANAGE,
        TENANT_CREDENTIAL_MANAGE,
        SCAN_SCOPE_APPROVE,
        VULNERABILITY_EXCEPTION_APPROVE,
        ENDPOINT_AGENT_MANAGE,
    }
)

#: Ranks a role may sit at: read, write, administer.
RANKS: tuple[int, ...] = (1, 2, 3)


@dataclass(frozen=True)
class Authority:
    """What one principal holds in one tenant — the ceiling of what it may hand out.

    Built by the route from the request's :class:`api.auth.TenantPrincipal`
    and passed to the services that define roles and grant memberships, which
    compare it against what is being handed out (:func:`exceeds_authority`).
    """

    rank: int
    permissions: frozenset[str]
    is_platform_admin: bool = False


def separation_of_duties_conflict(rank: int, permissions: frozenset[str]) -> str | None:
    """Why this combination may not be one role, or None when it may.

    The built-in table keeps the approvals apart from acting by construction —
    ``scope-approver`` and ``risk-approver`` are rank 1 and grant nobody — and a
    tenant-defined role is held to the same shape, by the platform admin as
    much as by anyone: a rank-2 role holding ``scan_scope.approve`` widens a
    scope and runs the scans, and an approver who may also grant memberships
    can approve and then hand the work to an account of their own.
    """
    approvals = sorted(permissions & APPROVAL_PERMISSIONS)
    if not approvals:
        return None
    if rank > 1:
        return (
            f"{', '.join(approvals)} is an approval and is held at read rank only: "
            "an approver who can also write acts on their own approval"
        )
    if TENANT_MEMBER_MANAGE in permissions:
        return (
            f"{', '.join(approvals)} cannot be combined with {TENANT_MEMBER_MANAGE}: "
            "an approver who grants memberships can delegate the act they approved"
        )
    return None


def exceeds_authority(rank: int, permissions: frozenset[str], held: Authority) -> str | None:
    """Why handing out ``rank``/``permissions`` would exceed ``held``, or None.

    The ceiling on defining a role and on granting one (#318): nobody hands out
    more than they have, in either half of a role's authority — the rank is
    what ``require_tenant`` gates on, the permission set is what
    ``require_permission`` gates on, and checking one alone leaks through the
    other (the reasoning :func:`api.services.service_tokens._refuse_escalation`
    gives for tokens). The platform admin has no ceiling: it already holds
    everything in every tenant.

    One exception, and it is the pre-existing one: :data:`APPROVAL_PERMISSIONS`
    may be handed out without being held by a member manager **at the admin
    rank** (3), because that is how the tenant ``admin`` has always staffed
    ``scope-approver`` and ``risk-approver``. It is the admin rank's and not
    any member manager's: a tenant may give ``tenant.member.manage`` to a
    "personnel" role at rank 1 or 2, and with the exception open to it, its
    holder could write an approver role and grant it to a second account of
    their own — approving a wider scope from one and scanning it from the
    other — or write one role holding both approvals the built-ins keep apart
    and take it. At rank 3 that power is the one the tenant admin already
    had; below it, staffing an approval is the tenant admin's call.
    """
    if held.is_platform_admin:
        return None
    if rank > held.rank:
        return f"rank {rank} is above the caller's rank {held.rank} in this tenant"
    delegable = (
        APPROVAL_PERMISSIONS
        if TENANT_MEMBER_MANAGE in held.permissions and held.rank >= ROLE_RANKS[ROLE_ADMIN]
        else frozenset()
    )
    beyond = sorted(permissions - held.permissions - delegable)
    if beyond:
        return f"the caller does not hold {', '.join(beyond)} in this tenant"
    return None


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
