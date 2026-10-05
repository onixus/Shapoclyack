"""Keep an account's authority in step with its identity-provider groups (#316).

Before this, the IdP decided an account's role and tenant once — when
just-in-time provisioning created it — and never again: taking somebody out of
``vm-admins`` at the identity provider left them an admin here. This module is
the one place that turns "these are the person's groups" into the role and
memberships they should hold, and it is called from both ways the groups
arrive:

* an **SSO login** with ``OCTO_IDP_AUTHORITATIVE=true`` — the groups are the
  ``OCTO_OIDC_ROLE_CLAIM`` values of the ID token just verified
  (``api/services/users.py:link_or_provision_sso_user``);
* a **SCIM** change — the groups are the SCIM groups the account is a member
  of (``api/services/scim.py``).

One mapping serves both: ``OCTO_OIDC_ROLE_MAP`` (group -> global role) and
``OCTO_IDP_GROUP_MAP`` (group -> tenant memberships).

Decisions worth stating:

* **Only IdP-sourced memberships are the IdP's.** A row granted by a person
  over the API is ``source = 'local'`` and is never added to, changed or
  removed here; where one exists for a tenant the groups also grant, the local
  row stands. Every row written before migration 0076 is local. The other
  choice — the IdP owns every membership — would wipe a tenant's hand-made
  grants the first time an administrator flipped the switch, which is the
  post-upgrade state this has to survive. The cost is stated in the docs: a
  local grant outlives the person's IdP groups until somebody revokes it.
* **The global role is the IdP's** in authoritative mode — that is what the
  mode is for, and the role is the most dangerous thing to leave stale. Not
  for SCIM tokens held to some tenants (it acts across all of them), and
  ``admin`` only where the caller may grant it.
* **No mapped group means no access.** The account is disabled with
  ``disabled_source = 'idp'``, and re-enabled when a mapped group comes back.
  Never one a person disabled (``NULL``) or a SCIM client did (``scim``).
* **Break-glass accounts are not touched**, at all (#315): the emergency door
  is for the day the IdP is the thing that is wrong.
* **A reduction ends the sessions** (#314): a removed or changed membership, a
  changed role, a disable. A JWT carries the account's generation, so the bump
  is what makes "removed from the group" take effect now rather than at the
  token's expiry. A grant alone ends nothing.

Every change is a row in ``audit_events`` in the caller's transaction, with
``"source": "idp"`` in the document so a filter can tell it from a person's.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

from sqlalchemy import select

from api.db import models
from api.services import audit as audit_service
from api.services import rbac as rbac_service
from api.services import sessions as sessions_service
from api.settings import Settings

logger = logging.getLogger(__name__)

SOURCE_LOCAL = "local"
SOURCE_IDP = "idp"
#: ``users.disabled_source`` values. NULL is a person.
DISABLED_BY_IDP = "idp"
DISABLED_BY_SCIM = "scim"

_GLOBAL_RANK = {"viewer": 1, "operator": 2, "admin": 3}


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class SyncScope:
    """What one reconcile may change.

    ``tenant_ids`` None means every tenant. ``manage_role`` covers the global
    role; ``manage_active`` the disable when no mapped group is left (and the
    re-enable when one comes back); ``allow_admin`` whether a group mapped to
    the global ``admin`` role is honoured.
    """

    tenant_ids: frozenset[str] | None = None
    manage_role: bool = True
    manage_active: bool = True
    allow_admin: bool = True

    def covers(self, tenant_id: str) -> bool:
        return self.tenant_ids is None or tenant_id in self.tenant_ids


#: An SSO login in authoritative mode: the IdP decides everything.
LOGIN_SCOPE = SyncScope()


@dataclass
class SyncResult:
    """What a reconcile changed. ``reduced`` is what ended the sessions."""

    granted: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)
    role: tuple[str, str] | None = None
    disabled: bool = False
    enabled: bool = False
    skipped: str | None = None

    @property
    def reduced(self) -> bool:
        return bool(self.changed or self.revoked or self.role or self.disabled)


def is_authoritative(settings: Settings) -> bool:
    """Whether SSO logins resync. Off with nothing mapped (see settings)."""
    return bool(settings.idp_authoritative and (settings.oidc_role_map or settings.idp_group_map))


def mapped_groups(settings: Settings, groups: Iterable[str], scope: SyncScope) -> list[str]:
    """The groups that grant something inside ``scope``, in a stable order.

    A group mapped only to a global role counts only where the scope manages
    the role: a token held to two tenants cannot keep an account alive on the
    strength of a mapping it is not allowed to apply.
    """
    found = []
    for group in sorted(set(groups)):
        if scope.manage_role and group in settings.oidc_role_map:
            found.append(group)
            continue
        if any(scope.covers(entry["tenant_id"]) for entry in settings.idp_group_map.get(group, [])):
            found.append(group)
    return found


def desired_role(settings: Settings, groups: Iterable[str], *, allow_admin: bool) -> str:
    """The global role the groups map to: the highest, else the default.

    With ``allow_admin`` false a group mapped to ``admin`` contributes nothing,
    so the answer falls to the next mapped role rather than to ``admin``.
    """
    mapped = [settings.oidc_role_map[group] for group in groups if group in settings.oidc_role_map]
    if not allow_admin:
        mapped = [role for role in mapped if role != "admin"]
    if not mapped:
        return settings.oidc_default_role
    return max(mapped, key=lambda role: _GLOBAL_RANK.get(role, 0))


def _desired_memberships(
    session, settings: Settings, groups: Iterable[str], scope: SyncScope
) -> dict[str, str]:
    """``{tenant_id: role}`` the groups grant inside ``scope``.

    Several groups granting one tenant resolve to the highest-ranked role, the
    rule ``role_from_claims`` already applies to the global role. A tenant that
    does not exist or a role it does not have grants nothing, with a warning:
    a mapping mistake must not be a reason to refuse a login.
    """
    best: dict[str, tuple[int, str]] = {}
    for group in sorted(set(groups)):
        for entry in settings.idp_group_map.get(group, []):
            tenant_id, role = entry["tenant_id"], entry["role"]
            if not scope.covers(tenant_id):
                continue
            if session.get(models.Tenant, tenant_id) is None:
                logger.warning(
                    "OCTO_IDP_GROUP_MAP maps group %r to unknown tenant %r; ignoring it.",
                    group,
                    tenant_id,
                )
                continue
            resolved = rbac_service.role_in_session(session, tenant_id, role, lock="share")
            if resolved is None:
                logger.warning(
                    "OCTO_IDP_GROUP_MAP maps group %r to role %r, which tenant %r does "
                    "not have; ignoring it.",
                    group,
                    role,
                    tenant_id,
                )
                continue
            current = best.get(tenant_id)
            if current is None or resolved.rank > current[0]:
                best[tenant_id] = (resolved.rank, role)
    return {tenant_id: role for tenant_id, (_, role) in best.items()}


def reconcile(
    session,
    settings: Settings,
    row: models.User,
    groups: Iterable[str],
    *,
    scope: SyncScope,
    audit: "audit_service.AuditContext | None",
) -> SyncResult:
    """Bring ``row``'s role, memberships and enabled state in line with ``groups``.

    Runs in the caller's session, so the changes, their audit rows and the
    session revocation commit together — or none of them do. The caller holds
    the account's row (``FOR UPDATE`` where it can race), which is what keeps
    two concurrent logins of one person from interleaving their writes.
    """
    groups = sorted({str(group) for group in groups})
    result = SyncResult()
    if row.erased_at is not None:
        result.skipped = "erased"
        return result
    if row.username in settings.break_glass_users:
        # Logged rather than audited: nothing changed, and a row per
        # emergency-account login would be noise around the one that matters
        # (``auth.break_glass_login``).
        logger.info("IdP resync skipped for break-glass account %r", row.username)
        result.skipped = "break-glass"
        return result

    username = row.username
    desired = _desired_memberships(session, settings, groups, scope)
    current = (
        session.execute(select(models.UserTenant).where(models.UserTenant.username == username))
        .scalars()
        .all()
    )
    held = {membership.tenant_id: membership for membership in current}

    for membership in current:
        if membership.source != SOURCE_IDP or not scope.covers(membership.tenant_id):
            continue
        want = desired.get(membership.tenant_id)
        if want is None:
            before = {"role": membership.role, "source": SOURCE_IDP}
            session.delete(membership)
            result.revoked.append(membership.tenant_id)
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_MEMBERSHIP_REVOKE,
                resource_type="membership",
                resource_id=username,
                tenant_id=membership.tenant_id,
                before=before,
                after={"source": SOURCE_IDP, "reason": "no mapped IdP group grants it"},
            )
        elif want != membership.role:
            previous = membership.role
            membership.role = want
            result.changed.append(membership.tenant_id)
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_MEMBERSHIP_GRANT,
                resource_type="membership",
                resource_id=username,
                tenant_id=membership.tenant_id,
                before={"role": previous, "source": SOURCE_IDP},
                after={"role": want, "source": SOURCE_IDP},
            )

    for tenant_id, role in sorted(desired.items()):
        if tenant_id in held:
            # Either the IdP's own row, handled above, or a local grant, which
            # is a person's decision and stands as it is.
            continue
        session.add(
            models.UserTenant(
                username=username,
                tenant_id=tenant_id,
                role=role,
                created_at=_now(),
                created_by=audit.actor if audit is not None else "idp",
                source=SOURCE_IDP,
            )
        )
        result.granted.append(tenant_id)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_MEMBERSHIP_GRANT,
            resource_type="membership",
            resource_id=username,
            tenant_id=tenant_id,
            before=None,
            after={"role": role, "source": SOURCE_IDP},
        )

    if scope.manage_role:
        role = desired_role(settings, groups, allow_admin=scope.allow_admin)
        # A scope that may not grant admin may not take it away either: the
        # demotion of a platform admin is a platform admin's decision.
        if role != row.role and (scope.allow_admin or row.role != "admin"):
            result.role = (row.role, role)
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_USER_ROLE,
                resource_type="user",
                resource_id=username,
                before={"role": row.role},
                after={"role": role, "source": SOURCE_IDP},
            )
            row.role = role

    if scope.manage_active:
        has_mapped = bool(mapped_groups(settings, groups, scope))
        if not has_mapped and row.disabled_at is None:
            row.disabled_at = _now()
            row.disabled_source = DISABLED_BY_IDP
            result.disabled = True
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_USER_DISABLE,
                resource_type="user",
                resource_id=username,
                before={"disabled": False},
                after={
                    "disabled": True,
                    "source": SOURCE_IDP,
                    "reason": "in no mapped IdP group",
                },
            )
        elif has_mapped and row.disabled_at is not None and row.disabled_source == DISABLED_BY_IDP:
            row.disabled_at = None
            row.disabled_source = None
            result.enabled = True
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_USER_DISABLE,
                resource_type="user",
                resource_id=username,
                before={"disabled": True},
                after={"disabled": False, "source": SOURCE_IDP},
            )

    if result.reduced or result.enabled:
        row.updated_at = _now()
        session.flush()
        if result.reduced:
            # Ends every access token and refresh-token family of the account,
            # in this transaction (#314). Re-enabling ends nothing that could
            # still be live, but the bump makes it a clean start, exactly as
            # PUT /users/{username}/disabled does.
            sessions_service.revoke_all_in_session(
                session, username, reason=sessions_service.END_REVOKED
            )
    elif result.granted:
        session.flush()
    return result


def describe(result: SyncResult) -> dict[str, Any]:
    """A loggable summary. No group names: they name the customer's directory."""
    return {
        "granted": result.granted,
        "changed": result.changed,
        "revoked": result.revoked,
        "role": list(result.role) if result.role else None,
        "disabled": result.disabled,
        "enabled": result.enabled,
        "skipped": result.skipped,
    }

