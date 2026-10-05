"""The permission catalogue, the role table, and the roles a tenant defines (#318).

:mod:`api.core.permissions` is what the API *enforces* for the built-in roles;
this module publishes the catalogue, and since the last part of #318 it is
also where a **tenant-defined role** lives: a name, a rank and an explicit set
of permissions, written by the tenant's own member managers under ``roles``/
``role_permissions`` with ``tenant_id`` set (the built-ins sit under ``""``).

**Resolution.** A built-in role still resolves from the compiled table without
touching the database (:func:`resolve`), so every membership written before
custom roles existed means exactly what it did. A tenant role is read from its
rows — the one authorization input that has to be, because a tenant wrote it —
and it fails *closed*: a name that is neither a built-in nor a role of *this*
tenant (deleted, renamed under a stale replica, another tenant's) resolves to
rank 1 and no permissions, never to an error and never to a guess. Whatever a
row says, the permissions it resolves to are cut to
:data:`~api.core.permissions.TENANT_GRANTABLE_PERMISSIONS`, so a row edited by
hand cannot reach a ``platform.*`` authority either.

**What a role may be.** Checked on every write, by everyone, platform admin
included:

* the name is lowercase, dash-separated, and not a built-in's (``admin`` in
  one tenant must not mean something else than in the next);
* every permission is in the catalogue and is one a tenant role can carry —
  ``config.write`` and ``platform.*`` are refused with 422;
* the approvals are not combined with writing or with granting memberships
  (:func:`api.core.permissions.separation_of_duties_conflict`).

**Who may write one.** ``tenant.member.manage`` in the tenant, and never more
than the writer holds (:func:`api.core.permissions.exceeds_authority`) — in
rank and in permissions, both for what the role becomes and for what it was,
so a member manager can neither define a role above themselves nor narrow or
delete one that is.

**Renaming and deleting never silently change anybody's access.** A rename
carries every membership that names the role to the new name in the same
transaction, so its holders keep exactly what they had. A delete is refused
with :class:`RoleInUse` while anybody holds the role; the caller either
revokes or regrants them first, or names ``reassign_to`` — a role the deleter
may grant, recorded per membership as a ``membership.grant`` with the role
before and after. The role row is taken ``FOR UPDATE`` by both, and
:func:`api.services.memberships.grant` takes it ``FOR SHARE`` before writing a
membership that names it, so a grant racing a delete either lands first (and
the delete sees the holder) or finds the role gone (and is refused).

**A built-in role added later.** Tenant role names are refused when they
collide with a built-in *today*; a release that adds a built-in role whose
name some tenant already uses has to rename that tenant's role in its own
migration, because :func:`resolve` checks the compiled table first and the
tenant's holders would otherwise acquire the new built-in's authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from api.core import permissions as permission_catalog
from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import tenants as tenants_service
from api.settings import Settings

#: ``roles.tenant_id`` of a role every tenant has. See :class:`models.RoleDefinition`.
BUILTIN_SCOPE = ""

#: Lowercase letters, digits and single dashes, starting with a letter: the
#: shape of the built-in names, so a tenant's ``soc-lead`` reads like one.
_ROLE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_ROLE_ID_MAX = 48
_DESCRIPTION_MAX = 200
#: Per tenant. A role table nobody can read to the end is not a separation of
#: duties, and the console renders the whole list on one page.
MAX_TENANT_ROLES = 64

_settings: Settings | None = None


class RoleExists(ValueError):
    """The name is taken in this tenant (or is a built-in's). Answered 409."""


class RoleInUse(ValueError):
    """Deleting the role is refused because memberships still name it.

    A ValueError like the module's other refusals, but its own class: the
    route answers it with 409 and a malformed name with 422, and the message
    says how many members hold it so the caller knows what ``reassign_to``
    would move.
    """


@dataclass(frozen=True)
class ResolvedRole:
    """One role as the authorization layer sees it."""

    name: str
    rank: int
    permissions: frozenset[str]
    builtin: bool


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "rbac.configure() not called"
    return _settings


def _now() -> datetime:
    # Naive UTC, like every other timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


# --- Resolution -------------------------------------------------------------


#: What a role name nobody can resolve is worth: the lowest rank, nothing else.
def _unresolved(name: str) -> ResolvedRole:
    return ResolvedRole(name=name, rank=1, permissions=frozenset(), builtin=False)


def _builtin(name: str) -> ResolvedRole | None:
    """A built-in *tenant* role, or None. ``platform-admin`` is not one."""
    if name not in permission_catalog.TENANT_ROLES:
        return None
    definition = permission_catalog.BUILTIN_ROLES[name]
    return ResolvedRole(
        name=name, rank=definition.rank, permissions=definition.permissions, builtin=True
    )


def _custom_row(
    session, tenant_id: str, role_id: str, *, lock: str | None = None
) -> models.RoleDefinition | None:
    stmt = select(models.RoleDefinition).where(
        models.RoleDefinition.role_id == role_id,
        models.RoleDefinition.tenant_id == tenant_id,
        models.RoleDefinition.builtin.is_(False),
    )
    if lock == "update":
        stmt = stmt.with_for_update()
    elif lock == "share":
        stmt = stmt.with_for_update(read=True)
    return session.execute(stmt).scalar_one_or_none()


def _held_permissions(session, tenant_id: str, role_id: str) -> frozenset[str]:
    keys = session.execute(
        select(models.RolePermission.permission_key).where(
            models.RolePermission.role_id == role_id,
            models.RolePermission.tenant_id == tenant_id,
        )
    ).scalars().all()
    return frozenset(keys)


def _resolved_custom(row: models.RoleDefinition, held: frozenset[str]) -> ResolvedRole:
    # Clamped and cut on the way *out*, not only checked on the way in: the
    # check constraints and the service are what write these rows, and this is
    # what a row that got past both — restored from a dump, edited by hand —
    # is still unable to do.
    rank = min(max(int(row.rank or 1), 1), 3)
    return ResolvedRole(
        name=row.role_id,
        rank=rank,
        permissions=held & permission_catalog.TENANT_GRANTABLE_PERMISSIONS,
        builtin=False,
    )


def role_in_session(
    session, tenant_id: str, role: str, *, lock: str | None = None
) -> ResolvedRole | None:
    """``role`` as it stands in ``tenant_id``, read in the caller's session.

    None when the name is neither a built-in tenant role nor a role this
    tenant defined. ``lock`` (``"share"``/``"update"``) takes the tenant role's
    row with it, which is how a grant and a delete of the same role serialise.
    """
    builtin = _builtin(role)
    if builtin is not None:
        return builtin
    row = _custom_row(session, tenant_id, role, lock=lock)
    if row is None:
        return None
    return _resolved_custom(row, _held_permissions(session, tenant_id, role))


def resolve(tenant_id: str, role: str, *, is_platform_admin: bool = False) -> ResolvedRole:
    """The rank and permissions ``role`` carries in ``tenant_id``. Never raises
    for an unknown name — see the module docstring for why it fails closed.

    The built-ins, and the platform admin, are answered from the compiled
    table without a query; only a tenant role costs one.
    """
    if is_platform_admin:
        return ResolvedRole(
            name=role,
            rank=permission_catalog.BUILTIN_ROLES[permission_catalog.ROLE_PLATFORM_ADMIN].rank,
            permissions=permission_catalog.PLATFORM_ADMIN_PERMISSIONS,
            builtin=True,
        )
    builtin = _builtin(role)
    if builtin is not None:
        return builtin
    if not role or not tenant_id:
        return _unresolved(role)
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        resolved = role_in_session(session, tenant_id, role)
    return resolved if resolved is not None else _unresolved(role)


def held_by(username: str, *, global_role: str) -> list[tuple[str | None, ResolvedRole]]:
    """Every role ``username`` holds, in every tenant, as ``(tenant_id, role)``.

    What the MFA policy asks (#504): not "what may this request do here" —
    :func:`resolve` — but "what could this password do anywhere". Resolved by
    the same rules as a request, so the answer cannot drift from what the
    account is actually allowed: the global ``admin`` holds the platform
    admin's permissions everywhere (``tenant_id`` None), an account with no
    membership holds its global role in ``default`` (also None: it comes from
    ``users.role``, not from a grant), and a membership naming a tenant role
    that no longer resolves holds nothing.

    Read across tenants on purpose, in the system scope — it runs during
    authentication, before a tenant is known, exactly like the membership
    lookup that finds one.
    """
    role = str(global_role or "").lower()
    if role == permission_catalog.ROLE_ADMIN:
        return [(None, resolve("", role, is_platform_admin=True))]
    settings = _require_settings()
    with tenant_scope.system("authentication: MFA policy"):
        with get_session(settings.postgres_url) as session:
            memberships = session.execute(
                select(models.UserTenant.tenant_id, models.UserTenant.role)
                .where(models.UserTenant.username == username)
                .order_by(models.UserTenant.tenant_id)
            ).all()
            if not memberships:
                return [(None, _builtin(role) or _unresolved(role))]
            return [
                (tenant_id, role_in_session(session, tenant_id, name) or _unresolved(name))
                for tenant_id, name in memberships
            ]


# --- Read side --------------------------------------------------------------


def list_permissions() -> list[dict[str, Any]]:
    """The whole catalogue, in key order, with whether a tenant role may hold it."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Permission).order_by(models.Permission.permission_key)
        ).scalars().all()
        return [
            {
                "permission_key": row.permission_key,
                "description": row.description,
                "tenant_grantable": row.permission_key
                in permission_catalog.TENANT_GRANTABLE_PERMISSIONS,
            }
            for row in rows
        ]


def list_roles(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Built-in roles, plus the ones ``tenant_id`` defined for itself.

    Built-ins first and then by name, so the list a console renders does not
    reorder itself when a tenant adds a role. With a tenant, each role also
    carries how many of its members hold it — what somebody about to delete or
    narrow a role needs to know first.
    """
    settings = _require_settings()
    scopes = [BUILTIN_SCOPE]
    if tenant_id:
        scopes.append(tenant_id)
    with get_session(settings.postgres_url) as session:
        roles = session.execute(
            select(models.RoleDefinition).where(
                models.RoleDefinition.tenant_id.in_(scopes)
            )
        ).scalars().all()
        grants = session.execute(
            select(
                models.RolePermission.role_id,
                models.RolePermission.tenant_id,
                models.RolePermission.permission_key,
            ).where(models.RolePermission.tenant_id.in_(scopes))
        ).all()
        holders: dict[str, int] = {}
        if tenant_id:
            holders = {
                role: int(count)
                for role, count in session.execute(
                    select(models.UserTenant.role, func.count(models.UserTenant.id))
                    .where(models.UserTenant.tenant_id == tenant_id)
                    .group_by(models.UserTenant.role)
                ).all()
            }
    held: dict[tuple[str, str], list[str]] = {}
    for role_id, scope, permission_key in grants:
        held.setdefault((role_id, scope), []).append(permission_key)
    items = [
        {
            "role_id": row.role_id,
            # None rather than "" on the way out: "every tenant's" is an
            # absence of a tenant, and a consumer comparing this against its
            # own tenant id should not have to know the sentinel.
            "tenant_id": row.tenant_id or None,
            "description": row.description,
            "builtin": row.builtin,
            "rank": row.rank,
            "permissions": sorted(held.get((row.role_id, row.tenant_id), [])),
            "member_count": holders.get(row.role_id, 0),
            "created_at": _iso(row.created_at),
            "created_by": row.created_by,
            "updated_at": _iso(row.updated_at),
            "updated_by": row.updated_by,
        }
        for row in roles
    ]
    items.sort(key=lambda role: (not role["builtin"], role["role_id"]))
    return items


# --- Write side -------------------------------------------------------------


def normalize_role_id(value: str) -> str:
    """One tenant role name as it is stored. Raises ValueError on anything else."""
    role_id = str(value or "").strip().lower()
    if len(role_id) < 2 or len(role_id) > _ROLE_ID_MAX or not _ROLE_ID_RE.match(role_id):
        raise ValueError(
            f"invalid role name {value!r}: 2-{_ROLE_ID_MAX} lowercase letters, digits "
            "and single dashes, starting with a letter"
        )
    if role_id in permission_catalog.BUILTIN_ROLES:
        raise RoleExists(f"role name {role_id!r} is a built-in role")
    return role_id


def _validated_definition(rank: int, permissions: list[str]) -> frozenset[str]:
    """The permission set a role may be given, or ValueError naming why not.

    Independent of who asks: these are refused for the platform admin too.
    """
    if rank not in permission_catalog.RANKS:
        raise ValueError(f"rank must be one of {', '.join(map(str, permission_catalog.RANKS))}")
    keys = frozenset(str(key).strip() for key in permissions)
    unknown = sorted(keys - set(permission_catalog.PERMISSIONS))
    if unknown:
        raise ValueError(f"unknown permission(s): {', '.join(unknown)}")
    platform_only = sorted(keys - permission_catalog.TENANT_GRANTABLE_PERMISSIONS)
    if platform_only:
        raise ValueError(
            f"{', '.join(platform_only)} cannot be held by a tenant role: "
            "it is the platform's authority, not a tenant's"
        )
    conflict = permission_catalog.separation_of_duties_conflict(rank, keys)
    if conflict:
        raise ValueError(conflict)
    return keys


def _refuse_above(
    actor: permission_catalog.Authority, rank: int, permissions: frozenset[str], what: str
) -> None:
    reason = permission_catalog.exceeds_authority(rank, permissions, actor)
    if reason:
        raise PermissionError(f"{what}: {reason}")


def _snapshot(row: models.RoleDefinition, permissions: frozenset[str]) -> dict[str, Any]:
    return {
        "role_id": row.role_id,
        "description": row.description,
        "rank": row.rank,
        "permissions": sorted(permissions),
    }


def _write_permissions(session, tenant_id: str, role_id: str, keys: frozenset[str]) -> None:
    session.query(models.RolePermission).filter(
        models.RolePermission.role_id == role_id,
        models.RolePermission.tenant_id == tenant_id,
    ).delete(synchronize_session=False)
    for key in sorted(keys):
        session.add(
            models.RolePermission(role_id=role_id, tenant_id=tenant_id, permission_key=key)
        )


def _holders(session, tenant_id: str, role_id: str) -> list[models.UserTenant]:
    return list(
        session.execute(
            select(models.UserTenant)
            .where(
                models.UserTenant.tenant_id == tenant_id,
                models.UserTenant.role == role_id,
            )
            .order_by(models.UserTenant.username)
            .with_for_update()
        ).scalars().all()
    )


def _one(tenant_id: str, role_id: str) -> dict[str, Any]:
    for item in list_roles(tenant_id):
        if item["role_id"] == role_id and item["tenant_id"] == tenant_id:
            return item
    raise LookupError(f"role not found: {role_id}")  # pragma: no cover - just written


def create_role(
    *,
    tenant_id: str,
    role_id: str,
    description: str = "",
    rank: int = 1,
    permissions: list[str],
    actor: permission_catalog.Authority,
    created_by: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Define one role in one tenant.

    LookupError for an unknown tenant; RoleExists for a taken name; ValueError
    for a malformed one or a definition no tenant role may have;
    PermissionError when it would exceed ``actor``.
    """
    settings = _require_settings()
    if tenants_service.get_tenant(tenant_id) is None:
        raise LookupError(f"tenant not found: {tenant_id}")
    role_id = normalize_role_id(role_id)
    keys = _validated_definition(rank, permissions)
    _refuse_above(actor, rank, keys, f"role {role_id!r} would exceed the caller")

    with get_session(settings.postgres_url) as session:
        count = session.execute(
            select(func.count())
            .select_from(models.RoleDefinition)
            .where(models.RoleDefinition.tenant_id == tenant_id)
        ).scalar_one()
        if count >= MAX_TENANT_ROLES:
            raise ValueError(f"a tenant may define at most {MAX_TENANT_ROLES} roles")
        if session.get(models.RoleDefinition, (role_id, tenant_id)) is not None:
            raise RoleExists(f"role already exists: {role_id}")
        row = models.RoleDefinition(
            role_id=role_id,
            tenant_id=tenant_id,
            description=str(description or "").strip()[:_DESCRIPTION_MAX],
            builtin=False,
            rank=rank,
            created_at=_now(),
            created_by=created_by,
        )
        try:
            # Two managers creating the same name at once both pass the check
            # above; the loser meets the primary key here, inside a SAVEPOINT
            # so the failure does not abort the transaction the audit row is
            # written in — the same shape as agent_groups.create_group.
            with session.begin_nested():
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise RoleExists(f"role already exists: {role_id}") from exc
        _write_permissions(session, tenant_id, role_id, keys)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_ROLE_CREATE,
            resource_type="role",
            resource_id=role_id,
            tenant_id=tenant_id,
            after=_snapshot(row, keys),
        )
    return _one(tenant_id, role_id)


def update_role(
    *,
    tenant_id: str,
    role_id: str,
    new_role_id: str | None = None,
    description: str | None = None,
    rank: int | None = None,
    permissions: list[str] | None = None,
    actor: permission_catalog.Authority,
    updated_by: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Rename a tenant role, or change what it may do. Fields left None stay.

    A changed definition applies to every member holding the role from their
    next request — that is what editing a role means, and why the old *and*
    the new definition have to be within ``actor``. A rename moves those
    members to the new name in the same transaction.
    """
    settings = _require_settings()
    current_id = str(role_id or "").strip().lower()
    with get_session(settings.postgres_url) as session:
        row = _custom_row(session, tenant_id, current_id, lock="update")
        if row is None:
            raise LookupError(f"role not found: {current_id}")
        before_keys = _held_permissions(session, tenant_id, current_id)
        before = _snapshot(row, before_keys)
        _refuse_above(
            actor, row.rank, before_keys, f"role {current_id!r} is stronger than the caller"
        )

        next_rank = row.rank if rank is None else rank
        next_keys = _validated_definition(
            next_rank, sorted(before_keys) if permissions is None else permissions
        )
        _refuse_above(
            actor, next_rank, next_keys, f"role {current_id!r} would exceed the caller"
        )

        target_id = current_id
        moved = 0
        if new_role_id is not None and new_role_id.strip().lower() != current_id:
            target_id = normalize_role_id(new_role_id)
            if session.get(models.RoleDefinition, (target_id, tenant_id)) is not None:
                raise RoleExists(f"role already exists: {target_id}")
            # The primary key is the name, and role_permissions points at it
            # without ON UPDATE CASCADE, so a rename is a new row, the
            # memberships moved onto it, and the old row deleted — one
            # transaction, so no committed state has a holder of a role that
            # does not exist. A request resolving across the commit can read
            # the old name from its membership and then find that row gone;
            # it gets the lowest authority for that one request, which is the
            # direction a race here has to fail in.
            renamed = models.RoleDefinition(
                role_id=target_id,
                tenant_id=tenant_id,
                description=row.description,
                builtin=False,
                rank=row.rank,
                created_at=row.created_at,
                created_by=row.created_by,
            )
            session.add(renamed)
            session.flush()
            moved = session.execute(
                update(models.UserTenant)
                .where(
                    models.UserTenant.tenant_id == tenant_id,
                    models.UserTenant.role == current_id,
                )
                .values(role=target_id)
                .execution_options(synchronize_session=False)
            ).rowcount or 0
            session.delete(row)
            session.flush()
            row = renamed

        if description is not None:
            row.description = str(description).strip()[:_DESCRIPTION_MAX]
        row.rank = next_rank
        row.updated_at = _now()
        row.updated_by = updated_by
        _write_permissions(session, tenant_id, target_id, next_keys)
        after = _snapshot(row, next_keys)
        if moved:
            after["memberships_renamed"] = moved
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_ROLE_UPDATE,
            resource_type="role",
            resource_id=target_id,
            tenant_id=tenant_id,
            before=before,
            after=after,
        )
    return _one(tenant_id, target_id)


def delete_role(
    *,
    tenant_id: str,
    role_id: str,
    reassign_to: str | None = None,
    actor: permission_catalog.Authority,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Delete a tenant role. Refused (RoleInUse) while held, unless ``reassign_to``.

    ``reassign_to`` is a role the members holding this one are regranted —
    a built-in or another role of this tenant, within what ``actor`` may
    grant, each move recorded as a ``membership.grant``. Returns the deleted
    name and how many memberships moved.
    """
    settings = _require_settings()
    current_id = str(role_id or "").strip().lower()
    with get_session(settings.postgres_url) as session:
        row = _custom_row(session, tenant_id, current_id, lock="update")
        if row is None:
            raise LookupError(f"role not found: {current_id}")
        held = _held_permissions(session, tenant_id, current_id)
        _refuse_above(actor, row.rank, held, f"role {current_id!r} is stronger than the caller")

        holders = _holders(session, tenant_id, current_id)
        target: ResolvedRole | None = None
        if reassign_to is not None:
            target_name = str(reassign_to).strip().lower()
            if target_name == current_id:
                raise ValueError("reassign_to must name a different role")
            target = role_in_session(session, tenant_id, target_name, lock="share")
            if target is None:
                raise ValueError(f"unknown role for this tenant: {target_name}")
            _refuse_above(
                actor,
                target.rank,
                target.permissions,
                f"cannot reassign to {target_name!r}",
            )
        if holders and target is None:
            raise RoleInUse(
                f"role {current_id} is held by {len(holders)} member(s); revoke or "
                "regrant them first, or name reassign_to"
            )

        if target is not None:
            for membership in holders:
                membership.role = target.name
                audit_service.record(
                    session,
                    audit,
                    action=audit_service.ACTION_MEMBERSHIP_GRANT,
                    resource_type="membership",
                    resource_id=membership.username,
                    tenant_id=tenant_id,
                    before={"role": current_id},
                    after={"role": target.name, "reason": f"role {current_id} deleted"},
                )
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_ROLE_DELETE,
            resource_type="role",
            resource_id=current_id,
            tenant_id=tenant_id,
            before=_snapshot(row, held),
            after=(
                {"reassigned_to": target.name, "memberships": len(holders)}
                if target is not None
                else None
            ),
        )
        session.delete(row)
    return {
        "role_id": current_id,
        "reassigned_to": target.name if target is not None else None,
        "memberships_reassigned": len(holders) if target is not None else 0,
    }
