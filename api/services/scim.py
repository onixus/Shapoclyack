"""SCIM 2.0 provisioning: ``/scim/v2/Users`` and ``/scim/v2/Groups`` (#316).

The protocol half of what ``api/services/idp_sync.py`` does for SSO logins: a
directory (Okta, Entra ID, Keycloak…) pushes accounts and group memberships,
and every change to an account's groups is turned into its role and tenant
memberships through the same maps an SSO login uses. The subset implemented is
what those clients send (RFC 7643/7644): list with ``userName eq`` /
``displayName eq`` filters and paging, get, create, ``PUT``, ``PATCH`` (users:
``active``, ``emails``; groups: ``members``, ``displayName``), and ``DELETE``.

Rules carrying the security value:

* **A user's ``id`` is its username**, which is the primary key and never
  changes; a ``userName`` that differs from it is refused (``mutability``).
* **``DELETE /Users/{id}`` deactivates**, it does not delete. The audit trail
  attributes history by username, and a deleted name could be issued to
  somebody else (the reasoning of the erasure tombstone, #332).
* **The token's binding is checked here, on every call** — not by the route,
  which only authenticates. A tenant-bound token sees the accounts that hold a
  membership in its tenants (and the ones it created), writes memberships in
  those tenants only, never touches the global role, and may deactivate only
  an account that belongs to none but its tenants and is not a platform admin.
  Seeing an account is not managing it: the global role and the lifecycle of
  everything else is ``all_tenants`` work.
* **SCIM manages IdP accounts, not local ones.** An account with a password is
  visible (a client checks ``userName`` before it creates) but its role and
  enabled state are not SCIM's; nor is a break-glass account (#315) anything
  SCIM can change.
* **What a person disabled stays disabled.** ``active: true`` re-enables only
  an account SCIM (or the IdP resync) disabled.
* **An account in no mapped group is disabled** (``disabled_source = 'idp'``)
  where the token may manage it, and comes back when a mapped group does — the
  rule an SSO login in authoritative mode applies. A freshly created SCIM user
  therefore cannot sign in until a group grants it something; without that it
  would fall back to the ``default`` tenant with the default role, which is
  access no mapping gave it.

Accounts created here sign in through SSO: the first login whose username
matches one that a SCIM token created, and that no identity is linked to yet,
links it (``api/services/users.py:link_or_provision_sso_user``).
"""

from __future__ import annotations

import logging
import re
import secrets
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import idp_sync
from api.services import sessions as sessions_service
from api.services.scim_tokens import ScimPrincipal
from api.settings import Settings

logger = logging.getLogger(__name__)

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_SPC = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

DEFAULT_COUNT = 100
MAX_COUNT = 200
MAX_GROUP_NAME = 256

_FILTER_RE = re.compile(r'^\s*([A-Za-z][A-Za-z0-9._:-]*)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.I)
_MEMBER_PATH_RE = re.compile(r'^members\s*\[\s*value\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\]$', re.I)
_EMAIL_PATH_RE = re.compile(r"^emails(\[.*\])?(\.value)?$", re.I)

_settings: Settings | None = None


class ScimError(ValueError):
    """A request SCIM answers with ``400`` and a ``scimType`` (RFC 7644 §3.12)."""

    def __init__(self, message: str, *, scim_type: str) -> None:
        super().__init__(message)
        self.scim_type = scim_type


class ScimConflict(ValueError):
    """A ``userName`` or ``displayName`` already taken: ``409 uniqueness``."""


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "scim.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.isoformat().replace("+00:00", "Z")


def _location(settings: Settings, kind: str, resource_id: str) -> str:
    base = settings.public_base_url.strip().rstrip("/")
    return f"{base}/scim/v2/{kind}/{urllib.parse.quote(resource_id, safe='')}"


def _bool(value: Any, what: str) -> bool:
    """SCIM booleans as clients send them: Entra ID sends ``"False"``."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ScimError(f"{what} must be a boolean", scim_type="invalidValue")


def _parse_filter(raw: str | None, allowed: str) -> str | None:
    """The value of ``<allowed> eq "<value>"``; None for no filter at all."""
    if raw is None or not raw.strip():
        return None
    match = _FILTER_RE.match(raw)
    if match is None or match.group(1).lower() != allowed.lower():
        raise ScimError(
            f'only the filter {allowed} eq "<value>" is supported', scim_type="invalidFilter"
        )
    return match.group(2).replace('\\"', '"').replace("\\\\", "\\")


def _page(start_index: int | None, count: int | None) -> tuple[int, int]:
    start = max(1, int(start_index or 1))
    size = DEFAULT_COUNT if count is None else max(0, min(MAX_COUNT, int(count)))
    return start, size


def _list_response(resources: list[dict[str, Any]], total: int, start: int) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


# --------------------------------------------------------------------------- #
# What a token may see and change
# --------------------------------------------------------------------------- #


def _memberships_of(session, username: str) -> set[str]:
    return set(
        session.execute(
            select(models.UserTenant.tenant_id).where(models.UserTenant.username == username)
        ).scalars()
    )


def _visible_users_clause(principal: ScimPrincipal):
    """SQL for "accounts this token can see". None for every account."""
    if principal.all_tenants:
        return None
    in_scope = select(models.UserTenant.username).where(
        models.UserTenant.tenant_id.in_(sorted(principal.tenant_ids))
    )
    return or_(
        models.User.username.in_(in_scope),
        models.User.created_by == principal.created_by_marker,
    )


def _visible_user(session, principal: ScimPrincipal, row: models.User | None) -> bool:
    if row is None or row.erased_at is not None:
        return False
    if principal.all_tenants or row.created_by == principal.created_by_marker:
        return True
    return bool(_memberships_of(session, row.username) & principal.tenant_ids)


def _account_scope(
    session, settings: Settings, principal: ScimPrincipal, row: models.User
) -> idp_sync.SyncScope:
    """What this token may change about this account, beyond memberships.

    The membership half of the scope is the token's own; the role and the
    lifecycle depend on the account too — see the module docstring.
    """
    idp_managed = not row.password_hash and row.username not in settings.break_glass_users
    if principal.all_tenants:
        account = idp_managed and (row.role != "admin" or principal.grant_platform_admin)
        return idp_sync.SyncScope(
            tenant_ids=None,
            manage_role=account,
            manage_active=account,
            allow_admin=principal.grant_platform_admin,
        )
    owned = (
        idp_managed
        and row.role != "admin"
        and _memberships_of(session, row.username) <= principal.tenant_ids
    )
    return idp_sync.SyncScope(
        tenant_ids=frozenset(principal.tenant_ids),
        manage_role=False,
        manage_active=owned,
        allow_admin=False,
    )


def _require_lifecycle(
    session, settings: Settings, principal: ScimPrincipal, row: models.User
) -> None:
    """Refuse a change to the account itself that this token may not make."""
    if row.username in settings.break_glass_users:
        raise PermissionError("a break-glass account is not managed by SCIM")
    if row.password_hash:
        raise PermissionError("a local account with a password is not managed by SCIM")
    if not _account_scope(session, settings, principal, row).manage_active:
        raise PermissionError(
            "this token may not change this account: it is a platform admin or "
            "belongs to tenants outside the token's binding"
        )


def _group_targets(settings: Settings, name: str) -> tuple[bool, set[str]]:
    """``(maps a global role, {tenants it grants})`` for one group name."""
    return (
        name in settings.oidc_role_map,
        {entry["tenant_id"] for entry in settings.idp_group_map.get(name, [])},
    )


def _group_in_scope(
    settings: Settings, principal: ScimPrincipal, name: str, owner: str | None
) -> bool:
    """Whether this token may see and change a group of this name.

    A tenant-bound token may hold a group whose mapping lands inside its
    tenants and nowhere else — never one mapped to a global role, which acts
    in every tenant. An unmapped group is visible only to the token that made
    it, so one tenant's directory cannot read another's group names.
    """
    if principal.all_tenants:
        return True
    global_role, tenants = _group_targets(settings, name)
    if global_role:
        return False
    if tenants:
        return tenants <= principal.tenant_ids
    return owner == principal.token_id


def _group_names_of(session, username: str) -> list[str]:
    return list(
        session.execute(
            select(models.ScimGroup.display_name)
            .join(
                models.ScimGroupMember, models.ScimGroupMember.group_id == models.ScimGroup.group_id
            )
            .where(models.ScimGroupMember.username == username)
        ).scalars()
    )


def _resync(
    session,
    settings: Settings,
    principal: ScimPrincipal,
    username: str,
    audit: "audit_service.AuditContext | None",
) -> None:
    """Re-derive one account's access from its SCIM groups, under its row lock."""
    row = session.get(models.User, username, with_for_update=True)
    if row is None or row.erased_at is not None:
        return
    result = idp_sync.reconcile(
        session,
        settings,
        row,
        _group_names_of(session, username),
        scope=_account_scope(session, settings, principal, row),
        audit=audit,
    )
    if result.reduced or result.granted or result.enabled:
        logger.info("SCIM resync of %r: %s", username, idp_sync.describe(result))


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #


def _active(row: models.User) -> bool:
    """SCIM's ``active``: false only where SCIM or a person said so.

    An account the resync disabled for having no mapped group is still
    ``active`` to the client — it is the client's group pushes that will
    bring it back, and answering ``false`` would invite a ``PATCH active``
    loop that could not change anything.
    """
    return row.disabled_at is None or row.disabled_source == idp_sync.DISABLED_BY_IDP


def _user_resource(session, settings: Settings, principal: ScimPrincipal, row: models.User):
    groups = (
        session.execute(
            select(models.ScimGroup)
            .join(
                models.ScimGroupMember, models.ScimGroupMember.group_id == models.ScimGroup.group_id
            )
            .where(models.ScimGroupMember.username == row.username)
            .order_by(models.ScimGroup.display_name)
        )
        .scalars()
        .all()
    )
    resource: dict[str, Any] = {
        "schemas": [SCHEMA_USER],
        "id": row.username,
        "userName": row.username,
        "active": _active(row),
        "groups": [
            {"value": group.group_id, "display": group.display_name}
            for group in groups
            if _group_in_scope(settings, principal, group.display_name, group.scim_token_id)
        ],
        "meta": {
            "resourceType": "User",
            "created": _iso(row.created_at),
            "lastModified": _iso(row.updated_at),
            "location": _location(settings, "Users", row.username),
        },
    }
    if row.email:
        resource["emails"] = [{"value": row.email, "primary": True}]
    return resource


def _load_user(session, principal: ScimPrincipal, user_id: str, *, lock: bool = False):
    row = session.get(models.User, user_id, with_for_update=lock or None)
    if not _visible_user(session, principal, row):
        raise LookupError(f"User {user_id} not found")
    return row


def _email_from(value: Any) -> str | None:
    """The primary (else first) address of a SCIM ``emails`` value."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        raise ScimError("emails must be a list", scim_type="invalidValue")
    entries = [entry for entry in value if isinstance(entry, dict) and entry.get("value")]
    primary = [entry for entry in entries if entry.get("primary") is True]
    chosen = (primary or entries or [None])[0]
    return str(chosen["value"]) if chosen else None


def _normalise_email(email: str | None) -> str | None:
    cleaned = (email or "").strip().lower()
    return cleaned[:320] or None


def _set_email(session, row: models.User, email: str | None) -> bool:
    """Write the address, **unverified**. True when it changed.

    Unverified on purpose: a verified address is what an SSO identity is
    linked to an account by (#156), and that assertion stays a console
    administrator's. SCIM accounts are linked by username instead.
    """
    cleaned = _normalise_email(email)
    if cleaned == row.email:
        return False
    if cleaned is not None:
        clash = session.execute(
            select(models.User.username).where(
                models.User.email == cleaned, models.User.username != row.username
            )
        ).first()
        if clash is not None:
            raise ScimConflict("email is already used by another account")
    row.email = cleaned
    row.email_verified = False
    return True


def _set_active(
    session,
    settings: Settings,
    principal: ScimPrincipal,
    row: models.User,
    active: bool,
    audit: "audit_service.AuditContext | None",
) -> None:
    if active == _active(row):
        return
    _require_lifecycle(session, settings, principal, row)
    now = _now()
    if not active:
        was_disabled = row.disabled_at is not None
        row.disabled_at = row.disabled_at or now
        row.disabled_source = idp_sync.DISABLED_BY_SCIM
        row.updated_at = now
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_DISABLE,
            resource_type="user",
            resource_id=row.username,
            before={"disabled": was_disabled},
            after={"disabled": True, "source": "scim"},
        )
        session.flush()
        sessions_service.revoke_all_in_session(
            session, row.username, reason=sessions_service.END_REVOKED
        )
        return
    if row.disabled_at is not None and row.disabled_source is None:
        raise PermissionError(
            "this account was disabled by a console administrator; SCIM cannot re-enable it"
        )
    if row.disabled_source == idp_sync.DISABLED_BY_SCIM:
        row.disabled_at = None
        row.disabled_source = None
        row.updated_at = now
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_DISABLE,
            resource_type="user",
            resource_id=row.username,
            before={"disabled": True},
            after={"disabled": False, "source": "scim"},
        )
        session.flush()
        # A clean start, as a person's re-enable is (#314).
        sessions_service.revoke_all_in_session(
            session, row.username, reason=sessions_service.END_REVOKED
        )
    # Back to what the groups say: a re-enabled account in no mapped group is
    # disabled again, this time as the IdP's.
    _resync(session, settings, principal, row.username, audit)


def list_users(
    principal: ScimPrincipal,
    *,
    filter: str | None = None,
    start_index: int | None = None,
    count: int | None = None,
) -> dict[str, Any]:
    settings = _require_settings()
    wanted = _parse_filter(filter, "userName")
    start, size = _page(start_index, count)
    with get_session(settings.postgres_url) as session:
        stmt = select(models.User).where(models.User.erased_at.is_(None))
        clause = _visible_users_clause(principal)
        if clause is not None:
            stmt = stmt.where(clause)
        if wanted is not None:
            stmt = stmt.where(models.User.username == wanted)
        total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = (
            session.execute(stmt.order_by(models.User.username).offset(start - 1).limit(size))
            .scalars()
            .all()
        )
        resources = [_user_resource(session, settings, principal, row) for row in rows]
    return _list_response(resources, int(total), start)


def get_user(principal: ScimPrincipal, user_id: str) -> dict[str, Any]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = _load_user(session, principal, user_id)
        return _user_resource(session, settings, principal, row)


def create_user(
    principal: ScimPrincipal,
    payload: dict[str, Any],
    *,
    audit: "audit_service.AuditContext | None",
) -> dict[str, Any]:
    """Create an IdP-managed account: no password, the default role.

    It starts in no group, so where the token may manage it the resync
    disables it straight away (``disabled_source = 'idp'``) until a group push
    grants it something — see the module docstring.
    """
    from api.services.users import _validate_username

    settings = _require_settings()
    name = payload.get("userName")
    if not isinstance(name, str) or not name.strip():
        raise ScimError("userName is required", scim_type="invalidValue")
    try:
        username = _validate_username(name)
    except ValueError as exc:
        raise ScimError(str(exc), scim_type="invalidValue") from exc
    active = _bool(payload.get("active", True), "active")
    now = _now()
    with get_session(settings.postgres_url) as session:
        if session.get(models.User, username) is not None:
            raise ScimConflict(f"userName {username!r} already exists")
        row = models.User(
            username=username,
            password_hash="",
            # The default role, unless that is ``admin`` and this token may not
            # make one: a default is not a way around the token's binding.
            role=(
                settings.oidc_default_role
                if settings.oidc_default_role != "admin" or principal.grant_platform_admin
                else "viewer"
            ),
            created_at=now,
            updated_at=now,
            password_changed_at=None,
            created_by=principal.created_by_marker,
            email=None,
            email_verified=False,
        )
        session.add(row)
        _set_email(session, row, _email_from(payload.get("emails")))
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_CREATE,
            resource_type="user",
            resource_id=username,
            after={"username": username, "role": row.role, "email": row.email, "source": "scim"},
        )
        if not active:
            _set_active(session, settings, principal, row, False, audit)
        _resync(session, settings, principal, username, audit)
        return _user_resource(session, settings, principal, row)


def replace_user(
    principal: ScimPrincipal,
    user_id: str,
    payload: dict[str, Any],
    *,
    audit: "audit_service.AuditContext | None",
) -> dict[str, Any]:
    """``PUT``: the attributes this platform stores are ``emails`` and ``active``."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = _load_user(session, principal, user_id, lock=True)
        name = payload.get("userName")
        if name is not None and name != row.username:
            raise ScimError("userName cannot be changed", scim_type="mutability")
        email = _email_from(payload.get("emails"))
        if _normalise_email(email) != row.email:
            _require_lifecycle(session, settings, principal, row)
            _set_email(session, row, email)
            row.updated_at = _now()
        if "active" in payload:
            _set_active(
                session, settings, principal, row, _bool(payload["active"], "active"), audit
            )
        session.flush()
        return _user_resource(session, settings, principal, row)


def _patch_ops(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if SCHEMA_PATCH not in (payload.get("schemas") or [SCHEMA_PATCH]):
        raise ScimError("not a PatchOp request", scim_type="invalidSyntax")
    ops = payload.get("Operations")
    if not isinstance(ops, list) or not ops:
        raise ScimError("Operations must be a non-empty list", scim_type="invalidSyntax")
    for op in ops:
        if not isinstance(op, dict) or str(op.get("op", "")).lower() not in (
            "add",
            "remove",
            "replace",
        ):
            raise ScimError(
                "each operation needs op add, remove or replace", scim_type="invalidSyntax"
            )
    return ops


def patch_user(
    principal: ScimPrincipal,
    user_id: str,
    payload: dict[str, Any],
    *,
    audit: "audit_service.AuditContext | None",
) -> dict[str, Any]:
    """``PATCH``: ``active`` and ``emails``; ``userName`` only to itself.

    The other core attributes a directory sends — ``name``, ``displayName``,
    ``externalId``, the enterprise extension — are accepted and not stored:
    this platform has nowhere to keep them, and refusing them would refuse
    every real client's update along with them.
    """
    settings = _require_settings()
    ops = _patch_ops(payload)
    with get_session(settings.postgres_url) as session:
        row = _load_user(session, principal, user_id, lock=True)
        for op in ops:
            kind = str(op["op"]).lower()
            path = str(op.get("path") or "").strip()
            value = op.get("value")
            if not path:
                if not isinstance(value, dict):
                    raise ScimError(
                        "an operation without a path needs an object value",
                        scim_type="invalidValue",
                    )
                changes = {str(key).lower(): item for key, item in value.items()}
            else:
                changes = {path.lower(): value}
            for key, item in changes.items():
                if key == "username":
                    if item != row.username:
                        raise ScimError("userName cannot be changed", scim_type="mutability")
                elif key == "active":
                    if kind == "remove":
                        raise ScimError("active cannot be removed", scim_type="mutability")
                    _set_active(session, settings, principal, row, _bool(item, "active"), audit)
                elif _EMAIL_PATH_RE.match(key):
                    email = None if kind == "remove" else _email_from(item)
                    if _normalise_email(email) != row.email:
                        _require_lifecycle(session, settings, principal, row)
                        _set_email(session, row, email)
                        row.updated_at = _now()
        session.flush()
        return _user_resource(session, settings, principal, row)


def deactivate_user(
    principal: ScimPrincipal,
    user_id: str,
    *,
    audit: "audit_service.AuditContext | None",
) -> None:
    """``DELETE``: deactivate and leave the account — see the module docstring."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = _load_user(session, principal, user_id, lock=True)
        _set_active(session, settings, principal, row, False, audit)


# --------------------------------------------------------------------------- #
# Groups
# --------------------------------------------------------------------------- #


def _group_resource(session, settings: Settings, principal: ScimPrincipal, group: models.ScimGroup):
    members = (
        session.execute(
            select(models.User)
            .join(models.ScimGroupMember, models.ScimGroupMember.username == models.User.username)
            .where(models.ScimGroupMember.group_id == group.group_id)
            .order_by(models.User.username)
        )
        .scalars()
        .all()
    )
    resource: dict[str, Any] = {
        "schemas": [SCHEMA_GROUP],
        "id": group.group_id,
        "displayName": group.display_name,
        "members": [
            {"value": member.username, "display": member.username}
            for member in members
            if _visible_user(session, principal, member)
        ],
        "meta": {
            "resourceType": "Group",
            "created": _iso(group.created_at),
            "lastModified": _iso(group.updated_at),
            "location": _location(settings, "Groups", group.group_id),
        },
    }
    if group.external_id:
        resource["externalId"] = group.external_id
    return resource


def _load_group(
    session, settings: Settings, principal: ScimPrincipal, group_id: str, *, lock=False
):
    group = session.get(models.ScimGroup, group_id, with_for_update=lock or None)
    if group is None or not _group_in_scope(
        settings, principal, group.display_name, group.scim_token_id
    ):
        raise LookupError(f"Group {group_id} not found")
    return group


def _display_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScimError("displayName is required", scim_type="invalidValue")
    name = value.strip()
    if len(name) > MAX_GROUP_NAME:
        raise ScimError(
            f"displayName must be at most {MAX_GROUP_NAME} characters", scim_type="invalidValue"
        )
    return name


def _member_ids(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    ids = []
    for entry in value:
        member = entry.get("value") if isinstance(entry, dict) else entry
        if not isinstance(member, str) or not member:
            raise ScimError("each member needs a value", scim_type="invalidValue")
        ids.append(member)
    return ids


def _rename(
    session,
    settings: Settings,
    principal: ScimPrincipal,
    group: models.ScimGroup,
    name: str,
) -> bool:
    if name == group.display_name:
        return False
    # Both ends: renaming is re-mapping, and a token must not move a group
    # into, or out of, a mapping it could not create.
    if not _group_in_scope(settings, principal, name, group.scim_token_id):
        raise PermissionError(f"this token may not manage a group named {name!r}")
    clash = session.execute(
        select(models.ScimGroup.group_id).where(
            models.ScimGroup.display_name == name, models.ScimGroup.group_id != group.group_id
        )
    ).first()
    if clash is not None:
        raise ScimConflict(f"displayName {name!r} already exists")
    group.display_name = name
    return True


def _set_members(
    session,
    principal: ScimPrincipal,
    group: models.ScimGroup,
    *,
    add: list[str] = (),
    remove: list[str] = (),
    replace: list[str] | None = None,
) -> set[str]:
    """Apply a member change and return every username whose groups changed."""
    current = set(
        session.execute(
            select(models.ScimGroupMember.username).where(
                models.ScimGroupMember.group_id == group.group_id
            )
        ).scalars()
    )
    if replace is not None:
        target = set(replace)
        # Members this token cannot see stay where they are: a replace from a
        # tenant-bound client is a statement about the members it knows.
        hidden = {
            username
            for username in current
            if not _visible_user(session, principal, session.get(models.User, username))
        }
        target |= hidden
    else:
        target = (current | set(add)) - set(remove)
    for username in target - current:
        if not _visible_user(session, principal, session.get(models.User, username)):
            raise ScimError(f"no such user: {username}", scim_type="invalidValue")
        session.add(models.ScimGroupMember(group_id=group.group_id, username=username))
    for username in current - target:
        if not _visible_user(session, principal, session.get(models.User, username)):
            raise ScimError(f"no such user: {username}", scim_type="invalidValue")
        session.execute(
            models.ScimGroupMember.__table__.delete().where(
                models.ScimGroupMember.group_id == group.group_id,
                models.ScimGroupMember.username == username,
            )
        )
    session.flush()
    return (target - current) | (current - target)


def _record_group(session, audit, action: str, group: models.ScimGroup, before=None, after=None):
    audit_service.record(
        session,
        audit,
        action=action,
        resource_type="scim_group",
        resource_id=group.group_id,
        before=before,
        after=after,
    )


def list_groups(
    principal: ScimPrincipal,
    *,
    filter: str | None = None,
    start_index: int | None = None,
    count: int | None = None,
) -> dict[str, Any]:
    settings = _require_settings()
    wanted = _parse_filter(filter, "displayName")
    start, size = _page(start_index, count)
    with get_session(settings.postgres_url) as session:
        stmt = select(models.ScimGroup).order_by(models.ScimGroup.display_name)
        if wanted is not None:
            stmt = stmt.where(models.ScimGroup.display_name == wanted)
        # Scope is decided by the mapping, which lives in settings rather than
        # in the table, so it is applied here. Groups are few: one per
        # directory group the client pushes.
        visible = [
            group
            for group in session.execute(stmt).scalars().all()
            if _group_in_scope(settings, principal, group.display_name, group.scim_token_id)
        ]
        page = visible[start - 1 : start - 1 + size]
        resources = [_group_resource(session, settings, principal, group) for group in page]
    return _list_response(resources, len(visible), start)


def get_group(principal: ScimPrincipal, group_id: str) -> dict[str, Any]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        group = _load_group(session, settings, principal, group_id)
        return _group_resource(session, settings, principal, group)


def create_group(
    principal: ScimPrincipal,
    payload: dict[str, Any],
    *,
    audit: "audit_service.AuditContext | None",
) -> dict[str, Any]:
    settings = _require_settings()
    name = _display_name(payload.get("displayName"))
    if not _group_in_scope(settings, principal, name, principal.token_id):
        raise PermissionError(f"this token may not manage a group named {name!r}")
    members = _member_ids(payload.get("members"))
    now = _now()
    with get_session(settings.postgres_url) as session:
        if (
            session.execute(
                select(models.ScimGroup.group_id).where(models.ScimGroup.display_name == name)
            ).first()
            is not None
        ):
            raise ScimConflict(f"displayName {name!r} already exists")
        external_id = payload.get("externalId")
        group = models.ScimGroup(
            group_id=secrets.token_hex(16),
            display_name=name,
            external_id=str(external_id)[:256] if external_id else None,
            scim_token_id=principal.token_id,
            created_at=now,
            updated_at=now,
        )
        session.add(group)
        session.flush()
        touched = _set_members(session, principal, group, add=members)
        _record_group(
            session,
            audit,
            audit_service.ACTION_SCIM_GROUP_CREATE,
            group,
            after={"display_name": name, "members": sorted(touched)},
        )
        for username in sorted(touched):
            _resync(session, settings, principal, username, audit)
        return _group_resource(session, settings, principal, group)


def _apply_group_change(
    session,
    settings: Settings,
    principal: ScimPrincipal,
    group: models.ScimGroup,
    *,
    name: str | None,
    add: list[str] = (),
    remove: list[str] = (),
    replace: list[str] | None = None,
    audit: "audit_service.AuditContext | None",
) -> None:
    before_name = group.display_name
    renamed = name is not None and _rename(session, settings, principal, group, name)
    touched = _set_members(session, principal, group, add=add, remove=remove, replace=replace)
    if not renamed and not touched:
        return
    group.updated_at = _now()
    _record_group(
        session,
        audit,
        audit_service.ACTION_SCIM_GROUP_UPDATE,
        group,
        before={"display_name": before_name},
        after={"display_name": group.display_name, "members_changed": sorted(touched)},
    )
    # A rename re-maps every member, not only the ones that moved.
    affected = set(touched)
    if renamed:
        affected |= set(
            session.execute(
                select(models.ScimGroupMember.username).where(
                    models.ScimGroupMember.group_id == group.group_id
                )
            ).scalars()
        )
    for username in sorted(affected):
        _resync(session, settings, principal, username, audit)


def replace_group(
    principal: ScimPrincipal,
    group_id: str,
    payload: dict[str, Any],
    *,
    audit: "audit_service.AuditContext | None",
) -> dict[str, Any]:
    settings = _require_settings()
    name = _display_name(payload.get("displayName"))
    members = _member_ids(payload.get("members"))
    with get_session(settings.postgres_url) as session:
        group = _load_group(session, settings, principal, group_id, lock=True)
        _apply_group_change(
            session, settings, principal, group, name=name, replace=members, audit=audit
        )
        return _group_resource(session, settings, principal, group)


def patch_group(
    principal: ScimPrincipal,
    group_id: str,
    payload: dict[str, Any],
    *,
    audit: "audit_service.AuditContext | None",
) -> dict[str, Any]:
    settings = _require_settings()
    ops = _patch_ops(payload)
    with get_session(settings.postgres_url) as session:
        group = _load_group(session, settings, principal, group_id, lock=True)
        for op in ops:
            kind = str(op["op"]).lower()
            path = str(op.get("path") or "").strip()
            value = op.get("value")
            member_match = _MEMBER_PATH_RE.match(path) if path else None
            if member_match is not None:
                if kind != "remove":
                    raise ScimError("only remove may name one member", scim_type="invalidPath")
                _apply_group_change(
                    session,
                    settings,
                    principal,
                    group,
                    name=None,
                    remove=[member_match.group(1)],
                    audit=audit,
                )
            elif path.lower() == "members":
                ids = _member_ids(value)
                if kind == "add":
                    _apply_group_change(
                        session, settings, principal, group, name=None, add=ids, audit=audit
                    )
                elif kind == "remove":
                    # No value removes them all (RFC 7644 §3.5.2.2).
                    _apply_group_change(
                        session,
                        settings,
                        principal,
                        group,
                        name=None,
                        replace=[] if value is None else None,
                        remove=ids,
                        audit=audit,
                    )
                else:
                    _apply_group_change(
                        session, settings, principal, group, name=None, replace=ids, audit=audit
                    )
            elif path.lower() == "displayname":
                _apply_group_change(
                    session, settings, principal, group, name=_display_name(value), audit=audit
                )
            elif path.lower() == "externalid":
                group.external_id = str(value)[:256] if value and kind != "remove" else None
            elif not path:
                if not isinstance(value, dict):
                    raise ScimError(
                        "an operation without a path needs an object value",
                        scim_type="invalidValue",
                    )
                fields = {str(key).lower(): item for key, item in value.items()}
                name = _display_name(fields["displayname"]) if "displayname" in fields else None
                replace = (
                    _member_ids(fields["members"])
                    if "members" in fields and kind == "replace"
                    else None
                )
                add = (
                    _member_ids(fields["members"]) if "members" in fields and kind == "add" else []
                )
                _apply_group_change(
                    session,
                    settings,
                    principal,
                    group,
                    name=name,
                    add=add,
                    replace=replace,
                    audit=audit,
                )
            else:
                raise ScimError(f"unsupported path {path!r}", scim_type="invalidPath")
        session.flush()
        return _group_resource(session, settings, principal, group)


def delete_group(
    principal: ScimPrincipal,
    group_id: str,
    *,
    audit: "audit_service.AuditContext | None",
) -> None:
    """Delete the group; each former member's access is re-derived without it."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        group = _load_group(session, settings, principal, group_id, lock=True)
        members = sorted(
            session.execute(
                select(models.ScimGroupMember.username).where(
                    models.ScimGroupMember.group_id == group.group_id
                )
            ).scalars()
        )
        _record_group(
            session,
            audit,
            audit_service.ACTION_SCIM_GROUP_DELETE,
            group,
            before={"display_name": group.display_name, "members": members},
        )
        session.delete(group)
        session.flush()
        for username in members:
            _resync(session, settings, principal, username, audit)


# --------------------------------------------------------------------------- #
# Discovery (RFC 7644 §4)
# --------------------------------------------------------------------------- #


def service_provider_config() -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_SPC],
        "documentationUri": "https://github.com/onixus/Shapoclyack/blob/main/docs/api-and-rbac.md#scim-20-provisioning",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": MAX_COUNT},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "SCIM token",
                "description": "An octo_scim_ bearer token issued under POST /api/auth/scim-tokens",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/scim/v2/ServiceProviderConfig",
        },
    }


def resource_types() -> dict[str, Any]:
    types = [
        {
            "schemas": [SCHEMA_RESOURCE_TYPE],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": SCHEMA_USER,
            "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User"},
        },
        {
            "schemas": [SCHEMA_RESOURCE_TYPE],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": SCHEMA_GROUP,
            "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group"},
        },
    ]
    return _list_response(types, len(types), 1)


def _attribute(name: str, kind: str = "string", **extra: Any) -> dict[str, Any]:
    attribute = {
        "name": name,
        "type": kind,
        "multiValued": False,
        "required": False,
        "caseExact": False,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": "none",
    }
    attribute.update(extra)
    return attribute


def schemas() -> dict[str, Any]:
    user = {
        "schemas": [SCHEMA_SCHEMA],
        "id": SCHEMA_USER,
        "name": "User",
        "attributes": [
            _attribute(
                "userName",
                required=True,
                caseExact=True,
                mutability="immutable",
                uniqueness="server",
            ),
            _attribute("active", "boolean"),
            _attribute(
                "emails",
                "complex",
                multiValued=True,
                subAttributes=[_attribute("value"), _attribute("primary", "boolean")],
            ),
            _attribute("groups", "complex", multiValued=True, mutability="readOnly"),
        ],
        "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{SCHEMA_USER}"},
    }
    group = {
        "schemas": [SCHEMA_SCHEMA],
        "id": SCHEMA_GROUP,
        "name": "Group",
        "attributes": [
            _attribute("displayName", required=True, uniqueness="server"),
            _attribute(
                "members",
                "complex",
                multiValued=True,
                subAttributes=[_attribute("value", mutability="immutable")],
            ),
        ],
        "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{SCHEMA_GROUP}"},
    }
    return _list_response([user, group], 2, 1)


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.ScimGroup).delete()
