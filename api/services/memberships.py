"""User -> tenant memberships and request tenant resolution (ROADMAP P0).

Before this, every tenant-scoped route took ``tenant_id`` as a query parameter
and trusted it: any authenticated viewer could read another tenant's assets,
endpoints, or schedules by typing a different id. Tenant context is now
*derived* here from the authenticated username, and a client-supplied
``tenant_id`` is only ever used to **select among** the tenants that user is
already entitled to.

Rules (in order):

* **Platform admin** — a user whose configured global role is ``admin`` acts
  across all tenants; this table does not constrain them. That matches the
  existing admin-only routes (tenant creation, config overrides).
* **Member** — the requested tenant must appear in the user's memberships,
  otherwise the request is refused. With no requested tenant, the user's
  default tenant is used: their only membership, else ``default`` when they
  are a member of it, else the first by name so the choice is stable.
* **No memberships at all** — pre-P0 behaviour is preserved: the user acts in
  the ``default`` tenant with their configured global role. Existing
  single-tenant installations therefore keep working untouched after the
  upgrade; granting any membership opts a user into strict scoping.

The role *inside* a tenant comes from the membership row when one exists and
falls back to the user's global role otherwise, so a membership can grant less
(a global operator who is only a viewer in tenant B) or more (a global viewer
who operates tenant C) than the configured global role.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from api.settings import Settings

VALID_ROLES = ("viewer", "operator", "admin")

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "memberships.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _to_dict(row: models.UserTenant) -> dict[str, Any]:
    return {
        "username": row.username,
        "tenant_id": row.tenant_id,
        "role": row.role,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
    }


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.UserTenant).delete()


def list_memberships(
    *, username: str | None = None, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.UserTenant)
        if username:
            stmt = stmt.where(models.UserTenant.username == username)
        if tenant_id:
            stmt = stmt.where(models.UserTenant.tenant_id == tenant_id)
        rows = session.execute(stmt).scalars().all()
    items = [_to_dict(row) for row in rows]
    items.sort(key=lambda m: (m["username"], m["tenant_id"]))
    return items


def grant(*, username: str, tenant_id: str, role: str, created_by: str | None = None) -> dict[str, Any]:
    """Create or update one membership. Idempotent on (username, tenant_id)."""
    settings = _require_settings()
    username = username.strip()
    if not username:
        raise ValueError("username required")
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {', '.join(VALID_ROLES)}")
    if tenants_service.get_tenant(tenant_id) is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")

    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.UserTenant).where(
                models.UserTenant.username == username,
                models.UserTenant.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if row is None:
            row = models.UserTenant(
                username=username,
                tenant_id=tenant_id,
                role=role,
                created_at=_now(),
                created_by=created_by,
            )
            session.add(row)
            session.flush()
        else:
            row.role = role
        return _to_dict(row)


def revoke(*, username: str, tenant_id: str) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.UserTenant).where(
                models.UserTenant.username == username,
                models.UserTenant.tenant_id == tenant_id,
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        session.delete(row)
        return True


def roles_for_user(username: str) -> dict[str, str]:
    """``{tenant_id: role}`` for one user. Empty when the user has none."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.UserTenant.tenant_id, models.UserTenant.role).where(
                models.UserTenant.username == username
            )
        ).all()
    return {tenant_id: role for tenant_id, role in rows}


def tenants_for_user(username: str, *, is_platform_admin: bool = False) -> list[str]:
    """Tenants the user may act in, in a stable order.

    Platform admins get every tenant; a user with no memberships gets the
    ``default`` tenant only (pre-P0 behaviour).
    """
    if is_platform_admin:
        return [t["tenant_id"] for t in tenants_service.list_tenants()]
    granted = sorted(roles_for_user(username))
    return granted or [tenants_service.DEFAULT_TENANT_ID]


def default_tenant_for_user(username: str, *, is_platform_admin: bool = False) -> str:
    allowed = tenants_for_user(username, is_platform_admin=is_platform_admin)
    if tenants_service.DEFAULT_TENANT_ID in allowed:
        return tenants_service.DEFAULT_TENANT_ID
    return allowed[0] if allowed else tenants_service.DEFAULT_TENANT_ID


def resolve_tenant(
    username: str,
    requested: str | None,
    *,
    global_role: str,
) -> tuple[str, str]:
    """Return ``(tenant_id, effective_role)`` for this request.

    Raises ``PermissionError`` when the caller asked for a tenant they hold no
    membership in — the route turns that into a 403.
    """
    is_platform_admin = global_role == "admin"
    requested = (requested or "").strip() or None

    if is_platform_admin:
        return (requested or tenants_service.DEFAULT_TENANT_ID), "admin"

    granted = roles_for_user(username)
    if not granted:
        # Pre-P0 installations: the user is confined to the default tenant and
        # keeps the global role there.
        tenant_id = requested or tenants_service.DEFAULT_TENANT_ID
        if tenant_id != tenants_service.DEFAULT_TENANT_ID:
            raise PermissionError(f"No access to tenant {tenant_id}")
        return tenant_id, global_role

    if requested is None:
        # Same choice as default_tenant_for_user, without a second query.
        tenant_id = (
            tenants_service.DEFAULT_TENANT_ID
            if tenants_service.DEFAULT_TENANT_ID in granted
            else sorted(granted)[0]
        )
    else:
        if requested not in granted:
            raise PermissionError(f"No access to tenant {requested}")
        tenant_id = requested
    return tenant_id, granted.get(tenant_id, global_role)
