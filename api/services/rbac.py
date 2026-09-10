"""The permission catalogue and the role table, read side (#318).

:mod:`api.core.permissions` is what the API *enforces*; this is what it
*publishes*. An operator about to grant somebody a membership needs to know
which roles exist and what each one can do, and the console needs to render
that list without a hard-coded copy of it — so migration 0049 seeds the three
tables and these two functions read them.

Nothing here is on the request path of an authorization decision. That is
deliberate and worth keeping: see the module docstring of
:mod:`api.core.permissions` for why a check that queried the database for its
own answer would be the wrong trade.

Custom roles per tenant are **not implemented** (#318 stays open for them).
The schema holds them — ``roles``/``role_permissions`` are keyed by
``(role_id, tenant_id)`` and the built-ins occupy ``tenant_id = ""`` — and
:func:`list_roles` already returns a tenant's own rows alongside the built-in
ones, so what is missing is the write side and the resolution of a non-built-in
role in :func:`api.core.permissions.permissions_for`, which today grants an
unknown role nothing.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.settings import Settings

#: ``roles.tenant_id`` of a role every tenant has. See :class:`models.RoleDefinition`.
BUILTIN_SCOPE = ""

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "rbac.configure() not called"
    return _settings


def list_permissions() -> list[dict[str, Any]]:
    """The whole catalogue, in key order."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Permission).order_by(models.Permission.permission_key)
        ).scalars().all()
        return [
            {"permission_key": row.permission_key, "description": row.description}
            for row in rows
        ]


def list_roles(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Built-in roles, plus the ones ``tenant_id`` defined for itself.

    Built-ins first and then by name, so the list a console renders does not
    reorder itself when a tenant adds a role.
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
        }
        for row in roles
    ]
    items.sort(key=lambda role: (not role["builtin"], role["role_id"]))
    return items
