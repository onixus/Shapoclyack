"""Every route either resolves a tenant or is on a reviewed list saying why not (#311).

Tenant isolation starts at the route: a handler that never asks
``resolve_tenant_principal`` which tenant it is in has nothing to filter by, and
since #311 it also never tells the database which tenant to hold it to. The
guards are dependencies, so a new route that forgets one is a route that looks
exactly like the ones around it — until somebody passes another tenant's id.

This test walks the dependency tree of every route the application mounts, with
every optional router switched on, and requires one of:

* a **tenant guard** — ``require_tenant``, ``require_permission``,
  ``require_path_tenant_permission`` (console callers) or ``require_agent``
  (sensors) — anywhere in the tree; or
* an entry in :data:`CROSS_TENANT_ROUTES` below, keyed by the endpoint
  function, with the reason it may answer without one.

The list is the review point. Adding to it is a statement that the route is
meant to see across tenants — sign-in, the platform admin's fleet views, a
readiness probe — and the reason is what the reviewer checks it against. An
entry whose route is gone fails too, so the list cannot rot into a set of
exemptions nobody can account for.

At runtime the same split is enforced separately (``api/db/tenant_scope.py``):
a route on this list that reads a tenant table has to *declare* the
cross-tenant scope (``tenant_scope.cross_tenant``, or the global-role gates that
declare it themselves), or its transaction fails.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.routing import APIRoute, iter_route_contexts

from api import auth
from api.core import permissions as permission_catalog
from tests.conftest import configured_client, make_settings, requires_postgres

pytestmark = requires_postgres

#: The dependencies that decide a request's tenant. Matched by qualified name,
#: which is what a closure made by a factory has in common across calls.
TENANT_GUARDS = frozenset(
    {
        auth.require_tenant(auth.Role.viewer).__qualname__,
        auth.require_permission(permission_catalog.AUDIT_READ).__qualname__,
        auth.require_path_tenant_permission(permission_catalog.AUDIT_READ).__qualname__,
        auth.require_agent.__qualname__,
    }
)

_AUTHENTICATION = (
    "authentication: establishes who is calling before there is a tenant; "
    "declares cross_tenant('authentication')"
)
_ACCOUNT = (
    "the caller's own account (factors, keys, password), which belongs to no "
    "tenant; declares an account cross_tenant scope"
)
_PLATFORM_ADMIN = (
    "platform admin only (require_role(admin) / require_platform_permission), "
    "installation-wide by definition; the gate declares system scope"
)
_NO_DATABASE = "reads no table at all"

#: Endpoint (``module:qualname``) -> why it has no tenant guard. Keep sorted by
#: module; the reason must say what the route reads across tenants, or that it
#: reads nothing.
CROSS_TENANT_ROUTES: dict[str, str] = {
    # Probes, metrics, the console and the API schema.
    "api.app:create_app.<locals>.metrics_endpoint": (
        "Prometheus exposition of this process's counters; " + _NO_DATABASE
    ),
    "api.app:create_app.<locals>.livez": "liveness, dependency-free by design (#331); " + _NO_DATABASE,
    "api.app:create_app.<locals>.readyz": (
        "readiness counts every tenant's unpublished backlog (nats_outbox, "
        "run_publications): the installation's state, no tenant's"
    ),
    "api.app:create_app.<locals>.health": "same checks as /readyz, older response shape",
    "api.app:create_app.<locals>.spa_fallback": "serves the console's static files; " + _NO_DATABASE,
    "Mount /_next": "the console's static assets; " + _NO_DATABASE,
    "fastapi.applications:FastAPI.setup.<locals>.openapi": (
        "API schema, unmounted in prod (#319); " + _NO_DATABASE
    ),
    "fastapi.applications:FastAPI.setup.<locals>.swagger_ui_html": "API docs page; " + _NO_DATABASE,
    "fastapi.applications:FastAPI.setup.<locals>.swagger_ui_redirect": (
        "API docs OAuth redirect; " + _NO_DATABASE
    ),
    "fastapi.applications:FastAPI.setup.<locals>.redoc_html": "API docs page; " + _NO_DATABASE,
    # Sensors fetch the installer before they hold any credential.
    "api.routes.agents:get_install_script": "the agent installer script; " + _NO_DATABASE,
    # Signing in and out.
    "api.routes.auth:login": _AUTHENTICATION,
    "api.routes.auth:refresh": _AUTHENTICATION,
    "api.routes.auth:logout": _AUTHENTICATION,
    "api.routes.auth:revoke_own_sessions": _AUTHENTICATION,
    "api.routes.auth:oidc_login": _AUTHENTICATION,
    "api.routes.auth:oidc_callback": _AUTHENTICATION,
    "api.routes.auth:agent_token": (
        "provisioning-key exchange: the key is what names the tenant, so it is "
        "looked up across tenants; declares cross_tenant('authentication')"
    ),
    "api.routes.auth:auth_exchange": "same exchange as agent_token, APEX contract shape",
    "api.routes.auth:sso_status": "whether SSO is configured, from settings; " + _NO_DATABASE,
    "api.routes.auth:me": (
        "the caller's memberships in every tenant they belong to — the tenant "
        "switcher is built from it; declares cross_tenant"
    ),
    # Tenants as objects, and the fleet views over them.
    "api.routes.auth:list_auth_events": _PLATFORM_ADMIN + "; auth_events has no tenant",
    "api.routes.auth:list_tenants": (
        "the tenants the caller may switch to, filtered in the route by membership "
        "(_visible_tenants); behind require_role, which declares system scope"
    ),
    "api.routes.auth:list_tenant_posture": (
        "posture of every tenant the caller belongs to, filtered by membership like "
        "list_tenants; behind require_role"
    ),
    "api.routes.auth:create_tenant": _PLATFORM_ADMIN,
    "api.routes.auth:set_tenant_quota": _PLATFORM_ADMIN,
    "api.routes.auth:clear_tenant_quota": _PLATFORM_ADMIN,
    "api.routes.maintenance:get_tenant_calendar": _PLATFORM_ADMIN + " (the provider's view of one customer's calendar)",
    "api.routes.config:update_config": _PLATFORM_ADMIN + " (installation-wide scanner overrides)",
    "api.routes.system:get_system_status": (
        "installation status for every role; cross-tenant counters are dropped in "
        "the route for callers without the platform permission"
    ),
    "api.routes.usage:get_usage_across_tenants": _PLATFORM_ADMIN,
    "api.routes.rbac:list_permissions": "the static permission catalogue; " + _NO_DATABASE,
    # Console accounts are installation-wide.
    "api.routes.users:list_users": _PLATFORM_ADMIN,
    "api.routes.users:create_user": _PLATFORM_ADMIN,
    "api.routes.users:set_user_password": _PLATFORM_ADMIN,
    "api.routes.users:set_user_role": _PLATFORM_ADMIN,
    "api.routes.users:set_user_email": _PLATFORM_ADMIN,
    "api.routes.users:set_user_disabled": _PLATFORM_ADMIN,
    "api.routes.users:revoke_user_sessions": _PLATFORM_ADMIN,
    "api.routes.users:delete_user": _PLATFORM_ADMIN,
    "api.routes.users:change_own_password": _ACCOUNT,
    "api.routes.mfa:mfa_status": _ACCOUNT,
    "api.routes.mfa:setup_totp": _ACCOUNT,
    "api.routes.mfa:confirm_totp": _ACCOUNT,
    "api.routes.mfa:verify_mfa": _AUTHENTICATION + " (second step of a sign-in)",
    "api.routes.mfa:disable_mfa": _ACCOUNT,
    "api.routes.mfa:reset_user_mfa": _PLATFORM_ADMIN,
    "api.routes.passkeys:registration_options": _ACCOUNT,
    "api.routes.passkeys:register_key": _ACCOUNT,
    "api.routes.passkeys:authentication_options": _AUTHENTICATION + " (second step of a sign-in)",
    "api.routes.passkeys:list_keys": _ACCOUNT,
    "api.routes.passkeys:revoke_key": _ACCOUNT,
}


def _dependency_names(dependant: Any) -> set[str]:
    names: set[str] = set()
    stack = list(dependant.dependencies)
    while stack:
        dependency = stack.pop()
        names.add(getattr(dependency.call, "__qualname__", repr(dependency.call)))
        stack.extend(dependency.dependencies)
    return names


def _endpoint_key(route: Any) -> str:
    endpoint = getattr(route, "endpoint", None)
    if endpoint is None:
        return f"{type(route).__name__} {getattr(route, 'path', '?')}"
    return f"{endpoint.__module__}:{endpoint.__qualname__}"


def _mounted_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The application with every optional router and page mounted."""
    web = tmp_path / "web-dist"
    (web / "_next").mkdir(parents=True)
    (web / "index.html").write_text("<html></html>", encoding="utf-8")
    settings = make_settings(
        tmp_path,
        service_tokens_enabled=True,
        reports_enabled=True,
        webhooks_enabled=True,
        notification_channels_enabled=True,
        endpoint_inventory_enabled=True,
        api_docs_enabled=True,
        web_dist=web,
    )
    return configured_client(tmp_path, monkeypatch, settings=settings).app


def _classify(app: Any) -> tuple[dict[str, list[str]], set[str]]:
    """``({unguarded endpoint: [routes]}, {every endpoint seen})``."""
    unguarded: dict[str, list[str]] = {}
    seen: set[str] = set()
    for context in iter_route_contexts(app.routes):
        route = context.original_route
        key = _endpoint_key(route)
        seen.add(key)
        label = f"{' '.join(sorted(getattr(context, 'methods', None) or []))} {context.path}".strip()
        if isinstance(route, APIRoute) and _dependency_names(context.dependant) & TENANT_GUARDS:
            continue
        unguarded.setdefault(key, []).append(label)
    return unguarded, seen


def test_every_route_has_a_tenant_guard_or_a_reviewed_reason(tmp_path, monkeypatch) -> None:
    unguarded, _ = _classify(_mounted_app(tmp_path, monkeypatch))

    missing = {key: routes for key, routes in unguarded.items() if key not in CROSS_TENANT_ROUTES}

    assert not missing, (
        "Routes with no tenant guard and no entry in CROSS_TENANT_ROUTES:\n"
        + "\n".join(f"  {key}: {', '.join(routes)}" for key, routes in sorted(missing.items()))
        + "\nGive the route a tenant guard (require_tenant / require_permission / "
        "require_path_tenant_permission / require_agent), or add it to the list with "
        "the reason it answers across tenants — and, if it reads a tenant table, "
        "declare tenant_scope.cross_tenant(...) on it (docs/tenant-isolation.md)."
    )


def test_the_allowlist_names_only_routes_that_exist_and_need_it(tmp_path, monkeypatch) -> None:
    """A stale entry is an exemption waiting for a new route to reuse its name."""
    unguarded, seen = _classify(_mounted_app(tmp_path, monkeypatch))

    stale = sorted(key for key in CROSS_TENANT_ROUTES if key not in seen)
    guarded_anyway = sorted(key for key in CROSS_TENANT_ROUTES if key in seen and key not in unguarded)

    assert not stale, f"CROSS_TENANT_ROUTES names endpoints that no longer exist: {stale}"
    assert not guarded_anyway, (
        f"CROSS_TENANT_ROUTES names endpoints that now have a tenant guard: {guarded_anyway}"
    )
    assert all(reason.strip() for reason in CROSS_TENANT_ROUTES.values())


def test_the_walk_sees_the_guards_it_is_looking_for(tmp_path, monkeypatch) -> None:
    """Guard against the test passing because it recognises nothing.

    If a refactor renamed the guards, every route would land in ``unguarded``
    and the first test would fail loudly — but a walk that stopped descending
    into sub-dependencies would *also* see no guards and fail the same way, for
    a reason that has nothing to do with routes. This pins the positive side:
    the ordinary tenant routes are recognised as guarded.
    """
    unguarded, seen = _classify(_mounted_app(tmp_path, monkeypatch))

    for key in (
        "api.routes.assets:list_assets",
        "api.routes.vulnerabilities:list_vulnerabilities",
        "api.routes.agents:heartbeat",
        "api.routes.auth:list_members",
    ):
        assert key in seen, key
        assert key not in unguarded, key
