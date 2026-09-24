"""Which tenant a database transaction acts for: the second line behind every ``WHERE`` (#311).

Tenant isolation is, first, a ``tenant_id`` predicate in every query a route
makes. This module is what catches the query that forgot it. Migration
``0067_tenant_rls`` puts row-level security on every table that carries a
``tenant_id``, as a **restrictive** policy that applies to one role only,
:data:`TENANT_ROLE`; a transaction acting for a tenant assumes that role and
names the tenant, so Postgres itself drops every other tenant's rows from what
the transaction reads and refuses every row of another tenant it tries to write.

Three scopes, decided per transaction when it begins:

* **tenant** — a request whose tenant is known. Declared where it is decided:
  ``api.auth.resolve_tenant_principal`` for a console user, service-token
  authentication for a token (before any route runs), ``require_agent`` for a
  sensor. Applied as ``SET LOCAL ROLE`` plus ``shapoclyack.tenant_id``.
* **system** — work that spans tenants by design: every background worker, the
  startup imports, CLI tools, authentication itself (it is what *finds* the
  tenant), and the routes a platform admin or a global role gate serves. Runs
  as the connecting role, exactly as before this module existed. Outside a
  request it is the only scope there is, so no worker has to opt in.
* **undeclared** — a request that has not said which of the two it is. It gets
  the tenant role *without* a tenant, and the policy then raises on any tenant
  table it touches (``unrecognized configuration parameter
  "shapoclyack.tenant_scope_undeclared"``). Loud on purpose: an empty answer is
  indistinguishable from "this tenant has none", and a route that reads tenant
  data before anyone decided whose it is has a bug worth a 500.

Why the tenant path takes a role rather than the system path taking a bypass
flag: superusers and table owners bypass row security. The shipped manifests
connect as the ``POSTGRES_USER`` of the official image — a superuser — so a
policy keyed on a GUC alone would be enforced on no stock installation until
somebody split the roles. ``SET ROLE`` to a role that is neither is what makes
the policies bite whoever the API connects as, and it leaves every worker on
the connecting role, where nothing it does changes.

``SET LOCAL`` (``set_config(..., true)``) is transaction-scoped: it ends at the
commit, which is exactly why it is applied from the session's ``after_begin``
hook — every transaction of a session, including the second and third of a
handler that commits more than once — and also why a pooled connection can
never carry one request's tenant into the next: the connection goes back to
the pool with the transaction over.

**Not** a defence against SQL injection: a statement an attacker controls can
``RESET ROLE`` or name another tenant. What it defends against is the query a
developer wrote without its predicate — the IDOR class of bug the issue is
about. Bound parameters and the SAST gate are the defence against the other.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Iterator

from sqlalchemy import text
from sqlalchemy.orm import Session, SessionTransaction

_log = logging.getLogger(__name__)

#: The role a tenant-scoped transaction assumes. NOLOGIN, created by migration
#: ``0067_tenant_rls``: it is the one thing the restrictive policies name, and
#: nobody ever connects as it — the API's own role switches to it with
#: ``SET LOCAL ROLE`` for the length of one transaction.
TENANT_ROLE = "shapoclyack_tenant"

#: Transaction-local setting naming the tenant. ``shapoclyack.`` like the audit
#: trail's ``shapoclyack.audit_retention``: one prefix for every GUC this
#: product defines, so ``SHOW ALL`` output is attributable.
TENANT_SETTING = "shapoclyack.tenant_id"

#: Never set by anything. The policies read it when :data:`TENANT_SETTING` is
#: empty, and reading a setting that does not exist is an error — which is how
#: an undeclared scope becomes a loud failure instead of an empty result.
UNDECLARED_SETTING = "shapoclyack.tenant_scope_undeclared"

MODE_OFF = "off"
MODE_ENFORCE = "enforce"
MODES = (MODE_OFF, MODE_ENFORCE)

KIND_TENANT = "tenant"
KIND_SYSTEM = "system"
KIND_UNDECLARED = "undeclared"


class TenantScopeConflict(RuntimeError):
    """One request tried to act for two tenants.

    Not something a caller can provoke — every guard resolves the same tenant
    from the same request — so it is a bug in how a route combines its guards,
    and it fails the request rather than picking one.
    """


@dataclass(frozen=True)
class Scope:
    """The scope a transaction begins in. ``tenant_id`` only for ``kind == "tenant"``."""

    kind: str
    tenant_id: str | None = None
    reason: str = ""


_PROCESS = Scope(KIND_SYSTEM, reason="outside a request")
_UNDECLARED = Scope(KIND_UNDECLARED)


class _RequestScope:
    """What one HTTP request has declared so far.

    Mutable, and shared by reference, on purpose: FastAPI runs a sync
    dependency in a worker thread under a *copy* of the request's context, so a
    ``ContextVar.set`` made there is gone by the time the handler runs. Every
    copy holds the same object, so an attribute written on it is seen by the
    handler, by the threads ``asyncio.to_thread`` starts for it, and by nothing
    else — the next request gets a new one from the middleware.

    A tenant, once declared, is sticky: nothing later in the same request can
    widen it back to ``system``. Declaration order between a route's guards is
    then irrelevant, which is the property that makes "a tenant guard anywhere
    in the dependency tree" enough.

    Closed when the request ends. A context copied out of the request — an
    asyncio task spawned on a long-lived loop, a callback registered while the
    request ran — still holds this object; once closed it resolves to the
    process scope, like any other work that outlives a request, instead of
    carrying one caller's tenant into whatever it does later.
    """

    __slots__ = ("closed", "system_reason", "tenant_id")

    def __init__(self) -> None:
        self.tenant_id: str | None = None
        self.system_reason: str | None = None
        self.closed = False

    def scope(self) -> Scope:
        if self.closed:
            return _PROCESS
        if self.tenant_id is not None:
            return Scope(KIND_TENANT, tenant_id=self.tenant_id)
        if self.system_reason is not None:
            return Scope(KIND_SYSTEM, reason=self.system_reason)
        return _UNDECLARED


_request: ContextVar[_RequestScope | None] = ContextVar("octo_tenant_request_scope", default=None)
_override: ContextVar[Scope | None] = ContextVar("octo_tenant_scope_override", default=None)

_mode = MODE_OFF


def configure(settings: Any) -> None:
    """Take ``OCTO_TENANT_RLS`` from ``settings``; called from ``create_app()``.

    Process-global, like the engine it hooks: a process reads its configuration
    once, and the value only decides what *requests* do — outside a request the
    scope is ``system`` whatever it says.
    """
    global _mode
    mode = str(getattr(settings, "tenant_rls", MODE_OFF) or MODE_OFF)
    if mode not in MODES:  # pragma: no cover - load_settings refuses it first
        raise ValueError(f"OCTO_TENANT_RLS must be one of {', '.join(MODES)}, not {mode!r}")
    _mode = mode


def mode() -> str:
    return _mode


def enforcing() -> bool:
    return _mode == MODE_ENFORCE


def current() -> Scope:
    """The scope a transaction beginning *now*, in this context, would get."""
    override = _override.get()
    if override is not None:
        return override
    request = _request.get()
    if request is None:
        return _PROCESS
    return request.scope()


# --- request binding (the middleware) ---------------------------------------


def bind_request() -> Token[_RequestScope | None]:
    """Start a request in the undeclared scope. The token restores the previous one."""
    return _request.set(_RequestScope())


def reset_request(token: Token[_RequestScope | None]) -> None:
    request = _request.get()
    if request is not None:
        request.closed = True
    _request.reset(token)


# --- declarations (route dependencies) ---------------------------------------


def declare_tenant(tenant_id: str) -> None:
    """This request acts for ``tenant_id``. No-op outside a request."""
    request = _request.get()
    if request is None:
        return
    tenant_id = (tenant_id or "").strip()
    if not tenant_id:
        raise TenantScopeConflict("a request cannot act for an empty tenant id")
    if request.tenant_id is None:
        request.tenant_id = tenant_id
    elif request.tenant_id != tenant_id:
        raise TenantScopeConflict(
            f"request already acts for tenant {request.tenant_id!r}, not {tenant_id!r}"
        )


def declare_system(reason: str) -> None:
    """This request spans tenants by design. Never widens a declared tenant."""
    request = _request.get()
    if request is None:
        return
    if request.system_reason is None:
        request.system_reason = reason


def cross_tenant(reason: str):
    """A route dependency declaring ``system`` scope, with the reason it may.

    For the routes that have no tenant guard and still read a tenant table —
    signing in, the caller's own list of tenants, a readiness probe that counts
    every tenant's backlog. Each one is also an entry in the reviewed allowlist
    of ``tests/test_route_tenant_guards.py``.
    """

    def _declare() -> None:
        declare_system(reason)

    _declare.__qualname__ = f"cross_tenant[{reason}]"
    return _declare


# --- explicit overrides (a block of code) -------------------------------------


@contextmanager
def system(reason: str) -> Iterator[None]:
    """Run a block across tenants, whatever the request declared.

    The escape hatch, and deliberately greppable: authentication (it is what
    finds the tenant) and the few identity checks that must see another
    tenant's row to refuse it by name. Anything opened inside keeps the scope
    it began with after the block ends — a transaction is scoped once, at its
    first statement.
    """
    token = _override.set(Scope(KIND_SYSTEM, reason=reason))
    try:
        yield
    finally:
        _override.reset(token)


@contextmanager
def tenant(tenant_id: str) -> Iterator[None]:
    """Run a block as ``tenant_id``: for tests, and for a worker that wants the
    database to hold it to one tenant while it handles that tenant's rows."""
    tenant_id = (tenant_id or "").strip()
    if not tenant_id:
        raise TenantScopeConflict("a block cannot act for an empty tenant id")
    token = _override.set(Scope(KIND_TENANT, tenant_id=tenant_id))
    try:
        yield
    finally:
        _override.reset(token)


# --- the engine hook ----------------------------------------------------------

# One round trip for both. ``set_config('role', ...)`` is ``SET LOCAL ROLE`` in
# the form that takes a bind parameter, like the ``lock_timeout`` in
# api/db/migrate.py: nothing is formatted into the statement text.
_NARROW = text(
    "SELECT set_config('role', :role, true), set_config(:setting, :tenant, true)"
)


def after_begin(session: Session, transaction: SessionTransaction, connection: Any) -> None:
    """``Session.after_begin``: scope the transaction that is starting.

    Registered on the Postgres session factory only (``api.db.engine``); the
    SQLite fallback has no roles and no row security, and is refused in prod.
    """
    if _mode != MODE_ENFORCE:
        return
    if transaction.nested:
        # A SAVEPOINT inside a transaction that was scoped when it began: the
        # settings hold inside it, and survive its rollback, because they were
        # made before it. Re-applying them cost a round trip per savepoint.
        return
    scope = current()
    if scope.kind == KIND_SYSTEM:
        return
    connection.execute(
        _NARROW,
        {
            "role": TENANT_ROLE,
            "setting": TENANT_SETTING,
            # Empty for undeclared: the policy reads that as "no tenant" and
            # falls through to UNDECLARED_SETTING, which raises.
            "tenant": scope.tenant_id or "",
        },
    )


# --- startup verification -----------------------------------------------------


class TenantRlsUnavailable(RuntimeError):
    """``OCTO_TENANT_RLS=enforce`` on a database that cannot enforce it."""


#: Model tables whose tenant role privileges are narrower than full DML, as
#: granted by 0067: the trail is append-only for everyone but retention.
_NARROWED_PRIVILEGES = {"audit_events": ("SELECT", "INSERT")}
_FULL_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")

#: Tenant data without a ``tenant_id`` column, held to the tenant through the
#: parent row it belongs to (0067): a tag is visible when its asset is.
PARENT_SCOPED_TABLES = {"asset_tags": "assets"}

_verified: set[str] = set()


def tenant_tables(metadata: Any) -> list[str]:
    """Every model table that must carry the tenant policies.

    Every table with a ``tenant_id`` column, and the tables in
    :data:`PARENT_SCOPED_TABLES` that hold tenant data without one.
    """
    return sorted(
        table.name
        for table in metadata.sorted_tables
        if "tenant_id" in table.c or table.name in PARENT_SCOPED_TABLES
    )


def _grant_hint(name: str, version: int) -> str:
    """How ``name`` gets permission to switch to the tenant role, by server version.

    ``WITH INHERIT FALSE`` is PostgreSQL 16 syntax. Before 16 an inherit-free
    membership exists only as a property of the *member* (``NOINHERIT``), which
    also stops it inheriting every other role it is a member of — so that hint
    says so rather than hiding it.
    """
    if version >= 160000:
        return f"GRANT {TENANT_ROLE} TO {name} WITH INHERIT FALSE"
    return (
        f"ALTER ROLE {name} NOINHERIT; GRANT {TENANT_ROLE} TO {name} "
        f"(PostgreSQL < 16: NOINHERIT applies to all of {name}'s memberships — "
        "or connect the API as a superuser, or run OCTO_TENANT_RLS=off)"
    )


def database_problems(connection: Any, metadata: Any) -> list[str]:
    """Why this database cannot enforce the second line, one line per reason.

    Empty means it can. Each entry names the fix, because the reader is an
    operator looking at a pod that refused to start.
    """
    problems: list[str] = []
    role = connection.execute(
        text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = :role"),
        {"role": TENANT_ROLE},
    ).first()
    if role is None:
        return [
            f"role {TENANT_ROLE} does not exist: run the migrations "
            "(python -m api.db.migrate); 0067_tenant_rls creates it"
        ]
    if role.rolsuper or role.rolbypassrls:
        problems.append(
            f"role {TENANT_ROLE} is SUPERUSER or BYPASSRLS, so row security never "
            f"applies to it: ALTER ROLE {TENANT_ROLE} NOSUPERUSER NOBYPASSRLS"
        )
    me = connection.execute(
        text(
            "SELECT current_user AS name, r.rolsuper, r.rolbypassrls,"
            " current_setting('server_version_num')::integer AS version"
            " FROM pg_roles r WHERE r.rolname = current_user"
        )
    ).one()
    if not me.rolsuper:
        # 16 distinguishes "may SET ROLE" from membership in general.
        privilege = "SET" if me.version >= 160000 else "MEMBER"
        can_switch = connection.execute(
            text("SELECT pg_has_role(current_user, :role, :privilege)"),
            {"role": TENANT_ROLE, "privilege": privilege},
        ).scalar_one()
        if not can_switch:
            problems.append(
                f"{me.name} cannot SET ROLE {TENANT_ROLE}: as a superuser run "
                + _grant_hint(me.name, me.version)
            )
    tables = tenant_tables(metadata)
    rows = connection.execute(
        text(
            "SELECT c.relname, c.relrowsecurity,"
            " pg_get_userbyid(c.relowner) AS owner,"
            " EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid"
            "   AND p.polpermissive AND p.polname = 'shapoclyack_unscoped') AS unscoped,"
            " EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid"
            "   AND NOT p.polpermissive AND to_regrole(:role) = ANY (p.polroles)) AS isolated"
            " FROM pg_class c"
            " WHERE c.relnamespace = current_schema()::regnamespace"
            "   AND c.relname = ANY (:tables)"
        ),
        {"role": TENANT_ROLE, "tables": tables},
    ).all()
    found = {row.relname: row for row in rows}
    uncovered = [
        name
        for name in tables
        if name not in found
        or not (found[name].relrowsecurity and found[name].isolated and found[name].unscoped)
    ]
    if uncovered:
        # Without the restrictive policy a tenant transaction sees the whole
        # table; without the permissive one every role row security applies
        # to — a non-owner API role, its workers included — sees none of it.
        owned_elsewhere = sorted(
            name for name in uncovered if name in found and found[name].owner != me.name
        )
        problems.append(
            "tenant policies missing or incomplete on " + ", ".join(uncovered)
            + ": run the migrations; a table another role owns"
            + (f" ({', '.join(owned_elsewhere)})" if owned_elsewhere else "")
            + " has to be protected by that owner — 0067 logged the statements, and "
            "docs/tenant-isolation.md lists them"
        )
    if not me.rolsuper and not me.rolbypassrls and not role.rolsuper:
        inherits = connection.execute(
            text("SELECT pg_has_role(current_user, :role, 'USAGE')"), {"role": TENANT_ROLE}
        ).scalar_one()
        foreign = [row.relname for row in rows if row.owner != me.name]
        if inherits and foreign:
            # The restrictive policy then applies to this role's *own*
            # statements on tables it does not own, and a worker reading
            # them would be told the tenant scope is undeclared.
            problems.append(
                f"{me.name} inherits {TENANT_ROLE}, so the tenant policy also applies to "
                f"its own statements on {', '.join(sorted(foreign))}: REVOKE {TENANT_ROLE} "
                f"FROM {me.name}; " + _grant_hint(me.name, me.version)
            )
    # One query for the lot. has_table_privilege() with a list answers "any
    # of", not "all of", so each privilege is its own row.
    wanted = [
        (table.name, privilege)
        for table in metadata.sorted_tables
        for privilege in _NARROWED_PRIVILEGES.get(table.name, _FULL_PRIVILEGES)
    ]
    missing = [
        f"{row.privilege} on {row.name}"
        for row in connection.execute(
            text(
                "SELECT w.name, w.privilege"
                " FROM unnest(CAST(:tables AS text[]), CAST(:privileges AS text[]))"
                "   AS w(name, privilege)"
                " WHERE to_regclass(quote_ident(current_schema()) || '.' || quote_ident(w.name))"
                "   IS NOT NULL"
                "   AND NOT has_table_privilege(:role,"
                "     quote_ident(current_schema()) || '.' || quote_ident(w.name), w.privilege)"
            ),
            {
                "role": TENANT_ROLE,
                "tables": [name for name, _ in wanted],
                "privileges": [privilege for _, privilege in wanted],
            },
        )
    ]
    # A serial column's INSERT needs its sequence: audit_events_id_seq is the
    # one the ownership split moves away from the migrating role.
    missing += [
        f"USAGE on sequence {row.seq}"
        for row in connection.execute(
            text(
                "SELECT s.oid::regclass::text AS seq"
                " FROM pg_class s"
                " WHERE s.relkind = 'S' AND s.relnamespace = current_schema()::regnamespace"
                "   AND NOT CASE WHEN s.relkind = 'S'"
                "     THEN has_sequence_privilege(:role, s.oid, 'USAGE') ELSE true END"
            ),
            {"role": TENANT_ROLE},
        )
    ]
    if missing:
        problems.append(
            f"{TENANT_ROLE} lacks " + ", ".join(missing)
            + f": GRANT them to {TENANT_ROLE} (the owner of those objects must run it)"
        )
    return problems


def verify_database(settings: Any) -> None:
    """Refuse to start when ``enforce`` would not, in fact, enforce.

    Called from ``create_app()`` once the database is reachable. "enforce" that
    silently meant "nothing" — a role nobody may switch to, a table without its
    policy — would be worse than "off", which at least says so. Checked once
    per database URL per process: it is a handful of catalog reads, and the
    schema does not change under a running replica.
    """
    if _mode != MODE_ENFORCE:
        return
    url = str(getattr(settings, "postgres_url", "") or "")
    if not url or url in _verified:
        return
    from api.db import models
    from api.db.engine import get_engine

    engine = get_engine(url)
    if engine.dialect.name != "postgresql":
        return
    with engine.connect() as connection:
        problems = database_problems(connection, models.Base.metadata)
    if problems:
        raise TenantRlsUnavailable(
            "OCTO_TENANT_RLS=enforce, but this database cannot enforce tenant row "
            "security (#311):\n"
            + "\n".join(f"    - {problem}" for problem in problems)
            + "\n    Fix the above, or start with OCTO_TENANT_RLS=off as a deliberate,"
            "\n    logged decision (docs/tenant-isolation.md)."
        )
    _verified.add(url)
    _log.info("Tenant row security is enforced (role %s)", TENANT_ROLE)


def reset_for_tests() -> None:
    global _mode
    _mode = MODE_OFF
    _verified.clear()
