"""Row-level security as the second line behind every tenant predicate (#311).

What is under test is the *second* line, so most of these tests do what the
first line exists to prevent: they query a tenant table with no ``tenant_id``
predicate at all and assert that Postgres, not the query, kept the other
tenant's rows out. The pieces:

* migration ``0067_tenant_rls`` — every table with a ``tenant_id`` column has
  row security and the restrictive policy for ``shapoclyack_tenant``, and that
  role can do everything a tenant request does (:func:`database_problems`);
* ``api/db/tenant_scope.py`` — a transaction begun in a tenant scope assumes
  the role and names the tenant, *every* transaction of the session and not
  just the first, and a pooled connection comes back with neither;
* the request wiring — a console request resolves its tenant once and every
  query after that is held to it; a platform admin, a worker and a CLI are not.
"""

from __future__ import annotations

import contextvars
import threading
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import Column, MetaData, String, Table, create_engine, delete, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from api.db import engine as db_engine
from api.db import models, tenant_scope
from api.db.engine import get_session
from tests.conftest import (
    POSTGRES_URL,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

TENANT_A = "rls-tenant-a"
TENANT_B = "rls-tenant-b"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _group(tenant_id: str, name: str) -> models.AgentGroup:
    return models.AgentGroup(
        group_id=f"grp-{uuid.uuid4().hex[:10]}", tenant_id=tenant_id, name=name, created_at=_now()
    )


@pytest.fixture
def enforce(tmp_path):
    """Enforce mode on the shared engine, and two tenants with one group each."""
    settings = make_settings(tmp_path, tenant_rls="enforce")
    tenant_scope.configure(settings)
    with get_session(POSTGRES_URL) as session:
        session.execute(delete(models.Tenant).where(models.Tenant.tenant_id.in_([TENANT_A, TENANT_B])))
    with get_session(POSTGRES_URL) as session:
        for tenant_id in (TENANT_A, TENANT_B):
            session.add(models.Tenant(tenant_id=tenant_id, name=tenant_id, created_at=_now()))
        session.flush()
        session.add(_group(TENANT_A, "alpha"))
        session.add(_group(TENANT_B, "bravo"))
    try:
        yield settings
    finally:
        tenant_scope.reset_for_tests()
        with get_session(POSTGRES_URL) as session:
            # Cascades to their groups (FK ON DELETE CASCADE).
            session.execute(
                delete(models.Tenant).where(models.Tenant.tenant_id.in_([TENANT_A, TENANT_B]))
            )


def _group_names(session) -> set[str]:
    # Deliberately no WHERE: this is the query a route forgot to filter.
    return set(session.execute(select(models.AgentGroup.name)).scalars().all()) & {"alpha", "bravo"}


# --------------------------------------------------------------------------- #
# The schema
# --------------------------------------------------------------------------- #


def test_every_tenant_table_carries_the_isolation_policy() -> None:
    """The migration covered every model table with a ``tenant_id``, and the
    role can do what a tenant request does. This is the test that fails when a
    later migration adds a tenant table and forgets its policy."""
    engine = create_engine(POSTGRES_URL, future=True)
    try:
        with engine.connect() as connection:
            problems = tenant_scope.database_problems(connection, models.Base.metadata)
    finally:
        engine.dispose()
    assert problems == []
    # And the list it checked is the real one, not an empty one.
    tables = tenant_scope.tenant_tables(models.Base.metadata)
    assert {"assets", "vulnerabilities", "jobs", "agents", "tenants", "audit_events"} <= set(tables)
    assert "users" not in tables


def test_a_tenant_table_without_its_policy_is_reported_by_name() -> None:
    """The negative of the test above: the check does look."""
    name = f"rls_probe_{uuid.uuid4().hex[:8]}"
    engine = create_engine(POSTGRES_URL, future=True)
    metadata = MetaData()
    for table in models.Base.metadata.sorted_tables:
        table.to_metadata(metadata)
    Table(name, metadata, Column("id", String, primary_key=True), Column("tenant_id", String))
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE TABLE "{name}" (id text PRIMARY KEY, tenant_id text)'))
        with engine.connect() as connection:
            problems = tenant_scope.database_problems(connection, metadata)
        assert any(name in problem and "no tenant-isolation policy" in problem for problem in problems)
        # A table created after 0067 by the migrating role still gets the
        # tenant role's privileges, from the default privileges it set.
        assert not any(f"on {name}" in problem for problem in problems if "lacks" in problem)
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP TABLE IF EXISTS "{name}"'))
        engine.dispose()


# --------------------------------------------------------------------------- #
# The engine hook
# --------------------------------------------------------------------------- #


def test_an_unfiltered_query_in_a_tenant_scope_sees_only_that_tenant(enforce) -> None:
    with tenant_scope.tenant(TENANT_A):
        with get_session(POSTGRES_URL) as session:
            assert _group_names(session) == {"alpha"}
            assert session.execute(text("SELECT current_user")).scalar_one() == tenant_scope.TENANT_ROLE
    with tenant_scope.tenant(TENANT_B):
        with get_session(POSTGRES_URL) as session:
            assert _group_names(session) == {"bravo"}


def test_a_tenant_scope_cannot_write_another_tenants_rows(enforce) -> None:
    with tenant_scope.tenant(TENANT_A):
        with pytest.raises(DBAPIError, match="row-level security"):
            with get_session(POSTGRES_URL) as session:
                session.add(_group(TENANT_B, "planted"))
                session.flush()
        with get_session(POSTGRES_URL) as session:
            # Neither visible to update nor to delete: zero rows, no error —
            # the same answer as for a row that does not exist.
            moved = session.execute(
                models.AgentGroup.__table__.update()
                .where(models.AgentGroup.name == "bravo")
                .values(description="rewritten by tenant a")
            )
            removed = session.execute(delete(models.AgentGroup).where(models.AgentGroup.name == "bravo"))
            assert (moved.rowcount, removed.rowcount) == (0, 0)
        with pytest.raises(DBAPIError, match="row-level security"):
            with get_session(POSTGRES_URL) as session:
                # Nor can one of its own rows be handed over to tenant b.
                session.execute(
                    models.AgentGroup.__table__.update()
                    .where(models.AgentGroup.name == "alpha")
                    .values(tenant_id=TENANT_B)
                )
    with get_session(POSTGRES_URL) as session:
        rows = session.execute(
            select(models.AgentGroup.name, models.AgentGroup.tenant_id, models.AgentGroup.description)
            .where(models.AgentGroup.tenant_id.in_([TENANT_A, TENANT_B]))
        ).all()
    assert sorted(rows) == [("alpha", TENANT_A, ""), ("bravo", TENANT_B, "")]


def test_the_scope_survives_every_commit_of_a_session(enforce) -> None:
    """``SET LOCAL`` ends with the transaction; the hook runs for each one.

    Handlers routinely commit more than once — ``get_session`` commits at the
    end, services commit halfway to publish — and a hook that ran once per
    session would leave the second transaction on the connecting role.
    """
    with tenant_scope.tenant(TENANT_A):
        with get_session(POSTGRES_URL) as session:
            assert _group_names(session) == {"alpha"}
            session.commit()
            assert _group_names(session) == {"alpha"}
            session.rollback()
            assert _group_names(session) == {"alpha"}
            session.add(_group(TENANT_A, "alpha-2"))
            session.commit()
            with pytest.raises(DBAPIError, match="row-level security"):
                session.add(_group(TENANT_B, "planted"))
                session.flush()
            session.rollback()


def test_a_pooled_connection_comes_back_without_the_tenant(enforce, tmp_path) -> None:
    """One connection in the pool, used by a tenant and then by a worker."""
    db_engine.configure(make_settings(tmp_path, db_pool_size=1, db_max_overflow=0))
    try:
        with tenant_scope.tenant(TENANT_A):
            with get_session(POSTGRES_URL) as session:
                tenant_backend = session.execute(text("SELECT pg_backend_pid()")).scalar_one()
                assert _group_names(session) == {"alpha"}
        with get_session(POSTGRES_URL) as session:
            assert session.execute(text("SELECT pg_backend_pid()")).scalar_one() == tenant_backend
            assert session.execute(text("SELECT current_user")).scalar_one() != tenant_scope.TENANT_ROLE
            leftover = session.execute(
                text("SELECT current_setting('shapoclyack.tenant_id', true)")
            ).scalar_one()
            assert leftover in ("", None)
            assert _group_names(session) == {"alpha", "bravo"}
        # And the next tenant on that connection is the next tenant, not the last.
        with tenant_scope.tenant(TENANT_B):
            with get_session(POSTGRES_URL) as session:
                assert session.execute(text("SELECT pg_backend_pid()")).scalar_one() == tenant_backend
                assert _group_names(session) == {"bravo"}
    finally:
        db_engine.reset_for_tests()


def test_an_undeclared_request_fails_loudly_on_tenant_tables(enforce) -> None:
    """A request nobody has scoped yet is refused, not answered with nothing."""
    token = tenant_scope.bind_request()
    try:
        with pytest.raises(DBAPIError, match="tenant_scope_undeclared"):
            with get_session(POSTGRES_URL) as session:
                _group_names(session)
        # Tables with no tenant in them are not the second line's business.
        with get_session(POSTGRES_URL) as session:
            session.execute(select(models.User.username)).all()
        # Once the request says whose it is, it works — and stays that tenant's.
        tenant_scope.declare_tenant(TENANT_A)
        tenant_scope.declare_system("a later dependency cannot widen it")
        with get_session(POSTGRES_URL) as session:
            assert _group_names(session) == {"alpha"}
    finally:
        tenant_scope.reset_request(token)


def test_a_context_copied_out_of_a_request_does_not_keep_its_tenant() -> None:
    """An asyncio task spawned on a long-lived loop during a request copies the
    request's context. Once the request is over, what that task does later is
    background work, not the caller's."""
    token = tenant_scope.bind_request()
    tenant_scope.declare_tenant(TENANT_A)
    copied = contextvars.copy_context()
    assert copied.run(tenant_scope.current).tenant_id == TENANT_A
    tenant_scope.reset_request(token)
    assert copied.run(tenant_scope.current).kind == tenant_scope.KIND_SYSTEM


def test_a_request_cannot_act_for_two_tenants() -> None:
    token = tenant_scope.bind_request()
    try:
        tenant_scope.declare_tenant(TENANT_A)
        tenant_scope.declare_tenant(TENANT_A)
        with pytest.raises(tenant_scope.TenantScopeConflict):
            tenant_scope.declare_tenant(TENANT_B)
    finally:
        tenant_scope.reset_request(token)


def test_workers_and_tools_see_every_tenant(enforce) -> None:
    """Outside a request there is nothing to scope to, and nothing is.

    Including a thread started *from* a tenant-scoped block: threads do not
    inherit context variables, which is what keeps a deployment or notification
    thread a request spawns working the way it always has.
    """
    with get_session(POSTGRES_URL) as session:
        assert _group_names(session) == {"alpha", "bravo"}

    seen: list[set[str]] = []

    def worker() -> None:
        with get_session(POSTGRES_URL) as session:
            seen.append(_group_names(session))

    with tenant_scope.tenant(TENANT_A):
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=30)
    assert seen == [{"alpha", "bravo"}]

    # An explicit system block inside a tenant-scoped one widens exactly that block.
    with tenant_scope.tenant(TENANT_A):
        with tenant_scope.system("test"):
            with get_session(POSTGRES_URL) as session:
                assert _group_names(session) == {"alpha", "bravo"}
        with get_session(POSTGRES_URL) as session:
            assert _group_names(session) == {"alpha"}


def test_off_leaves_every_transaction_on_the_connecting_role(enforce, tmp_path) -> None:
    tenant_scope.configure(make_settings(tmp_path, tenant_rls="off"))
    with tenant_scope.tenant(TENANT_A):
        with get_session(POSTGRES_URL) as session:
            assert _group_names(session) == {"alpha", "bravo"}
            assert session.execute(text("SELECT current_user")).scalar_one() != tenant_scope.TENANT_ROLE


def test_the_sqlite_fallback_is_untouched(tmp_path) -> None:
    """No roles, no row security, no hook: enforce mode is a no-op there."""
    tenant_scope.configure(make_settings(tmp_path, tenant_rls="enforce"))
    url = f"sqlite:///{tmp_path / 'fallback.db'}"
    try:
        with tenant_scope.tenant(TENANT_A):
            with get_session(url) as session:
                session.add(models.Tenant(tenant_id=TENANT_B, name="b", created_at=_now()))
            with get_session(url) as session:
                assert session.execute(select(models.Tenant.tenant_id)).scalars().all() == [TENANT_B]
    finally:
        tenant_scope.reset_for_tests()
        db_engine.reset_for_tests()


# --------------------------------------------------------------------------- #
# A role other than the owner (the split layout docs/operations.md recommends)
# --------------------------------------------------------------------------- #


@pytest.fixture
def login_role():
    """A throwaway LOGIN role that owns nothing, like a separate API role."""
    name = f"rls_probe_{uuid.uuid4().hex[:8]}"
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE ROLE "{name}" LOGIN'))
    url = make_url(POSTGRES_URL).set(username=name, password=None).render_as_string(hide_password=False)
    try:
        yield name, url
    finally:
        with admin.connect() as connection:
            connection.execute(text(f'DROP OWNED BY "{name}"'))
            connection.execute(text(f'DROP ROLE "{name}"'))
        admin.dispose()


def test_a_role_that_may_not_switch_is_named_with_the_grant_it_needs(login_role) -> None:
    name, url = login_role
    engine = create_engine(url, future=True)
    try:
        with engine.connect() as connection:
            problems = tenant_scope.database_problems(connection, models.Base.metadata)
    finally:
        engine.dispose()
    assert any(
        f"{name} cannot SET ROLE {tenant_scope.TENANT_ROLE}" in problem
        and "WITH INHERIT FALSE" in problem
        for problem in problems
    )


def test_a_non_owner_api_role_is_unrestricted_until_it_switches(login_role, enforce) -> None:
    """The split layout: the API connects as a role that owns no table.

    Row security applies to such a role on every table, so the permissive
    policy is what keeps its workers seeing every tenant — and the membership
    has to be granted without inheritance, or the restrictive policy would
    apply to it directly.
    """
    name, url = login_role
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'GRANT SELECT ON agent_groups TO "{name}"'))
        connection.execute(text(f'GRANT {tenant_scope.TENANT_ROLE} TO "{name}" WITH INHERIT FALSE'))
    engine = create_engine(url, future=True)
    try:
        with engine.connect() as connection:
            assert _group_names(connection) == {"alpha", "bravo"}
        with engine.begin() as connection:
            connection.execute(
                text("SELECT set_config('role', :role, true), set_config(:s, :t, true)"),
                {"role": tenant_scope.TENANT_ROLE, "s": tenant_scope.TENANT_SETTING, "t": TENANT_A},
            )
            assert _group_names(connection) == {"alpha"}
        with admin.connect() as connection:
            connection.execute(text(f'REVOKE {tenant_scope.TENANT_ROLE} FROM "{name}"'))
            connection.execute(text(f'GRANT {tenant_scope.TENANT_ROLE} TO "{name}" WITH INHERIT TRUE'))
        with engine.connect() as connection:
            # Inherited, the restrictive policy is this role's too: its own
            # "system" reads are refused, which the startup check reports.
            with pytest.raises(DBAPIError, match="tenant_scope_undeclared"):
                _group_names(connection)
    finally:
        engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'REVOKE {tenant_scope.TENANT_ROLE} FROM "{name}"'))
        admin.dispose()


# --------------------------------------------------------------------------- #
# Startup
# --------------------------------------------------------------------------- #


def test_enforce_refuses_to_start_on_a_database_that_cannot(tmp_path, monkeypatch) -> None:
    settings = make_settings(tmp_path, tenant_rls="enforce")
    tenant_scope.configure(settings)
    monkeypatch.setattr(
        tenant_scope, "database_problems", lambda connection, metadata: ["the role is missing"]
    )
    try:
        with pytest.raises(tenant_scope.TenantRlsUnavailable, match="the role is missing"):
            tenant_scope.verify_database(settings)
        # "off" is the switch that gets the product running while it is fixed.
        tenant_scope.configure(make_settings(tmp_path, tenant_rls="off"))
        tenant_scope.verify_database(settings)
    finally:
        tenant_scope.reset_for_tests()


def test_the_setting_is_refused_when_misspelled(monkeypatch) -> None:
    from api.settings import InsecureConfigurationError, load_settings

    monkeypatch.setenv("OCTO_ENV", "dev")
    monkeypatch.setenv("OCTO_TENANT_RLS", "enfroce")
    with pytest.raises(InsecureConfigurationError, match="OCTO_TENANT_RLS"):
        load_settings()
    monkeypatch.setenv("OCTO_TENANT_RLS", "OFF")
    assert load_settings().tenant_rls == "off"
    monkeypatch.delenv("OCTO_TENANT_RLS")
    assert load_settings().tenant_rls == "enforce"
