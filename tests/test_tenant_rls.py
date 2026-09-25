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
import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import Depends
from sqlalchemy import Column, MetaData, String, Table, create_engine, delete, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from api import auth
from api.db import engine as db_engine
from api.db import models, tenant_scope
from api.db.engine import get_session
from tests.conftest import (
    POSTGRES_URL,
    auth_headers,
    bearer,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

TENANT_A = "rls-tenant-a"
TENANT_B = "rls-tenant-b"
FIXTURES = Path(__file__).parent / "fixtures"


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
        assert any(name in problem and "tenant policies" in problem for problem in problems)
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


# --------------------------------------------------------------------------- #
# Through the API
# --------------------------------------------------------------------------- #


def _leaky_route(client: Any) -> None:
    """A route with its tenant guard and without its WHERE — the bug class #311 is about."""

    @client.app.get("/api/rls-probe/agent-groups")
    def list_every_group(
        _: Any = Depends(auth.require_tenant(auth.Role.viewer)),
    ) -> list[str]:
        with get_session(POSTGRES_URL) as session:
            return sorted(session.execute(select(models.AgentGroup.tenant_id)).scalars().all())


def _seed_groups_in_two_tenants(client: Any, admin: dict[str, str]) -> str:
    other = client.post("/api/tenants", headers=admin, json={"name": "Other"}).json()["tenant_id"]
    with get_session(POSTGRES_URL) as session:
        session.add(_group("default", "ours"))
        session.add(_group(other, "theirs"))
    return other


def test_a_route_that_forgot_its_where_still_answers_for_one_tenant(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    other = _seed_groups_in_two_tenants(client, admin)
    _leaky_route(client)

    operator = client.get("/api/rls-probe/agent-groups", headers=auth_headers(client, "operator"))
    assert operator.status_code == 200, operator.text
    assert operator.json() == ["default"]

    # The platform admin is authorized in every tenant, and its requests are
    # not narrowed: the cross-tenant views are built on that.
    everything = client.get("/api/rls-probe/agent-groups", headers=admin)
    assert sorted(everything.json()) == sorted(["default", other])


def test_a_route_with_no_guard_cannot_read_a_tenant_table(tmp_path, monkeypatch) -> None:
    """Every request starts undeclared (``TenantScopeMiddleware``). A route
    that neither resolves a tenant nor declares itself cross-tenant is refused
    by the database the moment it touches tenant data — the runtime twin of
    ``tests/test_route_tenant_guards.py``."""
    client = configured_client(tmp_path, monkeypatch)
    _seed_groups_in_two_tenants(client, auth_headers(client, "admin"))

    @client.app.get("/api/rls-probe/unguarded")
    def unguarded() -> list[str]:
        with get_session(POSTGRES_URL) as session:
            return sorted(session.execute(select(models.AgentGroup.tenant_id)).scalars().all())

    with pytest.raises(DBAPIError, match="tenant_scope_undeclared"):
        client.get("/api/rls-probe/unguarded")


def test_off_is_the_old_behaviour_through_the_api(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch, tenant_rls="off")
    admin = auth_headers(client, "admin")
    other = _seed_groups_in_two_tenants(client, admin)
    _leaky_route(client)

    operator = client.get("/api/rls-probe/agent-groups", headers=auth_headers(client, "operator"))
    assert sorted(operator.json()) == sorted(["default", other])


def test_a_service_token_is_held_to_its_tenant_even_behind_a_global_role_gate(
    tmp_path, monkeypatch
) -> None:
    """``GET /api/usage/tenants`` is ``require_role(admin)``, and an admin-role
    service token passes that on its role. The route's first line assumes a
    platform admin; the second one knows the caller is a tenant's token."""
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    other = client.post("/api/tenants", headers=admin, json={"name": "Other"}).json()["tenant_id"]
    token = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["*"], "role": "admin"},
    ).json()["token"]

    as_platform = client.get("/api/usage/tenants", headers=admin).json()
    assert {row["tenant_id"] for row in as_platform["tenants"]} >= {"default", other}

    as_token = client.get("/api/usage/tenants", headers=bearer(token))
    assert as_token.status_code == 200, as_token.text
    assert {row["tenant_id"] for row in as_token.json()["tenants"]} == {"default"}


# --------------------------------------------------------------------------- #
# Ids a client chooses: refused by name, not by a duplicate-key error
# --------------------------------------------------------------------------- #
#
# Two primary keys are picked by the caller rather than minted here — an
# agent's ``agent_id`` and an inventory ``snapshot_id`` — and both services
# refuse one that another tenant already holds. Under the tenant scope that
# other tenant's row is invisible, so without an explicit system-scoped look
# the refusal would become an INSERT that dies on the primary key: a 500, and
# one that still says "this id exists".


def _other_tenant(client: Any, admin: dict[str, str]) -> str:
    return client.post("/api/tenants", headers=admin, json={"name": "Other"}).json()["tenant_id"]


def test_an_agent_id_held_by_another_tenant_is_still_refused_by_name(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch)
    other = _other_tenant(client, auth_headers(client, "admin"))
    with get_session(POSTGRES_URL) as session:
        session.add(
            models.Agent(
                agent_id="rls-shared-id", tenant_id=other, registered_at=_now(), last_seen_at=_now()
            )
        )

    # The legacy shared token acts for the default tenant and names its own id.
    response = client.post(
        "/api/agent/register",
        headers={"Authorization": "Bearer test-agent-token"},
        json={"agent_id": "rls-shared-id", "hostname": "h"},
    )

    assert response.status_code == 403, response.text
    assert "different tenant" in response.json()["detail"]
    with get_session(POSTGRES_URL) as session:
        assert session.get(models.Agent, "rls-shared-id").tenant_id == other


def test_a_snapshot_id_held_by_another_tenant_is_still_a_conflict(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch, endpoint_inventory_enabled=True)
    other = _other_tenant(client, auth_headers(client, "admin"))
    body = json.loads((FIXTURES / "endpoint_inventory_v1_valid.json").read_text("utf-8"))
    body["collected_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    headers = {"Authorization": "Bearer test-agent-token"}
    assert client.post("/api/endpoint/inventory", headers=headers, json=body).status_code == 201
    with get_session(POSTGRES_URL) as session:
        session.execute(
            models.EndpointInventorySnapshot.__table__.update()
            .where(models.EndpointInventorySnapshot.snapshot_id == body["snapshot_id"])
            .values(tenant_id=other)
        )

    response = client.post("/api/endpoint/inventory", headers=headers, json=body)

    assert response.status_code == 409, response.text
    assert "different tenant" in response.json()["detail"]


# --------------------------------------------------------------------------- #
# Review round 1
# --------------------------------------------------------------------------- #


def test_a_forgotten_where_behind_a_global_role_gate_is_caught(tmp_path, monkeypatch) -> None:
    """``require_role`` let every caller who passed it into the system scope,
    so the second line protected nothing behind it. Only the platform admin's
    request is widened now; an operator's stays undeclared, and a query that
    forgot its tenant predicate fails instead of reading every tenant."""
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    other = _seed_groups_in_two_tenants(client, admin)

    @client.app.get("/api/rls-probe/role-gated")
    def leaky(_: Any = Depends(auth.require_role(auth.Role.operator))) -> list[str]:
        with get_session(POSTGRES_URL) as session:
            return sorted(session.execute(select(models.AgentGroup.tenant_id)).scalars().all())

    with pytest.raises(DBAPIError, match="tenant_scope_undeclared"):
        client.get("/api/rls-probe/role-gated", headers=auth_headers(client, "operator"))
    assert sorted(client.get("/api/rls-probe/role-gated", headers=admin).json()) == sorted(
        ["default", other]
    )


def test_system_status_counts_no_other_tenants_devices_for_a_viewer(tmp_path, monkeypatch) -> None:
    client = configured_client(tmp_path, monkeypatch, endpoint_inventory_enabled=True)
    admin = auth_headers(client, "admin")
    other = _other_tenant(client, admin)
    with get_session(POSTGRES_URL) as session:
        for index in range(3):
            session.add(
                models.EndpointDevice(
                    device_id=f"rls-dev-{index}", tenant_id=other, agent_id=f"rls-{index}",
                    hostname=f"h{index}", agent_version="1", first_seen=_now(),
                    last_seen=_now(), last_inventory_at=_now(),
                )
            )

    viewer = client.get("/api/system", headers=auth_headers(client, "viewer"))
    assert viewer.status_code == 200, viewer.text
    assert viewer.json()["endpoint_inventory"]["devices_total"] is None
    # The platform admin still sees the fleet.
    assert client.get("/api/system", headers=admin).json()["endpoint_inventory"]["devices_total"] == 3


def test_system_status_device_counts_are_nulls_for_a_viewer_on_the_first_line_too(
    tmp_path, monkeypatch
) -> None:
    """Under ``enforce`` the undeclared scope would already refuse the count, and
    the panel's fail-soft would turn that into a null — so the first-line rule
    (nulls without ``platform.fleet.read``) is pinned with the second line off."""
    client = configured_client(
        tmp_path, monkeypatch, endpoint_inventory_enabled=True, tenant_rls="off"
    )
    other = _other_tenant(client, auth_headers(client, "admin"))
    with get_session(POSTGRES_URL) as session:
        session.add(
            models.EndpointDevice(
                device_id="rls-dev-off", tenant_id=other, agent_id="rls-off", hostname="h",
                agent_version="1", first_seen=_now(), last_seen=_now(),
            )
        )
    viewer = client.get("/api/system", headers=auth_headers(client, "viewer")).json()
    assert viewer["endpoint_inventory"]["devices_total"] is None


def test_a_scrape_time_collector_can_count_every_tenants_rows(tmp_path, monkeypatch) -> None:
    """``/metrics`` declares the cross-tenant scope, so a collector that counts
    rows when scraped — what the observability work adds — counts the fleet
    instead of failing on the undeclared scope and dropping its series."""
    from prometheus_client.core import GaugeMetricFamily

    from api.services import metrics as metrics_service

    class _Groups:
        def collect(self):  # noqa: ANN202
            with get_session(POSTGRES_URL) as session:
                count = session.execute(text("SELECT count(*) FROM agent_groups")).scalar_one()
            yield GaugeMetricFamily("octo_rls_probe_agent_groups", "probe", value=count)

    client = configured_client(tmp_path, monkeypatch)
    _seed_groups_in_two_tenants(client, auth_headers(client, "admin"))
    collector = _Groups()
    metrics_service.REGISTRY.register(collector)
    try:
        scraped = client.get("/metrics")
    finally:
        metrics_service.REGISTRY.unregister(collector)
    assert scraped.status_code == 200, scraped.text
    assert "octo_rls_probe_agent_groups 2.0" in scraped.text


def test_an_operators_tenant_list_and_posture_are_their_memberships(tmp_path, monkeypatch) -> None:
    """The two non-admin routes that do span tenants — the caller's own —
    declare how: the membership lookup in an explicit system block, the
    posture one read per membership, each held to its tenant."""
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    other = _other_tenant(client, admin)
    operator = auth_headers(client, "operator")

    tenants = client.get("/api/tenants", headers=operator)
    assert tenants.status_code == 200, tenants.text
    assert [row["tenant_id"] for row in tenants.json()] == ["default"]
    posture = client.get("/api/tenants/posture", headers=operator)
    assert posture.status_code == 200, posture.text
    assert [row["tenant_id"] for row in posture.json()] == ["default"]
    assert other in {row["tenant_id"] for row in client.get("/api/tenants/posture", headers=admin).json()}


def test_a_tenant_cannot_rewrite_or_take_over_a_built_in_role(enforce) -> None:
    role_id = f"rls-builtin-{uuid.uuid4().hex[:6]}"
    with get_session(POSTGRES_URL) as session:
        session.add(
            models.RoleDefinition(role_id=role_id, tenant_id="", builtin=True, created_at=_now())
        )
    try:
        with tenant_scope.tenant(TENANT_A):
            with get_session(POSTGRES_URL) as session:
                table = models.RoleDefinition.__table__
                seen = session.execute(select(table.c.role_id).where(table.c.role_id == role_id)).all()
                assert len(seen) == 1  # readable: it is every tenant's
                rewritten = session.execute(
                    table.update().where(table.c.role_id == role_id).values(description="mine")
                )
                taken = session.execute(
                    table.update().where(table.c.role_id == role_id).values(tenant_id=TENANT_A)
                )
                removed = session.execute(table.delete().where(table.c.role_id == role_id))
                assert (rewritten.rowcount, taken.rowcount, removed.rowcount) == (0, 0, 0)
        with get_session(POSTGRES_URL) as session:
            row = session.get(models.RoleDefinition, (role_id, ""))
            assert row is not None and row.description == ""
    finally:
        with get_session(POSTGRES_URL) as session:
            session.execute(
                delete(models.RoleDefinition).where(models.RoleDefinition.role_id == role_id)
            )


def test_a_tenant_scope_records_only_its_own_tenants_audit_rows(enforce) -> None:
    """Pinned: a platform-level audit row (``tenant_id`` NULL) cannot be written
    from a tenant-scoped transaction — the ORM's INSERT … RETURNING reads the
    row back, and the row is not the tenant's to read. Nothing does this today;
    a tenant request that records a platform act has to use the system scope."""
    from api.services import audit as audit_service

    with tenant_scope.tenant(TENANT_A):
        with get_session(POSTGRES_URL) as session:
            audit_service.record(
                session, None, action="rls.probe", resource_type="probe", resource_id="own",
                tenant_id=TENANT_A,
            )
        with pytest.raises(DBAPIError, match="row-level security"):
            with get_session(POSTGRES_URL) as session:
                audit_service.record(
                    session, None, action="rls.probe", resource_type="probe",
                    resource_id="platform", tenant_id=None,
                )


def test_asset_tags_are_held_to_their_assets_tenant(enforce) -> None:
    """``asset_tags`` has no ``tenant_id``; its policy is its asset's visibility."""
    with get_session(POSTGRES_URL) as session:
        for tenant_id in (TENANT_A, TENANT_B):
            session.add(
                models.Asset(
                    asset_id=f"rls-asset-{tenant_id}", tenant_id=tenant_id, first_seen=_now(),
                    last_seen=_now(),
                )
            )
        session.flush()
        for tenant_id in (TENANT_A, TENANT_B):
            session.add(models.AssetTag(asset_id=f"rls-asset-{tenant_id}", key="env", value=tenant_id))
    try:
        with tenant_scope.tenant(TENANT_A):
            with get_session(POSTGRES_URL) as session:
                tags = session.execute(
                    select(models.AssetTag.value).where(models.AssetTag.key == "env")
                ).scalars().all()
                assert tags == [TENANT_A]
                changed = session.execute(
                    models.AssetTag.__table__.update()
                    .where(models.AssetTag.asset_id == f"rls-asset-{TENANT_B}")
                    .values(value="rewritten")
                )
                assert changed.rowcount == 0
            with pytest.raises(DBAPIError, match="row-level security"):
                with get_session(POSTGRES_URL) as session:
                    session.add(
                        models.AssetTag(asset_id=f"rls-asset-{TENANT_B}", key="planted", value="x")
                    )
                    session.flush()
    finally:
        with get_session(POSTGRES_URL) as session:
            session.execute(
                delete(models.AssetTag).where(
                    models.AssetTag.asset_id.in_([f"rls-asset-{TENANT_A}", f"rls-asset-{TENANT_B}"])
                )
            )
            session.execute(
                delete(models.Asset).where(
                    models.Asset.asset_id.in_([f"rls-asset-{TENANT_A}", f"rls-asset-{TENANT_B}"])
                )
            )


def test_a_savepoint_keeps_the_scope_without_setting_it_again(enforce) -> None:
    from sqlalchemy import event

    statements: list[str] = []
    engine = db_engine.get_engine(POSTGRES_URL)

    def record(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        if "set_config('role'" in statement:
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        with tenant_scope.tenant(TENANT_A):
            with get_session(POSTGRES_URL) as session:
                assert _group_names(session) == {"alpha"}
                savepoint = session.begin_nested()
                assert _group_names(session) == {"alpha"}
                savepoint.rollback()
                assert _group_names(session) == {"alpha"}
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert len(statements) == 1


def test_a_table_without_its_permissive_policy_or_sequence_grant_is_reported() -> None:
    """Only the restrictive policy, and every non-owner role — an API role
    split from the owner, its workers included — is denied the whole table.
    And a serial column's INSERT needs the sequence as well as the table."""
    name = f"rls_probe_{uuid.uuid4().hex[:8]}"
    engine = create_engine(POSTGRES_URL, future=True)
    metadata = MetaData()
    for table in models.Base.metadata.sorted_tables:
        table.to_metadata(metadata)
    Table(name, metadata, Column("id", String, primary_key=True), Column("tenant_id", String))
    try:
        with engine.begin() as connection:
            connection.execute(
                text(f'CREATE TABLE "{name}" (id serial PRIMARY KEY, tenant_id text)')
            )
            connection.execute(text(f'ALTER TABLE "{name}" ENABLE ROW LEVEL SECURITY'))
            connection.execute(
                text(
                    f'CREATE POLICY shapoclyack_tenant_isolation ON "{name}" AS RESTRICTIVE '
                    "FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant())"
                )
            )
            connection.execute(text(f'REVOKE ALL ON SEQUENCE "{name}_id_seq" FROM shapoclyack_tenant'))
        with engine.connect() as connection:
            problems = tenant_scope.database_problems(connection, metadata)
        assert any(name in problem and "tenant policies" in problem for problem in problems)
        assert any(f"USAGE on sequence {name}_id_seq" in problem for problem in problems)
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP TABLE IF EXISTS "{name}"'))
        engine.dispose()


def test_pre_16_hints_are_valid_sql_there() -> None:
    assert "WITH INHERIT FALSE" in tenant_scope._grant_hint("api", 160004)
    hint = tenant_scope._grant_hint("api", 150008)
    assert "WITH INHERIT" not in hint
    assert hint.startswith("ALTER ROLE api NOINHERIT; GRANT shapoclyack_tenant TO api")


# --------------------------------------------------------------------------- #
# The wave it merged with: #332 (retention, legal hold), #325 (tenant
# lifecycle, purge), #334 (scrape-time metrics)
# --------------------------------------------------------------------------- #


def test_deletion_steps_are_held_to_their_deletions_tenant(enforce) -> None:
    """``tenant_deletion_steps`` (#325) has no ``tenant_id``, like ``asset_tags``:
    a step belongs to the deletion it is part of, and ``tenant_deletions`` is
    itself held to the tenant — so a step is visible exactly when its deletion
    is, and one tenant's transaction cannot read how another's purge went."""
    ids = {tenant_id: f"rls-deletion-{tenant_id}" for tenant_id in (TENANT_A, TENANT_B)}
    with get_session(POSTGRES_URL) as session:
        for tenant_id, deletion_id in ids.items():
            session.add(
                models.TenantDeletion(
                    deletion_id=deletion_id, tenant_id=tenant_id, state="pending",
                    reason="rls probe", requested_by="admin", requested_at=_now(),
                    purge_after=_now(),
                )
            )
        session.flush()
        for tenant_id, deletion_id in ids.items():
            session.add(
                models.TenantDeletionStep(
                    deletion_id=deletion_id, step="postgres", position=0, last_error=tenant_id
                )
            )
    try:
        with tenant_scope.tenant(TENANT_A):
            with get_session(POSTGRES_URL) as session:
                seen = session.execute(
                    select(models.TenantDeletionStep.last_error).where(
                        models.TenantDeletionStep.deletion_id.in_(ids.values())
                    )
                ).scalars().all()
                assert seen == [TENANT_A]
                changed = session.execute(
                    models.TenantDeletionStep.__table__.update()
                    .where(models.TenantDeletionStep.deletion_id == ids[TENANT_B])
                    .values(state="done")
                )
                assert changed.rowcount == 0
            with pytest.raises(DBAPIError, match="row-level security"):
                with get_session(POSTGRES_URL) as session:
                    session.add(
                        models.TenantDeletionStep(
                            deletion_id=ids[TENANT_B], step="planted", position=1
                        )
                    )
                    session.flush()
    finally:
        with get_session(POSTGRES_URL) as session:
            # Cascades to the steps.
            session.execute(
                delete(models.TenantDeletion).where(
                    models.TenantDeletion.deletion_id.in_(ids.values())
                )
            )

