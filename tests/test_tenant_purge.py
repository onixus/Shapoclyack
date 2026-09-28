"""Purging a tenant, store by store (#325).

Every test that deletes seeds two tenants with a row in *every* table the
purge plan names, and a neighbour whose id begins with the victim's — ``acme``
and ``acme-eu`` — so a predicate, a subject, a consumer name or a key prefix
that matched too much takes the neighbour's data with it and fails here. The
purge must leave the victim with nothing and the neighbour with everything.

The rest pin the journal's promises: a step that fails is recorded and
retried, one that dies with its process is resumed by another replica from
where it was, a legal hold that appears between two batches stops the purge
with the remaining data intact, and nothing in the plan's reach is missing
from it — the last is checked against the live schema, not against a list.

Postgres-gated. The ClickHouse and object-storage steps run here against
precise fakes (``tests/fake_s3.py`` and a recording ClickHouse client); the
live JetStream runs are gated on ``OCTO_NATS_URL`` as well, which the
integration gate provides with Postgres. The live ClickHouse and S3 runs are in
``tests/test_tenant_purge_live.py``: their stores are not part of that gate, so
a skip of theirs must not be counted against the Postgres suite.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy import select, text, update

from api.db import models
from api.db.engine import get_session
from api.services import artifact_store
from api.services import audit as audit_service
from api.services import legal_hold
from api.services import tenant_lifecycle as lifecycle
from api.services import tenant_purge
from api.services import tenants as tenants_service
from api.services.artifact_store import keys, workspace
from api.services.tenant_purge import artifacts as purge_artifacts
from api.services.tenant_purge import clickhouse as purge_clickhouse
from api.services.tenant_purge import jetstream as purge_jetstream
from api.services.tenant_purge import postgres as purge_postgres
from api.services.tenant_purge.context import PurgeContext
from api.settings import Settings
from tests.conftest import NATS_URL, make_settings, requires_postgres, reset_service_state
from tests.fake_s3 import FakeS3Client

pytestmark = requires_postgres

VICTIM = "acme"
# Starts with the victim's id: see the module docstring.
NEIGHBOUR = "acme-eu"

_NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)

#: Every table the seeder fills, one row per tenant.
_SEEDED = set(purge_postgres.OUTBOX_TABLES + purge_postgres.POSTGRES_TABLES) | {
    "users",
    "user_tenants",
}


# --------------------------------------------------------------------------- #
# Fixtures and seeding
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    workspace.reset_marker_cache()


@pytest.fixture()
def settings(tmp_path):
    yield from purge_settings(tmp_path)


def purge_settings(tmp_path: Path) -> Iterator[Settings]:
    """The ``settings`` fixture's body; tests/test_tenant_purge_live.py shares it."""
    s = make_settings(
        tmp_path,
        tenant_deletion_grace_days=0,
        tenant_deletion_two_person=False,
        # Small, so every table's purge is more than one batch and a failure
        # can be injected between two of them.
        tenant_purge_batch_size=1,
        tenant_purge_interval_seconds=5,
        # No ClickHouse or NATS in most of these, and said so: a store that is
        # merely not configured fails its step (review round 1, finding 7).
        tenant_purge_unused_stores=("clickhouse", "jetstream"),
    )
    s.output_dir.mkdir(parents=True, exist_ok=True)
    s.state_dir.mkdir(parents=True, exist_ok=True)
    _forget_custom_roles(s)
    reset_service_state(s)
    tenants_service.load_tenants(s)
    for tenant_id in (VICTIM, NEIGHBOUR):
        tenants_service.create_tenant(name=tenant_id, tenant_id=tenant_id)
    yield s
    with get_session(s.postgres_url) as session:
        session.query(models.TenantLegalHold).delete()
    _forget_custom_roles(s)


def _forget_custom_roles(settings: Settings) -> None:
    """Tenant-defined roles have no foreign key to ``tenants``, so the suite's
    tenant reset leaves the neighbour's behind; the built-ins (``''``) stay."""
    with get_session(settings.postgres_url) as session:
        session.execute(text("DELETE FROM role_permissions WHERE tenant_id <> ''"))
        session.execute(text("DELETE FROM roles WHERE tenant_id <> ''"))


def _seed_value(table: sa.Table, column: sa.Column, tenant_id: str) -> Any:
    kind = column.type
    if isinstance(kind, sa.Boolean):
        return False
    if isinstance(kind, (sa.Integer, sa.Float, sa.Numeric)):
        return 1
    if isinstance(kind, sa.DateTime):
        return _NOW
    if isinstance(kind, sa.LargeBinary):
        return b"x"
    if isinstance(kind, sa.JSON):
        return {}
    if isinstance(kind, sa.String):
        # The tenant id first in every value, so a column that is unique
        # across tenants (a token prefix, a key lookup) cannot collide even
        # where the column is too short for the rest.
        value = f"{tenant_id}:{table.name}:{column.name}"
        return value[: kind.length] if kind.length else value
    raise AssertionError(f"no seed value for {table.name}.{column.name} ({kind!r})")


def seed_every_table(settings: Settings, tenant_id: str) -> dict[str, int]:
    """One row of ``tenant_id`` in every table the purge plan names.

    Generic on purpose: driven by the *migrated* schema (reflected, so column
    widths and server defaults are the database's), parents before children,
    so a table added to the plan is seeded without this function being edited
    — and a column it cannot fill fails loudly here.
    """
    known: dict[tuple[str, str], Any] = {
        ("tenants", "tenant_id"): tenant_id,
        ("permissions", "permission_key"): "audit.read",
    }
    counts: dict[str, int] = {}
    schema = sa.MetaData()
    with get_session(settings.postgres_url) as session:
        schema.reflect(bind=session.connection(), only=sorted(_SEEDED | {"tenants", "permissions"}))
        for table in schema.sorted_tables:
            if table.name not in _SEEDED:
                continue
            keys_ = list(table.primary_key.columns)
            row: dict[str, Any] = {}
            for column in table.columns:
                if column.name == "tenant_id":
                    row[column.name] = tenant_id
                    continue
                foreign = next(iter(column.foreign_keys), None)
                if foreign is not None:
                    target = (foreign.column.table.name, foreign.column.name)
                    if target in known:
                        row[column.name] = known[target]
                    elif not column.nullable:
                        raise AssertionError(f"{table.name}.{column.name} needs {target}")
                    continue
                if column.server_default is not None or column.identity is not None:
                    continue  # serial keys and server defaults fill themselves
                if column.nullable and not column.primary_key:
                    continue
                row[column.name] = _seed_value(table, column, tenant_id)
            inserted = session.execute(table.insert().values(row).returning(*keys_)).one()
            for column, value in zip(keys_, inserted):
                known[(table.name, column.name)] = value
            counts[table.name] = 1
    return counts


def _all_tables() -> tuple[str, ...]:
    return purge_postgres.OUTBOX_TABLES + purge_postgres.POSTGRES_TABLES


def _remaining(settings: Settings, tenant_id: str) -> dict[str, int]:
    with get_session(settings.postgres_url) as session:
        return purge_postgres.remaining(session, _all_tables(), tenant_id)


def _approve(settings: Settings, tenant_id: str = VICTIM) -> str:
    lifecycle.request_deletion(
        settings, tenant_id, confirm=tenant_id, reason="contract ended", actor="root"
    )
    described = lifecycle.approve_deletion(settings, tenant_id, confirm=tenant_id, actor="root")
    return described["deletion"]["deletion_id"]


def _deletion(settings: Settings, deletion_id: str) -> dict[str, Any]:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantDeletion, deletion_id)
        return lifecycle.deletion_dict(session, row)


def _step(settings: Settings, deletion_id: str, name: str) -> dict[str, Any]:
    return next(s for s in _deletion(settings, deletion_id)["steps"] if s["step"] == name)


def _make_due(settings: Settings, deletion_id: str) -> None:
    """Skip the backoff, as a platform admin's retry would."""
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.TenantDeletion)
            .where(models.TenantDeletion.deletion_id == deletion_id)
            .values(next_attempt_at=_NOW - timedelta(seconds=1))
        )


def _run_to_end(settings: Settings, *, limit: int = 20) -> list[str]:
    outcomes = []
    for _ in range(limit):
        result = tenant_purge.run_once(settings, owner="replica-1")
        outcomes.append(result["outcome"])
        if result["outcome"] in ("completed", "idle"):
            break
    return outcomes


# --------------------------------------------------------------------------- #
# The plan against the live schema
# --------------------------------------------------------------------------- #


def _schema(settings: Settings) -> tuple[set[str], list[tuple[str, str, str]]]:
    with get_session(settings.postgres_url) as session:
        tenant_tables = set(
            session.execute(
                text(
                    "SELECT table_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
                )
            ).scalars()
        )
        foreign_keys = [
            tuple(row)
            for row in session.execute(
                text(
                    "SELECT tc.table_name, ccu.table_name, rc.delete_rule "
                    "FROM information_schema.table_constraints tc "
                    "JOIN information_schema.constraint_column_usage ccu "
                    "  ON ccu.constraint_name = tc.constraint_name "
                    " AND ccu.table_schema = tc.table_schema "
                    "JOIN information_schema.referential_constraints rc "
                    "  ON rc.constraint_name = tc.constraint_name "
                    "WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'"
                )
            ).all()
        ]
    return tenant_tables, foreign_keys


def test_every_table_that_holds_a_tenant_is_in_the_plan(settings):
    """A table with a ``tenant_id`` — or a key to one that has it — cannot be missed.

    Walks the migrated schema rather than the models, because the database is
    what the purge has to empty. A new table lands in the plan, the outbox,
    the finalize step or ``RETAINED`` with a reason, or this fails.
    """
    tenant_tables, foreign_keys = _schema(settings)
    planned = (
        set(purge_postgres.OUTBOX_TABLES)
        | set(purge_postgres.POSTGRES_TABLES)
        | set(purge_postgres.FINALIZE_TABLES)
        | set(purge_postgres.RETAINED)
    )
    # Children of a tenant table that carry no tenant_id of their own. Tables
    # hanging off accounts (sessions, keys) are the account's, not a tenant's.
    reachable = set(tenant_tables)
    changed = True
    while changed:
        changed = False
        for child, parent, _rule in foreign_keys:
            if parent in reachable and child not in reachable and parent != "users":
                reachable.add(child)
                changed = True
    assert reachable - planned == set(), "tables the purge does not know about"
    assert planned - reachable - {"tenants"} == set(), "plan names a table the schema lacks"


def test_the_plan_deletes_children_before_the_parents_that_restrict_them(settings):
    """A NO ACTION or RESTRICT key fails the parent's DELETE while a child row
    exists, so the child has to come first — and a CASCADE child is listed
    first anyway, or its parent's batch would delete it unbatched."""
    _tenant_tables, foreign_keys = _schema(settings)
    order = {name: index for index, name in enumerate(_all_tables())}
    for child, parent, rule in foreign_keys:
        if child in order and parent in order and child != parent:
            assert order[child] < order[parent], (child, parent, rule)


def test_every_step_the_journal_names_has_a_function():
    assert tuple(tenant_purge.STEP_FUNCTIONS) == lifecycle.STEPS


# --------------------------------------------------------------------------- #
# A purge from start to finish
# --------------------------------------------------------------------------- #


def test_a_purge_removes_every_row_of_the_tenant_and_none_of_its_neighbour(settings):
    seeded = seed_every_table(settings, VICTIM)
    seed_every_table(settings, NEIGHBOUR)
    assert _remaining(settings, VICTIM) == {name: 1 for name in _all_tables()}

    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"

    assert _remaining(settings, VICTIM) == {}
    assert _remaining(settings, NEIGHBOUR) == {name: 1 for name in _all_tables()}
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Tenant, VICTIM) is None
        assert session.get(models.Tenant, NEIGHBOUR).status == "active"
        # The victim's only member is disabled rather than left to fall back to
        # the default tenant with its global role; the neighbour's is untouched.
        assert session.get(models.User, f"{VICTIM}:users:username").disabled_at is not None
        assert session.get(models.User, f"{NEIGHBOUR}:users:username").disabled_at is None
        assert (
            session.execute(
                select(models.UserTenant).where(models.UserTenant.tenant_id == VICTIM)
            ).first()
            is None
        )

    journal = _deletion(settings, deletion_id)
    assert journal["state"] == "completed"
    assert {step["state"] for step in journal["steps"]} <= {"done", "skipped"}
    tombstone = journal["outcome"]
    assert tombstone["tenant_id"] == VICTIM
    # Every table, with what it held: one row each, counted once.
    postgres_counts = {
        **tombstone["stores"]["outbox"],
        **tombstone["stores"]["postgres"],
    }
    assert {name: postgres_counts[name] for name in seeded if name in postgres_counts} == {
        name: 1 for name in _all_tables()
    }
    assert tombstone["stores"]["finalize"] == {"memberships": 1, "accounts_disabled": 1}
    # Not configured in this test: skipped, and the tombstone says so.
    assert set(tombstone["skipped"]) == {"clickhouse", "jetstream"}
    assert "audit_events" in tombstone["retained"]
    # No personal data in the proof: counts and the platform's own ids.
    assert "contract ended" not in json.dumps(tombstone)
    assert f"{VICTIM}:users:username" not in json.dumps(tombstone)


def test_the_audit_trail_outlives_the_tenant_and_records_the_purge(settings):
    with get_session(settings.postgres_url) as session:
        audit_service.record(
            session,
            None,
            action=audit_service.ACTION_MEMBERSHIP_GRANT,
            resource_type="membership",
            resource_id="someone",
            tenant_id=VICTIM,
        )
    _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    with get_session(settings.postgres_url) as session:
        kept = session.execute(
            select(models.AuditEvent.action).where(models.AuditEvent.tenant_id == VICTIM)
        ).scalars().all()
        platform = session.execute(
            select(models.AuditEvent.action, models.AuditEvent.actor)
            .where(
                models.AuditEvent.tenant_id.is_(None),
                models.AuditEvent.resource_id == VICTIM,
            )
            .order_by(models.AuditEvent.id)
        ).all()
    assert kept == ["membership.grant"]
    assert [action for action, _actor in platform] == [
        "tenant.delete.request",
        "tenant.delete.approve",
        "tenant.delete.complete",
    ]
    assert platform[-1][1] == "tenant-purge"


def test_a_deleted_tenants_id_is_never_handed_out_again(settings):
    _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    with pytest.raises(ValueError, match="not reused"):
        tenants_service.create_tenant(name="new acme", tenant_id=VICTIM)


# --------------------------------------------------------------------------- #
# Failure, retry and crash
# --------------------------------------------------------------------------- #


def test_a_failing_step_is_recorded_retried_with_backoff_and_resumed(settings, monkeypatch):
    seed_every_table(settings, VICTIM)
    seed_every_table(settings, NEIGHBOUR)
    deletion_id = _approve(settings)

    real = purge_postgres.delete_batch
    calls = {"n": 0}

    def flaky(session, name, tenant_id, limit):
        calls["n"] += 1
        # The third batch: nats_outbox took two (its row, then an empty one),
        # so this is run_publications' first.
        if calls["n"] == 3:
            raise RuntimeError("connection reset by peer")
        return real(session, name, tenant_id, limit)

    monkeypatch.setattr(purge_postgres, "delete_batch", flaky)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"

    journal = _deletion(settings, deletion_id)
    assert journal["state"] == "purging"
    assert journal["attempts"] == 1
    assert journal["last_error"].startswith("outbox: RuntimeError: connection reset")
    step = _step(settings, deletion_id, "outbox")
    assert step["state"] == "failed" and step["attempts"] == 1
    # Backed off: not due on the next tick.
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "idle"
    assert tenant_purge.backoff_seconds(settings, 1) == 5
    assert tenant_purge.backoff_seconds(settings, 3) == 20
    assert tenant_purge.backoff_seconds(settings, 40) == tenant_purge.MAX_BACKOFF_SECONDS

    monkeypatch.setattr(purge_postgres, "delete_batch", real)
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert _remaining(settings, VICTIM) == {}
    assert _remaining(settings, NEIGHBOUR) == {name: 1 for name in _all_tables()}
    tombstone = _deletion(settings, deletion_id)["outcome"]
    # The batches committed before the failure were counted once, not twice.
    assert tombstone["stores"]["outbox"] == {"nats_outbox": 1, "run_publications": 1}
    with get_session(settings.postgres_url) as session:
        failures = session.execute(
            select(models.AuditEvent).where(models.AuditEvent.action == "tenant.delete.fail")
        ).scalars().all()
    # Once per failing step, not once per retry.
    assert len(failures) == 1 and failures[0].after["step"] == "outbox"


class _Crash(BaseException):
    """The process dying: not an Exception, so nothing in the worker catches it."""


@pytest.mark.parametrize("step", ["outbox", "artifacts", "clickhouse", "postgres", "finalize"])
def test_a_step_that_dies_with_its_process_is_resumed_by_another_replica(
    settings, monkeypatch, step
):
    seed_every_table(settings, VICTIM)
    seed_every_table(settings, NEIGHBOUR)
    _seed_runs(settings)
    deletion_id = _approve(settings)

    real_batch = purge_postgres.delete_batch
    real_delete_run = workspace.delete_run
    calls = {"n": 0}

    def crash_later(real, after):
        def wrapper(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == after:
                raise _Crash()
            return real(*args, **kwargs)

        return wrapper

    real_stranded = purge_postgres._stranded_accounts  # noqa: SLF001
    clickhouse = _RecordingClickHouse(
        {
            "shapoclyack.shapoclyack_vulnerabilities": {
                purge_clickhouse._uuid_literal(VICTIM): 4,  # noqa: SLF001
            },
            "shapoclyack.shapoclyack_open_ports": {
                purge_clickhouse._uuid_literal(VICTIM): 2,  # noqa: SLF001
            },
        }
    )
    settings.clickhouse_url = "http://clickhouse.invalid:8123"
    monkeypatch.setattr(purge_clickhouse.clickhouse_client, "get_client", lambda url: clickhouse)
    if step == "artifacts":
        monkeypatch.setattr(workspace, "delete_run", crash_later(real_delete_run, 1))
    elif step == "clickhouse":
        # Between the first table's mutation and the second's.
        clickhouse.crash_on = "shapoclyack.shapoclyack_open_ports"
    elif step == "finalize":
        # Inside the last transaction: it rolls back whole, tenant row and all.
        monkeypatch.setattr(
            purge_postgres, "_stranded_accounts", crash_later(real_stranded, 1)
        )
    else:
        # The outbox step makes four calls with a batch of one (a row and an
        # empty batch per table): crash in its third, after nats_outbox has
        # committed — or deep inside the Postgres step.
        monkeypatch.setattr(
            purge_postgres, "delete_batch", crash_later(real_batch, 3 if step == "outbox" else 20)
        )
    with pytest.raises(_Crash):
        tenant_purge.run_once(settings, owner="replica-1")

    died = _step(settings, deletion_id, step)
    assert died["state"] == "running"
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantDeletion, deletion_id)
        assert row.lease_owner == "replica-1"
        # The lease is what keeps a second replica off it until it lapses.
    assert tenant_purge.run_once(settings, owner="replica-2")["outcome"] == "idle"
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.TenantDeletion)
            .where(models.TenantDeletion.deletion_id == deletion_id)
            .values(lease_until=_NOW - timedelta(seconds=1))
        )

    monkeypatch.setattr(purge_postgres, "delete_batch", real_batch)
    monkeypatch.setattr(workspace, "delete_run", real_delete_run)
    monkeypatch.setattr(purge_postgres, "_stranded_accounts", real_stranded)
    clickhouse.crash_on = None
    result = tenant_purge.run_once(settings, owner="replica-2")
    assert result["outcome"] == "completed"
    assert _step(settings, deletion_id, step)["attempts"] == 2
    assert _remaining(settings, VICTIM) == {}
    assert _remaining(settings, NEIGHBOUR) == {name: 1 for name in _all_tables()}
    store = artifact_store.get_store(settings)
    assert _run_keys(store, VICTIM) == []
    assert _run_keys(store, NEIGHBOUR) != []
    stores = _deletion(settings, deletion_id)["outcome"]["stores"]
    # Counted once across the two attempts.
    assert stores["clickhouse"] == {"vulnerabilities": 4, "open_ports": 2, "controls": 0}
    assert stores["postgres"]["vulnerabilities"] == 1
    assert stores["artifacts"]["legacy_runs"] == 1


def test_a_replica_that_lost_its_lease_stops_without_writing(settings):
    deletion_id = _approve(settings)
    owner = "replica-1"
    assert tenant_purge._claim(settings, owner) == deletion_id  # noqa: SLF001
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.TenantDeletion)
            .where(models.TenantDeletion.deletion_id == deletion_id)
            .values(lease_owner="replica-2")
        )
    assert tenant_purge.drive(settings, deletion_id, owner) == "lease_lost"
    assert {s["state"] for s in _deletion(settings, deletion_id)["steps"]} == {"pending"}


def test_rows_written_after_their_table_was_purged_send_the_purge_round_again(
    settings, monkeypatch
):
    """A writer that did not see the status must not have its row cascaded away
    unrecorded by ``DELETE FROM tenants``: finalize counts, and re-runs."""
    deletion_id = _approve(settings)
    real_finalize = purge_postgres.finalize
    state = {"late": False}

    def finalize_after_a_late_write(ctx):
        if not state["late"]:
            state["late"] = True
            with get_session(settings.postgres_url) as session:
                session.add(
                    models.RiskScoreSnapshot(
                        snapshot_id="late", tenant_id=VICTIM, recorded_at=_NOW
                    )
                )
        return real_finalize(ctx)

    monkeypatch.setitem(tenant_purge.STEP_FUNCTIONS, "finalize", finalize_after_a_late_write)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    assert _step(settings, deletion_id, "postgres")["state"] == "pending"
    assert "risk_score_snapshots" in _deletion(settings, deletion_id)["last_error"]
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert _remaining(settings, VICTIM) == {}
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["postgres"][
        "risk_score_snapshots"
    ] == 1


def test_a_running_job_holds_the_purge_until_it_is_final(settings):
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id="job-local",
                tenant_id=VICTIM,
                status="running",
                execution="local",
                command=[],
                queued_at=_NOW,
            )
        )
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "waiting"
    quiesce = _step(settings, deletion_id, "quiesce")
    assert quiesce["state"] == "waiting"
    assert "job-local" in quiesce["last_error"]
    # Waiting is not failing: nothing counted against the deletion.
    assert _deletion(settings, deletion_id)["attempts"] == 0

    with get_session(settings.postgres_url) as session:
        session.get(models.Job, "job-local").status = "succeeded"
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"


# --------------------------------------------------------------------------- #
# Legal hold
# --------------------------------------------------------------------------- #


def test_a_hold_placed_between_two_batches_stops_the_purge_with_the_rest_intact(
    settings, monkeypatch
):
    seed_every_table(settings, VICTIM)
    deletion_id = _approve(settings)
    real_batch = purge_postgres.delete_batch
    real_guard = PurgeContext.guard
    state = {"table": None, "placed": False}

    def tracking(session, name, tenant_id, limit):
        state["table"] = name
        return real_batch(session, name, tenant_id, limit)

    @contextmanager
    def guard_after_a_hold(self):
        # Between two batches — after the assets table's first one committed,
        # before the next guard — somebody else commits a hold: an older
        # replica's place_hold, or a hand-written INSERT. Not *inside* a batch:
        # the batch holds the tenant row, and the hold's foreign key waits on it.
        if state["table"] == "assets" and not state["placed"]:
            state["placed"] = True
            with get_session(settings.postgres_url) as other:
                other.add(
                    models.TenantLegalHold(
                        tenant_id=VICTIM, reason="matter 2026-31", set_by="counsel", set_at=_NOW
                    )
                )
        with real_guard(self) as session:
            yield session

    monkeypatch.setattr(purge_postgres, "delete_batch", tracking)
    monkeypatch.setattr(PurgeContext, "guard", guard_after_a_hold)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "blocked"

    journal = _deletion(settings, deletion_id)
    assert journal["state"] == "blocked"
    assert "legal hold" in journal["last_error"]
    left = _remaining(settings, VICTIM)
    assert left, "the purge went on after the hold"
    assert "provisioning_keys" in left and "vulnerabilities" not in left
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Tenant, VICTIM).status == "deleting"
    # Blocked is not due: releasing the hold does not by itself resume.
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "idle"
    with pytest.raises(legal_hold.LegalHoldActive):
        lifecycle.retry_deletion(settings, VICTIM, actor="root")

    monkeypatch.setattr(purge_postgres, "delete_batch", real_batch)
    monkeypatch.setattr(PurgeContext, "guard", real_guard)
    legal_hold.release_hold(settings, VICTIM)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "idle"
    lifecycle.retry_deletion(settings, VICTIM, actor="root")
    assert _run_to_end(settings)[-1] == "completed"
    assert _remaining(settings, VICTIM) == {}


def test_a_hold_placed_through_the_api_during_the_purge_is_honoured(settings, monkeypatch):
    """``place_hold`` takes the tenant row lock every batch also takes, so it
    is never refused for a tenant being deleted: it waits for the batch, and
    the next batch sees it."""
    seed_every_table(settings, VICTIM)
    deletion_id = _approve(settings)

    def hold_then_purge(ctx):
        # Three steps in: the outbox and the artifacts are gone already.
        placed = legal_hold.place_hold(
            settings, VICTIM, reason="preservation order", set_by="counsel"
        )
        assert placed["tenant_id"] == VICTIM
        return purge_postgres.postgres(ctx)

    monkeypatch.setitem(tenant_purge.STEP_FUNCTIONS, "postgres", hold_then_purge)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "blocked"
    assert "vulnerabilities" in _remaining(settings, VICTIM)
    assert _step(settings, deletion_id, "outbox")["state"] == "done"
    assert _step(settings, deletion_id, "postgres")["state"] == "failed"
    with get_session(settings.postgres_url) as session:
        blocked = session.execute(
            select(models.AuditEvent).where(models.AuditEvent.action == "tenant.delete.block")
        ).scalar_one()
    assert blocked.tenant_id is None and blocked.after["step"] == "postgres"


def test_the_tenant_row_cannot_be_deleted_under_a_hold_even_by_a_careless_path(settings):
    """The RESTRICT key from 0065 is still the backstop behind every check above."""
    legal_hold.place_hold(settings, VICTIM, reason="matter", set_by="counsel")
    with pytest.raises(sa.exc.IntegrityError):
        with get_session(settings.postgres_url) as session:
            session.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": VICTIM})


# --------------------------------------------------------------------------- #
# Artifacts: local volume and object storage
# --------------------------------------------------------------------------- #


def _write(store: artifact_store.ArtifactStore, key: str, body: bytes = b"{}") -> None:
    store.put_bytes(key, body)


def _seed_runs(settings: Settings) -> None:
    """Runs, flat runs, job inputs and reports for both tenants."""
    store = artifact_store.get_store(settings)
    for tenant_id in (VICTIM, NEIGHBOUR):
        segment = keys.tenant_segment(tenant_id)
        run = keys.run_ref(f"20260920T0000{len(tenant_id):02d}Z-aaaa", tenant_id)
        assert run.tenant == segment
        _write(store, keys.run_artifact(run, "summary.json"))
        _write(store, keys.run_artifact(run, "screenshots/login.png"), b"\x89PNG")
        # A flat run of an earlier release, owned only by its marker.
        flat = keys.run_ref(f"legacy-{tenant_id}")
        _write(store, keys.run_artifact(flat, "summary.json"))
        _write(
            store,
            keys.run_artifact(flat, "tenant.json"),
            json.dumps({"tenant_id": tenant_id}).encode(),
        )
        _write(store, keys.job_input(f"{tenant_id}:jobs:job_id", "targets.txt"), b"10.0.0.1\n")
        _write(store, keys.report_key(tenant_id, "rpt_0000000000000001.pdf"), b"%PDF")
    # A flat run with no marker is the default tenant's, and stays.
    _write(store, keys.run_artifact(keys.run_ref("legacy-unmarked"), "summary.json"))


def _run_keys(store: artifact_store.ArtifactStore, tenant_id: str) -> list[str]:
    found = [
        entry.key
        for entry in store.list_prefix(keys.tenant_runs_prefix(keys.tenant_segment(tenant_id)))
    ]
    found += [entry.key for entry in store.list_prefix(f"runs/legacy-{tenant_id}")]
    found += [entry.key for entry in store.list_prefix(f"reports/{tenant_id}")]
    found += [entry.key for entry in store.list_prefix(f"job_inputs/{tenant_id}:jobs:job_id")]
    return sorted(found)


def _purge_artifacts(settings: Settings) -> dict[str, Any]:
    seed_every_table(settings, VICTIM)
    seed_every_table(settings, NEIGHBOUR)
    _seed_runs(settings)
    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    return _deletion(settings, deletion_id)["outcome"]["stores"]["artifacts"]


def test_the_artifact_step_empties_the_tenants_runs_reports_and_inputs_on_a_volume(settings):
    counts = _purge_artifacts(settings)
    store = artifact_store.get_store(settings)
    assert _run_keys(store, VICTIM) == []
    assert len(_run_keys(store, NEIGHBOUR)) == 6
    assert store.exists("runs/legacy-unmarked/summary.json")
    # The segment directory itself is gone, not just its files.
    assert not (settings.output_dir / "runs" / "_tenants" / VICTIM).exists()
    assert (settings.output_dir / "runs" / "_tenants" / NEIGHBOUR).is_dir()
    assert counts == {
        "runs": 1,
        "run_objects": 2,
        "legacy_runs": 1,
        "legacy_run_objects": 2,
        "job_input_objects": 1,
        "report_objects": 1,
    }


def test_the_artifact_step_empties_a_bucket_the_same_way(settings, tmp_path):
    shared = FakeS3Client()
    settings.artifact_backend = "s3"
    settings.artifact_s3_bucket = "artifacts"
    settings.artifact_cache_dir = str(tmp_path / "cache")
    store = artifact_store.get_store(settings)
    store._client = shared  # noqa: SLF001 - the seam the lazy client exists for
    counts = _purge_artifacts(settings)
    assert _run_keys(store, VICTIM) == []
    assert len(_run_keys(store, NEIGHBOUR)) == 6
    assert not any(key.startswith(f"runs/_tenants/{VICTIM}/") for key in shared.objects)
    assert any(key.startswith(f"runs/_tenants/{NEIGHBOUR}/") for key in shared.objects)
    assert counts["run_objects"] == 2 and counts["legacy_runs"] == 1


def test_a_flat_run_whose_owner_cannot_be_read_fails_the_step_rather_than_be_guessed(
    settings,
):
    store = artifact_store.get_store(settings)
    _write(store, "runs/legacy-garbled/summary.json")
    _write(store, "runs/legacy-garbled/tenant.json", b"{not json")
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    step = _step(settings, deletion_id, "artifacts")
    assert step["state"] == "failed"
    assert "legacy-garbled" in step["last_error"]
    # Left for a person to look at, not deleted and not assumed to be the default's.
    assert store.exists("runs/legacy-garbled/summary.json")

    store.delete_prefix("runs/legacy-garbled")
    lifecycle.retry_deletion(settings, VICTIM, actor="root")
    assert _run_to_end(settings)[-1] == "completed"


# --------------------------------------------------------------------------- #
# ClickHouse (recorded client) and JetStream (skipped when not configured)
# --------------------------------------------------------------------------- #


class _RecordingClickHouse:
    """The statements the step issues, over in-memory tables — asynchronously.

    An ``ALTER … DELETE`` is recorded as a *pending* mutation, as ClickHouse
    does, and is applied only once ``system.mutations`` has been polled
    ``polls`` times for it: a step that submitted and counted at once would
    find its rows still there. ``fail_reason`` makes the pending mutation
    report ``latest_fail_reason`` instead of finishing.

    ``others`` are mutations on the same tables that are not this purge's —
    another tenant's ``UPDATE``, say — older than anything the step submits,
    and never finishing on their own. As in ClickHouse, a table applies its
    mutations in order: while one of them is failing, every later one reports
    the same reason and does not progress.
    """

    def __init__(
        self,
        rows: dict[str, dict[str, int]],
        *,
        fail_on: str | None = None,
        polls: int = 1,
    ) -> None:
        self.rows = rows  # table -> {uuid literal: count}
        self.fail_on = fail_on
        self.crash_on: str | None = None
        self.polls = polls
        self.fail_reason = ""
        # [table, uuid literal, polls seen] (+ mutation id, given on first sight)
        self.pending: list[list[Any]] = []
        # [table, command, latest_fail_reason, mutation id]
        self.others: list[list[Any]] = []
        self.statements: list[tuple[str, dict | None]] = []
        self._ids = 0

    def _id(self, entry: list[Any]) -> str:
        if len(entry) < 4:
            self._ids += 1
            entry.append(f"mutation_{self._ids}.txt")
        return entry[3]

    def command(self, statement: str, settings: dict | None = None) -> Any:
        self.statements.append((statement, settings))
        if statement.startswith("EXISTS TABLE "):
            return int(statement.split()[-1] in self.rows)
        table = statement.split(" FROM ")[-1].split()[0] if " FROM " in statement else ""
        if statement.startswith("ALTER TABLE "):
            table = statement.split()[2]
            if self.fail_on == table:
                raise RuntimeError("Code: 241. DB::Exception: Memory limit exceeded")
            if self.crash_on == table:
                raise _Crash()
            key = statement.split("tenant_id = ")[1]
            self.pending.append([table, key, 0])
            return None
        key = statement.split("tenant_id = ")[1]
        return self.rows.get(table, {}).get(key, 0)

    def query(self, statement: str):
        self.statements.append((statement, None))
        assert "system.mutations" in statement, statement
        assert "is_done = 0" in statement, statement
        database = statement.split("database = '")[1].split("'")[0]
        table = f"{database}.{statement.split('table = ')[1].split(chr(39))[1]}"
        needle = statement.split("position(command, '")[1].split("'")[0]
        others = [entry for entry in self.others if entry[0] == table]
        # A failing mutation holds every later one on its table.
        held = next((reason for _t, _c, reason, _id in others if reason), "")
        ours = [entry for entry in self.pending if entry[0] == table]
        rows: list[tuple[Any, ...]] = []
        if "ORDER BY" in statement:
            # The table's oldest unfinished mutation, whoever's it is.
            for _t, command, reason, mutation_id in others:
                rows.append((mutation_id, reason, int(needle in command)))
            for entry in ours:
                rows.append((self._id(entry), self.fail_reason or held, int(needle in entry[1])))
            limit = int(statement.split("LIMIT ")[1].split()[0])

            class _Oldest:
                result_rows = rows[:limit]

            return _Oldest()
        assert "position(command" in statement.split("WHERE")[1], statement
        for _t, command, reason, mutation_id in others:
            if needle in command:
                rows.append((mutation_id, reason))
        for entry in list(ours):
            if needle not in entry[1]:
                continue
            reason = self.fail_reason or held
            if reason:
                rows.append((self._id(entry), reason))
                continue
            entry[2] += 1
            if entry[2] >= self.polls:
                self.rows[table].pop(entry[1], None)
                self.pending.remove(entry)
            else:
                rows.append((self._id(entry), ""))

        class _Result:
            result_rows = rows

        return _Result()


def test_the_clickhouse_step_deletes_by_mutation_and_verifies(settings, monkeypatch):
    victim = purge_clickhouse._uuid_literal(VICTIM)  # noqa: SLF001
    neighbour = purge_clickhouse._uuid_literal(NEIGHBOUR)  # noqa: SLF001
    fake = _RecordingClickHouse(
        {
            "shapoclyack.shapoclyack_vulnerabilities": {victim: 7, neighbour: 3},
            "shapoclyack.shapoclyack_open_ports": {victim: 2, neighbour: 1},
        },
        fail_on="shapoclyack.shapoclyack_open_ports",
    )
    settings.clickhouse_url = "http://clickhouse.invalid:8123"
    monkeypatch.setattr(purge_clickhouse.clickhouse_client, "get_client", lambda url: fake)
    monkeypatch.setattr(purge_clickhouse, "POLL_SECONDS", 0)
    deletion_id = _approve(settings)

    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    step = _step(settings, deletion_id, "clickhouse")
    assert "Memory limit exceeded" in step["last_error"]
    # The first table's delete was recorded before the second failed, and the
    # second's count kept from before its ALTER — which may have reached
    # ClickHouse although the client saw an error.
    assert step["counts"] == {"vulnerabilities": 7, "open_ports_submitted": 2}

    fake.fail_on = None
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert fake.rows["shapoclyack.shapoclyack_vulnerabilities"] == {neighbour: 3}
    assert fake.rows["shapoclyack.shapoclyack_open_ports"] == {neighbour: 1}
    mutations = [s for s in fake.statements if s[0].startswith("ALTER TABLE")]
    # Submitted without waiting inside the statement; the step polls instead.
    assert all(options == {"mutations_sync": 0} for _stmt, options in mutations)
    # A literal built from a parsed UUID: nothing but hex digits reaches it.
    assert all(victim in stmt for stmt, _ in mutations)
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"] == {
        "vulnerabilities": 7,
        "open_ports": 2,
        "controls": 0,
    }


def test_an_unreachable_broker_fails_the_jetstream_step_rather_than_skipping_it(
    settings, monkeypatch
):
    settings.nats_url = "nats://127.0.0.1:1"
    monkeypatch.setattr(purge_jetstream.nats_bus, "get_bus", lambda url: None)
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    assert "could not connect" in _step(settings, deletion_id, "jetstream")["last_error"]


# --------------------------------------------------------------------------- #
# Live JetStream (ClickHouse and S3: tests/test_tenant_purge_live.py)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not NATS_URL, reason="OCTO_NATS_URL not set (live JetStream)")
def test_live_jetstream_retires_the_tenants_consumers_and_subjects(settings):
    from api.services import nats_bus

    nats_bus.reset_bus_for_tests()
    bus = nats_bus.get_bus(NATS_URL)
    assert bus is not None
    # Unique ids, so a shared broker's earlier runs cannot be counted here.
    victim = f"acme{uuid.uuid4().hex[:6]}"
    neighbour = f"{victim}-eu"
    for tenant_id in (victim, neighbour):
        tenants_service.create_tenant(name=tenant_id, tenant_id=tenant_id)
        assert bus.publish_job_offer({"job_id": f"{tenant_id}-j1", "tenant_id": tenant_id})
        assert bus.publish_job_offer(
            {"job_id": f"{tenant_id}-j2", "tenant_id": tenant_id, "agent_group": "dmz"}
        )
        assert bus.publish_ingest(
            {"tenant_id": tenant_id, "job_id": f"{tenant_id}-j1", "run_id": "r1"},
            msg_id=f"{tenant_id}-ingest-1",
        )
        assert bus.publish_asset_event(
            {"tenant_id": tenant_id, "kind": "asset_created", "event_id": f"{tenant_id}-e1"}
        )
    names = {name for name, _subjects in bus.consumers(nats_bus.STREAM_JOBS)}
    assert nats_bus.jobs_consumer_name(victim) in names
    assert nats_bus.jobs_consumer_name(victim, "dmz") in names
    # The trap: acme's "eu" group consumer and acme-eu's own consumer share a name.
    assert nats_bus.jobs_consumer_name(neighbour) in names

    settings.nats_url = NATS_URL
    deletion_id = _approve(settings, victim)
    try:
        assert _run_to_end(settings)[-1] == "completed"
        counts = _deletion(settings, deletion_id)["outcome"]["stores"]["jetstream"]
        assert counts["consumers"] == 2
        assert counts["job_offers"] == 2
        assert counts["ingest_results"] == 1
        assert counts["asset_events"] == 1
        assert counts["legacy_ingest_copies"] == 1

        for _key, stream, subject in purge_jetstream.tenant_subjects(victim):
            assert bus.subject_count(stream, subject) == 0
        for _key, stream, subject in purge_jetstream.tenant_subjects(neighbour):
            if _key in ("job_offers", "ingest_results", "asset_events"):
                assert bus.subject_count(stream, subject) >= 1, subject
        names = {name for name, _subjects in bus.consumers(nats_bus.STREAM_JOBS)}
        assert nats_bus.jobs_consumer_name(victim) not in names
        assert nats_bus.jobs_consumer_name(neighbour) in names
        assert nats_bus.jobs_consumer_name(neighbour, "dmz") in names
    finally:
        nats_bus.reset_bus_for_tests()


# --------------------------------------------------------------------------- #
# Review round 1
# --------------------------------------------------------------------------- #


def _clickhouse(settings, monkeypatch, fake) -> None:
    settings.clickhouse_url = "http://clickhouse.invalid:8123"
    monkeypatch.setattr(purge_clickhouse.clickhouse_client, "get_client", lambda url: fake)
    monkeypatch.setattr(purge_clickhouse, "POLL_SECONDS", 0)


def test_a_mutation_an_earlier_attempt_left_running_is_waited_for_not_submitted_again(
    settings, monkeypatch
):
    """The client's read timeout ended the last attempt; ClickHouse did not stop.
    The retry must wait for that mutation, not stack a second one beside it."""
    victim = purge_clickhouse._uuid_literal(VICTIM)  # noqa: SLF001
    table = "shapoclyack.shapoclyack_vulnerabilities"
    fake = _RecordingClickHouse({table: {victim: 5}}, polls=3)
    fake.pending.append([table, victim, 0])
    renewals = {"n": 0}
    real_renew = PurgeContext.renew

    def counting(self, session):
        if self.step == "clickhouse":
            renewals["n"] += 1
        return real_renew(self, session)

    monkeypatch.setattr(PurgeContext, "renew", counting)
    _clickhouse(settings, monkeypatch, fake)
    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    assert not [stmt for stmt, _ in fake.statements if stmt.startswith("ALTER TABLE")]
    assert fake.rows[table] == {}
    # Polled until done, the lease renewed between polls.
    polls = [stmt for stmt, _ in fake.statements if "system.mutations" in stmt]
    assert len(polls) >= 3
    assert renewals["n"] >= 3
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"]["vulnerabilities"] == 5


def test_a_failing_mutation_fails_the_step_with_clickhouses_own_reason(settings, monkeypatch):
    victim = purge_clickhouse._uuid_literal(VICTIM)  # noqa: SLF001
    table = "shapoclyack.shapoclyack_vulnerabilities"
    fake = _RecordingClickHouse({table: {victim: 5}})
    fake.fail_reason = "Code: 241. Memory limit (total) exceeded"
    _clickhouse(settings, monkeypatch, fake)
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    step = _step(settings, deletion_id, "clickhouse")
    assert "Memory limit (total) exceeded" in step["last_error"]
    assert "KILL MUTATION" in step["last_error"]
    # Retried: waited for, never submitted a second time.
    fake.fail_reason = ""
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert len([stmt for stmt, _ in fake.statements if stmt.startswith("ALTER TABLE")]) == 1


@pytest.mark.parametrize("step", ["clickhouse", "jetstream"])
def test_a_store_this_replica_does_not_know_fails_its_step_rather_than_skip_it(
    settings, step
):
    """Skipped only on the installation's word: a replica whose configuration
    drifted must not record another replica's store as holding nothing.
    (Approved where the configuration was whole: a replica like this one
    refuses the approval itself — tests/test_tenant_lifecycle.py.)"""
    deletion_id = _approve(settings)
    settings.tenant_purge_unused_stores = tuple(
        store for store in ("clickhouse", "jetstream") if store != step
    )
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    failed = _step(settings, deletion_id, step)
    assert failed["state"] == "failed"
    assert "OCTO_TENANT_PURGE_UNUSED_STORES" in failed["last_error"]
    settings.tenant_purge_unused_stores = ("clickhouse", "jetstream")
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    skipped = _deletion(settings, deletion_id)["outcome"]["skipped"]
    assert "declared unused" in skipped[step]


def test_a_long_flat_run_scan_keeps_its_lease(settings, monkeypatch):
    """Every flat run's marker is a store request; the scan renews the lease
    as it goes, or another replica takes the step over and starts again."""
    store = artifact_store.get_store(settings)
    for index in range(250):
        flat = keys.run_ref(f"legacy-other-{index:04d}")
        _write(store, keys.run_artifact(flat, "tenant.json"), b'{"tenant_id": "someone-else"}')
    renewals = {"n": 0, "scanning": False}
    real_renew = PurgeContext.renew
    real_scan = purge_artifacts._flat_runs  # noqa: SLF001

    def counting(self, session):
        if renewals["scanning"]:
            renewals["n"] += 1
        return real_renew(self, session)

    def scanning(ctx, store):
        renewals["scanning"] = True
        try:
            return real_scan(ctx, store)
        finally:
            renewals["scanning"] = False

    monkeypatch.setattr(PurgeContext, "renew", counting)
    monkeypatch.setattr(purge_artifacts, "_flat_runs", scanning)
    _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    # None of the 250 is the tenant's, so every renewal here is the scan's own:
    # one per hundred markers read.
    assert renewals["n"] >= 2, renewals


def test_a_store_that_fails_to_answer_is_not_an_unreadable_marker(settings, monkeypatch):
    store = artifact_store.get_store(settings)
    flat = keys.run_ref("legacy-throttled")
    _write(store, keys.run_artifact(flat, "tenant.json"), b'{"tenant_id": "someone-else"}')
    real_get = store.get_bytes

    def throttled(key):
        if key.endswith("legacy-throttled/tenant.json"):
            raise artifact_store.ArtifactStoreError("SlowDown: reduce your request rate")
        return real_get(key)

    monkeypatch.setattr(store, "get_bytes", throttled)
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    error = _step(settings, deletion_id, "artifacts")["last_error"]
    assert "SlowDown" in error
    assert "cannot be read" not in error


def test_rows_written_late_send_every_store_round_again(settings, monkeypatch):
    """The writer of a late row may have left objects and subjects too."""
    deletion_id = _approve(settings)
    real_finalize = purge_postgres.finalize
    state = {"late": False}

    def finalize_after_a_late_write(ctx):
        if not state["late"]:
            state["late"] = True
            with get_session(settings.postgres_url) as session:
                session.add(
                    models.RiskScoreSnapshot(snapshot_id="late-2", tenant_id=VICTIM, recorded_at=_NOW)
                )
        return real_finalize(ctx)

    monkeypatch.setitem(tenant_purge.STEP_FUNCTIONS, "finalize", finalize_after_a_late_write)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    for name in ("quiesce", "outbox", "jetstream", "artifacts", "clickhouse", "postgres"):
        assert _step(settings, deletion_id, name)["state"] == "pending", name


def test_a_report_key_that_is_not_there_is_not_counted(settings, tmp_path):
    """On a bucket, where a batch delete counts every key it was handed."""
    settings.artifact_backend = "s3"
    settings.artifact_s3_bucket = "artifacts"
    settings.artifact_cache_dir = str(tmp_path / "cache")
    store = artifact_store.get_store(settings)
    store._client = FakeS3Client()  # noqa: SLF001 - the seam the lazy client exists for
    with get_session(settings.postgres_url) as session:
        session.add(
            models.GeneratedReport(
                report_id="rpt_0000000000000009",
                tenant_id=VICTIM,
                kind="executive",
                fmt="pdf",
                status="ready",
                title="",
                size_bytes=1,
                delivery=[],
                generated_at=_NOW,
                storage_path="reports/elsewhere/rpt_0000000000000009.pdf",
            )
        )
    assert not store.exists("reports/elsewhere/rpt_0000000000000009.pdf")
    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["artifacts"]["report_objects"] == 0


def test_a_replica_that_loses_its_lease_mid_batch_does_not_count_what_it_removed(
    settings, monkeypatch
):
    """Counts go through the lease check: the loser's bookkeeping fails, so the
    new owner's count is the only one — nothing is counted twice."""
    _seed_runs(settings)
    deletion_id = _approve(settings)
    store = artifact_store.get_store(settings)
    real_delete = store.delete_prefix

    def delete_then_lose_the_lease(prefix):
        removed = real_delete(prefix)
        with get_session(settings.postgres_url) as session:
            session.execute(
                update(models.TenantDeletion)
                .where(models.TenantDeletion.deletion_id == deletion_id)
                .values(lease_owner="replica-2")
            )
        return removed

    monkeypatch.setattr(store, "delete_prefix", delete_then_lose_the_lease)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "lease_lost"
    assert _step(settings, deletion_id, "artifacts")["counts"] == {}


# --------------------------------------------------------------------------- #
# Review round 2
# --------------------------------------------------------------------------- #


def test_another_tenants_unfinished_mutation_is_neither_waited_for_nor_resubmitted_around(
    settings, monkeypatch
):
    """Only the tenant's own mutations count as "an earlier attempt's": a
    neighbour's long ``UPDATE`` on the same table is not one to wait for
    instead of submitting the delete."""
    victim = purge_clickhouse._uuid_literal(VICTIM)  # noqa: SLF001
    neighbour = purge_clickhouse._uuid_literal(NEIGHBOUR)  # noqa: SLF001
    table = "shapoclyack.shapoclyack_vulnerabilities"
    fake = _RecordingClickHouse({table: {victim: 5, neighbour: 3}})
    fake.others.append(
        [table, f"UPDATE protocol = 'udp' WHERE tenant_id = {neighbour}", "", "mutation_7.txt"]
    )
    _clickhouse(settings, monkeypatch, fake)
    # Waiting on the neighbour's mutation would fail the attempt at once.
    monkeypatch.setattr(purge_clickhouse, "MAX_WAIT_SECONDS", 0)
    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    alters = [stmt for stmt, _ in fake.statements if stmt.startswith("ALTER TABLE")]
    assert alters == [f"ALTER TABLE {table} DELETE WHERE tenant_id = {victim}"]
    assert fake.rows[table] == {neighbour: 3}
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"]["vulnerabilities"] == 5


def test_a_failing_mutation_of_another_tenant_is_named_as_what_holds_the_purge(
    settings, monkeypatch
):
    """ClickHouse 24.8 applies a table's mutations in order: a neighbour's
    failing ``UPDATE`` holds the tenant's ``DELETE`` behind it, and the delete
    then reports the neighbour's reason as its own. The step names the one to
    deal with — killing the tenant's own mutation would only have it submitted
    again behind the same wall."""
    victim = purge_clickhouse._uuid_literal(VICTIM)  # noqa: SLF001
    neighbour = purge_clickhouse._uuid_literal(NEIGHBOUR)  # noqa: SLF001
    table = "shapoclyack.shapoclyack_open_ports"
    fake = _RecordingClickHouse({table: {victim: 2, neighbour: 1}})
    # ClickHouse 24.8's own words, which quote the neighbour's expression.
    reason = (
        "Code: 395. DB::Exception: Value passed to 'throwIf' function is non-zero: "
        f"while executing 'FUNCTION if(equals(tenant_id, {neighbour}), "
        "_CAST(toString(throwIf(1)), 'LowCardinality(String)'), protocol)'. "
        "(FUNCTION_THROW_IF_VALUE_IS_NON_ZERO) (version 24.8.14.39 (official build))"
    )
    fake.others.append(
        [
            table,
            f"UPDATE protocol = toString(throwIf(1)) WHERE tenant_id = {neighbour}",
            reason,
            "mutation_25.txt",
        ]
    )
    _clickhouse(settings, monkeypatch, fake)
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    error = _step(settings, deletion_id, "clickhouse")["last_error"]
    assert "mutation_25.txt" in error and "not this tenant's" in error
    assert "mutation_id = 'mutation_25.txt'" in error
    assert "Code: 395, FUNCTION_THROW_IF_VALUE_IS_NON_ZERO" in error
    # Nothing tells the operator to kill the tenant's own, blocked mutation.
    assert "gives up on it" not in error
    # Not the neighbour's command or expression: the journal is no place for
    # its values, and ClickHouse's reason quotes them.
    assert "throwIf(1)" not in error
    assert purge_clickhouse._tenant_uuid(NEIGHBOUR) not in error  # noqa: SLF001

    fake.others.clear()
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert len([stmt for stmt, _ in fake.statements if stmt.startswith("ALTER TABLE")]) == 1
    assert fake.rows[table] == {neighbour: 1}
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"]["open_ports"] == 2


def test_rows_a_mutation_removed_between_two_attempts_are_still_counted(settings, monkeypatch):
    """The count is taken before the ``ALTER`` and kept with the step: the
    attempt that sees the mutation finished counts nothing left to remove."""
    victim = purge_clickhouse._uuid_literal(VICTIM)  # noqa: SLF001
    table = "shapoclyack.shapoclyack_vulnerabilities"
    fake = _RecordingClickHouse({table: {victim: 5}}, polls=100)
    _clickhouse(settings, monkeypatch, fake)
    monkeypatch.setattr(purge_clickhouse, "MAX_WAIT_SECONDS", 0)
    deletion_id = _approve(settings)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    assert "still running" in _step(settings, deletion_id, "clickhouse")["last_error"]

    # ClickHouse finishes it while the step waits for its backoff.
    fake.pending.clear()
    fake.rows[table].pop(victim)
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert len([stmt for stmt, _ in fake.statements if stmt.startswith("ALTER TABLE")]) == 1
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"] == {
        "vulnerabilities": 5,
        "open_ports": 0,
        "controls": 0,
    }


def test_a_step_that_returns_after_losing_its_lease_is_not_recorded_as_done(
    settings, monkeypatch
):
    """A step can finish without another checkpoint after its lease went to a
    second replica; the bookkeeping is the new owner's, not the loser's."""
    deletion_id = _approve(settings)

    def returns_after_the_lease_went(ctx):
        with get_session(settings.postgres_url) as session:
            session.execute(
                update(models.TenantDeletion)
                .where(models.TenantDeletion.deletion_id == deletion_id)
                .values(lease_owner="replica-2")
            )
        return {"jobs_cancelled": 1}

    monkeypatch.setitem(tenant_purge.STEP_FUNCTIONS, "quiesce", returns_after_the_lease_went)
    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "lease_lost"
    step = _step(settings, deletion_id, "quiesce")
    assert step["state"] == "running"
    assert step["counts"] == {}


@pytest.mark.skipif(not NATS_URL, reason="OCTO_NATS_URL not set (live JetStream)")
def test_live_a_legacy_copy_that_names_another_tenant_is_left_where_it_is(settings):
    """The copy is found by its message id alone; its ``tenant_id`` header is
    what says whose it is, and a copy naming the neighbour is not the victim's
    to delete — whatever its id."""
    from api.services import nats_bus

    nats_bus.reset_bus_for_tests()
    bus = nats_bus.get_bus(NATS_URL)
    assert bus is not None
    victim = f"acme{uuid.uuid4().hex[:6]}"
    neighbour = f"{victim}-eu"
    for tenant_id in (victim, neighbour):
        tenants_service.create_tenant(name=tenant_id, tenant_id=tenant_id)
    msg_id = f"{victim}-ingest-1"
    assert bus.publish_json(
        nats_bus.ingest_results_subject(victim),
        {"tenant_id": victim, "run_id": "r1"},
        msg_id=msg_id,
        headers={"tenant_id": victim},
    )
    assert bus.publish_json(
        nats_bus.SUBJECT_INGEST_RAW,
        {"tenant_id": neighbour, "run_id": "r1"},
        msg_id=f"{msg_id}-legacy",
        headers={"tenant_id": neighbour},
    )

    def legacy_copies() -> list[str]:
        found, seq = [], 1
        while (message := bus.next_message(nats_bus.STREAM_INGEST, nats_bus.SUBJECT_INGEST_RAW, seq)):
            seq = int(message.seq) + 1
            if dict(message.headers or {}).get("Nats-Msg-Id") == f"{msg_id}-legacy":
                found.append(dict(message.headers or {}).get("tenant_id"))
        return found

    assert legacy_copies() == [neighbour]
    settings.nats_url = NATS_URL
    deletion_id = _approve(settings, victim)
    try:
        assert _run_to_end(settings)[-1] == "completed"
        counts = _deletion(settings, deletion_id)["outcome"]["stores"]["jetstream"]
        assert counts["ingest_results"] == 1
        assert counts["legacy_ingest_copies"] == 0
        assert legacy_copies() == [neighbour]
    finally:
        nats_bus.reset_bus_for_tests()
