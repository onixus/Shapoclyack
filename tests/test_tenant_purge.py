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
live runs against ClickHouse 24.8, an S3 gateway and JetStream are at the end,
each gated on its own environment variable.
"""

from __future__ import annotations

import json
import os
import uuid
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
    s = make_settings(
        tmp_path,
        tenant_deletion_grace_days=0,
        tenant_deletion_two_person=False,
        # Small, so every table's purge is more than one batch and a failure
        # can be injected between two of them.
        tenant_purge_batch_size=1,
        tenant_purge_interval_seconds=5,
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
    """Answers the four statements the step issues, over an in-memory table."""

    def __init__(self, rows: dict[str, dict[str, int]], *, fail_on: str | None = None) -> None:
        self.rows = rows  # table -> {uuid literal: count}
        self.fail_on = fail_on
        self.crash_on: str | None = None
        self.statements: list[tuple[str, dict | None]] = []

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
            self.rows[table].pop(key, None)
            return None
        key = statement.split("tenant_id = ")[1]
        return self.rows.get(table, {}).get(key, 0)


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
    deletion_id = _approve(settings)

    assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
    step = _step(settings, deletion_id, "clickhouse")
    assert "Memory limit exceeded" in step["last_error"]
    # The first table's delete was recorded before the second failed.
    assert step["counts"] == {"vulnerabilities": 7}

    fake.fail_on = None
    _make_due(settings, deletion_id)
    assert _run_to_end(settings)[-1] == "completed"
    assert fake.rows["shapoclyack.shapoclyack_vulnerabilities"] == {neighbour: 3}
    assert fake.rows["shapoclyack.shapoclyack_open_ports"] == {neighbour: 1}
    mutations = [s for s in fake.statements if s[0].startswith("ALTER TABLE")]
    assert all(options == {"mutations_sync": 2} for _stmt, options in mutations)
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
# Live stores, each gated on its own variable
# --------------------------------------------------------------------------- #

CLICKHOUSE_URL = os.environ.get("OCTO_TEST_CLICKHOUSE_URL", "").strip()
S3_ENDPOINT = os.environ.get("OCTO_TEST_S3_ENDPOINT", "").strip()


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


@pytest.mark.skipif(not CLICKHOUSE_URL, reason="OCTO_TEST_CLICKHOUSE_URL not set (live ClickHouse)")
def test_live_clickhouse_mutation_removes_the_tenant_and_only_the_tenant(settings):
    from api.services import ch_transform, clickhouse_client

    # The schema a fresh installation boots with: the compose/k8s init script.
    setup = clickhouse_client.get_client(CLICKHOUSE_URL, database="default")
    init = Path(__file__).resolve().parents[1] / "k8s/shapoclyack/base/clickhouse/init-local.sql"
    for statement in init.read_text(encoding="utf-8").split(";"):
        body = "\n".join(
            line for line in statement.splitlines() if not line.strip().startswith("--")
        ).strip()
        if body:
            setup.command(body)
    client = clickhouse_client.get_client(CLICKHOUSE_URL)
    stamp = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    for tenant_id, rows in ((VICTIM, 3), (NEIGHBOUR, 2)):
        clickhouse_client.insert_rows(
            client,
            clickhouse_client.PORTS_TABLE,
            clickhouse_client.PORT_COLUMNS,
            [
                [ch_transform.tenant_to_uuid(tenant_id), f"10.0.0.{i}", 80 + i, "tcp", "r", stamp]
                for i in range(rows)
            ],
        )
    settings.clickhouse_url = CLICKHOUSE_URL
    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"

    def count(tenant_id: str) -> int:
        return int(
            client.command(
                f"SELECT count() FROM {clickhouse_client.PORTS_TABLE} "
                f"WHERE tenant_id = {purge_clickhouse._uuid_literal(tenant_id)}"  # noqa: SLF001
            )
        )

    assert count(VICTIM) == 0
    assert count(NEIGHBOUR) == 2
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"]["open_ports"] == 3
    client.command(f"TRUNCATE TABLE {clickhouse_client.PORTS_TABLE}")


@pytest.mark.skipif(not S3_ENDPOINT, reason="OCTO_TEST_S3_ENDPOINT not set (live S3 gateway)")
def test_live_object_storage_purge_against_an_s3_gateway(settings, tmp_path):
    import boto3

    bucket = f"purge-{uuid.uuid4().hex[:8]}"
    boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    ).create_bucket(Bucket=bucket)
    settings.artifact_backend = "s3"
    settings.artifact_s3_bucket = bucket
    settings.artifact_s3_endpoint_url = S3_ENDPOINT
    settings.artifact_s3_region = "us-east-1"
    settings.artifact_s3_access_key_id = "test"
    settings.artifact_s3_secret_access_key = "test"
    settings.artifact_s3_addressing_style = "path"
    settings.artifact_cache_dir = str(tmp_path / "cache")
    counts = _purge_artifacts(settings)
    store = artifact_store.get_store(settings)
    assert _run_keys(store, VICTIM) == []
    assert len(_run_keys(store, NEIGHBOUR)) == 6
    assert counts["run_objects"] == 2 and counts["report_objects"] == 1
