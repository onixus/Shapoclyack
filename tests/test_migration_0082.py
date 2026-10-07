"""Caller-owned idempotency across upgrade, rollback and a 0.46 rollout."""

from __future__ import annotations

import importlib.util
import hashlib
import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from api.db import migrate
from api.services import idempotency
from tests.conftest import POSTGRES_URL, make_settings, requires_postgres

pytestmark = requires_postgres
BEFORE = "0081_endpoint_release_variants"
REVISION = "0082_idempotency_actor_contract"


@pytest.fixture
def database(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = f"mig0082_{uuid.uuid4().hex[:10]}"
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
        # created_at is UTC without timezone; do not compare it to local time.
        conn.execute(
            text(f"ALTER DATABASE \"{name}\" SET timezone TO 'Europe/Istanbul'")
        )
    url = (
        make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    )
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    engine = create_engine(url)
    try:
        migrate._upgrade(BEFORE)  # noqa: SLF001
        yield engine, url
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def _seed(engine, *, key, actor=None, age_hours=0, response=None):
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO idempotency_records "
                "(tenant_id, endpoint, key, actor, request_digest, response, created_at) "
                "VALUES ('default', 'vulnerabilities.bulk', :key, :actor, 'digest', "
                "CAST(:response AS json), (clock_timestamp() AT TIME ZONE 'UTC') "
                "- make_interval(hours => :hours))"
            ),
            {"key": key, "actor": actor, "hours": age_hours, "response": response},
        )


def _snapshot(engine):
    with engine.connect() as conn:
        return [
            tuple(row)
            for row in conn.execute(
                text(
                    "SELECT id, tenant_id, endpoint, key, actor, request_digest, "
                    "response::text, created_at FROM idempotency_records ORDER BY id"
                )
            )
        ]


def _schema(engine):
    actor = next(
        c
        for c in inspect(engine).get_columns("idempotency_records")
        if c["name"] == "actor"
    )
    indexes = {i["name"] for i in inspect(engine).get_indexes("idempotency_records")}
    with engine.connect() as conn:
        trigger = conn.execute(
            text(
                "SELECT 1 FROM pg_trigger WHERE tgname = 'idempotency_records_cross_generation'"
            )
        ).first()
        function = conn.execute(
            text("SELECT to_regprocedure('idempotency_cross_generation()')")
        ).scalar()
        revision = conn.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
    return actor["nullable"], indexes, bool(trigger), bool(function), revision


def test_expired_unowned_rows_are_removed_and_owned_rows_are_preserved(database):
    engine, _ = database
    _seed(engine, key="legacy-completed", age_hours=25, response='{"succeeded":2}')
    _seed(engine, key="legacy-pending", age_hours=25)
    _seed(
        engine, key="owned-old", actor="alice", age_hours=25, response='{"succeeded":1}'
    )
    _seed(engine, key="owned-pending", actor="bob")
    owned = _snapshot(engine)[2:]
    migrate._upgrade(REVISION)  # noqa: SLF001
    assert _snapshot(engine) == owned
    nullable, indexes, trigger, function, revision = _schema(engine)
    assert not nullable and not trigger and not function
    assert revision == REVISION
    assert "uq_idempotency_legacy_tenant_endpoint_key" not in indexes
    assert "uq_idempotency_tenant_endpoint_actor_key" in indexes
    assert "ix_idempotency_created_at" in indexes
    # Unowned inserts fail even for a key no other caller holds.
    with pytest.raises(IntegrityError) as failure:
        _seed(engine, key="fresh-null")
    assert failure.value.orig.sqlstate == "23502"
    _seed(engine, key="same-key", actor="alice")
    _seed(engine, key="same-key", actor="bob")
    with pytest.raises(IntegrityError) as failure:
        _seed(engine, key="same-key", actor="alice")
    assert failure.value.orig.sqlstate == "23505"


@pytest.mark.parametrize("response", [None, '{"succeeded":2}'])
def test_live_unowned_record_refuses_upgrade_without_changing_anything(
    database, response
):
    engine, _ = database
    _seed(engine, key="expired", age_hours=25)
    _seed(engine, key="live", age_hours=23, response=response)
    _seed(engine, key="owned", actor="alice")
    before, schema = _snapshot(engine), _schema(engine)
    with pytest.raises(RuntimeError, match="unexpired.*without actor"):
        migrate._upgrade(REVISION)  # noqa: SLF001
    assert _snapshot(engine) == before
    assert _schema(engine) == schema
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE idempotency_records SET created_at = created_at - interval '2 hours' "
                "WHERE actor IS NULL"
            )
        )
    migrate._upgrade(REVISION)  # noqa: SLF001
    assert [row[3] for row in _snapshot(engine)] == ["owned"]


def test_downgrade_restores_the_expand_guard_without_losing_owned_answers(database):
    engine, _ = database
    _seed(engine, key="shared", actor="alice", response='{"succeeded":1}')
    _seed(engine, key="shared", actor="bob", response='{"succeeded":2}')
    before = _snapshot(engine)
    migrate._upgrade(REVISION)  # noqa: SLF001
    migrate._downgrade(BEFORE)  # noqa: SLF001
    assert _snapshot(engine) == before
    nullable, indexes, trigger, function, revision = _schema(engine)
    assert nullable and trigger and function and revision == BEFORE
    assert "uq_idempotency_legacy_tenant_endpoint_key" in indexes
    with pytest.raises(IntegrityError) as failure:
        _seed(engine, key="shared")
    assert failure.value.orig.sqlstate == "23505"
    _seed(engine, key="legacy-only", age_hours=25)
    with pytest.raises(IntegrityError):
        _seed(engine, key="legacy-only", actor="alice")
    migrate._upgrade(REVISION)  # noqa: SLF001
    assert _snapshot(engine) == before


def _release_046():
    # Frozen verbatim service from the published tag, not a rewritten mock.
    path = Path(__file__).parent / "fixtures" / "idempotency_046.py"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "5ba68d7a07c28845d819edbbc1ae0e07a6fc4c205e6482a8872bd9c475b0fa04"
    )
    spec = importlib.util.spec_from_file_location("release_046_idempotency", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("contender", [False, True])
def test_a_released_conflict_must_be_reserved_again(database, tmp_path, monkeypatch, contender):
    _, url = database
    settings = make_settings(tmp_path, postgres_url=url)
    common = {
        "tenant_id": "default", "actor": "alice", "endpoint": "vulnerabilities.bulk",
        "key": "released-conflict",
    }
    assert idempotency.reserve(settings, **common, request_digest="digest") is None
    lookup = idempotency._row_for  # noqa: SLF001
    released = False

    def release_between_conflict_and_read(session, **identity):
        nonlocal released
        if not released and identity["actor"] == "alice":
            released = True
            idempotency.release(settings, **common)
            row = lookup(session, **identity)
            assert row is None
            if contender:
                # A third replica gets the gap immediately after our read.
                assert idempotency.reserve(settings, **common, request_digest="digest") is None
            return row
        return lookup(session, **identity)

    monkeypatch.setattr(idempotency, "_row_for", release_between_conflict_and_read)
    if contender:
        with pytest.raises(idempotency.IdempotencyInFlight):
            idempotency.reserve(settings, **common, request_digest="digest")
    else:
        assert idempotency.reserve(settings, **common, request_digest="digest") is None
        # Success is permission to execute only with a reservation in place.
        idempotency.complete(settings, **common, response={"succeeded": 1})
        assert idempotency.reserve(settings, **common, request_digest="digest") == {"succeeded": 1}


def test_046_and_new_replicas_replay_complete_release_and_contend(database, tmp_path):
    engine, url = database
    old = _release_046()
    settings = make_settings(tmp_path, postgres_url=url)
    common = {
        "tenant_id": "default",
        "actor": "alice",
        "endpoint": "vulnerabilities.bulk",
    }
    # A real 0.46 reservation survives the contract unchanged.
    assert (
        old.reserve(settings, **common, key="before-upgrade", request_digest="digest")
        is None
    )
    before = _snapshot(engine)
    migrate._upgrade(REVISION)  # noqa: SLF001
    assert _snapshot(engine) == before
    old.complete(settings, **common, key="before-upgrade", response={"succeeded": 1})
    assert idempotency.reserve(
        settings, **common, key="before-upgrade", request_digest="digest"
    ) == {"succeeded": 1}
    for writer, reader in ((old, idempotency), (idempotency, old)):
        key = f"rolling-{writer.__name__}"
        assert (
            writer.reserve(settings, **common, key=key, request_digest="digest") is None
        )
        with pytest.raises(reader.IdempotencyInFlight):
            reader.reserve(settings, **common, key=key, request_digest="digest")
        writer.complete(settings, **common, key=key, response={"succeeded": 2})
        assert reader.reserve(settings, **common, key=key, request_digest="digest") == {
            "succeeded": 2
        }
        with pytest.raises(reader.IdempotencyMismatch):
            reader.reserve(settings, **common, key=key, request_digest="different")
        # Releasing a completed record cannot erase its replay.
        writer.release(settings, **common, key=key)
        assert reader.reserve(settings, **common, key=key, request_digest="digest") == {
            "succeeded": 2
        }
        assert (
            reader.reserve(
                settings, **{**common, "actor": "bob"}, key=key, request_digest="digest"
            )
            is None
        )
        reader.release(settings, **{**common, "actor": "bob"}, key=key)
        assert (
            writer.reserve(
                settings, **{**common, "actor": "bob"}, key=key, request_digest="digest"
            )
            is None
        )

    barrier = threading.Barrier(2)
    outcomes = []

    def claim(module):
        try:
            barrier.wait(timeout=10)
            result = module.reserve(
                settings, **common, key="race", request_digest="digest"
            )
            outcomes.append("winner" if result is None else result)
        except module.IdempotencyInFlight:
            outcomes.append("in-flight")
        except Exception as exc:
            outcomes.append(exc)

    threads = [
        threading.Thread(target=claim, args=(module,)) for module in (old, idempotency)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    assert sorted(outcomes, key=str) == ["in-flight", "winner"], outcomes
