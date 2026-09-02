"""Lazy singleton SQLAlchemy engine/session, keyed by settings.postgres_url.

Mirrors api/services/clickhouse_client.py's lazy-singleton-by-url pattern.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Column, Engine, MetaData, create_engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

_log = logging.getLogger(__name__)
_lock = threading.Lock()
_engine: Engine | None = None
_engine_url: str | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine(url: str) -> Engine:
    global _engine, _engine_url, _SessionLocal
    with _lock:
        if _engine is None or _engine_url != url:
            if _engine is not None:
                _engine.dispose()
            _engine = create_engine(url, pool_pre_ping=True, future=True)
            _engine_url = url
            _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
            _create_schema_if_unmanaged(_engine)
        return _engine


def get_session_factory(url: str) -> sessionmaker[Session]:
    """Return a sessionmaker factory configured for ``url``."""
    get_engine(url)
    assert _SessionLocal is not None
    return _SessionLocal


def _create_schema_if_unmanaged(engine: Engine) -> None:
    """Create tables from the models — **only** where Alembic does not run (#159).

    Two ways of bringing a database to the right shape means the two disagree
    eventually, and the disagreement is discovered in production: ``create_all``
    builds today's models and knows nothing of the ``alembic_version`` row, so a
    Postgres database it touched looks migrated to no revision at all while
    carrying columns a migration was supposed to add. It also silently papers
    over the case this is meant to catch — an API replica started against a
    database nobody migrated.

    SQLite is the exception rather than a second path: it is the dev and
    test-suite fallback (#174 refuses it in prod), it cannot be shared between
    replicas, and requiring a migration run before ``pytest`` would buy nothing.
    """
    if engine.dialect.name != "sqlite":
        return
    from api.db import models

    models.Base.metadata.create_all(engine)
    _add_missing_sqlite_columns(engine, models.Base.metadata)


def _add_missing_sqlite_columns(engine: Engine, metadata: MetaData) -> None:
    """Bring an existing SQLite file up to today's models, column by column.

    ``create_all`` creates tables that are absent and leaves existing ones
    alone, so a dev database created before a model grew a column keeps its
    old shape and the first query that names the new column fails with
    ``no such column``. Postgres has Alembic for this; the SQLite fallback
    has nothing, and "delete your dev database" is not a migration path
    anyone documents. This adds each missing column with ``ALTER TABLE …
    ADD COLUMN``, which SQLite supports for the additive case that a
    model change on ``main`` almost always is. It never drops, renames or
    retypes anything: a column the models no longer know about is left
    where it is.

    A NOT NULL column without a server default cannot be added to a table
    that already has rows, so it is added nullable; the models fill it on
    every insert, and a pre-existing row with NULL there is the honest
    state of data written before the column existed.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        present = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            spec = _sqlite_add_column_spec(engine, column)
            with engine.begin() as conn:
                conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" ADD COLUMN {spec}'
                )
            _log.info("sqlite: added missing column %s.%s", table.name, column.name)


def _sqlite_add_column_spec(engine: Engine, column: Column) -> str:
    type_sql = column.type.compile(dialect=engine.dialect)
    spec = f'"{column.name}" {type_sql}'
    default = column.server_default
    if default is not None and getattr(default, "arg", None) is not None:
        arg = default.arg
        literal = arg.text if hasattr(arg, "text") else str(arg)
        if not literal.startswith("'") and not literal.replace(".", "", 1).lstrip("-").isdigit():
            literal = "'" + literal.replace("'", "''") + "'"
        spec += f" DEFAULT {literal}"
        if not column.nullable:
            spec += " NOT NULL"
    return spec


@contextmanager
def get_session(url: str) -> Iterator[Session]:
    get_engine(url)
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def insert_if_absent(session: Session, row: object, key: str) -> bool:
    """Add ``row``, tolerating another writer inserting the same key first.

    Used by the P1.2 startup imports of the pre-Postgres JSON state files.
    Those run inside ``create_app()`` in *every* replica at once, so a
    check-then-insert can lose the race: without a SAVEPOINT the resulting
    IntegrityError would abort the whole transaction and take API startup down
    with it, on every restart. Scoping the failure to the one row makes losing
    the race a no-op — the row the winner inserted is the same row.

    Returns True when this session inserted it.
    """
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        _log.debug("Row %s already inserted by another writer; skipping", key)
        return False
    return True


def reset_for_tests() -> None:
    """Dispose the cached engine so a new URL (or a fresh test DB) takes effect."""
    global _engine, _engine_url, _SessionLocal
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _engine_url = None
        _SessionLocal = None
