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

from api.settings import Settings

_log = logging.getLogger(__name__)
_lock = threading.Lock()
_engine: Engine | None = None
_engine_url: str | None = None
_SessionLocal: sessionmaker[Session] | None = None
_pool_options: dict[str, int] | None = None


def configure(settings: Settings) -> None:
    """Pin the connection-pool sizing for engines built after this call (#335).

    Same shape as the ``configure(settings)`` the services use, and called from
    ``create_app()`` *before* the tenant store opens the first session — the
    engine is a lazy singleton keyed by URL, so options that arrive after it
    exists would apply to nobody. Changing them therefore disposes the cached
    engine rather than being silently ignored; in practice that only happens in
    tests, since a process reads its configuration once.

    Left unconfigured (tools, most of the test suite) the engine keeps
    SQLAlchemy's own defaults, which is what it did before this existed.
    """
    global _pool_options, _engine, _engine_url, _SessionLocal
    options = {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout,
    }
    with _lock:
        if options == _pool_options:
            return
        _pool_options = options
        if _engine is not None:
            _engine.dispose()
            _engine = None
            _engine_url = None
            _SessionLocal = None


def _pool_kwargs(url: str) -> dict[str, int]:
    """Pool sizing, but only where there is a queue to size.

    The SQLite fallback is a single file opened by one process (#174 refuses it
    in prod); SQLAlchemy gives it a pool class that takes neither ``pool_size``
    nor ``max_overflow``, so passing them there is a TypeError at engine
    construction rather than a tuning knob.
    """
    if _pool_options is None or url.startswith("sqlite"):
        return {}
    return dict(_pool_options)


def get_engine(url: str) -> Engine:
    global _engine, _engine_url, _SessionLocal
    with _lock:
        if _engine is None or _engine_url != url:
            if _engine is not None:
                _engine.dispose()
            _engine = create_engine(url, pool_pre_ping=True, future=True, **_pool_kwargs(url))
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
        lowered = literal.strip().lower()
        if lowered in ("true", "false"):
            # The models write ``server_default="false"`` for Boolean columns.
            # Quoting that would store the *text* 'false', which is truthy to
            # SQLAlchemy's Boolean processor; SQLite has no boolean type, so
            # the honest literal is the integer.
            literal = "1" if lowered == "true" else "0"
        elif not literal.startswith("'") and not literal.replace(".", "", 1).lstrip("-").isdigit():
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
    global _engine, _engine_url, _SessionLocal, _pool_options
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _engine_url = None
        _SessionLocal = None
        # Also drop the pool sizing: a test that configured a deliberately tiny
        # pool must not leave it for the rest of the session.
        _pool_options = None
