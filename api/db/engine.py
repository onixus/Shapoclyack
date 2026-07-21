"""Lazy singleton SQLAlchemy engine/session, keyed by settings.postgres_url.

Mirrors api/services/clickhouse_client.py's lazy-singleton-by-url pattern.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

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
        return _engine


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


def reset_for_tests() -> None:
    """Dispose the cached engine so a new URL (or a fresh test DB) takes effect."""
    global _engine, _engine_url, _SessionLocal
    with _lock:
        if _engine is not None:
            _engine.dispose()
        _engine = None
        _engine_url = None
        _SessionLocal = None
