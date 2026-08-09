"""Postgres advisory-lock leader election for singleton workers (ROADMAP P1.6).

Some background work is safe to run in every API replica and some is not. The
job reaper is safe — expiry is a property of the row and its sweep takes
candidates with ``FOR UPDATE SKIP LOCKED``, so concurrent reapers divide the
work. The schedule dispatcher is not: every replica wakes for the same due
schedule and writes the same bookkeeping.

A **session-scoped advisory lock** is the right primitive for that, rather than
a leader row with a heartbeat and a lease. The lock lives in the connection: if
the leader crashes, is OOM-killed, or is severed by a network partition, its
backend ends and Postgres drops the lock — no expiry to wait out and no lease
duration to tune wrong. A follower's very next attempt succeeds.

Two consequences worth knowing before using this:

- It holds one connection out of the pool for the process's lifetime. That is
  the price of a session-scoped lock; a transaction-scoped one
  (``pg_advisory_xact_lock``) would release at commit and elect a new leader on
  every tick.
- It is *not* fencing. Between the leader's backend dying and the leader's own
  process noticing, a new leader can exist while the old one still believes it
  leads. Callers must therefore stay idempotent under a brief double-run — the
  dispatcher is, via P1.5 idempotency keys. Do not use this to guard something
  that must never run twice.

SQLite (the fallback ``postgres_url`` in tests and no-DB deployments) has no
advisory locks and cannot be shared by replicas anyway, so the holder is always
the leader there — the alternative would disable the dispatcher in every test.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import SQLAlchemyError

from api.db.engine import get_engine

_log = logging.getLogger(__name__)

# Advisory-lock keys are a namespace of their own: any other application using
# `pg_advisory_lock` on this database shares it. The class id spells "SHAP" in
# ASCII to keep collisions with an unrelated tool implausible, and each worker
# gets its own object id below.
LOCK_CLASS_ID = 0x53484150
SCHEDULE_DISPATCHER_LOCK_ID = 1


class LeaderLock:
    """Tracks whether this process currently holds ``(class_id, object_id)``.

    ``acquire`` is the only method a caller needs on the happy path: it is
    idempotent, re-verifies a lock already held, and returns the current
    answer. Call it every tick rather than once at startup — leadership can be
    lost at any moment, and a leader that never re-checks would keep dispatching
    against a connection Postgres closed underneath it.
    """

    def __init__(self, url: str, *, object_id: int, name: str) -> None:
        self._url = url
        self._object_id = object_id
        self._name = name
        self._conn: Connection | None = None
        self._is_leader = False

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    def acquire(self) -> bool:
        """Return True if this process holds the lock after this call."""
        if self._is_leader:
            if self._connection_alive():
                return True
            # The backend holding the lock is gone, so the lock is gone with it.
            # Say so before trying again, or the log reads as if nothing moved.
            _log.warning("Lost %s leadership (database connection dropped)", self._name)
            self._reset()

        try:
            conn = self._connection()
            if conn is None:  # non-Postgres: single process by construction
                self._is_leader = True
                return True
            acquired = bool(
                conn.execute(
                    text("SELECT pg_try_advisory_lock(:class_id, :object_id)"),
                    {"class_id": LOCK_CLASS_ID, "object_id": self._object_id},
                ).scalar()
            )
        except SQLAlchemyError:
            # A database that is down is not a reason to elect anyone. Stay a
            # follower and retry on the next tick.
            _log.warning("Could not evaluate %s leadership", self._name, exc_info=True)
            self._reset()
            return False

        if acquired:
            _log.info("Acquired %s leadership", self._name)
            self._is_leader = True
        else:
            # Another replica leads. Hand the connection back rather than
            # parking it in every follower for the process's lifetime.
            self._reset()
        return self._is_leader

    def release(self) -> None:
        """Give up leadership now, so a peer takes over on its next tick.

        Without this, a graceful shutdown would still hold the lock until the
        backend actually terminates — a rolling restart would leave the
        schedule unattended for as long as that takes.
        """
        if self._conn is not None and self._is_leader:
            try:
                self._conn.execute(
                    text("SELECT pg_advisory_unlock(:class_id, :object_id)"),
                    {"class_id": LOCK_CLASS_ID, "object_id": self._object_id},
                )
            except SQLAlchemyError:
                _log.debug("Could not release %s cleanly", self._name, exc_info=True)
        was_leader = self._is_leader
        self._reset()
        if was_leader:
            _log.info("Released %s leadership", self._name)

    def _connection(self) -> Connection | None:
        """A dedicated connection, or None when the backend has no advisory locks."""
        if self._conn is not None:
            return self._conn
        engine = get_engine(self._url)
        if engine.dialect.name != "postgresql":
            return None
        conn = engine.connect()
        # Autocommit: an open transaction would pin the snapshot of a connection
        # that then sits idle for the process's lifetime, and `idle in
        # transaction` blocks VACUUM.
        self._conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        return self._conn

    def _connection_alive(self) -> bool:
        if self._conn is None:
            return True  # non-Postgres holder
        try:
            self._conn.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return False
        return True

    def _reset(self) -> None:
        self._is_leader = False
        if self._conn is not None:
            try:
                self._conn.close()
            except SQLAlchemyError:  # pragma: no cover - close is best-effort
                pass
            self._conn = None
