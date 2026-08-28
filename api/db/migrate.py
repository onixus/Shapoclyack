"""Serialized ``alembic upgrade head`` (#159).

Every API replica runs migrations in its initContainer. While ``replicas: 1``
was a correctness requirement that was safe by construction; P1.6 removed the
requirement and left the initContainer as it was, so N replicas now start N
concurrent ``upgrade head`` runs against one database. Alembic has no mutual
exclusion of its own: two runs read the same ``alembic_version`` row, both
decide the same revision is pending, and both apply it. What happens next
depends on the migration — a duplicate ``CREATE INDEX`` fails the pod and the
rollout retries it, while a data migration can apply twice and succeed.

This module wraps the upgrade in a **Postgres advisory lock**, the same
primitive P1.6 uses for scheduler leader election, so the replicas queue behind
each other. The waiters are not skipped: each one runs ``upgrade head`` after
acquiring the lock, which is a no-op once the leader is done, and stays correct
if the leader failed halfway.

Why a lock rather than a separate pre-rollout Job: plain kustomize has no
ordering hooks, so a Job would have to be applied and waited on out-of-band —
a second, undocumented deployment step that a ``kubectl apply -k`` does not
perform. Keeping the migration in the initContainer means the schema is always
brought to head by the same action that rolls out the code, and the lock
supplies the exclusion the initContainer never had.

Deliberately **blocking**, unlike ``LeaderLock``'s ``pg_try_advisory_lock``: a
replica that cannot get the lock must wait for the migration to finish, not
start against an unmigrated schema. ``lock_timeout`` bounds the wait so a stuck
migration surfaces as a failed pod with a named cause instead of an initContainer
that hangs until someone looks.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from api.services.leader_lock import LOCK_CLASS_ID


_log = logging.getLogger("api.db.migrate")

# Distinct from SCHEDULE_DISPATCHER_LOCK_ID (1) in the same class namespace:
# a migration and the schedule dispatcher must never exclude each other.
MIGRATION_LOCK_ID = 2

DEFAULT_LOCK_TIMEOUT_SECONDS = 600

_ALEMBIC_INI = Path(__file__).resolve().parent / "alembic.ini"


def _database_url() -> str:
    url = os.environ.get("OCTO_POSTGRES_URL", "").strip()
    if not url:
        raise RuntimeError(
            "OCTO_POSTGRES_URL must be set to run migrations.\n"
            "  This is the same connection the API uses; see docs/configuration.md."
        )
    return url


def _upgrade(revision: str) -> None:
    config = Config(str(_ALEMBIC_INI))
    command.upgrade(config, revision)


def run_upgrade(
    url: str,
    *,
    revision: str = "head",
    lock_timeout_seconds: int = DEFAULT_LOCK_TIMEOUT_SECONDS,
) -> None:
    """Bring the schema to ``revision``, holding the migration advisory lock.

    On a non-Postgres URL there is nothing to serialize — SQLite cannot be
    shared by replicas — so the upgrade runs directly rather than being skipped.
    """
    engine = create_engine(url, future=True)
    try:
        if engine.dialect.name != "postgresql":
            _log.info("Non-Postgres database: running migrations without a lock")
            _upgrade(revision)
            return

        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            # lock_timeout applies to pg_advisory_lock's wait. Without it a
            # replica behind a migration that never finishes waits forever, and
            # the pod reports nothing but "Init:0/1".
            # set_config() rather than SET: SET takes no bind parameters, so it
            # forces the value into the statement text, which is what the SAST
            # gate objects to. The function form takes one.
            conn.execute(
                text("SELECT set_config('lock_timeout', :timeout, false)"),
                {"timeout": f"{int(lock_timeout_seconds)}s"},
            )
            _log.info("Waiting for the migration lock")
            try:
                conn.execute(
                    text("SELECT pg_advisory_lock(:class_id, :object_id)"),
                    {"class_id": LOCK_CLASS_ID, "object_id": MIGRATION_LOCK_ID},
                )
            except SQLAlchemyError as exc:
                raise RuntimeError(
                    f"Timed out after {lock_timeout_seconds}s waiting for the migration "
                    "lock. Another replica is still migrating, or a previous migration "
                    "process is stuck holding it — check for a long-running query on "
                    "the database before retrying."
                ) from exc

            _log.info("Holding the migration lock, upgrading to %s", revision)
            try:
                # Runs on its own connection (Alembic builds its own engine in
                # env.py); the lock is only what keeps the *processes* apart.
                _upgrade(revision)
            finally:
                # Best-effort: the lock is session-scoped, so closing the
                # connection below releases it regardless. Unlocking explicitly
                # lets the next waiter start without waiting on TCP teardown.
                try:
                    conn.execute(
                        text("SELECT pg_advisory_unlock(:class_id, :object_id)"),
                        {"class_id": LOCK_CLASS_ID, "object_id": MIGRATION_LOCK_ID},
                    )
                except SQLAlchemyError:  # pragma: no cover - teardown is best-effort
                    _log.debug("Could not release the migration lock cleanly", exc_info=True)
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Alembic migrations under an advisory lock.")
    parser.add_argument("--revision", default="head", help="Target revision (default: head)")
    parser.add_argument(
        "--lock-timeout-seconds",
        type=int,
        default=int(os.environ.get("OCTO_MIGRATION_LOCK_TIMEOUT_SECONDS", DEFAULT_LOCK_TIMEOUT_SECONDS)),
        help="How long to wait for the migration lock before failing",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        run_upgrade(
            _database_url(),
            revision=args.revision,
            lock_timeout_seconds=args.lock_timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001 - this is a CLI boundary
        _log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
