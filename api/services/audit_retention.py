"""Retention for the append-only audit trail — a privileged job, not the API (#329).

Every other retention sweep in this repo runs inside the API process
(``endpoint_retention``, ``run_retention``, ``auth_audit._maybe_prune``). This
one cannot, and that is the whole point: migration 0037 makes ``audit_events``
refuse UPDATE and DELETE, and the only way past that refusal is
``audit_events_prune``, a SECURITY DEFINER function whose EXECUTE privilege the
recommended GRANT layout in ``docs/operations.md`` withholds from the API's
role. An API that could prune its own audit trail would be the control
removing itself.

So this is a CLI, meant for a Kubernetes ``CronJob`` (or a cron line, or a
one-off run) with credentials of its own::

    python -m api.services.audit_retention --days 365

``--days 0`` is refused rather than treated as "delete everything": the value
that means "keep forever" in ``OCTO_AUDIT_EVENT_RETENTION_DAYS`` must not
become "keep nothing" because a variable was unset in the job's environment.

The SQLite dev fallback has neither trigger nor function, so :func:`prune`
deletes directly there — the same split ``api/db/engine.py`` already makes
between a migrated Postgres and a developer's file.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, text

from api.db import models
from api.db.engine import get_engine, get_session
from api.settings import Settings, load_settings

LOG = logging.getLogger("shapoclyack.audit-retention")


def prune(settings: Settings, *, cutoff: datetime) -> int:
    """Delete audit rows older than ``cutoff``. Returns how many went.

    ``cutoff`` is naive UTC, like the column. On Postgres the delete happens
    inside ``audit_events_prune``; a caller without EXECUTE on it gets the
    database's refusal, unchanged, rather than a quiet no-op.
    """
    engine = get_engine(settings.postgres_url)
    if engine.dialect.name != "postgresql":
        with get_session(settings.postgres_url) as session:
            result = session.execute(
                delete(models.AuditEvent).where(models.AuditEvent.occurred_at < cutoff)
            )
            return int(result.rowcount or 0)
    with get_session(settings.postgres_url) as session:
        removed = session.execute(
            text("SELECT audit_events_prune(:cutoff)"), {"cutoff": cutoff}
        ).scalar_one()
        return int(removed or 0)


def sweep(settings: Settings, *, now: datetime | None = None) -> int:
    """One retention pass over ``audit_event_retention_days``. 0 keeps forever."""
    days = settings.audit_event_retention_days
    if days <= 0:
        LOG.info("audit retention disabled (audit_event_retention_days=0); nothing pruned")
        return 0
    moment = now or datetime.now(UTC).replace(tzinfo=None)
    cutoff = moment - timedelta(days=days)
    removed = prune(settings, cutoff=cutoff)
    LOG.info("pruned %d audit_events older than %s", removed, cutoff.isoformat())
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m api.services.audit_retention",
        description="Delete audit_events past the retention window (#329).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=int(os.environ.get("OCTO_AUDIT_EVENT_RETENTION_DAYS", "365")),
        help="Keep this many days of audit trail (default: OCTO_AUDIT_EVENT_RETENTION_DAYS or 365)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if args.days <= 0:
        LOG.error("--days must be at least 1; refusing to treat 0 as 'delete everything'")
        return 2
    settings = load_settings()
    settings.audit_event_retention_days = args.days
    try:
        sweep(settings)
    except Exception as exc:  # noqa: BLE001 - this is a CLI boundary
        LOG.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
