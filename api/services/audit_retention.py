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

Per tenant since #332. ``--days`` (``OCTO_AUDIT_EVENT_RETENTION_DAYS``) is the
platform default, pruned by ``audit_events_prune``; a tenant with an audit
window of its own is pruned by ``audit_events_prune_tenant`` on that window,
and a tenant on legal hold is pruned by neither. Both functions check the hold
and the override themselves (migration 0065), so this job cannot delete a held
tenant's trail even when it is handed a wrong plan — or is an image that
predates the policy table and calls only the first. The retention role
therefore needs ``SELECT`` on ``tenant_retention_policies`` and
``tenant_legal_holds`` to build its plan, and ``EXECUTE`` on both functions;
see docs/data-retention.md.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_, text

from api.db import models
from api.db.engine import get_engine, get_session
from api.services import legal_hold, retention_policy
from api.settings import Settings, load_settings

LOG = logging.getLogger("shapoclyack.audit-retention")


def prune(settings: Settings, *, cutoff: datetime) -> int:
    """The default pass: rows older than ``cutoff``. Returns how many went.

    ``cutoff`` is naive UTC, like the column. On Postgres the delete happens
    inside ``audit_events_prune``; a caller without EXECUTE on it gets the
    database's refusal, unchanged, rather than a quiet no-op. Rows of a tenant
    on legal hold, or of one with an audit window of its own, are not this
    pass's to delete (#332) — the function skips them, and so does the SQLite
    branch here.
    """
    engine = get_engine(settings.postgres_url)
    if engine.dialect.name != "postgresql":
        with get_session(settings.postgres_url) as session:
            plan = retention_policy.load_plan(
                settings, retention_policy.AUDIT_EVENTS, session=session
            )
            conditions = [models.AuditEvent.occurred_at < cutoff]
            if plan.excluded:
                conditions.append(
                    or_(
                        models.AuditEvent.tenant_id.is_(None),
                        models.AuditEvent.tenant_id.not_in(sorted(plan.excluded)),
                    )
                )
            result = session.execute(delete(models.AuditEvent).where(*conditions))
            return int(result.rowcount or 0)
    with get_session(settings.postgres_url) as session:
        removed = session.execute(
            text("SELECT audit_events_prune(:cutoff)"), {"cutoff": cutoff}
        ).scalar_one()
        return int(removed or 0)


def prune_tenant(settings: Settings, tenant_id: str, *, cutoff: datetime) -> int:
    """One tenant's rows older than ``cutoff``; none while it is on legal hold."""
    engine = get_engine(settings.postgres_url)
    if engine.dialect.name != "postgresql":
        with get_session(settings.postgres_url) as session:
            if legal_hold.is_on_legal_hold(session, tenant_id):
                return 0
            result = session.execute(
                delete(models.AuditEvent).where(
                    models.AuditEvent.tenant_id == tenant_id,
                    models.AuditEvent.occurred_at < cutoff,
                )
            )
            return int(result.rowcount or 0)
    with get_session(settings.postgres_url) as session:
        removed = session.execute(
            text("SELECT audit_events_prune_tenant(:tenant_id, :cutoff)"),
            {"tenant_id": tenant_id, "cutoff": cutoff},
        ).scalar_one()
        return int(removed or 0)


def sweep(settings: Settings, *, now: datetime | None = None) -> int:
    """One retention pass: the platform default, then each tenant's own window.

    ``audit_event_retention_days`` of 0 keeps forever for every tenant without
    a window of its own; a tenant that set one is still pruned on it.
    """
    moment = now or datetime.now(UTC).replace(tzinfo=None)
    plan = retention_policy.load_plan(settings, retention_policy.AUDIT_EVENTS)
    removed = 0
    if plan.default_days > 0:
        cutoff = moment - timedelta(days=plan.default_days)
        removed += prune(settings, cutoff=cutoff)
        LOG.info("pruned audit_events older than %s (platform default)", cutoff.isoformat())
    else:
        LOG.info("audit retention default disabled (audit_event_retention_days=0)")
    for tenant_id, days in sorted(plan.overrides.items()):
        cutoff = moment - timedelta(days=days)
        removed += prune_tenant(settings, tenant_id, cutoff=cutoff)
        LOG.info("pruned tenant %s's audit_events older than %s", tenant_id, cutoff.isoformat())
    if plan.held:
        LOG.info("audit retention skipped %d tenant(s) on legal hold", len(plan.held))
    LOG.info("pruned %d audit_events in total", removed)
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
