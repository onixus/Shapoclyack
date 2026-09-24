"""The database reads behind the scrape-time series on /metrics (#334).

``api/services/metrics.py`` holds the collectors; this module holds what they
read. Two snapshots, each one short transaction:

* :func:`cluster_snapshot` — the sensor/agent fleet, the job queue and the
  endpoint devices. Every replica reads the same tables, so every replica
  reports the same numbers; they used to be *set* by whichever replica handled
  the last job event or retention sweep, and replicas disagreed for good.
* :func:`tenant_snapshot` — the opt-in per-tenant product series
  (OCTO_METRICS_TENANT_TOP_N), with the tenant label capped.

Every statement goes through :func:`scrape_session`, and nothing else in the
scrape path opens a session. That is deliberate: it is the one place to put
whatever a scrape needs from the database layer — today a statement timeout,
tomorrow the row-level-security scope these cluster-wide aggregates will need.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import endpoint_inventory
from api.services import job_states, job_store, vuln_states
from api.services import tenants as tenants_service
from api.settings import Settings
from scanner.pipeline.report import SEVERITY_ORDER

_settings: Settings | None = None

#: Per statement, on Postgres. The queries are grouped scans; what this guards
#: against is waiting behind a lock — a migration's ALTER TABLE — for longer
#: than Prometheus waits for the scrape, holding a worker thread and a pooled
#: connection the whole time.
STATEMENT_TIMEOUT_MS = 2000

#: The ``tenant`` label of every tenant that is not among the top N. Tenant
#: ids start with a letter or digit, so no tenant can be called this.
TENANT_OTHER = "_other"
#: Worst first, as the console orders them; any other stored value is
#: reported as ``unknown``, the way findings are normalised on write.
TENANT_SEVERITIES = tuple(sorted(SEVERITY_ORDER, key=lambda severity: -SEVERITY_ORDER[severity]))
TENANT_SCAN_STATUSES = tuple(sorted(job_states.TERMINAL))
TENANT_SCAN_WINDOW = timedelta(hours=24)


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _now() -> datetime:
    """Naive UTC, like the columns it is compared with."""
    return datetime.now(UTC).replace(tzinfo=None)


@contextmanager
def scrape_session(settings: Settings) -> Iterator[Any]:
    """The only way a scrape reads the database.

    ``set_config(…, true)`` scopes the timeout to this transaction, so it ends
    with the scrape: a session-level setting would stay on the pooled
    connection and cancel the next request that drew it at 2 s.

    When row-level security lands (#311), whichever of #311 and #334 merges
    second wraps this body in #311's system scope — these are cluster-wide
    aggregates by design, and an undeclared tenant scope makes every statement
    here raise. The scrape tests fail until it does.
    """
    with get_session(settings.postgres_url) as session:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(select(func.set_config("statement_timeout", str(STATEMENT_TIMEOUT_MS), True)))
        yield session


@dataclass(frozen=True)
class ClusterSnapshot:
    """What every replica reports alike, read once per snapshot TTL."""

    fleet: agents_service.FleetHeartbeats
    jobs_queued: int
    jobs_running: int
    #: ``{"active": n, "stale": m}``, or ``None`` with the endpoint inventory off.
    endpoint_devices: dict[str, int] | None


def cluster_snapshot(now: datetime | None = None) -> ClusterSnapshot | None:
    """Fleet, queue and endpoint devices, in one transaction.

    ``None`` when nothing was configured: tools and unit tests that import the
    registry with no database behind it have nothing to report, which is not
    an error to log on every scrape.
    """
    settings = _settings
    if settings is None:
        return None
    now = now or _now()
    with scrape_session(settings) as session:
        fleet = agents_service.fleet_heartbeats(
            session, now=now, stale_seconds=settings.agent_stale_seconds
        )
        queued, running = job_store.job_counts(session)
        devices = (
            endpoint_inventory.device_state_counts(
                session, now=now, stale_hours=settings.endpoint_stale_hours
            )
            if settings.endpoint_inventory_enabled
            else None
        )
    return ClusterSnapshot(fleet=fleet, jobs_queued=queued, jobs_running=running, endpoint_devices=devices)


@dataclass(frozen=True)
class TenantSnapshot:
    """The opt-in per-tenant series, every label combination present."""

    #: ``(tenant, severity) -> open findings`` (any state but CLOSED).
    open_findings: dict[tuple[str, str], int]
    #: ``tenant -> open findings past due and not under an accepted exception``.
    sla_breached: dict[str, int]
    #: ``(tenant, status) -> scans that finished in the last 24 hours``.
    scans_finished: dict[tuple[str, str], int]


def _nameable(tenant_id: str) -> bool:
    """Whether an id may stand as a label: the rule tenant creation enforces.

    Rows that predate that rule may hold anything (``nats_bus`` encodes them
    before they reach a subject); they are counted, under ``_other``, but
    never named.
    """
    try:
        tenants_service._validate_tenant_id(tenant_id)  # noqa: SLF001 - the one definition of the rule
    except ValueError:
        return False
    return True


def tenant_snapshot(now: datetime | None = None) -> TenantSnapshot | None:
    """The top-N tenants by volume keep their id; everyone else is ``_other``.

    Volume is open findings plus scans finished in the window, ties broken by
    id so the set does not flap between two equal tenants. Label values come
    from the tenants table only, never from the finding or job rows.
    ``None`` while OCTO_METRICS_TENANT_TOP_N is 0 — the default.
    """
    settings = _settings
    if settings is None or not settings.metrics_tenant_top_n:
        return None
    now = now or _now()
    finding = models.Vulnerability
    job = models.Job
    breached = case(
        (
            and_(
                finding.due_at.is_not(None),
                finding.due_at <= now,
                or_(finding.exception_until.is_(None), finding.exception_until <= now),
            ),
            1,
        ),
        else_=0,
    )
    with scrape_session(settings) as session:
        tenant_ids = session.execute(select(models.Tenant.tenant_id)).scalars().all()
        findings = session.execute(
            select(finding.tenant_id, finding.severity, func.count(), func.sum(breached))
            .where(finding.state.in_(tuple(vuln_states.ACTIVE)))
            .group_by(finding.tenant_id, finding.severity)
        ).all()
        scans = session.execute(
            select(job.tenant_id, job.status, func.count())
            .where(job.status.in_(TENANT_SCAN_STATUSES), job.finished_at >= now - TENANT_SCAN_WINDOW)
            .group_by(job.tenant_id, job.status)
        ).all()

    volume: dict[str, int] = {}
    for tenant_id, _severity, count, _breached in findings:
        volume[tenant_id] = volume.get(tenant_id, 0) + int(count)
    for tenant_id, _status, count in scans:
        volume[tenant_id] = volume.get(tenant_id, 0) + int(count)
    candidates = [tenant_id for tenant_id in tenant_ids if _nameable(tenant_id)]
    named = set(
        sorted(candidates, key=lambda tenant_id: (-volume.get(tenant_id, 0), tenant_id))[
            : settings.metrics_tenant_top_n
        ]
    )
    labels = [*sorted(named), TENANT_OTHER]

    def label(tenant_id: str) -> str:
        return tenant_id if tenant_id in named else TENANT_OTHER

    open_findings = {(tenant, severity): 0 for tenant in labels for severity in TENANT_SEVERITIES}
    sla_breached = dict.fromkeys(labels, 0)
    scans_finished = {(tenant, status): 0 for tenant in labels for status in TENANT_SCAN_STATUSES}
    for tenant_id, severity, count, breached_count in findings:
        severity = severity if severity in SEVERITY_ORDER else "unknown"
        open_findings[(label(tenant_id), severity)] += int(count)
        sla_breached[label(tenant_id)] += int(breached_count or 0)
    for tenant_id, status, count in scans:
        scans_finished[(label(tenant_id), status)] += int(count)
    return TenantSnapshot(
        open_findings=open_findings, sla_breached=sla_breached, scans_finished=scans_finished
    )
