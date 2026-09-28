"""The database reads behind the scrape-time series on /metrics (#334).

``api/services/metrics.py`` holds the collectors; this module holds what they
read. Two snapshots, each one short transaction:

* :func:`cluster_snapshot` — the sensor/agent fleet, the job queue and the
  endpoint devices. Every replica reads the same tables, so every replica
  reports the same numbers; they used to be *set* by whichever replica handled
  the last job event or retention sweep, and replicas disagreed for good.
* :func:`tenant_snapshot` — the opt-in per-tenant product series
  (OCTO_METRICS_TENANT_TOP_N), with the tenant label capped and the named set
  fixed for the wall-clock hour.

Every statement goes through :func:`scrape_session`, and nothing else in the
scrape path opens a session. That is deliberate: it is the one place to put
whatever a scrape needs from the database layer — today a statement timeout,
tomorrow the row-level-security scope these cluster-wide aggregates will need.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import endpoint_inventory
from api.services import job_states, job_store, vuln_states
from api.services import tenants as tenants_service
from api.services import vulnerabilities as vulnerabilities_service
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
#: The named set changes only on this wall-clock boundary. Every replica ranks
#: on the numbers the period began with, so they agree on it however far apart
#: their minutes fall — a tenant named by one replica and still inside
#: ``_other`` on another is counted twice by every ``sum(max by (tenant, …))``.
TENANT_MEMBERSHIP_SECONDS = 3600


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def tenant_series_enabled() -> bool:
    """Whether :func:`tenant_snapshot` reads anything at all."""
    return _settings is not None and bool(_settings.metrics_tenant_top_n)


def _now() -> datetime:
    """Naive UTC, like the columns it is compared with."""
    return datetime.now(UTC).replace(tzinfo=None)


def membership_epoch(timestamp: float | None = None) -> int:
    """The wall-clock period the named tenants belong to: the hour, as a number."""
    return int((time.time() if timestamp is None else timestamp) // TENANT_MEMBERSHIP_SECONDS)


def membership_start(now: datetime) -> datetime:
    """When ``now``'s period began, naive UTC like the columns."""
    epoch = membership_epoch(now.replace(tzinfo=UTC).timestamp())
    return datetime.fromtimestamp(epoch * TENANT_MEMBERSHIP_SECONDS, UTC).replace(tzinfo=None)


@contextmanager
def scrape_session(settings: Settings) -> Iterator[Any]:
    """The only way a scrape reads the database.

    ``set_config(…, true)`` scopes the timeout to this transaction, so it ends
    with the scrape: a session-level setting would stay on the pooled
    connection and cancel the next request that drew it at 2 s.

    In the system scope of row-level security (#311): these are cluster-wide
    aggregates by design, and an undeclared tenant scope would make every
    statement here raise. ``/metrics`` declares the cross-tenant scope for its
    request as well; this covers a collector run from anywhere else.
    """
    with tenant_scope.system("metrics scrape: cluster-wide aggregates"):
        with get_session(settings.postgres_url) as session:
            if session.get_bind().dialect.name == "postgresql":
                session.execute(
                    select(func.set_config("statement_timeout", str(STATEMENT_TIMEOUT_MS), True))
                )
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
    """The top-N tenants keep their id; everyone else is ``_other``.

    **Who is named** is decided on the findings that were open when the
    current hour began (:data:`TENANT_MEMBERSHIP_SECONDS`): first seen before
    it and not closed by then. That number is the same whenever in the hour
    it is read, so replicas refreshing a minute apart name the same tenants,
    and the set can change only on the hour — not on every finished scan, as
    it did when scans were part of the volume. Ties go to the lower id. The
    one thing that moves it within the hour is history being rewritten: an
    old finding reopened (its ``closed_at`` is cleared) or rows purged.

    Candidates are the *active* rows of the tenants table, never the ids on
    finding or job rows. **The counts** are live: open findings, breaches and
    scans as of ``now``. ``None`` while OCTO_METRICS_TENANT_TOP_N is 0 — the
    default.
    """
    settings = _settings
    if settings is None or not settings.metrics_tenant_top_n:
        return None
    now = now or _now()
    ranked_at = membership_start(now)
    finding = models.Vulnerability
    job = models.Job
    open_now = finding.state.in_(tuple(vuln_states.ACTIVE))
    # The console's own definition, so the two cannot drift.
    breached = and_(*vulnerabilities_service._sla_filters("breached", now))  # noqa: SLF001
    open_when_ranked = and_(
        finding.first_seen_at < ranked_at,
        or_(finding.closed_at.is_(None), finding.closed_at >= ranked_at),
    )
    with scrape_session(settings) as session:
        tenant_ids = (
            session.execute(select(models.Tenant.tenant_id).where(models.Tenant.status == "active"))
            .scalars()
            .all()
        )
        findings = session.execute(
            select(
                finding.tenant_id,
                finding.severity,
                func.sum(case((open_now, 1), else_=0)),
                func.sum(case((breached, 1), else_=0)),
                func.sum(case((open_when_ranked, 1), else_=0)),
            )
            # Open now, or closed since the hour began: still open when it did.
            .where(or_(open_now, finding.closed_at >= ranked_at))
            .group_by(finding.tenant_id, finding.severity)
        ).all()
        scans = session.execute(
            select(job.tenant_id, job.status, func.count())
            .where(job.status.in_(TENANT_SCAN_STATUSES), job.finished_at >= now - TENANT_SCAN_WINDOW)
            .group_by(job.tenant_id, job.status)
        ).all()

    ranking: dict[str, int] = {}
    for tenant_id, _severity, _open, _breached, open_at_start in findings:
        ranking[tenant_id] = ranking.get(tenant_id, 0) + int(open_at_start or 0)
    candidates = [tenant_id for tenant_id in tenant_ids if _nameable(tenant_id)]
    named = set(
        sorted(candidates, key=lambda tenant_id: (-ranking.get(tenant_id, 0), tenant_id))[
            : settings.metrics_tenant_top_n
        ]
    )
    labels = [*sorted(named), TENANT_OTHER]

    def label(tenant_id: str) -> str:
        return tenant_id if tenant_id in named else TENANT_OTHER

    open_findings = {(tenant, severity): 0 for tenant in labels for severity in TENANT_SEVERITIES}
    sla_breached = dict.fromkeys(labels, 0)
    scans_finished = {(tenant, status): 0 for tenant in labels for status in TENANT_SCAN_STATUSES}
    for tenant_id, severity, open_count, breached_count, _open_at_start in findings:
        severity = severity if severity in SEVERITY_ORDER else "unknown"
        open_findings[(label(tenant_id), severity)] += int(open_count or 0)
        sla_breached[label(tenant_id)] += int(breached_count or 0)
    for tenant_id, status, count in scans:
        scans_finished[(label(tenant_id), status)] += int(count)
    return TenantSnapshot(
        open_findings=open_findings, sla_breached=sla_breached, scans_finished=scans_finished
    )
