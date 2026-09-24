"""The database reads behind the scrape-time series on /metrics (#334).

``api/services/metrics.py`` holds the collectors; this module holds what they
read: :func:`cluster_snapshot` — the sensor/agent fleet, the job queue and the
endpoint devices, in one short transaction. Every replica reads the same
tables, so every replica reports the same numbers; they used to be *set* by
whichever replica handled the last job event or retention sweep, and replicas
disagreed for good.

Every statement goes through :func:`scrape_session`, and nothing else in the
scrape path opens a session. That is deliberate: it is the one place to put
whatever a scrape needs from the database layer — today a statement timeout,
tomorrow the row-level-security scope these cluster-wide aggregates will need.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import endpoint_inventory, job_store
from api.settings import Settings

_settings: Settings | None = None

#: Per statement, on Postgres. The queries are grouped scans; what this guards
#: against is waiting behind a lock — a migration's ALTER TABLE — for longer
#: than Prometheus waits for the scrape, holding a worker thread and a pooled
#: connection the whole time.
STATEMENT_TIMEOUT_MS = 2000

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
