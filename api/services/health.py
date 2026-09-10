"""Dependency probes behind ``GET /readyz`` and ``GET /api/health`` (#331).

Readiness is a statement about *this replica's ability to serve requests*, so
every dependency it names is actually touched: Postgres answers ``SELECT 1``,
NATS completes a round trip to the server, ClickHouse answers a query. The
previous health endpoint reported NATS from a local ``_started`` flag, which
stays True across a broker that went away, and never touched Postgres at all —
so a replica whose database was unreachable kept answering 200 and kept taking
traffic.

Only configured dependencies are checked. NATS and ClickHouse are opt-in
sidecars (empty URL disables them), and an installation that runs neither is
ready, not degraded — an absent dependency is not a failing one. Postgres is
always checked: the tenant store lives there, so a replica without it can serve
nothing.

A configured dependency is not automatically a *blocking* one. ClickHouse backs
analytics only, and it is a single pod with no PDB even in ``overlays/prod-ha``
(#335): letting it decide readiness means one broker restart takes every API
replica out of its Service at once, which is a full outage of everything the
control plane does — jobs, agents, runs — bought in exchange for a dashboard.
So ClickHouse is reported and degrades ``/api/health``, but does not fail
``/readyz``. Postgres and NATS do: without them a replica cannot serve a
request or dispatch a job, and taking it out of the Service is the point.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import text

from api.db import engine as db_engine
from api.services import clickhouse_client
from api.services import nats_bus
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.health")

STATUS_OK = "ok"
STATUS_ERROR = "error"


# Dependencies a replica cannot serve without, and which therefore decide the
# status code of /readyz. Everything else in ``checks`` is advisory: reported,
# and enough to call the installation degraded, but not enough to pull the
# replica out of its Service.
BLOCKING_CHECKS = frozenset({"postgres", "nats"})


@dataclass(frozen=True)
class Readiness:
    """Outcome of one readiness sweep.

    ``checks`` maps a dependency name to ``ok``/``error`` and carries only the
    dependencies this installation configured, so a client can tell "ClickHouse
    is down" from "there is no ClickHouse here".

    ``ready`` answers the kubelet and counts only :data:`BLOCKING_CHECKS`;
    ``healthy`` answers a human and counts every check that ran. They differ
    exactly when an advisory dependency is down, which is the case worth being
    able to see.
    """

    ready: bool
    checks: dict[str, str]

    @property
    def healthy(self) -> bool:
        return all(status == STATUS_OK for status in self.checks.values())


def check_readiness(settings: Settings) -> Readiness:
    checks = {"postgres": STATUS_OK if _postgres_ok(settings) else STATUS_ERROR}
    if settings.nats_url:
        checks["nats"] = STATUS_OK if _nats_ok(settings) else STATUS_ERROR
    if settings.clickhouse_url:
        checks["clickhouse"] = (
            STATUS_OK if clickhouse_client.ping(settings.clickhouse_url) else STATUS_ERROR
        )
    return Readiness(
        ready=all(
            status == STATUS_OK for name, status in checks.items() if name in BLOCKING_CHECKS
        ),
        checks=checks,
    )


def _postgres_ok(settings: Settings) -> bool:
    """``SELECT 1`` over the shared engine, on a connection taken from the pool.

    Fail-soft with a log rather than an exception: a probe that 500s tells the
    kubelet the same thing a 503 does, and loses the reason on the way. The
    engine's ``pool_pre_ping`` means a connection handed out here is one a real
    request would have got, so this catches a database that is gone as well as
    one that is merely slow to answer.
    """
    try:
        connection_engine = db_engine.get_engine(settings.postgres_url)
        with connection_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        LOG.warning("readiness: Postgres check failed", exc_info=True)
        return False


def _nats_ok(settings: Settings) -> bool:
    bus = nats_bus.get_bus(settings.nats_url)
    return bus is not None and bus.round_trip()
