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
``/readyz``. Postgres still does: without it a replica can serve nothing, and
taking it out of the Service is the point.

NATS used to block too, and no longer does (P2 of
``docs/architecture-review-2026-09-18.ru.md``). The capability matrix behind
that change is in ``docs/high-availability.md`` § *What a NATS outage costs*;
the short form is that with the broker down a replica still authenticates,
still serves every read and write that is not a scan result, still hands out
jobs — agents claim over HTTP and the offer is only a notification — and still
accepts result uploads. Failing readiness on it therefore traded a degraded
installation for an unavailable one, in every replica simultaneously, since
they share one broker.

What made that trade defensible before was that a publish lost with the broker
was lost for good. It is not any more: ``api/services/nats_outbox.py`` records
the refused ingest message and republishes it when NATS returns, and the
backlog it has not recovered is reported here as ``ingest_backlog``. That check
is advisory on purpose and for the same reason as ClickHouse — a shared backlog
that unreadied every replica would be the outage this change removed, wearing a
different name. It degrades ``/api/health``, raises ``octo_nats_outbox_backlog``
and is the operator's signal that availability is now ahead of analytics.

Object storage (#336) is checked on the same terms as ClickHouse, and for the
same reason rather than a weaker one: every replica shares one bucket, so a
bucket that is briefly unreachable would fail *all* of their probes at once and
empty the Service. Reported and degrading, not blocking — an operator sees
"artifacts: error" while the API goes on serving everything that is not a
run artifact. The filesystem backend is not probed at all: it has no endpoint
to be unreachable, and a full volume is not a question ``head_bucket`` asks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import text

from api.db import engine as db_engine
from api.services import artifact_store
from api.services import clickhouse_client
from api.services import nats_bus
from api.services import nats_outbox
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.health")

STATUS_OK = "ok"
STATUS_ERROR = "error"


# Dependencies a replica cannot serve without, and which therefore decide the
# status code of /readyz. Everything else in ``checks`` is advisory: reported,
# and enough to call the installation degraded, but not enough to pull the
# replica out of its Service.
# NATS is deliberately absent: see the module docstring, and do not add it back
# without also taking the outbox away, because the two are one decision.
BLOCKING_CHECKS = frozenset({"postgres"})


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
        # Reported next to the broker rather than instead of it: "NATS is down"
        # and "NATS was down and the analytics never caught up" are different
        # states, and the second one outlives the first.
        checks["ingest_backlog"] = STATUS_ERROR if _backlogged(settings) else STATUS_OK
    if settings.clickhouse_url:
        checks["clickhouse"] = (
            STATUS_OK if clickhouse_client.ping(settings.clickhouse_url) else STATUS_ERROR
        )
    if artifact_store.is_remote(settings):
        checks["artifacts"] = STATUS_OK if _artifacts_ok(settings) else STATUS_ERROR
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


def _artifacts_ok(settings: Settings) -> bool:
    """Whether this replica can reach the artifact bucket.

    Fail-soft with a log, like the Postgres probe: the reason belongs in the
    replica's own logs, and an exception here would be reported to the kubelet
    as an unhealthy API rather than as unreachable storage.
    """
    try:
        ok, detail = artifact_store.get_store(settings).healthy()
    except Exception:  # noqa: BLE001
        LOG.warning("readiness: artifact store check failed", exc_info=True)
        return False
    if not ok:
        LOG.warning("readiness: artifact store is not usable: %s", detail)
    return ok


def _nats_ok(settings: Settings) -> bool:
    bus = nats_bus.get_bus(settings.nats_url)
    return bus is not None and bus.round_trip()


def _backlogged(settings: Settings) -> bool:
    """Whether refused publications are piling up unrecovered.

    One indexed count per probe, and fail-soft inside ``nats_outbox``: a
    database that cannot answer this is the blocking Postgres check's business,
    not a second 503 with a worse explanation.
    """
    return nats_outbox.is_backlogged(settings)
