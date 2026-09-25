"""Prometheus metrics registry (Phase P3.4).

A single process-wide ``CollectorRegistry`` shared by the HTTP middleware
(``api/app.py``), the job lifecycle (``api/services/jobs.py``), and the
ClickHouse ingest worker (``api/services/ch_ingest_worker.py``). Scraped via
``GET /metrics`` (unauthenticated, matching standard Prometheus practice —
restrict at the network/gateway layer, not app auth).

Most series here are pushed by the code path they describe. The ones at the
bottom are read when Prometheus asks (#334): the process view, the SQLAlchemy
pool, and — through ``api.services.metrics_sources`` — the sensor/agent fleet,
the job queue, the endpoint devices and the opt-in per-tenant series. The catalogue,
with the bound on every label, is docs/observability.md;
tests/test_observability_assets.py fails when a series here has no entry there,
or when a dashboard or alert names one that is not here.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    GCCollector,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
    generate_latest,
)
from prometheus_client.core import (
    CounterMetricFamily,
    GaugeHistogramMetricFamily,
    GaugeMetricFamily,
    Metric,
)
from prometheus_client.utils import floatToGoString

if TYPE_CHECKING:  # pragma: no cover - typing only
    from api.services.metrics_sources import ClusterSnapshot as MetricsClusterSnapshot
    from api.services.metrics_sources import TenantSnapshot as MetricsTenantSnapshot

LOG = logging.getLogger("shapoclyack.metrics")

REGISTRY = CollectorRegistry()

# The process view (#334). These three are what ``prometheus_client`` registers
# on its *default* registry by itself; a private one starts empty, so until
# they were added here /metrics had no memory, CPU, file-descriptor or GC series
# at all. One process per pod (``python -m api`` runs a single uvicorn worker),
# so ``instance`` is the process and nothing needs the multiprocess mode.
ProcessCollector(registry=REGISTRY)
PlatformCollector(registry=REGISTRY)
GCCollector(registry=REGISTRY)

HTTP_REQUESTS_TOTAL = Counter(
    "octo_http_requests_total",
    "Total HTTP requests handled by the API.",
    ["method", "path", "status"],
    registry=REGISTRY,
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "octo_http_request_duration_seconds",
    "HTTP request duration in seconds.",
    ["method", "path"],
    registry=REGISTRY,
)

JOB_DURATION_SECONDS = Histogram(
    "octo_job_duration_seconds",
    "Scan job duration from started_at to finished_at, in seconds.",
    ["status", "execution"],
    # Explicit buckets: the prometheus_client default set tops out at 10s, so
    # every real scan landed in +Inf and no quantile was computable (docs/slo.md
    # SLO 4). Spans 30s (a small lab /24) to 8h (a large agent sweep).
    buckets=(30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 14400, 28800),
    registry=REGISTRY,
)
# octo_jobs_queued / octo_jobs_running are read from the jobs table at scrape
# time: see CLUSTER_COLLECTOR at the bottom (#334).

AGENT_INGEST_IN_FLIGHT = Gauge(
    "octo_agent_ingest_in_flight",
    "Sensor result uploads being ingested on a worker thread right now.",
    registry=REGISTRY,
)
AGENT_INGEST_WAITING = Gauge(
    "octo_agent_ingest_waiting",
    "Sensor result uploads queued for an ingest slot. Each one is holding its "
    "archive in memory, so this is a memory figure as much as a queue depth.",
    registry=REGISTRY,
)
AGENT_INGEST_REJECTED_TOTAL = Counter(
    "octo_agent_ingest_rejected_total",
    "Result uploads answered 503 because no ingest slot was available, by "
    "reason (queue_full, timeout). A rising count means the sensors are "
    "uploading faster than this replica ingests.",
    ["reason"],
    registry=REGISTRY,
)

JOB_LEASE_EXPIRED_TOTAL = Counter(
    "octo_job_lease_expired_total",
    "Jobs whose executor stopped renewing its lease, by what the reaper did "
    "(requeued, failed).",
    ["outcome"],
    registry=REGISTRY,
)

JOB_CANCELLATIONS_TOTAL = Counter(
    "octo_job_cancellations_total",
    "Scans stopped on an operator's request, by how the stop ended (#360): "
    "queued (never handed out), confirmed (the agent reported it put the scan "
    "down), unconfirmed (the grace period expired first), late_results (an "
    "unconfirmed one whose partial archive turned up afterwards and was kept "
    "\u2014 its outcome is already counted under unconfirmed).",
    ["outcome"],
    registry=REGISTRY,
)

RUN_PUBLICATIONS_TOTAL = Counter(
    "octo_run_publications_total",
    "Publications of an accepted run — store, run directory, latest_run.json, "
    "ingest.results.{tenant} — by outcome (published, deferred, dead, "
    "adopted, requeued, discarded). Anything but published means the run was "
    "accepted and is not visible yet; dead means it will not become visible "
    "without an operator, and requeued/discarded are that operator's answer.",
    ["outcome"],
    registry=REGISTRY,
)

RUN_PUBLICATION_STALE_NOTES_TOTAL = Counter(
    "octo_run_publication_stale_notes_total",
    "Runs published after their publication had failed, whose \"run not "
    "published\" note could not be taken off the job's error. The job then says "
    "the opposite of what happened; the API log names it.",
    registry=REGISTRY,
)

RUN_PUBLICATION_LEASE_RENEWALS_TOTAL = Counter(
    "octo_run_publication_lease_renewal_total",
    "Renewals of a running publication's hold on its row, by outcome: renewed; "
    "late (the previous hold had already lapsed — a peer could have claimed the "
    "row meanwhile); superseded (another attempt has claimed or an operator "
    "requeued the row since this attempt took it); failed (the renewal did not "
    "reach the database). Anything but renewed is the precondition of a "
    "second, parallel attempt at the same publication.",
    ["outcome"],
    registry=REGISTRY,
)

RUN_PUBLICATION_BACKLOG = Gauge(
    "octo_run_publication_backlog",
    "Accepted runs whose publication is still owed, by status (pending, "
    "dead). Cluster-wide (every replica reports the same query), so aggregate "
    "with max(), not sum().",
    ["status"],
    registry=REGISTRY,
)

JOB_IDEMPOTENT_REPLAYS_TOTAL = Counter(
    "octo_job_idempotent_replays_total",
    "Requests recognised as a replay of one already applied, by operation "
    "(start, results).",
    ["operation"],
    registry=REGISTRY,
)

IDEMPOTENT_REPLAYS_TOTAL = Counter(
    "octo_idempotent_replays_total",
    "Write requests answered from a stored Idempotency-Key record instead of "
    "being executed again, by endpoint (#346). Separate from "
    "octo_job_idempotent_replays_total, which counts the scan-start and "
    "results paths that hang their key on the job row itself.",
    ["endpoint"],
    registry=REGISTRY,
)

BULK_ACTION_ITEMS_TOTAL = Counter(
    "octo_bulk_action_items_total",
    "Ids processed by a bulk write, by endpoint, action and per-id outcome "
    "(ok, not_found, conflict, invalid, deadline) — #346. 'deadline' is an id "
    "the request never reached because it spent its time budget, so a rising "
    "share of it means batches are being cut short and resent rather than "
    "failing. A batch is a partial success "
    "by design, so the ratio here is what says whether an operator's "
    "selection matched what they may act on. There is no 'forbidden': an id "
    "outside the caller's write scope is reported missing, never refused, for "
    "the same reason the single-id routes 404 it.",
    ["endpoint", "action", "outcome"],
    registry=REGISTRY,
)

AUTH_ATTEMPTS_TOTAL = Counter(
    "octo_auth_attempts_total",
    "Access decisions, by outcome (success, failure, locked, denied). "
    "'locked' is a login attempt refused by the rate limiter before the "
    "password was checked (#157); 'denied' is an authenticated principal "
    "refused an action, e.g. a scan outside the tenant's approved scope "
    "(#226).",
    ["outcome"],
    registry=REGISTRY,
)

MFA_VERIFICATIONS_TOTAL = Counter(
    "octo_mfa_verifications_total",
    "Second-factor checks, by outcome (success, failure, recovery, "
    "setup_success, setup_failure). 'recovery' is a sign-in that spent a "
    "recovery code rather than an authenticator code (#315): it is a success, "
    "and a rate worth watching — a user burning codes has lost their phone, "
    "and a spike across accounts is an incident. The webauthn_* outcomes "
    "(webauthn_success, webauthn_failure, webauthn_setup_success, "
    "webauthn_setup_failure) are the same checks made with a security key.",
    ["outcome"],
    registry=REGISTRY,
)

BREAK_GLASS_LOGINS_TOTAL = Counter(
    "octo_break_glass_logins_total",
    "Password logins accepted on an installation where SSO is configured and "
    "OCTO_LOCAL_LOGIN=break-glass (#315). Every increment is an operator "
    "deliberately using the emergency door, so this is the series to alert on "
    "rather than to graph — see docs/operations.md § Break-glass local login.",
    registry=REGISTRY,
)

QUOTA_DENIED_TOTAL = Counter(
    "octo_quota_denied_total",
    "Actions refused because a tenant's purchased limit was reached, by "
    "resource (assets, scans). 'scans' is a refused scan start the operator "
    "sees as a 429; 'assets' counts ingest events where newly discovered "
    "assets were not registered — nobody is told about that one interactively, "
    "which is why it is a metric.",
    ["resource"],
    registry=REGISTRY,
)

SCAN_POLICY_REFUSALS_TOTAL = Counter(
    "octo_scan_policy_refusals_total",
    "Scans refused by a tenant's scan policy (#362), by reason. 'safe_only' "
    "and 'avoid_ports' are a start the operator sees as a 403; "
    "'agent_unsupported' is a job left in the queue because the agent that "
    "asked for it does not declare the 'scan_policy' capability and so cannot "
    "pace itself — that one is the series to alert on, because nobody is told "
    "about it interactively and the scan simply does not happen.",
    ["reason"],
    registry=REGISTRY,
)

NATS_CONSUMER_PENDING = Gauge(
    "octo_nats_consumer_pending",
    "JetStream durable consumer pending message count (consumer lag).",
    ["consumer"],
    registry=REGISTRY,
)
NATS_CONSUMER_PENDING_TIMESTAMP = Gauge(
    "octo_nats_consumer_pending_timestamp_seconds",
    "Unix time at which this replica last refreshed octo_nats_consumer_pending "
    "for the consumer. The count is read on each poll, so a worker that has "
    "stopped polling leaves its last value standing instead of a rising one; "
    "this is the series that ages when that happens (#334). Prometheus stamps "
    "every sample of the count with the scrape time, so the count's own "
    "timestamp() cannot tell.",
    ["consumer"],
    registry=REGISTRY,
)

NATS_STREAM_CONFIG_DRIFT = Gauge(
    "octo_nats_stream_config_drift",
    "1 when a JetStream stream runs with a setting other than the one this API "
    "replica asked for, by stream and setting. Reconciling an existing stream "
    "is deliberately fail-soft, so this is the only signal that a "
    "duplicate_window or replica count never took — and the duplicate window is "
    "what keeps an outbox replay from doubling a run in ClickHouse.",
    ["stream", "setting"],
    registry=REGISTRY,
)
NATS_LEGACY_INGEST_TOTAL = Counter(
    "octo_nats_legacy_ingest_total",
    "Publishes of the deprecated ingest.raw_results copy of each run, by "
    "outcome. Nothing in this installation subscribes to it (the ClickHouse "
    "worker is bound to ingest.results.>), so outcome=refused is a broker or "
    "an account policy rejecting a subject on its way out — worth a ticket, "
    "never a reason to hold the run's real publish back.",
    ["outcome"],
    registry=REGISTRY,
)

NATS_OUTBOX_BACKLOG = Gauge(
    "octo_nats_outbox_backlog",
    "Publications the broker refused and has not accepted since, split by "
    "kind (ingest or asset_event) and status (pending, dead, or stale for the "
    "pending rows older than the alert window). Cluster-wide — every replica "
    "reports the same query, so aggregate with max(), not sum(). kind=ingest "
    "delays the ClickHouse projection; kind=asset_event delays webhook fan-out.",
    ["kind", "status"],
    registry=REGISTRY,
)
NATS_OUTBOX_TOTAL = Counter(
    "octo_nats_outbox_total",
    "NATS outbox entries by kind and outcome (recorded, republished, dead, "
    "dropped — 'dropped' meaning the outbox was disabled and the message is "
    "simply gone).",
    ["kind", "outcome"],
    registry=REGISTRY,
)

CH_INGEST_BATCH_DURATION_SECONDS = Histogram(
    "octo_ch_ingest_batch_duration_seconds",
    "Time to transform + insert one ingest message into ClickHouse.",
    registry=REGISTRY,
)
CH_INGEST_MESSAGES_TOTAL = Counter(
    "octo_ch_ingest_messages_total",
    "ClickHouse ingest messages processed, by outcome.",
    ["result"],
    registry=REGISTRY,
)

# Endpoint inventory (Agent_plan.md S9 / §15). Labels are deliberately
# low-cardinality — no agent, device, asset, tenant, or product names.
ENDPOINT_SUBMISSIONS_TOTAL = Counter(
    "octo_endpoint_inventory_submissions_total",
    "Endpoint inventory submissions, by outcome "
    "(accepted, replay, rate_limited, too_large, conflict, invalid, error).",
    ["result"],
    registry=REGISTRY,
)
ENDPOINT_INGEST_DURATION_SECONDS = Histogram(
    "octo_endpoint_inventory_ingest_duration_seconds",
    "Endpoint inventory submission handling duration in seconds.",
    registry=REGISTRY,
)
ENDPOINT_SOFTWARE_ITEMS = Histogram(
    "octo_endpoint_inventory_software_items",
    "Software entries per accepted endpoint inventory snapshot.",
    buckets=(1, 10, 50, 100, 250, 500, 1000, 2500, 5000),
    registry=REGISTRY,
)
ENDPOINT_SOFTWARE_CHANGES_TOTAL = Counter(
    "octo_endpoint_inventory_software_changes_total",
    "Software change events generated, by event type.",
    ["event_type"],
    registry=REGISTRY,
)
# octo_endpoint_devices is read at scrape time too: CLUSTER_COLLECTOR (#334).
ENDPOINT_RETENTION_DELETED_TOTAL = Counter(
    "octo_endpoint_retention_deleted_total",
    "Rows deleted by the endpoint-inventory retention job, by table.",
    ["table"],
    registry=REGISTRY,
)
SCHEDULER_IS_LEADER = Gauge(
    "octo_scheduler_is_leader",
    "1 when this replica holds the schedule-dispatcher advisory lock (ROADMAP P1.6).",
    registry=REGISTRY,
)
ASSET_EVENTS_PUBLISHED_TOTAL = Counter(
    "octo_asset_events_published_total",
    "Asset-level events by kind and publish outcome (ROADMAP Phase 10.2). "
    "outcome=deferred means the broker did not take the event and it is in "
    "nats_outbox, to be published — and to feed its webhooks — when the broker "
    "is back. outcome=skipped is the same event with nowhere to wait: "
    "OCTO_NATS_OUTBOX_ENABLED=false, or a database that refused the rows, so "
    "the event exists only in the run's diff.json (or, for the operator's "
    "decommissioned_host, in the asset row and the audit log) and its "
    "notification is never sent.",
    ["kind", "outcome"],
    registry=REGISTRY,
)
AUDIT_EVENTS_PUBLISHED_TOTAL = Counter(
    "octo_audit_events_published_total",
    "Administrative audit events published to events.audit.{tenant} by outcome "
    "(#328). outcome=skipped means no broker was configured or reachable and "
    "outcome=error that a publish was attempted and failed — in both cases the "
    "row is committed and readable via GET /api/audit, so this counter measures "
    "a missing notification, never a missing record. No kind label, unlike the "
    "asset counter: the action is a dotted verb and would be one series each.",
    ["outcome"],
    registry=REGISTRY,
)
WORKFLOW_EVENTS_TOTAL = Counter(
    "octo_workflow_events_total",
    "Remediation-workflow events by kind and outcome (#349). outcome=queued "
    "means at least one subscription took it, no_subscription that the tenant "
    "has none matching (the ordinary case, not a failure), and error that the "
    "fan-out itself failed — in which case the notification is lost while the "
    "change that produced it is committed.",
    ["kind", "outcome"],
    registry=REGISTRY,
)
SLA_ESCALATIONS_TOTAL = Counter(
    "octo_sla_escalations_total",
    "Findings escalated by the SLA worker, by action (reassigned, "
    "severity_bumped) (#349).",
    ["action"],
    registry=REGISTRY,
)
WEBHOOK_DELIVERIES_TOTAL = Counter(
    "octo_webhook_deliveries_total",
    "Webhook deliveries by outcome (queued, delivered, retrying, dead) "
    "(ROADMAP Phase 10.3). outcome=dead is the dead-letter queue.",
    ["outcome"],
    registry=REGISTRY,
)
WEBHOOK_DELIVERY_DURATION_SECONDS = Histogram(
    "octo_webhook_delivery_duration_seconds",
    "Duration of one webhook delivery attempt in seconds.",
    # The per-request timeout defaults to 10s, so the default buckets (topping
    # out at 10s) would leave every timed-out attempt in +Inf.
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
    registry=REGISTRY,
)
WEBHOOK_DELIVERY_QUEUE = Gauge(
    "octo_webhook_delivery_queue",
    "Webhook deliveries currently in the table, by status. Cluster-wide (every "
    "replica reports the same query), so aggregate with max(), not sum().",
    ["status"],
    registry=REGISTRY,
)
TICKET_SYNC_LAG_SECONDS = Gauge(
    "octo_ticket_sync_lag_seconds",
    "How long the oldest still-due linked ticket has waited to be read back "
    "(#347), as of the last tick of the inbound sync worker. It grows when a "
    "tracker is unreachable, when one tick cannot drain the estate, and when "
    "no replica holds the leader lock — which is the case the manual button "
    "used to hide entirely. Reported only by the leader; followers leave it at "
    "0, so aggregate with max(), not sum().",
    ["transport"],
    registry=REGISTRY,
)
TICKET_SYNC_POLLS_TOTAL = Counter(
    "octo_ticket_sync_polls_total",
    "Tickets read back by the inbound sync worker, by transport and outcome. "
    "outcome=applied means the tracker's status moved the finding, "
    "outcome=unchanged that it agreed with the finding's state, and "
    "outcome=failed that the ticket could not be read at all.",
    ["transport", "outcome"],
    registry=REGISTRY,
)
TICKET_SYNC_IS_LEADER = Gauge(
    "octo_ticket_sync_is_leader",
    "1 when this replica holds the ticket-sync advisory lock (#347). Sums to "
    "1 across a healthy cluster; 0 everywhere means nothing is reading "
    "trackers back and every ticket-driven closure is waiting on a human.",
    registry=REGISTRY,
)
ENDPOINT_RETENTION_RUN_DURATION_SECONDS = Histogram(
    "octo_endpoint_retention_run_duration_seconds",
    "Duration of one endpoint-inventory retention sweep in seconds.",
    registry=REGISTRY,
)


# --- SQLAlchemy connection pool (#334) ------------------------------------
#
# Per replica, unlike the fleet and backlog gauges: each API process has its
# own pool, and sum() across replicas is the number of connections the
# installation holds against the server's max_connections (#335). The two
# event series are fed by ``api.db.engine.InstrumentedQueuePool``; the gauges
# are read off the live pool at scrape time by :class:`DbPoolCollector`.

DB_POOL_CHECKOUT_DURATION_SECONDS = Histogram(
    "octo_db_pool_checkout_duration_seconds",
    "Time a caller waited for a Postgres connection from this replica's pool: "
    "the queue wait, plus the handshake when the pool had to open a new "
    "connection. Checkouts that timed out are observed too, so a pool at its "
    "limit shows here as a tail at OCTO_DB_POOL_TIMEOUT before it shows as "
    "errors.",
    # From a pooled hand-over (well under a millisecond) to past the 30 s default
    # of OCTO_DB_POOL_TIMEOUT: a checkout that gives up waited a little *more*
    # than the timeout, and a top bucket equal to it put every one of them in
    # +Inf, where no quantile can be read.
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 40, 60),
    registry=REGISTRY,
)
DB_POOL_CHECKOUT_TIMEOUTS_TOTAL = Counter(
    "octo_db_pool_checkout_timeouts_total",
    "Checkouts that gave up after OCTO_DB_POOL_TIMEOUT because the pool and its "
    "overflow were all in use. Each one is a request that failed without "
    "reaching the database; the answer is a bigger pool or finding what holds "
    "connections, not a longer timeout.",
    registry=REGISTRY,
)


class DbPoolCollector:
    """Gauges read off the live SQLAlchemy pool when Prometheus asks.

    Read rather than kept in step with pool events: a gauge that events move
    drifts the first time one is missed, and ``checkedout()``/``checkedin()``
    are the numbers the pool itself decides with. No engine yet (a replica
    that has not touched its database), or a pool that is not a queue (the
    SQLite fallback), reports nothing rather than zeros: an empty pool and no
    pool are different answers.
    """

    _FAMILIES = (
        ("octo_db_pool_size", "Connections this replica's pool keeps open (OCTO_DB_POOL_SIZE)."),
        (
            "octo_db_pool_max_overflow",
            "Connections the pool may open beyond its size under load "
            "(OCTO_DB_MAX_OVERFLOW); size + max_overflow is the most this replica "
            "will ever hold.",
        ),
        (
            "octo_db_pool_timeout_seconds",
            "How long a checkout waits for a free connection before failing (OCTO_DB_POOL_TIMEOUT).",
        ),
        (
            "octo_db_pool_checked_out",
            "Connections in use right now. Includes the one each leader lock this "
            "replica holds keeps for as long as it leads, so the floor is not zero.",
        ),
        ("octo_db_pool_checked_in", "Open connections idle in the pool."),
        ("octo_db_pool_overflow", "Overflow connections open right now, beyond the pool's size."),
    )

    def describe(self) -> Iterator[Metric]:
        for name, documentation in self._FAMILIES:
            yield GaugeMetricFamily(name, documentation)

    def collect(self) -> Iterator[Metric]:
        # Imported here, not at module level: the engine module imports this
        # one for the two event series above.
        from api.db import engine as db_engine

        status = db_engine.pool_status()
        values = (
            None
            if status is None
            else (
                status.size,
                status.max_overflow,
                status.timeout,
                status.checked_out,
                status.checked_in,
                status.overflow,
            )
        )
        for index, (name, documentation) in enumerate(self._FAMILIES):
            family = GaugeMetricFamily(name, documentation)
            if values is not None:
                family.add_metric([], values[index])
            yield family


DB_POOL_COLLECTOR = DbPoolCollector()
REGISTRY.register(DB_POOL_COLLECTOR)


# --- Cluster-wide and per-tenant series, read from the database (#334) -----
#
# Read from shared tables at scrape time by :class:`SnapshotCollector`, through
# ``api.services.metrics_sources`` (the one place a scrape opens a session).
# Every replica therefore reports the same numbers: aggregate with max(), not
# sum(). The job queue and the endpoint devices used to be *set* here by
# whichever replica handled the last job event or retention sweep, so replicas
# disagreed indefinitely and max() picked the most stale of them.
#
# Labels come from fixed vocabularies (docs/observability.md § Label bounds).
# The one tenant label is on the opt-in tenant series, capped at
# OCTO_METRICS_TENANT_TOP_N ids plus ``_other``.

#: How long one cluster snapshot answers scrapes for. /metrics answers anyone
#: who can reach it unless OCTO_METRICS_TOKEN is set, so without a cache every
#: request to it would be a query against the database; with it the cost is
#: one short transaction per replica per TTL, however often it is asked. Well
#: under the 60 s sensor heartbeat, so the ages it reports are late by at most
#: this.
CLUSTER_TTL_SECONDS = 15.0
#: How long a snapshot may still be served while a fresh one cannot be taken
#: (the pool has no room). Past this the series are withdrawn: absent is
#: honest, an old number drawn as a current one is not.
CLUSTER_MAX_STALE_SECONDS = 60.0
#: The per-tenant series scan the findings table; a minute is fresh enough for
#: a product dashboard and a quarter of the work.
TENANT_TTL_SECONDS = 60.0
TENANT_MAX_STALE_SECONDS = 180.0
#: Connections that must be free before a scrape takes one. One is not enough:
#: checking for one free connection and then taking it races the next request,
#: which then waits OCTO_DB_POOL_TIMEOUT — longer than Prometheus waits for the
#: scrape. A check, not a reservation: a burst in between can still make the
#: scrape wait, which the statement timeout does not bound.
POOL_HEADROOM = 2
#: How often a snapshot that the pool keeps too busy to take is logged. The
#: series are gone meanwhile, and the alerts on them with them; once per scrape
#: would bury the line, never would hide it.
STARVED_WARNING_INTERVAL_SECONDS = 600.0
#: Why a refresh that was due produced no snapshot.
MISS_REASONS = ("pool_busy", "error")


class SnapshotCollector:
    """Series rendered from one cached database snapshot per TTL.

    What keeps a scrape from costing more than one snapshot per TTL:

    * the TTL, measured from the last *attempt*, failed ones included — so a
      query that keeps failing is tried once per TTL, not once per request to
      an unauthenticated endpoint, and logged as often;
    * a non-blocking lock, so while one scrape runs the query the others are
      answered from the previous snapshot instead of each parking a worker
      thread behind it;
    * no attempt while the pool has fewer than :data:`POOL_HEADROOM`
      connections free. A busy pool is when the dashboards are being read, and
      a scrape that waited OCTO_DB_POOL_TIMEOUT for a connection would lose the
      whole /metrics answer — the pool gauges with it — to Prometheus's scrape
      timeout, and take a connection from a request to do it.

    A failed attempt withdraws the series rather than freezing them. Either
    way the gap is visible: :class:`SnapshotHealthCollector` exports how old
    the last snapshot is and the refreshes that were missed, and a snapshot
    the pool keeps too busy to take is logged.

    ``epoch``, when given, is a second expiry besides the TTL: a snapshot taken
    under another epoch is retaken at the next scrape. The tenant series use
    the wall-clock hour, the period their named set is fixed for.
    """

    def __init__(
        self,
        *,
        render: Callable[[Any], list[Metric]],
        snapshot: Callable[[], Any],
        ttl: float,
        max_stale: float,
        clock: Callable[[], float] = time.monotonic,
        pool_too_busy: Callable[[], bool] | None = None,
        epoch: Callable[[], int] | None = None,
    ) -> None:
        self._render = render
        self._snapshot_fn = snapshot
        self._ttl = ttl
        self._max_stale = max_stale
        self._clock = clock
        self._pool_too_busy = pool_too_busy or _pool_too_busy
        self._epoch = epoch
        self._lock = threading.Lock()
        self._snapshot: Any = None
        self._taken_at: float | None = None
        self._attempted_at: float | None = None
        self._attempted_epoch: int | None = None
        self._started_at = clock()
        self._succeeded_at: float | None = None
        self._starved_warned_at: float | None = None
        self.misses = dict.fromkeys(MISS_REASONS, 0)

    def render(self, snapshot: Any) -> list[Metric]:
        """The families for ``snapshot``; without one, described but empty."""
        return self._render(snapshot)

    def expire(self) -> None:
        """Make the next scrape try afresh, keeping the current snapshot until then."""
        self._attempted_at = None

    def reset_for_tests(self) -> None:
        with self._lock:
            self._snapshot = None
            self._taken_at = None
            self._attempted_at = None
            self._attempted_epoch = None

    def age(self) -> float:
        """Seconds since the last snapshot was taken, or since start if none was."""
        since = self._succeeded_at if self._succeeded_at is not None else self._started_at
        return max(0.0, self._clock() - since)

    def describe(self) -> Iterator[Metric]:
        # Described even when empty, so the registry reserves the names and the
        # catalogue checks see them without a database.
        return iter(self._render(None))

    def collect(self) -> Iterator[Metric]:
        return iter(self._render(self._current()))

    def _current(self) -> Any:
        now = self._clock()
        if self._lock.acquire(blocking=False):
            try:
                self._refresh(now)
            finally:
                self._lock.release()
        # Read after this scrape's refresh, or while somebody else's is still
        # running: whatever is there is served only while it is recent enough
        # to be true.
        snapshot, taken_at = self._snapshot, self._taken_at
        if taken_at is None or now - taken_at > self._max_stale:
            return None
        return snapshot

    def _due(self, now: float) -> bool:
        if self._attempted_at is None or now - self._attempted_at >= self._ttl:
            return True
        return self._epoch is not None and self._epoch() != self._attempted_epoch

    def _refresh(self, now: float) -> None:
        if not self._due(now):
            return
        if self._pool_too_busy():
            # Not an attempt: the next scrape looks again.
            self.misses["pool_busy"] += 1
            self._warn_if_starved(now)
            return
        self._attempted_at = now
        self._attempted_epoch = self._epoch() if self._epoch is not None else None
        try:
            snapshot = self._snapshot_fn()
        except Exception as exc:  # noqa: BLE001 - one collector must not fail the scrape
            self.misses["error"] += 1
            LOG.warning(
                "Could not read %s for /metrics (%s: %s); the series are withdrawn until "
                "the next attempt in %.0f s",
                self._name(),
                type(exc).__name__,
                _first_line(exc),
                self._ttl,
            )
            LOG.debug("scrape snapshot failed", exc_info=True)
            self._snapshot, self._taken_at = None, None
            return
        self._snapshot, self._taken_at = snapshot, now
        self._succeeded_at = now
        self._starved_warned_at = None

    def _warn_if_starved(self, now: float) -> None:
        """Log, once per interval, a snapshot the pool has kept too busy to take.

        Six leader-lock workers each hold a connection for as long as they
        lead, so a small pool may never have :data:`POOL_HEADROOM` free: the
        series would then never appear and nothing would say why.
        """
        if self.age() <= self._max_stale:
            return
        if (
            self._starved_warned_at is not None
            and now - self._starved_warned_at < STARVED_WARNING_INTERVAL_SECONDS
        ):
            return
        self._starved_warned_at = now
        from api.db import engine as db_engine

        LOG.warning(
            "%s has not been read for /metrics for %.0f s: the database pool never had "
            "%d connections free when it was due (%s). Its series are withdrawn and the "
            "alerts on them cannot fire. Raise OCTO_DB_POOL_SIZE or OCTO_DB_MAX_OVERFLOW; "
            "leader-lock workers hold one connection each for as long as they lead.",
            self._name(),
            self.age(),
            POOL_HEADROOM,
            db_engine.pool_status(),
        )

    def _name(self) -> str:
        return getattr(self._snapshot_fn, "__name__", "a snapshot")


def _first_line(exc: BaseException) -> str:
    """The cause, not the statement: a driver error's first line, bounded."""
    text = str(exc).strip()
    return text.splitlines()[0][:200] if text else ""


class SnapshotHealthCollector:
    """How old each snapshot is and how many refreshes it missed, per replica.

    Read from the collectors' own state, never from the database: this is what
    is left to look at when the database is what is wrong. The age counts from
    process start until the first snapshot, so a replica that never managed
    one still has an age to alert on.
    """

    def __init__(self, collectors: dict[str, SnapshotCollector]) -> None:
        self._collectors = collectors

    def describe(self) -> Iterator[Metric]:
        # With samples: they cost nothing to read, and the catalogue checks
        # learn the labels from them.
        return self.collect()

    def collect(self) -> Iterator[Metric]:
        return iter(self._families())

    def _families(self) -> list[Metric]:
        age = GaugeMetricFamily(
            "octo_metrics_snapshot_age_seconds",
            "Seconds since this replica last read the snapshot behind a group of "
            "scrape-time series (cluster: fleet, queue, devices; tenant: the "
            "per-tenant series), or since it started if it never has. Per replica.",
            labels=["snapshot"],
        )
        misses = CounterMetricFamily(
            "octo_metrics_snapshot_misses",
            "Snapshot refreshes that were due and produced nothing: pool_busy (not "
            "attempted, fewer than two connections free) or error (the query "
            "failed). Per replica.",
            labels=["snapshot", "reason"],
        )
        for name, collector in self._collectors.items():
            age.add_metric([name], collector.age())
            for reason in MISS_REASONS:
                misses.add_metric([name, reason], collector.misses[reason])
        return [age, misses]


def _pool_too_busy() -> bool:
    from api.db import engine as db_engine

    status = db_engine.pool_status()
    return status is not None and status.free < POOL_HEADROOM


def _cluster_snapshot() -> MetricsClusterSnapshot | None:
    from api.services import metrics_sources

    return metrics_sources.cluster_snapshot()


def _tenant_snapshot() -> MetricsTenantSnapshot | None:
    from api.services import metrics_sources

    return metrics_sources.tenant_snapshot()


def _tenant_pool_too_busy() -> bool:
    """Off — the default — the tenant snapshot reads nothing, so it neither
    waits for the pool nor reports being starved by it."""
    from api.services import metrics_sources

    return metrics_sources.tenant_series_enabled() and _pool_too_busy()


def _membership_epoch() -> int:
    from api.services import metrics_sources

    return metrics_sources.membership_epoch()


def _cluster_families(snapshot: MetricsClusterSnapshot | None) -> list[Metric]:
    agents = GaugeMetricFamily(
        "octo_agents",
        "Registered sensors (agent_kind=scanner) and endpoint agents "
        "(agent_kind=endpoint), by state: idle/busy/error as last reported by one "
        "heard from within OCTO_AGENT_STALE_SECONDS, stale past it, or "
        "disabled/quarantined by an operator whatever it reports. Cluster-wide: "
        "aggregate with max(), not sum().",
        labels=["agent_kind", "state"],
    )
    ages = GaugeHistogramMetricFamily(
        "octo_agent_heartbeat_age_seconds",
        "Seconds since each active (neither disabled nor quarantined) sensor or "
        "agent was last heard from, as a distribution per kind; "
        "histogram_quantile() over max by (le, agent_kind) gives percentiles. "
        "Cluster-wide.",
        labels=["agent_kind"],
    )
    oldest = GaugeMetricFamily(
        "octo_agent_heartbeat_age_max_seconds",
        "The longest silence among active sensors or agents of a kind; absent for "
        "a kind with none. Cluster-wide.",
        labels=["agent_kind"],
    )
    threshold = GaugeMetricFamily(
        "octo_agent_stale_threshold_seconds",
        "OCTO_AGENT_STALE_SECONDS: the heartbeat age past which an agent is "
        "reported stale. Cluster-wide.",
    )
    queued = GaugeMetricFamily(
        "octo_jobs_queued",
        "Scan jobs waiting for a sensor or a local slot, read from the jobs table "
        "at scrape time. Cluster-wide: aggregate with max(), not sum().",
    )
    running = GaugeMetricFamily(
        "octo_jobs_running",
        "Scan jobs claimed, running or being cancelled, read from the jobs table "
        "at scrape time. Cluster-wide: aggregate with max(), not sum().",
    )
    devices = GaugeMetricFamily(
        "octo_endpoint_devices",
        "Endpoint devices by staleness (OCTO_ENDPOINT_STALE_HOURS), read at scrape "
        "time; absent with the endpoint inventory off. Cluster-wide: aggregate "
        "with max(), not sum().",
        labels=["state"],
    )
    families = [agents, ages, oldest, threshold, queued, running, devices]
    if snapshot is None:
        return families
    # Not at module level, and not before there is a snapshot: describe()
    # runs while this module is still being imported, and the agents service
    # imports the engine, which imports this module.
    from api.services import agents as agents_service

    fleet = snapshot.fleet
    for (kind, state), count in sorted(fleet.counts.items()):
        agents.add_metric([kind, state], count)
    for kind in agents_service.FLEET_KINDS:
        buckets = [
            (floatToGoString(bound), count)
            for bound, count in zip(
                agents_service.HEARTBEAT_AGE_BUCKETS, fleet.age_buckets[kind], strict=True
            )
        ]
        buckets.append(("+Inf", fleet.age_totals[kind]))
        ages.add_metric([kind], buckets, fleet.age_sums[kind])
        if kind in fleet.age_max:
            oldest.add_metric([kind], fleet.age_max[kind])
    threshold.add_metric([], fleet.stale_seconds)
    queued.add_metric([], snapshot.jobs_queued)
    running.add_metric([], snapshot.jobs_running)
    if snapshot.endpoint_devices is not None:
        for state in ("active", "stale"):
            devices.add_metric([state], snapshot.endpoint_devices[state])
    return families


def _tenant_families(snapshot: MetricsTenantSnapshot | None) -> list[Metric]:
    open_findings = GaugeMetricFamily(
        "octo_tenant_open_findings",
        "Open findings (any state but CLOSED) per tenant and severity. Opt-in "
        "(OCTO_METRICS_TENANT_TOP_N): the top N tenants by open findings when "
        "the hour began keep their id, so the set changes only on the hour; the "
        "rest are summed into tenant=\"_other\". Cluster-wide.",
        labels=["tenant", "severity"],
    )
    breached = GaugeMetricFamily(
        "octo_tenant_sla_breached_findings",
        "Open findings past their SLA due date and not under an accepted "
        "exception, per tenant (top N, the rest as _other). Cluster-wide.",
        labels=["tenant"],
    )
    scans = GaugeMetricFamily(
        "octo_tenant_scans_finished_24h",
        "Scans that finished in the last 24 hours, per tenant (top N, the rest as "
        "_other) and outcome. A window count, not a counter: use it as it is. "
        "Cluster-wide.",
        labels=["tenant", "status"],
    )
    if snapshot is not None:
        for (tenant, severity), count in sorted(snapshot.open_findings.items()):
            open_findings.add_metric([tenant, severity], count)
        for tenant, count in sorted(snapshot.sla_breached.items()):
            breached.add_metric([tenant], count)
        for (tenant, status), count in sorted(snapshot.scans_finished.items()):
            scans.add_metric([tenant, status], count)
    return [open_findings, breached, scans]


def cluster_collector(
    *,
    snapshot: Callable[[], Any] | None = None,
    clock: Callable[[], float] = time.monotonic,
    pool_too_busy: Callable[[], bool] | None = None,
) -> SnapshotCollector:
    """The fleet, the job queue and the endpoint devices (tests build their own)."""
    return SnapshotCollector(
        render=_cluster_families,
        snapshot=snapshot or _cluster_snapshot,
        ttl=CLUSTER_TTL_SECONDS,
        max_stale=CLUSTER_MAX_STALE_SECONDS,
        clock=clock,
        pool_too_busy=pool_too_busy,
    )


def tenant_collector(
    *,
    snapshot: Callable[[], Any] | None = None,
    clock: Callable[[], float] = time.monotonic,
    pool_too_busy: Callable[[], bool] | None = None,
) -> SnapshotCollector:
    """The opt-in per-tenant series; no samples while they are off."""
    return SnapshotCollector(
        render=_tenant_families,
        snapshot=snapshot or _tenant_snapshot,
        ttl=TENANT_TTL_SECONDS,
        max_stale=TENANT_MAX_STALE_SECONDS,
        clock=clock,
        pool_too_busy=pool_too_busy or _tenant_pool_too_busy,
        epoch=_membership_epoch,
    )


CLUSTER_COLLECTOR = cluster_collector()
REGISTRY.register(CLUSTER_COLLECTOR)
TENANT_COLLECTOR = tenant_collector()
REGISTRY.register(TENANT_COLLECTOR)
SNAPSHOT_HEALTH = SnapshotHealthCollector({"cluster": CLUSTER_COLLECTOR, "tenant": TENANT_COLLECTOR})
REGISTRY.register(SNAPSHOT_HEALTH)


def render() -> tuple[bytes, str]:
    """Return the current metrics snapshot and its Prometheus content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
