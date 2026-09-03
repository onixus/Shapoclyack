"""Prometheus metrics registry (Phase P3.4).

A single process-wide ``CollectorRegistry`` shared by the HTTP middleware
(``api/app.py``), the job lifecycle (``api/services/jobs.py``), and the
ClickHouse ingest worker (``api/services/ch_ingest_worker.py``). Scraped via
``GET /metrics`` (unauthenticated, matching standard Prometheus practice —
restrict at the network/gateway layer, not app auth).
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

REGISTRY = CollectorRegistry()

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
JOBS_QUEUED = Gauge(
    "octo_jobs_queued",
    "Scan jobs currently queued.",
    registry=REGISTRY,
)
JOBS_RUNNING = Gauge(
    "octo_jobs_running",
    "Scan jobs currently running.",
    registry=REGISTRY,
)

JOB_LEASE_EXPIRED_TOTAL = Counter(
    "octo_job_lease_expired_total",
    "Jobs whose executor stopped renewing its lease, by what the reaper did "
    "(requeued, failed).",
    ["outcome"],
    registry=REGISTRY,
)

JOB_IDEMPOTENT_REPLAYS_TOTAL = Counter(
    "octo_job_idempotent_replays_total",
    "Requests recognised as a replay of one already applied, by operation "
    "(start, results).",
    ["operation"],
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

NATS_CONSUMER_PENDING = Gauge(
    "octo_nats_consumer_pending",
    "JetStream durable consumer pending message count (consumer lag).",
    ["consumer"],
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
ENDPOINT_DEVICES = Gauge(
    "octo_endpoint_devices",
    "Endpoint devices known to the installation, by derived staleness state.",
    ["state"],
    registry=REGISTRY,
)
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
    "outcome=skipped means the broker was disabled or unreachable, so the "
    "events exist only in the run's diff.json.",
    ["kind", "outcome"],
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
ENDPOINT_RETENTION_RUN_DURATION_SECONDS = Histogram(
    "octo_endpoint_retention_run_duration_seconds",
    "Duration of one endpoint-inventory retention sweep in seconds.",
    registry=REGISTRY,
)


def render() -> tuple[bytes, str]:
    """Return the current metrics snapshot and its Prometheus content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
