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
ENDPOINT_RETENTION_RUN_DURATION_SECONDS = Histogram(
    "octo_endpoint_retention_run_duration_seconds",
    "Duration of one endpoint-inventory retention sweep in seconds.",
    registry=REGISTRY,
)


def render() -> tuple[bytes, str]:
    """Return the current metrics snapshot and its Prometheus content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
