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


def render() -> tuple[bytes, str]:
    """Return the current metrics snapshot and its Prometheus content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
