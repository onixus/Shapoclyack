# Service level objectives

Objectives for a Shapoclyack installation, defined against the Prometheus
series the API already exports (`GET /metrics`, ROADMAP P3.4). Scrape wiring is
in [k8s/README.md](../k8s/README.md) ("Metrics scraping"); the series catalogue
for endpoint inventory is in [operations.md](operations.md).

**These targets are starting values, not measured commitments.** They were set
from the shape of the system, not from a production baseline — no scale
fixtures exist yet (ROADMAP P3.7/P3.8). Run the platform for a full window,
look at the achieved numbers, and move the targets before you page anyone on
them.

## Scope and measurement window

- **Window:** rolling 30 days, evaluated per installation (not per tenant —
  no metric carries a `tenant_id` label, by design).
- **Reporting period:** calendar month.
- **Applies to:** the API process. The scanner (`scanner/main.py`) and remote
  agent (`agent/worker.py`) run no HTTP server and export nothing directly;
  their contribution is visible only through `octo_job_duration_seconds`.

## SLIs and objectives

| # | SLO | SLI | Target |
|---|---|---|---|
| 1 | API availability | share of API requests not returning 5xx | **99.5 %** |
| 2 | API latency | p95 of read requests | **< 500 ms** |
| 3 | Job completion | share of finished jobs that succeeded | **≥ 95 %** |
| 4 | Job duration | p95 of successful `default`-profile jobs | **within the profile's expected window** (set per installation) |
| 5 | Ingest freshness | ClickHouse ingest consumer lag | **< 1 000 messages, 99 % of samples** |
| 6 | Ingest correctness | share of ingest messages processed without error | **≥ 99.9 %** |
| 7 | Endpoint inventory acceptance | share of submissions with `result="accepted"` | **≥ 99 %** |

### 1. API availability

```promql
1 - (
  sum(rate(octo_http_requests_total{status=~"5.."}[30d]))
  /
  sum(rate(octo_http_requests_total[30d]))
)
```

4xx is excluded: an expired JWT or a bad filter is the client's outcome, not an
outage. `/metrics` and `/api/health` are included in the denominator — they are
cheap and always-succeeding, so they inflate the ratio slightly; exclude them
with `path!~"/metrics|/api/health"` if you want a stricter reading.

### 2. API latency

```promql
histogram_quantile(0.95, sum by (le) (
  rate(octo_http_request_duration_seconds_bucket{method="GET"}[5m])
))
```

Measured on `GET` only. `POST /api/jobs` starts a scan and `POST
/api/agents/{id}/results` uploads an archive; neither belongs in a
user-facing-latency number. The `path` label is the **route template**
(`/api/runs/{run_id}/hosts`), not the raw URL, so cardinality stays bounded —
per-endpoint breakdowns are safe:

```promql
topk(5, histogram_quantile(0.95, sum by (le, path) (
  rate(octo_http_request_duration_seconds_bucket{method="GET"}[5m])
)))
```

The default `prometheus_client` histogram buckets top out at 10 s; anything
slower lands in `+Inf` and the quantile saturates. That is the signal to
profile (P3.8), not to widen the buckets.

### 3. Job completion

```promql
sum(rate(octo_job_duration_seconds_count{status="succeeded"}[30d]))
/
sum(rate(octo_job_duration_seconds_count[30d]))
```

The histogram observes only terminal jobs (`succeeded` / `failed`), and only
when both `started_at` and `finished_at` are present — a job killed before it
recorded a finish time is invisible here. A `cancelled` job (ROADMAP P1.3) is
deliberately not observed: it never executed, so counting it would charge an
operator's decision against the success ratio. Cross-check against
`octo_jobs_running`: a gauge stuck above zero with no matching histogram
increments means jobs are being lost, and that is worse than a failure rate.
`octo_jobs_running` counts both `running` and `claimed` jobs — a claimed job is
out with a worker, so folding it into `octo_jobs_queued` would read as a
backlog nothing is working on.

### 4. Job duration

```promql
histogram_quantile(0.95, sum by (le) (
  rate(octo_job_duration_seconds_bucket{status="succeeded"}[30d])
))
```

Bucketed from 30 s to 8 h (`api/services/metrics.py`) — the
`prometheus_client` default set stops at 10 s, which put every real scan in
`+Inf`. A p95 pinned at the top bucket means scans exceed 8 h, not that the
quantile is exact.

Deliberately left without a repository-wide number. Scan duration is a function
of target-set size, profile, rate limits, and whether NSE/Pulse stages run —
a value that fits a /24 lab is meaningless for 50k assets. Set it per
installation from your own p95 after a month, and split by `execution`
(`local` vs. agent) before comparing anything.

### 5. Ingest freshness

```promql
octo_nats_consumer_pending{consumer="octo-ch-ingest"}
```

Only exported when NATS **and** the ClickHouse ingest worker are both enabled
(`OCTO_NATS_URL`, `OCTO_CLICKHOUSE_URL`, `OCTO_CH_INGEST_ENABLED`) — on a
default install the series is simply absent, and this SLO does not apply. The
gauge is refreshed on each consumer poll, so a worker that has stopped polling
leaves a *stale* value rather than a rising one; alert on staleness too:

```promql
octo_nats_consumer_pending{consumer="octo-ch-ingest"} > 1000
or
(time() - timestamp(octo_nats_consumer_pending{consumer="octo-ch-ingest"})) > 300
```

This is queue depth, not end-to-end latency. There is no scan-finished →
row-queryable timer today; add one before promising a freshness number in a
customer-facing SLA.

### 6. Ingest correctness

```promql
sum(rate(octo_ch_ingest_messages_total{result="ok"}[30d]))
/
sum(rate(octo_ch_ingest_messages_total[30d]))
```

Pair with `octo_ch_ingest_batch_duration_seconds` — a rising batch duration at
a constant message rate is the earliest sign that the unpartitioned
`ReplacingMergeTree` tables are hitting read/merge amplification (ROADMAP P3.8).

### 7. Endpoint inventory acceptance

```promql
sum(rate(octo_endpoint_inventory_submissions_total{result="accepted"}[30d]))
/
sum(rate(octo_endpoint_inventory_submissions_total[30d]))
```

`result="replay"` counts as a *failure* here on purpose: idempotent replay is
correct behaviour, but a sustained replay share means an agent is retrying
without progressing. Break the ratio down by `result` before acting —
`rate_limited` and `too_large` are operator-tunable, `invalid` and `conflict`
are contract bugs.

## Error budget policy

| Burn | Response |
|---|---|
| < 50 % of the monthly budget | normal delivery |
| ≥ 50 % | reliability work takes priority over new scope in the affected area |
| ≥ 100 % | feature work in that area stops until the objective is met for one full window |

## Alerting

Alert on **budget burn rate**, not on threshold crossings — a single slow scrape
is not an incident. A fast-burn page (2 % of the monthly budget in 1 h) and a
slow-burn ticket (5 % in 6 h) are the usual starting pair.

## Known gaps

Each of these limits what can honestly be claimed today:

- ~~**Single-process gauges.**~~ Closed by ROADMAP P1.2: `octo_jobs_queued` /
  `octo_jobs_running` are now counted in the shared `jobs` table, so every
  replica reports the same queue depth and a restart no longer resets them.
  Because every replica publishes the *same* cluster-wide number, aggregate
  across replicas with `max()`, not `sum()`.
- **No per-tenant SLIs.** No metric carries a tenant label (deliberate —
  cardinality), so per-customer objectives are not derivable from `/metrics`.
- **No tracing.** OpenTelemetry is not wired up, so a slow request cannot be
  attributed to Postgres vs. ClickHouse vs. filesystem from metrics alone.
- **No baseline at scale.** Targets 2, 4, and 5 are still starting values. The
  1k/10k/50k fixtures exist (`tests/fixtures/scale_seed.py`, P3.7) and the
  query paths behind them have been profiled ([scale-profile.md](scale-profile.md),
  P3.8) — but that pass calls the services in-process, so it excludes FastAPI
  routing, serialization, auth, and the network, and it runs one query at a
  time. Re-deriving the API-latency target still needs an end-to-end
  measurement under concurrency. What the profiling did establish: the asset
  list is no longer N+1-bound (77 ms for a 5000-row page at 50k assets), and
  the ClickHouse diff helpers are bounded rather than fast — they refuse
  above `max_rows` instead of returning a truncated, silently wrong diff.
