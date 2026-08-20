# Service level objectives

Objectives for a Shapoclyack installation, defined against the Prometheus
series the API already exports (`GET /metrics`, ROADMAP P3.4). Scrape wiring is
in [k8s/README.md](../k8s/README.md) ("Metrics scraping"); the series catalogue
for endpoint inventory is in [operations.md](operations.md).

**SLO 2 (GET p95 < 500 ms) is backed by a recorded end-to-end run**
([#185](https://github.com/onixus/Shapoclyack/issues/185), 2026-08-20, below).
SLO 4 remains per-installation (scan duration depends on target-set size).
SLO 5 still has no ingest-enabled measurement on the kind lab — the 1 000
message lag stays a starting value until ClickHouse ingest is on. Move a
target before you page anyone on it if your stand is slower than this lab.

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
| 8 | Authentication | login attempts by outcome | **no target** — a security signal, alerted on directly ([below](#8-authentication-a-security-signal-not-an-availability-one)) |

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

### Measured GET latency (#185)

Recorded 2026-08-20 on kind `shapoclyack-dev`, overlay `kind-dev`, **one** API
replica (`shapoclyack-aio:kind-dev`), Mac host, `GET` through FastAPI with
JWT. Dataset: tenant `scale-test` from `tests/fixtures/scale_seed.py`
(`--skip-clickhouse`). 40 requests per cell. Probe:
`python -m tests.fixtures.api_latency` ([development.md](development.md#end-to-end-api-latency-185)).

p95 milliseconds:

| Route | 1k × conc 1 | 1k × 32 | 10k × 32 | 50k × 32 |
|---|---:|---:|---:|---:|
| `/api/assets?limit=100` | 5.4 | 166.5 | 179.9 | 179.8 |
| `/api/runs?limit=100` | 1.3 | 32.0 | 34.6 | 33.1 |
| `/api/jobs?limit=100` | 2.3 | 69.9 | 69.7 | 67.3 |
| `/api/agents?limit=100` | 2.1 | 72.7 | 72.9 | 97.1 |
| `/api/schedules?limit=100` | 2.3 | 84.2 | 67.8 | 67.1 |
| `/api/vulnerabilities?limit=100` | 2.4 | 88.4 | 74.1 | 93.2 |
| `/api/system` | 20.8 | 538.3 | 583.0 | 498.1 |

Server histogram `octo_http_request_duration_seconds` GET p95 (cumulative
since process start, all GET routes) was **89–159 ms** across these runs —
the same order as the client p95 on list routes, so the queue is not sitting
in front of the metrics middleware on this stand.

**What this says about SLO 2.** The 500 ms GET p95 holds for paginated list
routes at 50k assets and 32 concurrent clients on one replica. It is **tight
or missed** on `GET /api/system` at 32 concurrent (p95 498–583 ms) — that
route is versions + enrichment-DB freshness, not the estate list. Keep 500 ms
for the list SLO; treat `/api/system` as a separate, heavier read. Two
replicas (#188) are not in this baseline.

**SLO 4 / 5 on this stand.** After the API pod restart there were no
`octo_job_duration_seconds` observations, and `octo_nats_consumer_pending` for
`octo-ch-ingest` was absent (ingest off). Those two targets stay
installation-specific / starting values until a stand with job history and
ClickHouse ingest is measured.

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

`octo_job_lease_expired_total{outcome="requeued"}` is the fleet-health signal
underneath the ratio above: a rising rate means agents are dying mid-job and
their work is being handed to someone else. `outcome="failed"` means a job
exhausted `OCTO_JOB_MAX_ATTEMPTS` (or was a local job whose replica died) and
was given up on — those *do* land in the failure side of SLO 3.

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

### 8. Authentication (a security signal, not an availability one)

`octo_auth_attempts_total{outcome}` has no objective attached, and it is listed
here because it is the one series on this page you alert on directly rather
than through a burn rate. There is no error budget for password guessing: a
sustained failure rate is not a fraction of acceptable, it is an event.

```promql
# Refusals by the login limiter — someone is being stopped, repeatedly.
sum(rate(octo_auth_attempts_total{outcome="locked"}[5m])) > 0

# Failures far above the daily norm, whether or not any lock has tripped
# (a slow, distributed attempt stays under the per-pair limit by design).
sum(rate(octo_auth_attempts_total{outcome="failure"}[15m]))
> 5 * sum(rate(octo_auth_attempts_total{outcome="failure"}[7d] offset 5m))
```

Both are ticket-level, not page-level: the limiter is already refusing the
traffic, and the value of the alert is that someone reads
`GET /api/auth/events` (see
[api-and-rbac.md](api-and-rbac.md#login-rate-limiting-and-the-auth-audit-trail))
and decides whether a *successful* login followed the failures. That last
question is the one the metric cannot answer on its own — `outcome="success"`
carries no username, deliberately, since a per-user label is unbounded
cardinality driven by whatever an attacker types.

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

The expressions that actually fire live in
[`k8s/shapoclyack/examples/prometheus-slo.rules.yaml`](../k8s/shapoclyack/examples/prometheus-slo.rules.yaml)
(#186). Do not copy thresholds from this page into a scrape config — they will
drift. The Prometheus Operator wrapper is
[`prometheusrule-slo.example.yaml`](../k8s/shapoclyack/examples/prometheusrule-slo.example.yaml);
installs without the operator load the same file via `rule_files` (see
[k8s/README.md](../k8s/README.md#metrics-scraping-prometheus)). Scheduler
leadership (`sum(octo_scheduler_is_leader) > 1` and `== 0`) is in that file
too, with `for:` windows that survive a rolling update.

## Known gaps

Each of these limits what can honestly be claimed today:

- ~~**Single-process gauges.**~~ Closed by ROADMAP P1.2: `octo_jobs_queued` /
  `octo_jobs_running` are now counted in the shared `jobs` table, so every
  replica reports the same queue depth and a restart no longer resets them.
  Because every replica publishes the *same* cluster-wide number, aggregate
  across replicas with `max()`, not `sum()`.
- ~~**Jobs can be lost silently.**~~ Closed by ROADMAP P1.4: an abandoned job
  no longer sits in flight forever with the gauge stuck above zero. It is
  requeued or failed within `OCTO_JOB_LEASE_SECONDS`, and either way it now
  reaches the histogram or the counter above rather than nothing.
- ~~**Scheduler leadership is observable but unaliased.**~~ Closed by
  [#186](https://github.com/onixus/Shapoclyack/issues/186):
  `ShapoclyackSchedulerSplitBrain` (`sum > 1`, `for: 5m`) and
  `ShapoclyackSchedulerNoLeader` (`sum == 0`, `for: 10m`) in
  `prometheus-slo.rules.yaml`. Both require the series to exist so a missing
  scrape does not page.
- **No per-tenant SLIs.** No metric carries a tenant label (deliberate —
  cardinality), so per-customer objectives are not derivable from `/metrics`.
- **Tracing is opt-in.** Set `OCTO_OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP
  HTTP traces URL; empty means no TracerProvider. API request spans do not
  replace Prometheus SLIs, and they are not scan observations. Scanner
  wall-clock stays in `stage_timings.json` (see
  [scan-performance.md](scan-performance.md)).
- ~~**No baseline at scale for API latency.**~~ Closed by
  [#185](https://github.com/onixus/Shapoclyack/issues/185): GET p95 was
  measured through FastAPI under concurrency on kind `shapoclyack-dev` (see
  [Measured GET latency](#measured-get-latency-185)). SLO 4 (job duration) is
  still per-installation — this stand had no `octo_job_duration_seconds`
  samples after the API restart. SLO 5 (ingest lag) does not apply until
  ClickHouse ingest is enabled; the series was absent on this lab. In-process
  query-path numbers remain in [scale-profile.md](scale-profile.md).
