# Observability

What the API exports on `GET /metrics`, how to wire it into Prometheus and
Grafana, and what each series and each label is bounded by
([#334](https://github.com/onixus/Shapoclyack/issues/334)). Objectives and the
error-budget policy built on these series are in [slo.md](slo.md); scrape
wiring without the Prometheus Operator is in
[k8s/README.md](../k8s/README.md#metrics-scraping-prometheus).

| What | Where |
|---|---|
| Series definitions | `api/services/metrics.py` (one private registry) |
| Alert rules, source of truth | `k8s/shapoclyack/examples/prometheus-slo.rules.yaml` |
| Alert unit tests (`promtool test rules`) | `k8s/shapoclyack/examples/prometheus-slo.rules.test.yaml` |
| Grafana dashboards | `k8s/shapoclyack/base/grafana-dashboards/*.json` |
| ServiceMonitor + PrometheusRule, opt-in | component `k8s/shapoclyack/base/monitoring` |
| Dashboards as sidecar ConfigMaps, opt-in | component `k8s/shapoclyack/base/grafana-dashboards` |
| `prod-ha` with both components | `k8s/shapoclyack/overlays/prod-ha-monitoring` |

Sensor-side metrics (the `agent/` process on a scanning node) are not part of
this page; they are tracked in [#366](https://github.com/onixus/Shapoclyack/issues/366).
Everything below is what the **API** knows, including what it knows about the
sensors from their heartbeats.

## Wiring it up

### Scraping

The API serves `/metrics` on its only port (`8080`, Service `shapoclyack-api`,
port name `http`). Base already carries `prometheus.io/scrape` annotations on
the pod template for annotation-driven Prometheus setups; with the Prometheus
Operator, use the ServiceMonitor from the `base/monitoring` component or from
`examples/servicemonitor.example.yaml`. **Use one or the other**: an API scraped
both ways arrives under two `job` values, and every `sum()` counts it twice.
The dashboards therefore pick exactly one `job`.

`/metrics` is open unless `OCTO_METRICS_TOKEN` is set (#319), in which case the
scraper sends it as a bearer token. The series name every route template,
queue depth, login outcomes and, since #334, the Python version
(`python_info`), so keep the endpoint off the public Ingress either way.

### Why `prod-ha` does not include the monitoring objects

The issue asked whether the ServiceMonitor/PrometheusRule wiring should be
promoted into `overlays/prod-ha`. It is not, and is packaged as opt-in
components instead:

1. **Both kinds come from the Prometheus Operator's CRDs**
   (`monitoring.coreos.com/v1`), which nothing in this repository installs. On a
   cluster without them `kubectl apply -k` stops with `no matches for kind` and
   exits non-zero, so `prod-ha` would fail to apply everywhere the operator is
   not installed — including clusters that scrape through the pod annotations
   and need nothing else.
2. **Prometheus picks both objects up only through its `serviceMonitorSelector`
   / `ruleSelector`**, and the label those select on belongs to the
   installation (kube-prometheus-stack: `release: <helm release name>`). A
   default in the repository would be wrong for almost everyone, and a wrong
   label applies cleanly and is silently never read.
3. **Nothing is lost by default**: the pod annotations already get the API
   scraped, and `examples/prometheus-slo.rules.yaml` loads through `rule_files`.

The Grafana dashboards need no CRD — their ConfigMaps apply anywhere and are
inert without a sidecar — but they are opt-in as well: ~120 kB of ConfigMaps
has no use on an installation without Grafana. They are a separate component
so that a cluster with Grafana and without the operator can take them alone.

### Enabling the components

`overlays/prod-ha-monitoring` is `prod-ha` plus both components and renders in
CI (`k8s/scripts/validate-kustomize.sh`). Any other overlay takes them with the
same two lines:

```yaml
components:
  - ../../base/monitoring          # ServiceMonitor + PrometheusRule (needs the CRDs)
  - ../../base/grafana-dashboards  # two ConfigMaps for the Grafana sidecar
```

Then give the two operator objects the label your Prometheus selects on. The
narrow way is a patch on the `monitoring.coreos.com` group only (commented out,
ready to fill, in `overlays/prod-ha-monitoring/kustomization.yaml`):

```yaml
patches:
  - target:
      group: monitoring.coreos.com
    patch: |-
      - op: add
        path: /metadata/labels/release
        value: kube-prometheus-stack
```

For the dashboards, the Grafana chart's dashboards sidecar must be enabled
(`sidecar.dashboards.enabled: true`), select the label `grafana_dashboard`
(the ConfigMaps carry the value `"1"`), and watch this namespace.
kube-prometheus-stack does all three by default (`labelValue: "1"`,
`searchNamespace: ALL`); the standalone grafana chart watches only Grafana's
own namespace unless `sidecar.dashboards.searchNamespace` names this one or is
`ALL`. The ConfigMaps also carry `grafana_folder: Shapoclyack`, honoured where
the chart sets `sidecar.dashboards.folderAnnotation: grafana_folder` together
with `sidecar.dashboards.provider.foldersFromFilesStructure: true`.

Outside Kubernetes, import the two JSON files as they are (Dashboards → New →
Import): both choose their Prometheus data source through a variable, and
neither references an installation-specific uid.

## Aggregating across replicas

An API replica is one process (`python -m api` runs a single uvicorn worker),
so `instance` is the process. Series fall into three groups, and the
aggregation that is correct differs:

| Group | Examples | Aggregate with |
|---|---|---|
| Per replica: this process's own state | HTTP, DB pool, process, sensor-upload queue, ClickHouse batch timings, `octo_nats_consumer_pending_timestamp_seconds` | `sum()` for a total, `by (instance)` to find the odd replica |
| Events, counted by whichever replica handled them | every `*_total` counter, job durations | `sum(rate(…))` / `sum(increase(…))` |
| Cluster-wide: read from a shared table, so **every replica reports the same number** | `octo_agents`, the heartbeat ages, `octo_jobs_queued`, `octo_jobs_running`, `octo_nats_outbox_backlog`, `octo_run_publication_backlog`, `octo_webhook_delivery_queue`, `octo_endpoint_devices`, `octo_nats_consumer_pending`, `octo_ticket_sync_lag_seconds` | `max()` — `sum()` multiplies by however many replicas the HPA runs |

`tests/test_observability_assets.py` fails if a dashboard or an alert applies
`sum()` directly to a cluster-wide series.

## Label bounds

Every label on every series comes from a fixed vocabulary in the code. No
series carries a tenant, agent id, hostname, user, asset, address or URL label:
each of those is one series per tenant/agent/host/…, and several are chosen by
whoever sends the request. `tests/test_observability_assets.py` rejects such a
label on any registered series.

A **tenant label** was considered for the fleet series and left out: tenants
are created at runtime, so the series count would grow with the customer list
on every series the label touched. Per-tenant figures come from the API instead
— `GET /api/agents/summary` for the fleet, the console's posture and SLA pages
for findings — and the Product dashboard is installation-wide.

Two labels on the HTTP series are worth spelling out, because the client
controls the request they describe:

- `path` is the matched route's template. A request no route matched — a 404
  on an API without the console build, a CORS preflight the middleware answers
  before routing — is `path="<unmatched>"`. Until #334 the raw URL stood in, so
  every path a scanner probed became a series of its own on every replica. The
  template is the one FastAPI reports for the route, which for routes on an
  included router is relative to that router: `/api/agents` and
  `/api/v1/agents` are both `path="/agents"`; routes declared on the app itself
  (`/api/health`, `/metrics`) keep their full path.
- `method` is one of `GET HEAD POST PUT PATCH DELETE OPTIONS`, and `OTHER` for
  anything else.

## Catalogue

Scope: **R** per replica, **C** cluster-wide (use `max()`), **E** events
counted where they happen (use `sum()`).

### HTTP

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_http_requests_total` | counter | `method` (7 + `OTHER`), `path` (route templates + `<unmatched>`), `status` (HTTP status codes) | E |
| `octo_http_request_duration_seconds` | histogram | `method`, `path` as above | E |

### Scan jobs

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_job_duration_seconds` | histogram, 30 s – 8 h buckets | `status` (`succeeded`, `failed`), `execution` (`local`, `agent`) | E |
| `octo_jobs_queued`, `octo_jobs_running` | gauge | — | C |
| `octo_job_lease_expired_total` | counter | `outcome` (`requeued`, `failed`) | E |
| `octo_job_cancellations_total` | counter | `outcome` (`queued`, `confirmed`, `unconfirmed`, `late_results`) | E |
| `octo_job_idempotent_replays_total` | counter | `operation` (`start`, `results`) | E |
| `octo_scan_policy_refusals_total` | counter | `reason` (`safe_only`, `avoid_ports`, `agent_unsupported`) | E |
| `octo_quota_denied_total` | counter | `resource` (`assets`, `scans`) | E |

### Sensor and agent fleet

Read from the `agents` table when Prometheus asks — see
[Sensors and agents](#sensors-and-agents) below for how.

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_agents` | gauge | `agent_kind` (`scanner`, `endpoint`), `state` (`idle`, `busy`, `error`, `stale`, `disabled`, `quarantined`) — always all 12 | C |
| `octo_agent_heartbeat_age_seconds` | gauge histogram (`_bucket`, `_gcount`, `_gsum`), 30 s – 7 d | `agent_kind` | C |
| `octo_agent_heartbeat_age_max_seconds` | gauge | `agent_kind`; absent for a kind with no active agent | C |
| `octo_agent_stale_threshold_seconds` | gauge | — (`OCTO_AGENT_STALE_SECONDS`) | C |

### Sensor result uploads

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_agent_ingest_in_flight` | gauge | — | R |
| `octo_agent_ingest_waiting` | gauge | — (each waiting upload holds its archive in memory) | R |
| `octo_agent_ingest_rejected_total` | counter | `reason` (`queue_full`, `timeout`) | E |

### Run publication

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_run_publications_total` | counter | `outcome` (`published`, `deferred`, `dead`, `adopted`, `requeued`, `discarded`) | E |
| `octo_run_publication_backlog` | gauge | `status` (`pending`, `dead`) | C |
| `octo_run_publication_lease_renewal_total` | counter | `outcome` (`renewed`, `late`, `superseded`, `failed`) | E |
| `octo_run_publication_stale_notes_total` | counter | — | E |

### NATS and the outbox

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_nats_consumer_pending` | gauge | `consumer` (`octo-ch-ingest-results`, `octo-webhook-fanout`, `octo-webhook-audit-fanout`) | C |
| `octo_nats_consumer_pending_timestamp_seconds` | gauge | `consumer` as above; when this replica last read the count | R |
| `octo_nats_stream_config_drift` | gauge | `stream` (the streams the API declares), `setting` (`num_replicas`, `duplicate_window`) | R |
| `octo_nats_legacy_ingest_total` | counter | `outcome` (`published`, `refused`) | E |
| `octo_nats_outbox_backlog` | gauge | `kind` (`ingest`, `asset_event`), `status` (`pending`, `stale`, `dead`) | C |
| `octo_nats_outbox_total` | counter | `kind` as above, `outcome` (`recorded`, `republished`, `dead`, `dropped`, `discarded`) | E |

`octo_nats_consumer_pending` is refreshed on each poll, so a worker that has
stopped polling leaves its last value standing. Its timestamp in Prometheus is
the scrape time, not the time it was read; the separate
`octo_nats_consumer_pending_timestamp_seconds` is what ages, and what
`ShapoclyackClickHouseIngestStale` reads. Until #334 that alert used
`timestamp()` of the count, and both SLO 5 alerts matched the consumer's
retired name `octo-ch-ingest`, so neither could fire.

### ClickHouse ingest

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_ch_ingest_messages_total` | counter | `result` (`ok`, `error`) | E |
| `octo_ch_ingest_batch_duration_seconds` | histogram | — | R |

### Endpoint inventory

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_endpoint_inventory_submissions_total` | counter | `result` (`accepted`, `replay`, `rate_limited`, `too_large`, `conflict`, `invalid`, `error`) | E |
| `octo_endpoint_inventory_ingest_duration_seconds` | histogram | — | R |
| `octo_endpoint_inventory_software_items` | histogram, 1 – 5000 | — | E |
| `octo_endpoint_inventory_software_changes_total` | counter | `event_type` (`installed`, `removed`, `updated`) | E |
| `octo_endpoint_devices` | gauge | `state` (`active`, `stale`) | C |
| `octo_endpoint_retention_deleted_total` | counter | `table` (`endpoint_software_items`, `endpoint_software_changes`) | E |
| `octo_endpoint_retention_run_duration_seconds` | histogram | — | R |

### Findings, events and notifications

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_asset_events_published_total` | counter | `kind` (`new_asset`, `new_open_port`, `new_cve`, `cert_expiring`, `decommissioned_host`), `outcome` (`published`, `deferred`, `skipped`) | E |
| `octo_audit_events_published_total` | counter | `outcome` (`published`, `skipped`, `error`) | E |
| `octo_workflow_events_total` | counter | `kind` (the eight `WORKFLOW_EVENT_KINDS`), `outcome` (`queued`, `no_subscription`, `error`) | E |
| `octo_sla_escalations_total` | counter | `action` (`reassigned`, `severity_bumped`) | E |
| `octo_webhook_deliveries_total` | counter | `outcome` (`queued`, `delivered`, `retrying`, `dead`) | E |
| `octo_webhook_delivery_duration_seconds` | histogram, 50 ms – 30 s | — | R |
| `octo_webhook_delivery_queue` | gauge | `status` (the delivery statuses) | C |
| `octo_ticket_sync_polls_total` | counter | `transport` (`jira`, `servicenow`, `defectdojo`), `outcome` (`applied`, `unchanged`, `failed`) | E |
| `octo_ticket_sync_lag_seconds` | gauge | `transport` as above; leader only, followers report 0 | C |
| `octo_bulk_action_items_total` | counter | `endpoint` (`assets.bulk`, `vulnerabilities.bulk`), `action` (the bulk actions the request schemas allow), `outcome` (`ok`, `not_found`, `conflict`, `invalid`, `deadline`) | E |
| `octo_idempotent_replays_total` | counter | `endpoint` as above | E |

### Access

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_auth_attempts_total` | counter | `outcome` (`success`, `failure`, `locked`, `denied`) | E |
| `octo_mfa_verifications_total` | counter | `outcome` (`success`, `failure`, `recovery`, `setup_success`, `setup_failure`, and the same four `webauthn_*`) | E |
| `octo_break_glass_logins_total` | counter | — alert on any increase | E |

### Leadership

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_scheduler_is_leader` | gauge | — ; sums to exactly 1 across replicas | R |
| `octo_ticket_sync_is_leader` | gauge | — ; sums to exactly 1 across replicas | R |

### Connection pool

See [Database pool](#database-pool) below.

| Series | Type | Labels and their bound | Scope |
|---|---|---|---|
| `octo_db_pool_size` | gauge | — (`OCTO_DB_POOL_SIZE`) | R |
| `octo_db_pool_max_overflow` | gauge | — (`OCTO_DB_MAX_OVERFLOW`) | R |
| `octo_db_pool_timeout_seconds` | gauge | — (`OCTO_DB_POOL_TIMEOUT`) | R |
| `octo_db_pool_checked_out` | gauge | — | R |
| `octo_db_pool_checked_in` | gauge | — | R |
| `octo_db_pool_overflow` | gauge | — | R |
| `octo_db_pool_checkout_duration_seconds` | histogram, 1 ms – 60 s | — | E |
| `octo_db_pool_checkout_timeouts_total` | counter | — | E |

### Process

The collectors `prometheus_client` puts on its default registry, which the
API's private registry did not have until #334:

| Series | Type | Labels |
|---|---|---|
| `process_resident_memory_bytes`, `process_virtual_memory_bytes` | gauge | — |
| `process_cpu_seconds_total` | counter | — |
| `process_open_fds`, `process_max_fds` | gauge | — |
| `process_start_time_seconds` | gauge | — (`changes()` over it counts restarts) |
| `python_gc_objects_collected_total`, `python_gc_objects_uncollectable_total`, `python_gc_collections_total` | counter | `generation` (`0`, `1`, `2`) |
| `python_info` | gauge | `implementation`, `major`, `minor`, `patchlevel`, `version` |

The `process_*` series are read from `/proc` and exist on Linux only.

## Sensors and agents

The API has always known when each sensor (`agent_kind=scanner`) and each
Lariska endpoint agent (`agent_kind=endpoint`) was last heard from; since #334
that is on `/metrics`, computed from the `agents` table with one grouped query:

- `octo_agents{agent_kind,state}` — a count for all 12 combinations, zeros
  included, so an absent series means "not measured", never "none".
  `idle`/`busy`/`error` is what an agent heard from within
  `OCTO_AGENT_STALE_SECONDS` last reported; `stale` is an active agent past
  it; `disabled`/`quarantined` is an operator's decision, whatever the agent
  reports.
- `octo_agent_heartbeat_age_seconds{agent_kind}` — the distribution of
  heartbeat ages over active agents, exported as a *gauge histogram*: the
  buckets describe the fleet now, not events over time, so they are used
  without `rate()`:

  ```promql
  histogram_quantile(0.95, max by (le, agent_kind) (octo_agent_heartbeat_age_seconds_bucket))
  ```

  Buckets are dense around the sensor's 60 s heartbeat and the default 120 s
  threshold (30, 60, 90, 120, 300 s) and coarse beyond (15 min, 1 h, 6 h, 1 d,
  7 d), so a percentile that falls between two far-apart buckets is an
  interpolation. `octo_agent_heartbeat_age_max_seconds` gives the exact
  longest silence.
- Disabled and quarantined agents are left out of the ages: they are silent on
  purpose, and would otherwise pin the oldest age on every panel.

**Cost and failure behaviour.** `/metrics` is unauthenticated unless
`OCTO_METRICS_TOKEN` is set, so the query is not run per scrape: one answer is
reused for 15 s per replica, however often the endpoint is asked, and while one
scrape refreshes it concurrent scrapes are answered from the previous snapshot
rather than queued. The query runs under a 2 s `statement_timeout` on Postgres,
and not at all while this replica's pool has no connection free — a saturated
pool is when the dashboards are read, and a scrape waiting
`OCTO_DB_POOL_TIMEOUT` for a connection would lose the whole `/metrics` answer
to the scrape timeout. A snapshot older than 60 s is withdrawn rather than
served, and a failed query withdraws the series immediately: gaps are honest,
frozen numbers are not.

**Alerts.** `ShapoclyackSensorsStale` (ticket, 15 m) fires on any active sensor
past the threshold — a sensor that is gone on purpose should be disabled or
deleted in the Sensor Fleet page rather than left to hold the alert open.
`ShapoclyackNoSensorOnline` (page, 15 m) fires when jobs are queued, sensors are
registered, and none of them is online; an installation in local execution mode
has no sensors and does not fire it. Endpoint agents are not alerted on: a
laptop asleep is not an incident.

## Database pool

Each API replica has one SQLAlchemy pool (`api/db/engine.py`; the only engine
the API process builds — `alembic` and `api/db/migrate.py` run in their own
processes). Its size is `OCTO_DB_POOL_SIZE` + up to `OCTO_DB_MAX_OVERFLOW`
under load, per replica, against a server whose `max_connections` all replicas
share ([high-availability.md](high-availability.md)).

- The gauges are read off the live pool at scrape time. `checked_out` never
  idles at zero: every leader-locked worker this replica currently leads holds
  one connection for as long as it leads (`api/services/leader_lock.py`), and
  there are six of them (schedule dispatcher, report dispatcher, software and
  retro CVE matching, SLA escalation, ticket sync).
- `octo_db_pool_checkout_duration_seconds` is the time to obtain a connection:
  the queue wait, plus the handshake when the pool opens a new one. Checkouts
  that time out are observed too; the buckets reach past the 30 s default
  timeout so they land in a finite bucket.
- `octo_db_pool_checkout_timeouts_total` counts checkouts that gave up after
  `OCTO_DB_POOL_TIMEOUT`. Each one is a request that answered 500 without
  reaching the database.

`ShapoclyackDbPoolSaturated` (ticket) fires when a replica holds 90 % of its
limit for 10 m; `ShapoclyackDbPoolCheckoutTimeouts` (ticket) fires on the
first timeout. A longer timeout only makes the failing requests slower: raise
the pool within the server's budget, or find what is holding connections.

## Dashboards

Both use a `datasource` variable and a single-select `job` variable (see
[Scraping](#scraping)); the Platform dashboard adds a multi-select `instance`.

**Shapoclyack / Platform** (`shapoclyack-platform`) — overview stats (replicas
up, request rate, 5xx share against SLO 1, GET p95 against SLO 2, scheduler
leaders, restarts in the last hour); API rate/errors/duration with the slowest
and failing routes; database pool per replica; sensors and agents; NATS
consumers, outbox and run publication; ingest (ClickHouse, sensor uploads,
endpoint inventory, consumer read age); workers and leadership; process
(memory, CPU, file descriptors, GC, uptime).

**Shapoclyack / Product** (`shapoclyack-product`) — scans (finished, success
ratio against SLO 3, duration, queue, refusals, cancellations, publication);
findings and notifications (asset events, SLA escalations, workflow events,
webhooks, ticket sync, bulk actions); endpoint inventory (devices, agents,
submissions against SLO 7, software per snapshot and changes); access (sign-in
outcomes, second factor, break-glass logins, replayed writes). Installation-wide
— see [Label bounds](#label-bounds).

## Alerting

All rules live in `k8s/shapoclyack/examples/prometheus-slo.rules.yaml`; the
PrometheusRule objects in `examples/prometheusrule-slo.example.yaml` and
`base/monitoring/prometheusrule-slo.yaml` are generated from it by
`k8s/scripts/render-prometheusrule-slo.py`. The SLO alerts are described in
[slo.md](slo.md#alerting). Added in #334:

| Alert | Severity | Fires when |
|---|---|---|
| `ShapoclyackDbPoolSaturated` | ticket | a replica's `checked_out` ≥ 90 % of size + max_overflow for 10 m |
| `ShapoclyackDbPoolCheckoutTimeouts` | ticket | any checkout timed out in the last 10 m, per replica |
| `ShapoclyackSensorsStale` | ticket | an active sensor has been stale for 15 m |
| `ShapoclyackNoSensorOnline` | page | jobs queued, sensors registered, none online, for 15 m |

## Keeping this true

A dashboard or alert that names a series or label the API does not export
fails nowhere: the panel is empty and the alert never fires. So:

- `tests/test_observability_assets.py` checks every series and every label the
  dashboards and rules name against the live registry, that cluster-wide
  series are never summed, that no series carries an unbounded label, that
  consumer matchers name a consumer the API reports, and that this page covers
  every exported `octo_` family.
- `k8s/scripts/validate-prometheus-rules.sh` (both CI pipelines) runs
  `promtool check rules`, the `promtool test rules` unit tests above, and parses
  every dashboard query by turning it into a recording rule
  (`k8s/scripts/grafana-queries-as-rules.py`). It uses a `promtool` on `PATH`
  or `$PROMTOOL`, and the pinned Prometheus image through docker otherwise.
