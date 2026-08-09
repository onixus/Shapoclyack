# Operations

## Run directories

Every scan writes to:

```text
scanner/output/runs/<run_id>/
```

The directory can contain:

- run metadata and normalized summaries;
- resolved and alive hosts;
- open ports and service aggregates;
- Nmap XML and tool logs;
- vulnerability and enrichment JSON;
- Markdown, HTML, and PDF reports;
- diff and normalized asset events;
- DefectDojo exports;
- diagnostic stage output.

Artifact presence depends on the enabled stages and whether a stage produced
data.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Successful run |
| `1` | Unexpected internal error |
| `2` | Configuration validation error |
| `3` | No valid targets after input validation |
| `4` | External tool failed after retries |
| `130` | Interrupted by the operator |

Automation should distinguish invalid configuration/inputs from transient tool
failure.

## Resume

Checkpoints are stored under `scanner/state`. Preserve both state and the
corresponding run output when moving or resuming a run.

```bash
python -m scanner.main \
  --config scanner/config/default.yaml \
  --resume
```

Do not resume after changing target scope or incompatible stage settings.
Start a new run instead so provenance stays clear.

## Scheduling

Two scheduling models exist:

- `scanner/scheduler.py` and the Kubernetes CronJob for simple single-tenant
  installations;
- API-managed tenant schedules for the platform deployment.

The API dispatcher skips a schedule tick while its previous job is still
running. Use this behavior to prevent overlapping long scans; it is not a
replacement for capacity planning.

The dispatcher runs in every API replica but dispatches only in the one holding
its advisory lock, so multiple replicas need no special configuration — see
[architecture.md](architecture.md#schedule-dispatcher-leadership). Confirm which
replica leads with `octo_scheduler_is_leader` on `/metrics`; the fleet-wide sum
should always be exactly 1.

## Diffs and events

Run diffs compare current and previous compatible results. Normalized events
include new assets, open ports, CVEs, certificate-expiry findings, and manual
decommissioning. Verify that both compared runs use equivalent scope and
profiles before treating a count change as a security event.

## Alerts and exports

Supported integrations include Slack/Telegram summary alerts, SMTP, DefectDojo,
and report artifacts. Configure credentials only through secrets or environment
injection. Test notification delivery with non-sensitive data before enabling
production findings.

## Retention

Retention must cover all stateful layers:

| Layer | Retain/backup |
|---|---|
| Run filesystem/PVC | Raw artifacts, reports, checkpoints |
| PostgreSQL | Tenants, keys metadata, assets, schedules, overrides, endpoint inventory |
| ClickHouse | Analytical vulnerability and port history |
| NATS | Pending jobs and ingest messages |

Set retention according to legal, operational, and privacy requirements. Scan
artifacts can contain internal hostnames, IPs, software versions, and
vulnerability evidence.

### Endpoint inventory retention

Endpoint inventory is the one layer with an automatic policy. The API runs an
in-process sweep every `OCTO_ENDPOINT_RETENTION_INTERVAL_SECONDS` (6h) that,
per tenant:

- deletes `endpoint_software_items` for snapshots received more than
  `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` (90) ago, keeping the
  snapshot summary row — submission history, digests, counts, and collector
  warnings stay queryable;
- deletes `endpoint_software_changes` older than
  `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` (365) — the audit trail
  deliberately outlives the raw software rows it was derived from.

A device's current snapshot is never pruned regardless of age: it backs the
diff for that device's next submission, so pruning it would report a quiet
endpoint's entire software list as freshly installed.

Sizing: one snapshot row plus up to
`OCTO_ENDPOINT_INVENTORY_MAX_SOFTWARE_ITEMS` (5000) software rows per accepted
submission, bounded per agent by
`OCTO_ENDPOINT_INVENTORY_RATE_LIMIT_PER_HOUR` (12). At one daily snapshot of
~1500 packages per endpoint, 10,000 endpoints hold roughly 1.35 billion
software rows over the 90-day window — plan for a daily-or-slower collection
cadence, or shorten the window, before scaling past a few thousand endpoints.

Runbook:

- **Storage growing faster than expected** — check
  `octo_endpoint_inventory_software_items` (entries per snapshot) and
  `octo_endpoint_inventory_submissions_total{result="accepted"}`. Lower the
  collection cadence on the Lariska side first; shorten
  `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` second.
- **Sweep not running** — the System page shows "Last Retention Sweep"; a
  never-run sweep means `OCTO_ENDPOINT_RETENTION_ENABLED` is off or the API
  pod restarted within the interval. The worker is in-process, so with several
  API replicas each one sweeps; deletes are idempotent, so overlap is safe.
- **Sweep too heavy** — lower `OCTO_ENDPOINT_RETENTION_BATCH_SIZE`; each
  statement deletes at most that many rows.
- **Rollback** — retention deletes are irreversible; restore from the
  PostgreSQL backup. Disable the sweep (`OCTO_ENDPOINT_RETENTION_ENABLED=false`)
  before investigating an unexpected data-loss report so the next interval
  cannot compound it.
- **Ingestion rejected** — `octo_endpoint_inventory_submissions_total{result}`
  separates `rate_limited`, `too_large`, `conflict`, and `invalid`. A body over
  `OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES` is refused with `413` from the
  `Content-Length` header alone; a request without `Content-Length` is refused
  with `411` and never buffered.

Tenant offboarding: endpoint data has no bespoke delete/export flow and follows
whatever general tenant-deletion mechanism the platform adopts. The endpoint FK
chain cascades from `tenants` (migration `0006_endpoint_fk_cascade`), so
deleting a tenant row removes its devices, identifiers, snapshots, software
rows, and change events; a linked asset being deleted only nulls the device's
`asset_id`.

## Logs and observability

Use structured application logs and correlate by tenant, `job_id`, `run_id`,
and `agent_id`. Do not log secrets or full authorization headers.

Useful checks:

```bash
curl --fail http://localhost:8080/api/health
kubectl -n network-scan get pods,jobs,cronjobs
kubectl -n network-scan logs deployment/shapoclyack-api --tail=200
```

`GET /metrics` exposes the Prometheus series used by the dashboards and alerts
referenced above. Objectives, PromQL, and the error-budget policy built on these
series are in [slo.md](slo.md); scrape wiring for Kubernetes is in
[k8s/README.md](../k8s/README.md). Endpoint-inventory series (all labels are low-cardinality —
no agent, device, asset, tenant, or product names):

| Series | Use |
|---|---|
| `octo_endpoint_inventory_submissions_total{result}` | Accept/replay/reject breakdown; alert on a sustained non-`accepted` share |
| `octo_endpoint_inventory_ingest_duration_seconds` | Ingest latency |
| `octo_endpoint_inventory_software_items` | Entries per snapshot; drives storage growth |
| `octo_endpoint_inventory_software_changes_total{event_type}` | Installed/removed/updated volume |
| `octo_endpoint_devices{state}` | Active vs. stale endpoints; alert when the stale share climbs |
| `octo_endpoint_retention_deleted_total{table}` | Rows the sweep removed |
| `octo_endpoint_retention_run_duration_seconds` | Sweep cost; alert if it approaches the sweep interval |

## Backups

At minimum:

1. quiesce or coordinate writers;
2. back up PostgreSQL with a database-native method;
3. snapshot artifact and ClickHouse volumes consistently;
4. export deployment manifests without secret values;
5. test restore into an isolated namespace.

NATS streams are operational queues. Design recovery so a restored message
cannot silently duplicate an already-ingested result.
