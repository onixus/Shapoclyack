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

## Backup and disaster recovery

### Recovery objectives and verification status

The base deployment takes a logical PostgreSQL backup every day at 02:15 UTC.
That schedule gives a **design RPO of at most 24 hours** for PostgreSQL, assuming
the scheduled backup succeeds and is uploaded. The initial **RTO target is 60
minutes** for restoring the base stack into an isolated namespace. Targets are
not measurements: issue #158 remains open until a restore drill is run on real
data and the measured values below are replaced with actual numbers.

| Measure | Target | Last measured |
|---|---:|---:|
| PostgreSQL RPO | <= 24 h | **Not yet measured** |
| Full base-stack RTO | <= 60 min | **Not yet measured** |
| PostgreSQL `pg_restore` duration | n/a | **Not yet measured** |
| Restore drill date | n/a | **Not yet performed** |

Do not mark the backup/restore GA blocker complete while any `Not yet` value
remains in this table.

### PostgreSQL scheduled backup

`k8s/shapoclyack/base/backup/postgres-cronjob.yaml` runs `pg_dump` in custom
format, creates a SHA-256 checksum, and uploads both files to S3 or an
S3-compatible object store. `concurrencyPolicy: Forbid` prevents overlapping
backups. The backup credentials come from `Secret/shapoclyack-backup`; the
External Secrets Operator example in
`k8s/shapoclyack/examples/externalsecret.example.yaml` documents the expected
keys and keeps credentials out of manifests.

For a one-off validation, create a Job from the CronJob and inspect its result:

```bash
kubectl -n network-scan create job \
  --from=cronjob/shapoclyack-postgres-backup \
  shapoclyack-postgres-backup-manual
kubectl -n network-scan logs -f job/shapoclyack-postgres-backup-manual
```

A successful run writes `backup_success` with the object prefix. Verify the dump
and its `.sha256` object exist in external storage before treating the run as a
usable recovery point.

When kube-state-metrics and Prometheus Operator are installed, apply
`k8s/shapoclyack/examples/prometheusrule-backup.example.yaml`. It uses
`kube_cronjob_status_last_successful_time` to alert when the last successful
backup is older than 26 hours and also reports failed backup Jobs. This keeps a
missed backup visible without an operator manually listing CronJobs.

### PostgreSQL restore drill

Always test recovery in a namespace that is separate from production. The
restore script refuses the base `network-scan` namespace unless
`ALLOW_PRODUCTION_RESTORE=1` is deliberately set.

1. Create an isolated namespace/overlay and deploy the same Shapoclyack base
   version that will consume the backup. Provide the PostgreSQL and API secrets,
   but keep ingress and external integrations disabled.
2. Download `shapoclyack.dump` and `shapoclyack.dump.sha256` from the same backup
   prefix.
3. Run:

```bash
scripts/restore-postgres.sh \
  --namespace shapoclyack-restore \
  --backup ./shapoclyack.dump \
  --checksum ./shapoclyack.dump.sha256
```

The script verifies SHA-256, restores with `pg_restore --clean --if-exists`,
restarts the API Deployment so its `migrate` init container runs
`alembic upgrade head`, waits for a successful rollout, then verifies database
readiness, `alembic_version`, and the `tenants` table. Record the emitted
`db_restore_seconds` and `recovery_seconds` values in the verification table
above.

Calculate the measured RPO from the timestamp represented by the selected
backup object to the declared incident/drill recovery point. Record both the
selected backup timestamp and the drill start time so another operator can
reproduce the calculation.

A restore that completes `pg_restore` but cannot start the current API image is
a failed drill, not a successful database restore.

### Artifact PVC recovery

`scanner-data` contains reports, raw scan artifacts, checkpoints, and other run
state. The base PVC intentionally does not assume a storage vendor or a
`VolumeSnapshotClass`, so the repository cannot safely provide one universal
snapshot object.

For production, configure CSI `VolumeSnapshot` or the storage provider's native
snapshot/backup mechanism for `scanner-data`. Restore the snapshot to a **new
PVC in the isolated namespace** and mount that PVC into the recovery deployment
before validating reports or attempting resume. Do not overwrite the production
PVC during a drill.

Snapshot cadence must be chosen so artifact retention is compatible with the
PostgreSQL RPO. If PostgreSQL is restored to time T but the artifact PVC is much
older, runs referenced by the database may have missing files.

### ClickHouse recovery

The base ClickHouse StatefulSet is single-replica and stores data under
`clickhouse-data`. Production installations must choose one of these recovery
methods and test it with the PostgreSQL drill:

- ClickHouse native `BACKUP`/`RESTORE` to configured external object storage; or
- a CSI/storage-provider snapshot of `clickhouse-data`, taken while writes are
  quiesced or using a storage mechanism documented as application-consistent.

Restore ClickHouse into the isolated namespace before enabling the ingest
worker. Validate `/ping`, expected tables, and representative historical
queries. Do not infer ClickHouse consistency merely because a PVC snapshot
object exists.

### NATS / JetStream recovery

JetStream is an operational queue, not the source of truth for assets or scan
history. Recover durable stores first. Only then decide whether a JetStream
snapshot is required for messages that were accepted but not durably processed.

Shapoclyack publishes with stable `Nats-Msg-Id` values and uses idempotent
result/event identifiers. The EVENTS stream also has a duplicate window. A
restored stream can nevertheless contain messages whose effects already exist
in PostgreSQL or ClickHouse, especially when the queue snapshot and database
backup were taken at different times.

Recovery order:

1. restore and validate PostgreSQL, artifact PVC, and ClickHouse;
2. keep API/worker consumers that mutate durable state paused while inspecting
   the JetStream snapshot boundary;
3. identify queued messages newer than the durable recovery point and preserve
   their original `Nats-Msg-Id` / idempotency identifiers;
4. restore/replay only the required range;
5. re-enable consumers and verify duplicate/idempotency counters and durable
   record counts before exposing the recovered stack.

Never replay a restored stream by republishing every message with new message
IDs. That defeats the deduplication mechanisms the recovery procedure relies
on.

### Pod disruption and API availability

`k8s/shapoclyack/base/api-pdb.yaml` sets `minAvailable: 1`. With the current base
`replicas: 1`, a voluntary eviction is blocked rather than reducing API
availability to zero. Production overlays that need drain-friendly maintenance
should run two or more API replicas; the scheduler is already protected by its
PostgreSQL advisory-lock leadership mechanism.

### NetworkPolicy decision

`k8s/shapoclyack/examples/networkpolicy-agent.example.yaml` deliberately remains
an example instead of a base resource. NetworkPolicy enforcement and ingress
controller labels vary by CNI/environment, and the platform can legitimately
need environment-specific egress to DNS, S3-compatible backup storage, NATS,
ClickHouse, webhooks, scanners, vulnerability sources, SMTP, or ticketing
systems. Applying a guessed restrictive policy in base can silently break
backup and integrations; applying the current example unchanged would also
permit API ingress from any namespace.

Production deployments should copy/patch the example into their overlay and use
explicit namespace/pod selectors plus the exact external egress destinations
for that environment. Treat the absence of an environment-specific policy as a
production deployment finding, not as a reason to ship a misleading universal
base policy.
