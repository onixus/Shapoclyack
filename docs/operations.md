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
- `sarif.json` — OASIS SARIF v2.1.0 export of the run's vulnerabilities
  (`reporting.sarif_export`, on by default);
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

## Active checks and target authorization

Every org-profile stage is passive except one. `org_profile.dns_hygiene.axfr_probe`
attempts a **zone transfer (AXFR)** against each nameserver of each seed domain.
That is a request the target's nameserver records as an attempted transfer, so
it needs the same authorization as any other active test — the platform will not
infer it from the fact that a scan was started.

- **Default is off**, and the flag exists only in the scanner config file. It is
  deliberately absent from the API config overrides (`EDITABLE_PATHS` in
  `api/services/config_override.py`), because those overrides are
  installation-wide rather than per-tenant and would enable AXFR for every
  tenant's scans at once; and it is absent from the start-scan request, because
  that would put the decision on the `operator` who launches a scan rather than
  on whoever authorizes the target. Enabling it is a deployment change, made by
  whoever can edit the scanner config and reviewed like one.
- **Only this run's own seed domains** are probed. Attribution candidates from
  the related-domains stage are never probed: a wrongly attributed domain would
  mean an active request against a third party's infrastructure.
- **A nameserver on a non-public address is refused**, not dialled. NS records
  are written by the scanned party, so `ns1.target.example -> 10.0.0.5` would
  turn the probe into a TCP/53 connection inside the agent's own network. The
  refusal is logged as `refusing AXFR against <ns>` and recorded in the artifact
  as `status: refused`.
- **A successful transfer is never written down.** `dns_hygiene.json` records
  only `status: open` and the number of records; the zone itself reaches neither
  the artifact directory nor `scan.log`. If you need the zone contents, transfer
  it yourself with `dig axfr` — the scanner will not keep a copy for you.

Before switching `axfr_probe` on, confirm the engagement covers active testing
of the domains in `org_profile.dns_hygiene.domains` (or of every base domain the
run derives from its scope, when that list is empty).

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
| PostgreSQL | Tenants, keys metadata, assets, schedules, overrides, endpoint inventory, risk snapshots |
| ClickHouse | Analytical vulnerability and port history |
| NATS | Pending jobs and ingest messages |

Set retention according to legal, operational, and privacy requirements. Scan
artifacts can contain internal hostnames, IPs, software versions, and
vulnerability evidence.

### ClickHouse analytical data retention (ROADMAP #187)

ClickHouse tables `shapoclyack.shapoclyack_vulnerabilities` and `shapoclyack.shapoclyack_open_ports`
define a table-level TTL policy:
```sql
TTL timestamp + INTERVAL 90 DAY
```
Expired partitions and rows are merged and deleted automatically in the background
by ClickHouse without requiring external cron scripts. To modify the retention window,
run:
```sql
ALTER TABLE shapoclyack.shapoclyack_vulnerabilities MODIFY TTL timestamp + INTERVAL 180 DAY;
ALTER TABLE shapoclyack.shapoclyack_open_ports MODIFY TTL timestamp + INTERVAL 180 DAY;
```

### Scan run artifact retention (ROADMAP #187)

Scan artifacts written to `output_dir/runs/<run_id>/` accumulate over time on persistent storage.
An in-process retention worker runs every `OCTO_RUN_RETENTION_INTERVAL_SECONDS` (1h) and
deletes expired run directories whose age exceeds `OCTO_RUN_RETENTION_DAYS` (30).

- Age is determined from `run_meta.json` timestamps (`finished_at`, `started_at`) or directory mtime.
- `0` days disables the reaper.
- Safe across multiple API replicas (directory removal is idempotent and fail-soft).

### ClickHouse ingest consumer subjects (#230)

Stream `INGEST` carries the whole `ingest.>` tree, but the ClickHouse worker
only wants scan results. Its durable consumer therefore filters on
`ingest.results.>`; the S8 endpoint-inventory subject
(`ingest.endpoint_inventory.{tenant}`) and the legacy `ingest.raw_results`
duplicate of every result no longer reach it.

JetStream will not change the filter subject of an existing durable, so the
consumer was renamed `octo-ch-ingest` → `octo-ch-ingest-results`. The API
creates the new one on start. **Delete the retired consumer after the upgrade**,
otherwise it keeps a pending count that no one drains:

```
nats consumer rm INGEST octo-ch-ingest
```

The new durable starts at `DeliverPolicy.ALL`, so it replays whatever the
stream still retains. That is safe to repeat: both ClickHouse tables are
`ReplacingMergeTree` keyed on what the transform emits, and every publish
carries a `Nats-Msg-Id`.

### Risk snapshot retention (#229)

`risk_score_snapshots` (migration `0023`) gains one row per tenant on every
finished run, plus one per manual `POST /api/vulnerabilities/risk-history/snapshot`.
The table arrived after #187 closed, so nothing bounded it until #229: the
service had a `prune_snapshots()` that only its own unit test ever called.

An in-process sweep runs every `OCTO_RISK_SNAPSHOT_RETENTION_INTERVAL_SECONDS`
(6h) in every API replica and deletes snapshots older than
`OCTO_RISK_SNAPSHOT_RETENTION_DAYS` (90), across all tenants. `0` days disables
the sweep, as does `OCTO_RISK_SNAPSHOT_RETENTION_ENABLED=false`.

The delete is a range delete on `(tenant_id, recorded_at)`, so replicas sweeping
the same rows is a no-op for whichever loses. Keep the window at or above the
window the console charts: `/risk-history` defaults to the last 90 points, and a
shorter retention silently shortens the trend line.

### Screenshot retention


Web screenshots (ROADMAP P4.4) are the other automatic policy. A PNG of a
login page can still hold names after the DOM overlay, so pixels must not
live as long as the rest of a run directory.

The API walks `output_dir/runs/*/screenshots/*.png` every
`OCTO_SCREENSHOT_RETENTION_INTERVAL_SECONDS` (1h) and unlinks files whose
age — the older of the PNG mtime and `run_meta.json` — exceeds
`OCTO_SCREENSHOT_RETENTION_DAYS` (14). `screenshots.json` is kept: it names
what was captured, not the pixels. `0` days disables the reaper.

Several API replicas may sweep the same tree; a missing file is a no-op.
Disabling `OCTO_SCREENSHOT_RETENTION_ENABLED` stops the worker; existing
PNGs stay until the run directory is pruned.

The stage itself is off by default (`screenshots.enabled`). Turning it on
needs Playwright + Chromium on the scanner host (`pip install playwright &&
playwright install chromium`). Without that binary the stage writes
`skipped_reason: playwright.unavailable` and no files. Capture is not in
the default image.

PNG download is operator-or-higher. A viewer requesting
`/api/runs/{id}/download/screenshots/…png` gets `404`, same as a missing
file.

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

Agent results upload rejected: an archive over
`OCTO_AGENT_RESULTS_MAX_BODY_BYTES` is refused with `413` from the
`Content-Length` header alone, before the multipart body is read; an upload
without `Content-Length` gets `411`. An archive that passes the transport cap
but whose tar headers add up to more than 512 MiB expanded is refused as
`archive expands to more than ... bytes` — the job stays in flight and the run
directory is not created, so the agent may retry with a smaller archive. Raise
the transport cap for a legitimately large run; the expansion ceiling is a
constant (`api/services/results_ingest.MAX_UNCOMPRESSED_BYTES`) because the
shared `output_dir` is what it protects.

Tenant offboarding: endpoint data has no bespoke delete/export flow and follows
whatever general tenant-deletion mechanism the platform adopts. The endpoint FK
chain cascades from `tenants` (migration `0006_endpoint_fk_cascade`), so
deleting a tenant row removes its devices, identifiers, snapshots, software
rows, and change events; a linked asset being deleted only nulls the device's
`asset_id`.

## Agent installation and upgrade

An agent can be installed three ways: by hand from the snippets on `/agents`
(systemd, Docker, Kubernetes — press **Generate key** there first, since the
snippets open with a `<PROVISIONING_KEY>` placeholder), by running the
installer directly, or by letting the API push it over SSH.

```bash
curl -sSL https://<api-host>/api/agent/install.sh | sudo bash -s -- --server https://<api-host> --key <provisioning-key> --tenant <tenant-id>
```

`scripts/install-agent.sh` covers Ubuntu/Debian, RHEL/Rocky/Alma/Fedora, Alpine
and Arch, and takes `--agent-id`, `--install-dir`, `--docker` and `--nats-url`
as options (`--help` lists them).

With `--docker` it is a thin wrapper: it runs `ghcr.io/onixus/shapoclyack:latest`
as the container `shapoclyack-agent` (`--restart always`, host network) with the
server URL, provisioning key, tenant and agent id in the environment, and exits.

Without it, the native path installs Python and a virtualenv under
`/opt/shapoclyack-agent`, creates a `shapoclyack` system account, writes
`/etc/shapoclyack/agent.env` (`0600`, owned by that account), and — where
systemd is present — installs and enables `shapoclyack-agent.service`
(`Restart=always`, `EnvironmentFile=/etc/shapoclyack/agent.env`). Without
systemd the agent is started with `nohup` and is **not** restarted on boot; on
such a host, supervise it yourself.

**The native path does not ship the agent source.** The API serves no agent
bundle, so the package has to come from somewhere explicit: pass
`--bundle-url <URL>` with a tarball containing the `agent` package, or stage
that package in the install directory beforehand. With neither, the installer
**fails** and says why — it will not leave systemd restarting a worker that
cannot import its own module. Before starting the service it runs
`import agent.worker` and checks the unit is still active three seconds after
start, because `Type=simple` means "started" on its own proves nothing. Use
`--docker` (or the Kubernetes snippet) for a host that has no checkout.

**The provisioning key is on the command line.** During installation it is
visible in the host's process list, and afterwards it lives in `agent.env`.
Rotate the key if the host is shared or the shell history is retained.

### SSH push deployment

`POST /api/agent/deploy/ssh` (operator, and the **Deploy agent** dialog in the
UI) runs the same installer from the API: connect → mint a tenant provisioning
key → `curl … | bash` the installer on the target → wait up to 30 s for the
agent's first heartbeat. Paramiko is used when installed, otherwise the
OpenSSH CLI (with `sshpass` for password auth).

Operational limits worth knowing before relying on it:

- deployment state is **in-memory in the API process** — the last 100 runs, gone
  on restart, and only pollable on the replica that started the run;
- **host keys are not verified** on either path
  (`AutoAddPolicy` / `StrictHostKeyChecking=no`), so use it on a trusted path
  to the target;
- SSH credentials cross the API and are used for the run only — nothing is
  persisted;
- a heartbeat that has not arrived within the verification window is reported as
  a warning, not a failure: the install may still be fine, so check `/agents`.

### Upgrade

`POST /api/agents/{id}/upgrade` (the drawer's **Upgrade** button) sets
`upgrade_requested` on the agent record. That is a marker for the operator
surface — no channel carries it to the host, and the agent does not act on it.
The upgrade itself runs on the host. `scripts/update-agent.sh` is not installed
by the installer — copy it to the target and run it as root, telling it where
the new package comes from:

```bash
sudo bash update-agent.sh --bundle-url https://internal.example/shapoclyack-agent.tar.gz
```

It reads `/etc/shapoclyack/agent.env`, refreshes the virtualenv's build tooling,
replaces the `agent` package from that tarball, verifies the result imports, and
restarts `shapoclyack-agent.service` or the `shapoclyack-agent` container. With
no `--bundle-url` it refuses to run unless you pass `--restart-only`, which
refreshes dependencies and restarts **without** changing the agent package and
reports exactly that. There is no self-update: nothing polls the server for a
new version. For a Docker install, pull the new image and re-run the installer
with `--docker` (or roll the Kubernetes deployment).

**Removing an agent** from `/agents` (`DELETE /api/agents/{id}`) only forgets the
registration. Stop `shapoclyack-agent.service` (or the container) on the host
first, otherwise the next heartbeat registers it again.

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
the scheduled backup succeeds and is uploaded. The **RTO target is 60 minutes**
for restoring Postgres + API into an isolated namespace (the path
`scripts/restore-postgres.sh` implements). ClickHouse and the artifact PVC have
no in-repo snapshot object — see below.

| Measure | Target | Last measured |
|---|---:|---:|
| PostgreSQL RPO | <= 24 h | 3 min (backup `2026-08-20T09:21:29Z` → recovery `2026-08-20T09:24:32Z` on kind `shapoclyack-dev`; the CronJob still bounds worst-case at 24 h) |
| Full base-stack RTO | <= 60 min | 31 s (`recovery_seconds` from the restore script: `pg_restore` + API migrate rollout) |
| PostgreSQL `pg_restore` duration | n/a | < 1 s (`db_restore_seconds=0` at 1 s resolution; 82 KiB custom dump of the live lab: 5 assets, 10 identifiers, 3 users, 2 jobs) |
| Restore drill date | n/a | 2026-08-20 |

Namespace `shapoclyack-restore`, overlay `k8s/shapoclyack/overlays/kind-restore`.
Row counts after restore matched the source. JetStream was **not** replayed —
Postgres is the durable store; see [NATS / JetStream recovery](#nats--jetstream-recovery).
ClickHouse and `scanner-data` were not snapshotted (kind `local-path` has no
`VolumeSnapshotClass`); that remains an install-specific choice, not an unmeasured
Postgres drill.

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

1. Create an isolated namespace and deploy the same Shapoclyack Postgres + API
   version that will consume the backup. On the kind lab that is
   `kubectl apply -k k8s/shapoclyack/overlays/kind-restore` (namespace
   `shapoclyack-restore`, no NodePort, no NATS/ClickHouse/scan Jobs). Elsewhere:
   same image tag as the source, Postgres and API secrets present, ingress and
   external integrations disabled. Wait until Postgres is Ready and the API has
   rolled out once — the restore script then replaces that empty schema.
2. Download `shapoclyack.dump` and `shapoclyack.dump.sha256` from the same backup
   prefix. On the kind lab, dump the source with the CronJob's `pg_dump` flags
   (`--format=custom --compress=6 --no-owner --no-privileges`) and a SHA-256
   sidecar; S3 upload is not required for the restore path itself.
3. Run:

```bash
scripts/restore-postgres.sh \
  --namespace shapoclyack-restore \
  --backup ./shapoclyack.dump \
  --checksum ./shapoclyack.dump.sha256
```

The script verifies SHA-256, restores with `pg_restore --clean --if-exists`,
restarts the API Deployment so its `migrate` init container brings the schema to
head (`python -m api.db.migrate`, see
[Upgrade and rollback](#one-supported-path-to-the-current-schema)), waits for a
successful rollout, then verifies database
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

## Upgrade and rollback

### One supported path to the current schema

`python -m api.db.migrate` — `alembic upgrade head` holding a PostgreSQL
advisory lock — run by the `migrate` init container on the API Deployment. Every
replica runs it and they queue on the lock, so a scaled Deployment no longer
starts N concurrent migrations. Each waiter still performs the upgrade after
acquiring the lock: skipping it would leave a replica running against whatever
schema the leader reached before it failed.

`models.Base.metadata.create_all` no longer runs on PostgreSQL. It is restricted
to SQLite, which is the dev and test fallback and is refused in production
anyway. Two ways to build the schema means the two eventually disagree, and the
disagreement is found in production: `create_all` builds today's models while
writing no `alembic_version`, so the database looks migrated to no revision at
all.

`OCTO_MIGRATION_LOCK_TIMEOUT_SECONDS` (default 600) bounds the wait for the lock.
On expiry the init container fails with a message naming the cause instead of
hanging at `Init:0/1`.

### The expand/contract rule

A rolling update runs the new schema against the **old** code: migrations
complete before the first new pod starts, while old pods keep serving. A
migration that removes or renames something the running version still uses takes
the API down during its own upgrade, and takes it down again if the deployment
is rolled back.

Therefore every schema change is split across two releases:

| Phase | Release N (expand) | Release N+1 (contract) |
|---|---|---|
| Add a column | Add it **nullable** or with a default; new code writes it, old code ignores it | Add `NOT NULL` once every row is populated and no old replica is left |
| Remove a column | Stop reading and writing it in code; leave it in the database | Drop it |
| Rename | Add the new name, write both, read the new with a fallback to the old | Drop the old name |
| Change a type | Add the new column, backfill, dual-write | Drop the old column |

The rule to apply when unsure: **release N's migration must leave release N-1's
code working.** That is what makes both the rolling update and the rollback
below safe, and it is the reason a rollback procedure can be short.

### Upgrade

1. Confirm the target image tag exists in GHCR. Images are published by the
   local Jenkins job `shapoclyack-publish` (`Jenkinsfile.publish`), started by
   hand with the release tag as `TAG` — not by pushing a git tag and not by
   `gh release create`. The Actions workflow that used to do it is disabled
   (its triggers are commented out; `workflow_dispatch` remains for a manual
   cross-check). `DRY_RUN` defaults to true, so a first run builds without
   publishing.
2. Take a backup and confirm it is current — see
   [PostgreSQL scheduled backup](#postgresql-scheduled-backup). The rollback
   path below assumes one exists.
3. Read the release's `CHANGELOG.md` entry for migrations. A migration that
   cannot be written in expand/contract form (a genuinely destructive one) is a
   maintenance window, not a rolling update, and must say so in the release
   notes.
4. Update the image tags and apply. Watch the `migrate` init container first —
   it is where a schema problem appears:

   ```bash
   kubectl -n network-scan logs deploy/shapoclyack-api -c migrate --follow
   kubectl -n network-scan rollout status deploy/shapoclyack-api
   ```

5. Verify: `GET /api/system` reports the new version, `GET /metrics` is served,
   and `sum(octo_scheduler_is_leader)` is exactly 1 across replicas.

### If a migration fails halfway

`api/db/migrations/env.py` wraps the whole upgrade in **one** transaction
(`context.begin_transaction()` around `run_migrations()`, not per revision), and
PostgreSQL executes DDL transactionally. A failing statement therefore rolls back
every revision in that run, and `alembic_version` still names the revision the
database was on before it started — there is no half-applied schema to
reconcile, and the init container fails instead of letting the API start on one.

The exception to be aware of: a migration that does its own commit, or that
operates outside the transaction (a concurrent index build), is not covered by
this. Any such migration must say so in its docstring, because it changes what
this section promises.

1. Read the init container's log — it names the failing revision.
2. Do **not** delete the pod repeatedly hoping it passes: a migration that
   failed on data will fail identically on the next attempt, and the advisory
   lock means each retry also blocks any other replica.
3. If the failure is environmental (disk, connection, lock timeout waiting for
   an unrelated long transaction), fix that and let the rollout retry.
4. If the failure is in the migration itself, roll back the image tag to the
   previous release (below). By the expand/contract rule the previous code runs
   against the current schema, so this is a safe place to stand while the
   migration is corrected.
5. `alembic downgrade` is **not** part of the routine path. Downgrade scripts
   are not exercised by CI and cannot restore data a migration dropped. The
   supported way back from a schema change that must be undone is a restore
   from backup into a fresh namespace — see
   [PostgreSQL restore drill](#postgresql-restore-drill).

### Rollback

```bash
kubectl -n network-scan rollout undo deploy/shapoclyack-api
kubectl -n network-scan rollout status deploy/shapoclyack-api
```

This reverts the code, not the schema — and by the expand/contract rule it does
not need to. The previous release's code runs against the newer schema because
release N's migration was required to leave release N-1 working.

Two consequences worth stating plainly:

- **Rolling back past a contract migration is not supported.** Once the
  contract half of a change has been applied, the code from before the expand
  half no longer matches the database. Roll back at most one release, or
  restore from backup.
- A rollback leaves the schema at the newer revision. That is intended: the next
  attempt at the upgrade is then a no-op on the migration and a plain image
  change.

Verify a rollback the same way as an upgrade, and confirm that jobs claimed by
the newer replicas are still progressing — a lease expiring during the rollout
is requeued by the reaper (P1.4), which is expected and not a failure.

### Legacy JSON state import

`api/services/{jobs,agents}.py` still import pre-P1.2 `state/api_{jobs,agents}.json`
once at startup, renaming them `*.imported` afterwards. That code is a one-time
migration aid for installations upgrading from before the Postgres control
plane. It is scheduled for removal in the **second** release after `0.41`: one
release is not enough, since an installation may skip a version, and keeping it
indefinitely means every future start pays for a path nothing has used in years.
An installation older than that must upgrade through `0.41` first, or accept
that the queued jobs and registered agents in those files are lost — neither is
state that a scan cannot recreate.

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
