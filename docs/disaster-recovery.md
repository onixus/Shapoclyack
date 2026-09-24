# Disaster recovery

What to restore, from what, in which order, and how to tell that it worked —
for all four stateful parts of an installation, not only PostgreSQL
([#333](https://github.com/onixus/Shapoclyack/issues/333)). The PostgreSQL
backup CronJob and its restore drill were already in place and stay documented
where they were, in
[operations.md § Backup and disaster recovery](operations.md#backup-and-disaster-recovery);
this page is the runbook around them.

The one rule everything below follows: **PostgreSQL is the reference point.**
It is the source of truth for everything the console shows except the contents
of a run. Every other store is restored, replayed or accepted *relative to the
moment PostgreSQL was restored to*, and the reconciliation section says what
each mismatch costs.

## What lives where

| Store | Holds | Source of truth for | Shipped protection | Lost without a backup |
|---|---|---|---|---|
| PostgreSQL | tenants, users, jobs, assets, findings and their lifecycle, audit trail, schedules, integrations (secrets envelope-encrypted), `run_publications`, `nats_outbox` | everything the console lists and decides on | `base/backup/postgres-cronjob.yaml`: `pg_dump` daily 02:15 UTC to S3 (`base`, `overlays/prod`). `overlays/prod-ha` deletes it: the managed provider's snapshots/PITR replace it ([high-availability.md](high-availability.md#external-postgres)) | the installation |
| Run artifacts | run directories: reports, raw tool output, `vulnerabilities.json`, screenshots, SARIF | the contents of a run | `OCTO_ARTIFACT_BACKEND=s3`: the bucket, which outlives the cluster. `local`: nothing by default — the `scanner-data` PVC; `examples/pvc-snapshot.example.yaml` is the CSI snapshot to schedule | reports and raw evidence of past runs; findings and assets stay (they are in Postgres) |
| ClickHouse | `shapoclyack_vulnerabilities`, `_open_ports`, `_controls` | nothing — a projection of runs, fed from `ingest.results.*` | `base/backup/clickhouse-cronjob.yaml` (this change): `BACKUP DATABASE … TO S3` daily 02:45 UTC, with a manifest | analytics history. **No console page reads ClickHouse**; its only in-product consumer is the advisory `clickhouse` check in `/api/health`. Dashboards and BI built on it lose their history |
| NATS JetStream | streams `JOBS`, `INGEST`, `EVENTS` and their consumers' cursors | nothing — transport | none, deliberately (see [JetStream](#jetstream)) | messages accepted but not yet consumed |

Base ships NATS and ClickHouse running but **unused**: `OCTO_NATS_URL` and
`OCTO_CLICKHOUSE_URL` are empty in `base/api-deployment.yaml` until an
installation enables them (`examples/nats-api-patch.yaml`,
`examples/clickhouse-ingest-api-patch.yaml`). On such an installation
ClickHouse is empty and JetStream carries nothing; their rows below apply once
they are turned on.

### Keys that are in no backup

A restored database is useless without these. None of them is in any dump or
snapshot the repository takes, on purpose: they live in the Secret store
(`examples/externalsecret.example.yaml`), and that store's own backup is the
place they are recovered from. Escrow them before you need them.

| Secret | Without the original value after a restore |
|---|---|
| `OCTO_MASTER_KEY` (and `OCTO_MASTER_KEY_PREVIOUS` mid-rotation) | Every encrypted value in Postgres — webhook secrets and headers, ticket tokens, chat webhook URLs, TOTP secrets — is unreadable: with a different key, each such delivery dead-letters on its first attempt ([operations.md § When a row cannot be decrypted](operations.md#when-a-row-cannot-be-decrypted)); with none, a `prod` API refuses to start while such rows exist ([§ Secrets at rest](operations.md#secrets-at-rest)). The only way forward is re-entering every integration credential and re-enrolling every TOTP user. **This is the one that cannot be regenerated.** |
| `OCTO_JWT_SECRET` | Console sessions end; everybody signs in again. Nothing else. |
| `OCTO_AGENT_JWT_SECRET` | Sensors meet a `401` and re-exchange their provisioning keys (bcrypt hashes in Postgres) on their next pass — self-healing ([operations.md § Rotating the agent JWT signing key](operations.md#rotating-the-agent-jwt-signing-key)). |
| `shapoclyack-backup` (bucket credentials) | Nothing is restorable. Keep a read-only copy of these credentials outside the cluster. |
| Postgres / ClickHouse / NATS passwords, NATS route password | Not stored in any backup (`pg_dump --no-owner --no-privileges`; ClickHouse users come from `users.xml`). Set new values; nothing is lost. |
| `OCTO_OIDC_CLIENT_SECRET`, SMTP password, TLS keys | Re-issue from the IdP / mail provider / cert-manager. |

## Recovery objectives

| Store | RPO (design) | RTO target | Measured — see [the drill](#drill) |
|---|---|---|---|
| PostgreSQL, `pg_dump` CronJob | ≤ 24 h + dump time (daily 02:15 UTC) | ≤ 60 min, Postgres + API into a fresh namespace | kind, 2026-08-20: 31 s end to end (82 KiB, 5 assets). Local stack, 2026-09-24: 10k assets, `pg_restore` + migrate 1.3–1.7 s |
| PostgreSQL, managed (`prod-ha`) | the provider's PITR, typically minutes | the provider's | not measured here |
| Artifacts, S3 backend | 0 while the bucket survives; the bucket's own versioning/replication otherwise | 0 (the API reads the bucket; no restore step) | n/a |
| Artifacts, local PVC + VolumeSnapshot | the snapshot interval | provisioning a PVC from a snapshot — storage-specific | not measured: no CSI snapshot class in this environment or on kind |
| ClickHouse, BACKUP CronJob | ≤ 24 h from the backup alone (daily 02:45 UTC); down to what `INGEST` still retains when the broker survived ([replay](#closing-the-gap-from-ingest)) | ≤ 4 h — advisory: the console does not wait for it | local stack, 10k assets: restore 1.8–2.7 s, INGEST replay of the post-backup run 2.7–3.3 s after the API was ready |
| JetStream | not backed up: messages in flight at the failure | the API recreates the streams on connect | local stack: all three streams back on the first API start after they were deleted (ready in 3.1–4.1 s) |

The PostgreSQL target is the existing one; the ClickHouse target is a new,
deliberately loose one. It is loose because ClickHouse is a projection nothing
in the console reads, so restoring it is never on the path to the console
coming back, and because each of the three ways to recover it — restore,
replay, rebuild — can be chosen after the fact.

## Decision tree

```text
What was lost?
│
├─ ClickHouse only (pod, PVC or data) ──────────────► § ClickHouse, choose A/B/C
│
├─ JetStream only (NATS PVCs) ──────────────────────► § JetStream: let the API recreate the
│                                                     streams; then ClickHouse option A or C
│                                                     for runs that were in INGEST unconsumed
│
├─ Artifact volume only (local backend) ────────────► § Artifacts: PVC from the latest snapshot;
│                                                     § Reconciling: artifacts older than Postgres
│
├─ PostgreSQL only ─────────────────────────────────► restore-postgres.sh (or provider PITR),
│                                                     then § Reconciling restore points — every row
│
└─ The cluster / everything ────────────────────────► § Full restore, in order
```

## Full restore, in order

The order is dictated by what depends on what: the API's migrate step needs
Postgres, reconciliation needs the API, and nothing may reach the restored
stack — users, sensors, integrations — until reconciliation is done.

0. **Decide and record the restore points.** Write down the incident time and,
   for each store, the backup you are going to use and the moment it
   represents: `T_pg` (dump object prefix, or the PITR target), `T_art`
   (snapshot name, or "live bucket"), `T_ch` (the `backup_success` line's
   `id`). Everything in § Reconciling is phrased in these.
1. **Secrets.** Recreate the Secrets from the escrow — `OCTO_MASTER_KEY` first
   ([above](#keys-that-are-in-no-backup)).
2. **PostgreSQL** to `T_pg`: `scripts/restore-postgres.sh` into a fresh
   namespace ([operations.md § PostgreSQL restore drill](operations.md#postgresql-restore-drill)),
   or the provider's PITR for `prod-ha`. Deploy the API with
   `OCTO_ALLOW_SCAN_START=false` and **no Ingress/NodePort yet**: nothing may
   submit a scan, and no sensor may claim a queued one, until step 6.
3. **Artifacts.** S3: nothing to do — point the API at the same bucket. Local:
   create `scanner-data` from the snapshot *before* applying the overlay
   (`examples/pvc-snapshot.example.yaml`, § Artifacts).
4. **ClickHouse** to `T_ch`, or not at all — § ClickHouse, option A, B or C.
   Leave `OCTO_CLICKHOUSE_URL` / ingest off until step 7.
5. **NATS.** Start it empty. The API creates `JOBS`, `INGEST` and `EVENTS` with
   the configured limits on connect; nothing needs restoring (§ JetStream). If
   the old JetStream survived, keep `INGEST` for step 7 and purge `JOBS`.
6. **Reconcile** Postgres against the other stores — § Reconciling restore
   points, top to bottom.
7. **Ingest back on.** Set `OCTO_CLICKHOUSE_URL`, roll the API; if `INGEST`
   survived, [replay it](#closing-the-gap-from-ingest).
8. **Verify** — § Verification checklist.
9. **Open the doors.** Ingress/DNS to the restored API, then
   `OCTO_ALLOW_SCAN_START=true`. Sensors reconnect by themselves.

## Reconciling restore points

Postgres is at `T_pg`. For each other store, find the row that matches its
restore point and do what it says. The backup schedules are laid out so the
harmless direction is the default: the ClickHouse backup (02:45) and the PVC
snapshot (take it after the dump finishes) are both *newer* than the 02:15
dump of the same night, and an S3 bucket that survived is newer by definition.

### Artifacts newer than Postgres (`T_art ≥ T_pg` — the default)

Runs published between `T_pg` and `T_art` are in the store and **listed in the
console** — the run list is read from the store, each run filed under its
tenant — but Postgres has no job for them, and their assets and findings were
folded into a database that has since been rolled back. Nothing is disclosed
across tenants (ownership comes from the run's path and `tenant.json`), and
nothing breaks; the runs are simply orphans until run retention ages them out.
List them, and either leave them or re-scan what they covered:

```bash
kubectl -n "$NS" exec deploy/shapoclyack-api -- python -c "
from sqlalchemy import select
from api.db import models
from api.db.engine import get_session
from api.services import runs
from api.settings import load_settings
s = load_settings()
page, _ = runs.list_runs(s, limit=100000)
with get_session(s.postgres_url) as session:
    known = set(session.scalars(select(models.Job.run_id).where(models.Job.run_id.is_not(None))))
for run in page:
    if run.run_id not in known:
        print(run.run_id)
"
```

A run started by hand with `scanner.main` never had a job either, so it shows
up in this list too.

### Artifacts older than Postgres (`T_art < T_pg`)

The expensive direction. Jobs that finished between `T_art` and `T_pg` say
*succeeded* and point at runs whose files are gone: reports answer 404, and
the console shows a scan with no artifacts. Their findings and assets are
intact (they are Postgres rows). List them, tell the tenants, re-scan:

```bash
kubectl -n "$NS" exec deploy/shapoclyack-api -- python -c "
from datetime import datetime
from sqlalchemy import select
from api.db import models
from api.db.engine import get_session
from api.settings import load_settings
t_art = datetime.fromisoformat('2026-09-24T02:30:00')  # UTC, as stored
with get_session(load_settings().postgres_url) as session:
    for row in session.execute(
        select(models.Job.tenant_id, models.Job.job_id, models.Job.run_id, models.Job.finished_at)
        .where(models.Job.status == 'succeeded', models.Job.finished_at > t_art)
        .order_by(models.Job.finished_at)
    ):
        print(*row)
"
```

This is why the snapshot is taken after the dump and not before.

### ClickHouse older than Postgres (`T_ch < T_pg`)

Rows for runs published between `T_ch` and `T_pg` are missing. Replay `INGEST`
([below](#closing-the-gap-from-ingest)) if the broker survived and still holds
them; otherwise accept the gap or rebuild (option C). The console is not
affected either way.

### ClickHouse newer than Postgres (`T_ch ≥ T_pg` — the default)

ClickHouse has rows for runs Postgres does not know — the same runs as the
orphaned artifacts above. Analytics then describe what was actually scanned,
which is the truth; leave them. If a dashboard must match the console exactly,
delete them by `run_id` with the list above.

### What rolling Postgres back to `T_pg` does to Postgres itself

These follow from the restore regardless of the other stores:

| What | After the restore | Do |
|---|---|---|
| Jobs `queued`, `claimed`, `running`, `cancelling` at `T_pg` | They come back in that state. Some ran after `T_pg` (their runs are the orphans above); the queued ones would be **claimed and run again** by sensors — against targets whose change windows may have moved | Before step 9, cancel the ones you do not want re-run: `POST /api/jobs/{job_id}/cancel`. `OCTO_ALLOW_SCAN_START=false` blocks new submissions, not claims of rows already queued, and the change freeze is an admission gate too |
| `run_publications` pending at `T_pg` | Their staging trees were on pods that no longer exist; after `OCTO_RUN_PUBLICATION_ORPHAN_DEADLINE_SECONDS` they go `dead` with *the replica that accepted this upload is gone* | If the run reached the store after `T_pg` it is already published — discard the row. Otherwise re-scan ([operations.md § Runs accepted but not published](operations.md#runs-accepted-but-not-published-run_publications)) |
| `nats_outbox` rows at `T_pg` | The reconciler republishes them — including ones the broker had since accepted | A copy whose first one landed more than the duplicate window (24 h) ago is accepted again: ClickHouse collapses it (ReplacingMergeTree); a webhook receiver may see that asset event twice |
| Webhook deliveries pending at `T_pg` | Re-attempted | Receivers that dedupe by event id see nothing; others may see a repeat |
| Users, memberships, service tokens, provisioning keys, sensors created after `T_pg` | Gone | Re-create; sensors registered after `T_pg` need a new provisioning key and a re-install |
| Sessions and refresh tokens | Those issued after `T_pg` are gone | Users sign in again |
| Workflow events (SLA breaches, sensors offline) announced after `T_pg` | Their markers are gone, so the escalation worker announces them again | Expect a second notification for each; nothing to do |
| Audit events after `T_pg` | Gone from Postgres | If the SIEM forwarder ran ([#328](https://github.com/onixus/Shapoclyack/issues/328)), the SIEM holds them — it is the record of the gap. Say so in the incident report |

## ClickHouse

### The backup

`k8s/shapoclyack/base/backup/clickhouse-cronjob.yaml` runs daily at 02:45 UTC,
half an hour after the Postgres dump, with the same `shapoclyack-backup`
Secret and keys. The work is done by the ClickHouse **server**: the pod issues

```sql
BACKUP DATABASE shapoclyack TO S3('<url>', '<key id>', '<secret>') SETTINGS id = '<id>' ASYNC
```

polls `system.backups` until the server reports `BACKUP_CREATED`, and then
writes `manifest.jsonl` into the backup's directory: one line per table with its part
and row counts, **read back from the uploaded backup** (`count.txt` of every
part, through the `s3()` table function) rather than from the live tables,
plus the SHA-256 of the backup's own `.backup` file list. The logic is
`base/backup/clickhouse-backup.sh`, mounted from a generated ConfigMap, so
`scripts/dr-drill.py` runs the same bytes. A run ends with one line:

```text
backup_success id=shapoclyack-20260924T024500Z database=shapoclyack url=https://BUCKET.s3.REGION.amazonaws.com/PREFIX/clickhouse/20260924T024500Z tables=3 rows=70141 files=44 total_size=805469 compressed_size=804867 seconds=2
```

Layout: `s3://BUCKET/PREFIX/clickhouse/<stamp>/` — the ClickHouse backup,
with `manifest.jsonl` inside — next to the Postgres dumps at
`s3://BUCKET/PREFIX/<stamp>/`. With `endpoint_url` set (MinIO, Ceph RGW) the
URL is path-style under that endpoint.

What it needs that the Postgres job does not:

- **The server reaches the bucket**, not the pod. An egress NetworkPolicy on
  ClickHouse must allow the S3 endpoint, and for an endpoint with a private CA
  the CA must be in the ClickHouse image's trust store. The pod itself only
  talks to `shapoclyack-clickhouse-client:9000`, which
  `base/networkpolicy-datastores.yaml` admits for the
  `app.kubernetes.io/component: clickhouse-backup` label and nothing else (the
  Postgres dump's `backup` label is not admitted to ClickHouse, nor this one
  to Postgres).
- **Bucket permissions** for `PREFIX/clickhouse/*`: `s3:PutObject`,
  `s3:GetObject`, `s3:ListBucket`, `s3:AbortMultipartUpload`, and
  `s3:DeleteObject` — the server writes a `.lock` object while the backup runs
  and deletes it at the end (seen in the drill's S3 request log). The restore
  needs `GetObject` and `ListBucket` only — give the restore its own read-only
  key.
- **Retention is a bucket lifecycle rule** on `PREFIX/clickhouse/`, expiring
  by age. That is safe precisely because every backup is a full one.

**Why full and not incremental.** An incremental backup (`base_backup`) cannot
outlive its base, so an age-based lifecycle rule silently breaks the chain.
And the saving does not survive merges: these are ReplacingMergeTree tables,
whose merges rewrite whole parts, and a rewritten part is new to the
incremental. Measured on a 50,500-asset fixture (ClickHouse 24.8.14, S3
emulated by moto): full backup 3,994,901 bytes; incremental after inserting
~1 % new rows 58,718 bytes (1.5 %); the same incremental after the new part
merged into the old one (`OPTIMIZE … FINAL`, which background merges do by
themselves) 4,028,797 bytes — 101 % of the full.

**Credentials.** `CLICKHOUSE_PASSWORD` reaches `clickhouse-client` through
its environment; the S3 key pair has to travel inside the statement, because
the server is the one talking to S3, so it is written to the client's stdin
and never to an argument. The server masks the secret as `[HIDDEN]` in
`system.backups`, `system.query_log` and its own log (checked on 24.8.14) —
**the access key id stays visible there**, which is an identifier, not a
secret. `clickhouse-client`, however, prints the entire statement after any
error it reports, secret included; the script passes everything the client
writes through a filter that drops that block and masks both secrets wherever
else they might appear. The pod runs as uid 101 with a read-only root
filesystem, no service-account token, and a memory-backed `/tmp`.

A CSI snapshot of `clickhouse-data` is an alternative only where the storage
documents it as application-consistent or writes are stopped while it is
taken; nothing verifies it the way the manifest verifies a BACKUP, so a
snapshot object existing proves nothing about the tables in it.

A failed or stale backup: `examples/prometheusrule-backup.example.yaml` carries
`ShapoclyackClickHouseBackupStale` (last success older than 26 h) and
`ShapoclyackClickHouseBackupJobFailed`, next to the Postgres pair. Both are
`warning`, not `critical`: a stale ClickHouse backup lengthens a recovery, it
does not put the source of truth at risk.

### Choosing how to recover

| | A — restore the backup | B — start empty | C — rebuild from artifacts |
|---|---|---|---|
| What you get | history up to `T_ch`, plus whatever `INGEST` replays | analytics from now on | history for runs still inside `OCTO_RUN_RETENTION_DAYS` |
| Cost | minutes; the backup's size in S3 reads | nothing | re-reading and re-transforming every retained run — **no tool ships for this**; it would be the `ch_transform` step the ingest worker runs, over the artifact store |
| Loses | runs between `T_ch` and the failure, unless replayed | all history | history older than run retention (the vulnerability and port tables keep 90 days, controls 365); and every row is re-scored with *today's* enrichment and asset criticality, so historical `contextual_score`/`epss_score` values change |
| Use when | the default | nobody uses the dashboards, or the backup is unusable | only if both A and B are unacceptable — it is engineering work, not a procedure |

### Restoring (option A)

Into a ClickHouse that is empty — a new PVC, whose first boot has already run
`init.sql` and created the three tables empty, is exactly that. With ingest
still off:

```bash
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…     # read-only key; never printed
URL=https://BUCKET.s3.REGION.amazonaws.com/PREFIX/clickhouse/20260924T024500Z

scripts/restore-clickhouse.sh --namespace shapoclyack-restore --backup-url "$URL" --dry-run
scripts/restore-clickhouse.sh --namespace shapoclyack-restore --backup-url "$URL"
```

The script runs `clickhouse-client` inside the ClickHouse pod
(`kubectl exec -i`, SQL on stdin) and stops, each with its own exit code, when:

1. the manifest is unreadable or names no table (4);
2. the backup no longer matches its manifest — per-table part and row counts
   recounted from the bucket, and the `.backup` digest, so a manifest paired
   with another backup fails even when the counts agree (6); a table name in
   the manifest that is not a plain identifier is refused before it reaches a
   statement (6);
3. a table the backup holds already has rows in the target (7) — RESTORE would
   append, and ReplacingMergeTree would then keep whichever copy merged last.
   Drop the database deliberately first if that is what you mean.

`--dry-run` stops there. Otherwise it creates the tables
(`structure_only`), stops merges on them, runs `RESTORE … ASYNC`, polls it, and
compares each restored table's `count()` to the manifest (8 on a mismatch).
Merges are stopped so that the comparison is against the counts the backup
stored and not against what a merge has deduplicated since; they are started
again however the script exits. `network-scan` is refused unless
`ALLOW_PRODUCTION_RESTORE=1`, as in the Postgres script. `--local` runs a
`clickhouse-client` on the operator's host instead of `kubectl exec`.

### Closing the gap from INGEST

When the broker survived, `INGEST` still holds every run published in the last
`OCTO_NATS_INGEST_MAX_AGE_SECONDS` (7 days) or `OCTO_NATS_INGEST_MAX_BYTES`
(10 GiB), whichever is hit first. The ingest worker's durable consumer has
already acknowledged the ones after `T_ch`, so the restored tables would never
see them. Delete the consumer and let the API recreate it — it is created at
`DeliverPolicy.ALL`, i.e. a replay of everything the stream retains:

```bash
nats consumer rm INGEST octo-ch-ingest-results      # from a host with the CLI
kubectl -n "$NS" rollout restart deployment/shapoclyack-api
```

The replay is idempotent — the tables are keyed on what the transform emits,
and the same message produces the same rows — and it re-scores with the
enrichment data of the moment, like any ingest. Runs whose archive was over
the 4 MB inline cap were never in the stream with a body; for those the
artifacts are the record, as always ([operations.md § NATS outbox](operations.md#nats-outbox)).
In the drill a run published after the backup was absent after the restore
(0 of 100 rows) and back 2.7–3.3 s after the API came up.

## Artifacts

**S3 backend** ([#336](https://github.com/onixus/Shapoclyack/issues/336)). The
bucket is the artifact store, and it is outside the cluster — a lost cluster
loses nothing there, and `T_art` is "now". Protect the bucket itself against
deletion: versioning, and, where the provider has it, replication or object
lock. If versioning is on, expire only **noncurrent** versions in a lifecycle
rule; an expiry rule on current objects is the second retention policy
[high-availability.md](high-availability.md#object-storage-artifacts-s3-patchyaml)
warns against. The per-pod cache is an `emptyDir` and needs nothing.

**Local backend.** The runs are files on `scanner-data`. Kubernetes has no
scheduled snapshots of its own; schedule `VolumeSnapshot`s with whatever your
storage offers (Velero, the CSI driver's snapshot policies, a CronJob you
own), **after** the 02:15 dump finishes, and name each after its moment.
`k8s/shapoclyack/examples/pvc-snapshot.example.yaml` has the snapshot, and the
restore into the isolated namespace: a pre-provisioned `VolumeSnapshotContent`
(`deletionPolicy: Retain`, so deleting the drill namespace never deletes the
production restore point) re-binds the storage-side snapshot there, and the
`scanner-data` claim is created from it **before** the overlay is applied —
`dataSource` is immutable, so a claim the overlay created empty cannot be
pointed at the snapshot afterwards. A CSI snapshot of a volume being written is
crash-consistent: a scan that was mid-write is a partial run directory, which
is what a crashed scan leaves anyway. kind's `local-path` provisioner has no
snapshot support, so none of this can be exercised there.

## JetStream

JetStream is not backed up, and the recommended recovery is to let the API
recreate the streams. What each one holds, and what losing it costs:

| Stream | Carries | Also durable in | Lost with the stream |
|---|---|---|---|
| `JOBS` (work queue, 24 h) | job offers per tenant | the `jobs` row in Postgres; sensors also claim over HTTP (`POST /api/agent/jobs/claim`) | nothing — a job without an offer is claimed over HTTP |
| `INGEST` (7 d / 10 GiB) | `ingest.results.*`: each accepted run's archive for the ClickHouse projection | the run in the artifact store; `nats_outbox` only for publishes the broker **refused** | ClickHouse rows of runs the ingest worker had not consumed — an analytics gap, closable by option A's replay only while a stream holds them, or by option C |
| `EVENTS` (30 d / 1 GiB) | asset, workflow and audit events: the webhook fan-out and the SIEM forwarder's NATS source | audit events are Postgres rows; asset events are in the run's `diff.json`; workflow events are derived from Postgres state, with `workflow_event_markers` recording which were announced | the webhooks and SIEM lines of events published but not yet fanned out — nothing re-sends them. The SIEM forwarder's database source (`OCTO_AUDIT_SYSLOG_SOURCE=db`) does not depend on the stream |

The `nats_outbox` table (migration `0059`) does not change this: it holds a
message only while the broker refuses it, and deletes the row the moment the
stream has it. A message the broker accepted is the broker's.

**Re-creation.** Start NATS with an empty store. On connect the API creates
all three streams with the configured subjects, retention, limits, duplicate
windows and replica count (`nats_bus._ensure_stream`); the ingest worker, the
webhook fan-out and the SIEM forwarder create their durables when they bind,
and sensors create their tenant's consumer on their first fetch. The drill
deleted all three streams and got them back — `JOBS` work-queue 24 h,
`INGEST` 7 d with a 24 h duplicate window, `EVENTS` 30 d — on the first API
start.

**`nats stream backup` / `restore`** exists and is not recommended. A restored
stream brings back consumer cursors from the snapshot's moment: the webhook
fan-out re-sends everything after that moment, and the ClickHouse consumer
re-delivers from its old position. The one case it pays for is keeping
`INGEST` across a broker loss for the replay above; if you take it, restore it
with the consumers stripped (`nats stream restore` then `nats consumer rm` on
each durable) and let the services recreate them — the fan-out comes back at
`DeliverPolicy.NEW`, the ingest worker at `ALL`.

If the broker survived a Postgres restore, purge `JOBS` before sensors
reconnect (`nats stream purge JOBS`): its offers name jobs the restored
database may not have.

Never recover messages by republishing them with new message ids — a
hand-rolled replay from a dump of the stream, say. Every publisher sets a
stable `Nats-Msg-Id`, and the duplicate windows and ReplacingMergeTree keys
that make the replays above safe rely on it.

## Verification checklist

A restore is done when all of these hold, not when the commands exit 0:

- `restore_success` from `scripts/restore-postgres.sh`, and the API rolled out
  once on the restored database (migrate init container green).
- `/readyz` 200; `/api/health` — `postgres` ok; `clickhouse` ok if it was
  restored; `nats_outbox` and `run_publications` understood (a `dead` row after
  a restore is expected — see the table above — and needs a decision).
- A platform admin can sign in and `GET /api/assets?tenant_id=<tenant>` returns
  the tenant's count as of `T_pg`; spot-check a report from a run before
  `T_pg` (artifacts readable).
- `restore_success` from `scripts/restore-clickhouse.sh` (per-table counts
  equal to the manifest), and — after ingest is back on — the
  `octo_ch_ingest_messages_total{result="ok"}` counter moving.
- `nats stream ls` lists `JOBS`, `INGEST`, `EVENTS`.
- The reconciliation lists (orphan runs, runs missing files, stale queued jobs,
  lost sensors) are written into the incident record, with what was done.

## Drill

`scripts/dr-drill.py` runs the whole cycle — seed, back up, wipe, restore,
verify — on a local stack, through the same artifacts the cluster runs: the
CronJob's `pg_dump` flags, `restore-postgres.sh`'s `pg_restore` flags and the
API's own `python -m api.db.migrate`, the CronJob's `clickhouse-backup.sh`,
and `restore-clickhouse.sh --local`. It seeds with
`tests.fixtures.scale_seed`, fingerprints both stores (Postgres row counts of
every table plus MD5 over `assets`, `asset_identifiers`, `tenants`, `users`;
ClickHouse `count()` and `sum(cityHash64(*))` per table, `FINAL`), and after
the restore boots the API, signs in and reads the tenant's assets back. With
`--nats-url` it also runs the two JetStream legs: a run published through
`INGEST` *after* the ClickHouse backup, which the restore loses and the replay
brings back, and a JetStream whose three streams are deleted and recreated by
the API. It is destructive by design and refuses to start without
`--destroy-and-restore`.

```bash
CLICKHOUSE_PASSWORD=… AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… \
python3 scripts/dr-drill.py --destroy-and-restore \
  --postgres-url postgresql://postgres@localhost:5432/shapo_drill \
  --clickhouse-client "clickhouse client" --clickhouse-port 9000 --clickhouse-http-port 8123 \
  --clickhouse-pid "$(pgrep -f 'clickhouse server' | head -n 1)" \
  --s3-endpoint http://127.0.0.1:9000 --s3-bucket drill-backups \
  --nats-url nats://127.0.0.1:4222 --assets 10000 --out drill.json
```

### Recorded: 2026-09-24, 10k assets

**Environment.** One Linux container, 4 vCPU shared with about ten other
workloads (load average 4.2–8.1 during the runs), 15 GiB RAM. PostgreSQL 16.13
with `fsync=off`, `synchronous_commit=off`, `full_page_writes=off` — restore
times are therefore optimistic against real disks. ClickHouse 24.8.14.39
(single binary). S3 emulated by moto 5.2.3 on localhost — no network, no real
object-store latency. NATS 2.10.29. Not kind, not a cluster: no scheduling,
image pulls or PVC provisioning are in these numbers.

**Data.** `scale_seed --assets 10000`: 10,000 assets, 13,558 identifiers in
Postgres (everything else near-empty: one tenant, one user); 69,991 ClickHouse
rows plus 150 from the drill's run A — 70,141 in the backup. The dump is
848 KB, the ClickHouse backup 805 KB in 44 files. A real installation of 10k
assets also has findings, jobs, audit history and run artifacts, so these
sizes are a floor, not an estimate.

Three runs, all verified (fingerprints equal, API served 10,000 assets,
`/api/health` `postgres` and `clickhouse` ok, run B 0 → 100 rows by replay,
three streams recreated). Wall seconds / CPU seconds of the processes the drill
started / ClickHouse server CPU seconds:

| Phase | Run 1 | Run 2 | Run 3 | Median wall |
|---|---|---|---|---:|
| `pg_dump` + SHA-256 | 0.24 / 0.13 / — | 0.21 / 0.13 / — | 0.38 / 0.12 / — | 0.24 |
| ClickHouse backup (CronJob script) | 1.45 / 0.30 / 0.11 | 1.75 / 0.30 / 0.12 | 1.88 / 0.32 / 0.12 | 1.75 |
| Postgres restore: `pg_restore` + migrate | 1.29 / 0.82 / — | 1.47 / 0.79 / — | 1.72 / 0.93 / — | 1.47 |
| ClickHouse restore, `--dry-run` | 0.23 / 0.15 / 0.03 | 0.52 / 0.15 / 0.04 | 0.34 / 0.15 / 0.04 | 0.34 |
| ClickHouse restore | 2.03 / 0.63 / 0.16 | 1.76 / 0.58 / 0.14 | 2.73 / 0.66 / 0.19 | 2.03 |
| API boot → assets served | 4.32 / 3.12 / — | 8.14 / 4.96 / — | 6.00 / 3.24 / — | 6.00 |
| **RTO, all four in sequence** | 7.87 | 11.89 | 10.78 | **10.78** |
| **RTO, console path** (Postgres + API) | 5.61 | 9.61 | 7.72 | **7.72** |

- `pg_restore` alone took 0.39–0.44 s; the rest of the Postgres row is the
  migrate step on an already-current schema (0.81–1.24 s).
- The ClickHouse backup's wall time is bounded by the 1 s status poll, not by
  the work (0.11–0.12 s of server CPU).
- INGEST replay: the API was ready in 4.3–4.6 s, and ClickHouse matched its
  pre-disaster fingerprint 2.7–3.3 s later.
- JetStream re-creation: all three streams present with their configured
  limits once the API was ready (3.1–4.1 s).
- The two ingest phases and the replay phase take ~20 s of wall time each in
  the raw output; most of that is the API's own shutdown with a NATS
  connection open, after the measured work is done.
- Postgres server CPU is not in the table (its backends are not the drill's
  children).

A single 50k-asset run (no JetStream legs, same machine): dump 3.47 MB,
ClickHouse backup 3.99 MB / 349,930 rows, `pg_restore` 1.33 s, ClickHouse
restore 2.45 s, RTO 10.2 s in sequence and 7.2 s on the console path.

**RPO in this drill** is zero by construction — nothing wrote between the
backup and the wipe except the run the replay recovered. The achievable RPO is
the schedule's: up to 24 h for Postgres and for ClickHouse from its backup,
and for ClickHouse down to the stream's retention when `INGEST` survives.

### On kind or the Arch stand

Not run for this change — there is no cluster in the environment it was made
in. The sequence, with the objects from this repository:

```bash
# Source: a stand with shapoclyack-backup pointing at a bucket (MinIO is fine).
kubectl -n network-scan create job --from=cronjob/shapoclyack-postgres-backup   pg-drill
kubectl -n network-scan create job --from=cronjob/shapoclyack-clickhouse-backup ch-drill
kubectl -n network-scan logs job/ch-drill            # backup_success … url=…

# Target: the isolated namespace (Postgres + API + ClickHouse, no NATS, no backups).
kubectl apply -k k8s/shapoclyack/overlays/kind-restore
aws s3 cp s3://BUCKET/PREFIX/<stamp>/shapoclyack.dump .          # and .sha256
scripts/restore-postgres.sh --namespace shapoclyack-restore \
  --backup ./shapoclyack.dump --checksum ./shapoclyack.dump.sha256
scripts/restore-clickhouse.sh --namespace shapoclyack-restore --backup-url "$URL" --dry-run
scripts/restore-clickhouse.sh --namespace shapoclyack-restore --backup-url "$URL"
```

Record `db_restore_seconds`/`recovery_seconds` and `restore_success` in the
tables above, with the stand's shape. Both ClickHouse servers — the source's
for BACKUP, the restore namespace's for RESTORE — need to reach the bucket; on
kind with MinIO in-cluster that is the cluster network.
