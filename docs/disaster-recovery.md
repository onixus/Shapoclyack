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
| ClickHouse | `shapoclyack_vulnerabilities`, `_open_ports`, `_controls` | nothing — a projection of runs, fed from `ingest.results.*` | `base/backup/clickhouse-cronjob.yaml`: `BACKUP DATABASE … TO S3` daily 02:45 UTC, with a manifest | analytics history. **No console page reads ClickHouse**; its only in-product consumer is the advisory `clickhouse` check in `/api/health`. Dashboards and BI built on it lose their history |
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
| `shapoclyack-backup`, `shapoclyack-clickhouse-backup-s3` (bucket keys) | Nothing is restorable. Keep a read-only key for the bucket outside the cluster. |
| Postgres / ClickHouse (`default` and `shapoclyack_backup`) / NATS passwords, NATS route password | Not stored in any backup (`pg_dump --no-owner --no-privileges`; ClickHouse users come from `users.xml`). Set new values; nothing is lost. |
| `OCTO_OIDC_CLIENT_SECRET`, SMTP password, TLS keys | Re-issue from the IdP / mail provider / cert-manager. |

## Recovery objectives

| Store | RPO (design) | RTO target | Measured — see [the drill](#drill) |
|---|---|---|---|
| PostgreSQL, `pg_dump` CronJob | ≤ 24 h + dump time (daily 02:15 UTC) | ≤ 60 min, Postgres + API into a fresh namespace | kind, 2026-08-20: 31 s end to end (82 KiB, 5 assets). Local stack, 2026-09-24: 10k assets, `pg_restore` + migrate 1.2–1.7 s |
| PostgreSQL, managed (`prod-ha`) | the provider's PITR, typically minutes | the provider's | not measured here |
| Artifacts, S3 backend | 0 while the bucket survives; the bucket's own versioning/replication otherwise | 0 (the API reads the bucket; no restore step) | n/a |
| Artifacts, local PVC + VolumeSnapshot | the snapshot interval | provisioning a PVC from a snapshot — storage-specific | not measured: no CSI snapshot class in this environment or on kind |
| ClickHouse, BACKUP CronJob | ≤ 24 h from the backup alone (daily 02:45 UTC); down to what `INGEST` still retains when the broker survived ([replay](#closing-the-gap-from-ingest)) | ≤ 4 h — advisory: the console does not wait for it | local stack, 10k assets: restore 2.0–3.4 s, INGEST replay of the post-backup run 1.6–2.3 s after the API was ready |
| JetStream | not backed up: messages in flight at the failure | the API recreates the streams on connect | local stack: all three streams back on the first API start after they were deleted (ready in 3.0–4.6 s) |

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
│                                                     streams. ClickHouse is intact; the runs
│                                                     that were in INGEST unconsumed are a gap
│                                                     only option C closes — or accept it
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

The order is dictated by what depends on what: the artifact claim has to exist
before the overlay that would otherwise create it empty, the API's migrate
step needs Postgres, reconciliation needs the API, and nothing may reach the
restored stack — users, sensors, integrations — until reconciliation is done.
`NS` below is the namespace you restore into.

0. **Decide and record the restore points.** Write down the incident time and,
   for each store, the backup you are going to use and the moment it
   represents: `T_pg` (dump object prefix, or the PITR target), `T_art`
   (snapshot name, or "live bucket"), `T_ch` (the `backup_success` line's
   `id`). Everything in § Reconciling is phrased in these.
1. **Namespace and Secrets.** `kubectl create namespace "$NS"`, then recreate
   the Secrets there from the escrow — `OCTO_MASTER_KEY` first
   ([above](#keys-that-are-in-no-backup)).
2. **Artifacts, before anything that mounts them.** S3 backend: nothing to
   create — the API will read the same bucket. Local backend: create the
   `scanner-data` claim from the snapshot now, with the objects in
   `examples/pvc-snapshot.example.yaml` (§ Artifacts). The overlay renders a
   `scanner-data` claim too, and `dataSource` is immutable: applied first, it
   leaves an empty volume no snapshot can be put into, and Postgres is then
   restored beside no artifacts at all.
3. **The stack**, with the API unreachable and unable to scan:
   `kubectl apply -k <your restore overlay>` with `OCTO_ALLOW_SCAN_START=false`
   in the API's environment and **no Ingress/NodePort** — nothing may submit a
   scan, and no sensor may claim a queued one, until step 10. `overlays/kind-restore`
   is that overlay for the lab. The existing `scanner-data` claim is left as it
   is by the apply.
4. **PostgreSQL** to `T_pg`: `scripts/restore-postgres.sh --namespace "$NS" …`
   ([operations.md § PostgreSQL restore drill](operations.md#postgresql-restore-drill)),
   or the provider's PITR for `prod-ha`.
5. **ClickHouse** to `T_ch`, or not at all — § ClickHouse, option A, B or C.
   Leave `OCTO_CLICKHOUSE_URL` / ingest off until step 9.
6. **NATS.** Start it empty. The API creates `JOBS`, `INGEST` and `EVENTS` with
   the configured limits on connect; nothing needs restoring (§ JetStream). If
   the old JetStream survived, keep `INGEST` for step 9 and purge `JOBS`.
7. **Reconcile** Postgres against the other stores — § Reconciling restore
   points, top to bottom.
8. **Re-apply what the rollback undid.** Every revocation made after `T_pg` is
   undone by the restore: disabled and deleted accounts, revoked memberships,
   service tokens and provisioning keys, quarantined or deleted sensors, ended
   sessions, password and second-factor resets
   ([§ below](#what-rolling-postgres-back-to-t_pg-does-to-postgres-itself)).
   Take the list from the SIEM's copy of the audit trail and apply each again
   **before** step 10, then end every console session.
9. **Ingest back on.** Set `OCTO_CLICKHOUSE_URL`, roll the API; if `INGEST`
   survived, [replay it](#closing-the-gap-from-ingest).
10. **Verify** — § Verification checklist — **then open the doors**:
    Ingress/DNS to the restored API, and `OCTO_ALLOW_SCAN_START=true`. Sensors
    reconnect by themselves.

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
from api.services.artifact_store import workspace
from api.settings import load_settings
s = load_settings()
with get_session(s.postgres_url) as session:
    known = set(session.scalars(select(models.Job.run_id).where(models.Job.run_id.is_not(None))))
for ref in workspace.run_refs(s):
    if ref.run_id not in known:
        print(ref.tenant or '-', ref.run_id)
"
```

`workspace.run_refs` lists keys and nothing else; the run listing the console
uses reads every run's summary, which on the S3 backend would pull each run
into the API pod's cache. A run started by hand with `scanner.main` never had
a job either, so it shows up in this list too.

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
which is the truth; leave them. If a dashboard must match the console exactly:

- `shapoclyack_open_ports` and `shapoclyack_controls` carry `run_id` —
  `ALTER TABLE … DELETE WHERE run_id IN (…)` with the list above;
- `shapoclyack_vulnerabilities` does not. It keeps the latest observation per
  (tenant, asset, CVE), stamped with its run's start in `timestamp`, so rows
  from after `T_pg` are `timestamp > T_pg` — but where one replaced an older
  observation of the same pair, the older row is already gone after a merge,
  and deleting the newer leaves no row for that pair until the next scan. That
  is usually the worse picture; leave this table alone.

### What rolling Postgres back to `T_pg` does to Postgres itself

These follow from the restore regardless of the other stores:

| What | After the restore | Do |
|---|---|---|
| Jobs `queued`, `claimed`, `running`, `cancelling` at `T_pg` | They come back in that state. Some ran after `T_pg` (their runs are the orphans above); the queued ones would be **claimed and run again** by sensors — against targets whose change windows may have moved | Before step 10, cancel the ones you do not want re-run: `POST /api/jobs/{job_id}/cancel`. `OCTO_ALLOW_SCAN_START=false` blocks new submissions, not claims of rows already queued, and the change freeze is an admission gate too |
| `run_publications` pending at `T_pg` | Their staging trees were on pods that no longer exist; after `OCTO_RUN_PUBLICATION_ORPHAN_DEADLINE_SECONDS` they go `dead` with *the replica that accepted this upload is gone* | If the run reached the store after `T_pg` it is already published — discard the row. Otherwise re-scan ([operations.md § Runs accepted but not published](operations.md#runs-accepted-but-not-published-run_publications)) |
| `nats_outbox` rows at `T_pg` | The reconciler republishes them — including ones the broker had since accepted | A copy whose first one landed more than the duplicate window (24 h) ago is accepted again: ClickHouse collapses it (ReplacingMergeTree); a webhook receiver may see that asset event twice |
| Webhook deliveries pending at `T_pg` | Re-attempted | Receivers that dedupe by event id see nothing; others may see a repeat |
| Users, memberships, service tokens, provisioning keys, sensors created after `T_pg` | Gone | Re-create; sensors registered after `T_pg` need a new provisioning key and a re-install |
| **Revocations made after `T_pg`** — `user.disable`, `user.delete`, `membership.revoke`, `service_token.revoke`, `provisioning_key.revoke`, `agent.disable` / `agent.quarantine` / `agent.delete`, `user.password_reset` / `user.password_change`, `user.mfa_reset` / `user.mfa_disable`, `user.webauthn_revoke`, a tenant's change freeze or suspension | **Undone.** The account, token, key or sensor works again, with the password or second factor it had at `T_pg` — including a reset made *because* it was compromised. Once tenant erasure and purge land ([#332](https://github.com/onixus/Shapoclyack/issues/332), [#325](https://github.com/onixus/Shapoclyack/issues/325)), an erasure done after `T_pg` comes back the same way, in Postgres and in a ClickHouse backup taken before it | Step 8: list these actions after `T_pg` from the SIEM (the restored database has no record of them) and apply each again before any door opens. Then end every console session (`POST /api/users/{username}/sessions/revoke-all` per account). Without a SIEM copy there is no list — say so in the incident report, and rotate what you know was revoked |
| Sessions and refresh tokens | Those issued after `T_pg` are gone; those revoked after `T_pg` are valid again | End them all (step 8); users sign in again |
| Workflow events (SLA breaches, sensors offline) announced after `T_pg` | Their markers are gone, so the escalation worker announces them again | Expect a second notification for each; nothing to do |
| Audit events after `T_pg` | Gone from Postgres | If the SIEM forwarder ran ([#328](https://github.com/onixus/Shapoclyack/issues/328)), the SIEM holds them — it is the record of the gap. Say so in the incident report |

## ClickHouse

### The backup

`k8s/shapoclyack/base/backup/clickhouse-cronjob.yaml` runs daily at 02:45 UTC,
half an hour after the Postgres dump. The work is done by the ClickHouse
**server**: the pod issues

```sql
BACKUP DATABASE shapoclyack TO S3('<url>', '<key id>', '<secret>')
    SETTINGS id = '<id>', deduplicate_files = 0 ASYNC
```

polls `system.backups` until the server reports `BACKUP_CREATED`, and then
writes `manifest.jsonl` into the backup's directory: one line per table with its part
and row counts, **read back from the uploaded backup** (`count.txt` of every
part, through the `s3()` table function) rather than from the live tables,
plus the SHA-256 of the backup's own `.backup` file list. The logic is
`base/backup/clickhouse-backup.sh`, mounted from a generated ConfigMap, so
`scripts/dr-drill.py` runs the same bytes. A run ends with one line:

```text
backup_success id=shapoclyack-20260924T024500Z database=shapoclyack url=https://BUCKET.s3.REGION.amazonaws.com/PREFIX/clickhouse/20260924T024500Z tables=3 rows=70639 files=144 total_size=828883 compressed_size=828883 seconds=2
```

`deduplicate_files = 0` is not an optimisation choice. With ClickHouse's
default, a file whose bytes the backup already holds is stored once, and every
part whose `count.txt` says the same number — the controls table writes one
row per control per run, so every run's part has the same count — shares one
object. The manifest counts objects, so three parts of 1,000 rows read as one;
the restore then counted 3,000 and failed a valid backup. Before it writes the
manifest the job also compares the parts `.backup` *lists* with the `count.txt`
objects it can *read*, per table, and fails (`reason=parts_unreadable`, no
manifest) where they differ — deduplicated or missing objects, either way a
manifest that would fail its own restore. The cost is the bytes of identical
small files stored more than once.

A run that finds another backup of the database still `CREATING_BACKUP` in
`system.backups` stops with `reason=backup_in_flight`: the script gives up
waiting at `CLICKHOUSE_BACKUP_TIMEOUT_SECONDS`, but the server's BACKUP carries
on, and the Job's retry (`backoffLimit: 2`) must not start a second one beside
it. The running one is visible — and can be ended with `KILL QUERY` on its
`query_id` — in `system.backups`.

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
- **A bucket key of its own**, in `shapoclyack-clickhouse-backup-s3` — the
  same keys as the Postgres job's `shapoclyack-backup` (bucket, prefix,
  endpoint, region, key pair), a different key pair. Scope it to
  `PREFIX/clickhouse/*`: `s3:PutObject`, `s3:GetObject`,
  `s3:AbortMultipartUpload`, and `s3:DeleteObject` — the server writes a
  `.lock` object while the backup runs and deletes it at the end (seen in the
  drill's S3 request log) — plus `s3:ListBucket` on the bucket with a prefix
  condition. On the Postgres job's key that `DeleteObject` would reach every
  dump. `examples/externalsecret.example.yaml` has the ExternalSecret. The
  restore needs `GetObject` and `ListBucket` only — give it a read-only key.
- **A ClickHouse account of its own**, `shapoclyack_backup`
  (`base/clickhouse/configmap.yaml`, password in
  `shapoclyack-clickhouse-backup`): `BACKUP ON shapoclyack.*`, `S3 ON *.*`,
  `CREATE TEMPORARY TABLE ON *.*` (the `s3()` reads need it) and
  `SELECT ON system.backups`. Checked on 24.8.14 with this ConfigMap's
  `users.xml` merged over the image's: it cannot `SELECT` the tables, `DROP`,
  `INSERT`, `RESTORE`, call `url()`, run `SYSTEM` or manage users. What it
  keeps: `S3 ON *.*` has no URL scope in 24.8, so the account can make the
  server fetch from any S3-style URL, and `BACKUP` can write the database to a
  bucket of the caller's choosing — which is what a backup is. Its password is
  `from_env` and must never be unset: on 24.8 an unset variable is an **empty
  password**, with one warning in the log. The StatefulSet therefore reads it
  from a Secret base always generates (a placeholder, like the other
  data-plane passwords — replace it) and not `optional`.
- **Retention is a bucket lifecycle rule** on `PREFIX/clickhouse/`, expiring
  by age. That is safe precisely because every backup is a full one.

**Why full and not incremental.** An incremental backup (`base_backup`) cannot
outlive its base, so an age-based lifecycle rule silently breaks the chain.
And the saving does not survive a merge that reaches old data: merges rewrite
whole parts, and a rewritten part is new to the incremental. Measured on a
50,500-asset fixture (ClickHouse 24.8.14, S3 emulated by moto): full backup
3,994,901 bytes; incremental after inserting ~1 % new rows 58,718 bytes
(1.5 %); the same incremental after the new part was merged into the old one
with `OPTIMIZE … FINAL`, 4,028,797 bytes — 101 % of the full. Background merges
are not that eager — they combine similarly sized parts, so a day's small
parts mostly merge with each other — but every merge that folds in a large old
part moves that part's whole size into the next incremental, and a TTL merge
does the same; how much an incremental saves is then a property of the merge
history, not something a lifecycle rule can rely on.

**Credentials.** `CLICKHOUSE_PASSWORD` reaches `clickhouse-client` through
its environment; the S3 key pair has to travel inside the statement, because
the server is the one talking to S3, so it is written to the client's stdin
and never to an argument. The server masks the secret as `[HIDDEN]` in
`system.backups`, `system.query_log` and its own log (checked on 24.8.14) —
**the access key id stays visible there**, which is an identifier, not a
secret. `clickhouse-client`, however, repeats the statement after any error
it reports, as sent — so with the secret in its SQL-escaped form — and a parse
error quotes the statement's tail inside its own message, with no block around
it. The script passes everything the client writes through a filter that
drops the `(query: …)` block and masks the secret, raw and escaped, and the
ClickHouse password wherever they appear. Both scripts are exercised under
busybox `ash` and busybox `awk`/`sed`, as in the Alpine image. The pod runs as
uid 101 with a read-only root filesystem, no service-account token, and a
memory-backed `/tmp`.

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

Into a ClickHouse whose tables are empty — a new PVC, whose first boot has
already run `init.sql` and created the three tables empty, is exactly that —
and **with ingest off**: nothing may write between the checks and the restore.

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
   `.backup` also lists parts whose `count.txt` is not an object of its own —
   a backup taken with `deduplicate_files` on, or objects lost since — and
   refusing it here is what keeps it from failing with exit 8 and the data
   already in (6);
3. any table in the target database has rows (7) — RESTORE would append, and
   ReplacingMergeTree would then keep whichever copy merged last. Drop the
   database deliberately first if that is what you mean.

`--dry-run` stops there. Otherwise it drops the target database — empty, by
check 3, which is repeated right before the `DROP` — and rebuilds it from the
backup's own definitions: a first boot of a *newer* release creates tables
whose columns differ from an older backup's, and RESTORE into those fails with
`CANNOT_RESTORE_TABLE`. It then creates the tables (`structure_only`), stops
merges on them, runs `RESTORE … ASYNC`, polls it, and compares each restored
table's `count()` to the manifest (8 on a mismatch). Merges are stopped so
that the comparison is against the counts the backup stored and not against
what a merge has deduplicated since; they are started again however the
script exits — `Ctrl-C` and a dropped SSH session included (an `EXIT` trap
alone does not run on a signal in dash or busybox `ash`). `network-scan` is
refused unless `ALLOW_PRODUCTION_RESTORE=1`, as in the Postgres script.
`--local` runs a `clickhouse-client` on the operator's host instead of
`kubectl exec`.

**Schema.** ClickHouse has no migrations here: `init.sql` runs on a first
boot only, and the API only ever creates the controls table when it is
missing. After the rebuild the tables have the *backup's* columns. Where the
release that booted the server has columns the backup lacks, the script
prints one line per column —
`schema_drift table=… column=… type=… only_in=target` — and succeeds: the
restore worked, and the release's own upgrade step for that column (the
`ALTER` an in-place upgrade of an older volume needs as well) is what applies
now.

**Exit 8** means the data is in: whatever RESTORE wrote stays, merges run
again, and a rerun stops at check 3 (exit 7). Compare the counts the script
printed; keep the result if the difference is understood, or
``DROP DATABASE `shapoclyack` SYNC`` and run the restore again.

### Closing the gap from INGEST

When the broker survived, `INGEST` still holds every run published in the last
`OCTO_NATS_INGEST_MAX_AGE_SECONDS` (7 days) or `OCTO_NATS_INGEST_MAX_BYTES`
(10 GiB), whichever is hit first. The ingest worker's durable consumer has
already acknowledged the ones after `T_ch`, so the restored tables would never
see them. Delete the consumer and let the API recreate it — it is created at
`DeliverPolicy.ALL`, i.e. a replay of everything the stream retains:

```bash
# NATS requires credentials (#225) and is reachable in-cluster only; the API
# pod has both, in OCTO_NATS_URL, and the client library.
kubectl -n "$NS" exec deploy/shapoclyack-api -- python -c "
import asyncio, os, nats
from api.services.nats_bus import tls_connect_options
async def main():
    nc = await nats.connect(os.environ['OCTO_NATS_URL'], **tls_connect_options())
    await nc.jetstream().delete_consumer('INGEST', 'octo-ch-ingest-results')
    await nc.close()
asyncio.run(main())
"
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

**Local backend.** The runs are files on `scanner-data` — and so is
`scanner/state`: `latest_run.json` and the checkpoints of interrupted scans
(operations.md § Resume). A restored volume brings back the checkpoints of
`T_art`; the jobs they belonged to are either finished or requeued in the
restored database, so **do not resume from a restored checkpoint** — start a
new run. Kubernetes has no
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
reconnect — its offers name jobs the restored database may not have — the same
way as the consumer above, with `await nc.jetstream().purge_stream('JOBS')`.

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
- JetStream has `JOBS`, `INGEST`, `EVENTS` — the monitoring endpoint needs no
  credentials: `kubectl -n "$NS" exec sts/shapoclyack-nats -- wget -qO- 'http://127.0.0.1:8222/jsz?streams=1'`.
- The reconciliation lists (orphan runs, runs missing files, stale queued jobs,
  lost sensors, re-applied revocations) are written into the incident record,
  with what was done.

## Drill

`scripts/dr-drill.py` runs the whole cycle — seed, back up, wipe, restore,
verify — on a local stack, through the same artifacts the cluster runs: the
CronJob's `pg_dump` flags, `restore-postgres.sh`'s `pg_restore` flags and the
API's own `python -m api.db.migrate`, the CronJob's `clickhouse-backup.sh` —
signed in as `shapoclyack_backup` when `CLICKHOUSE_BACKUP_PASSWORD` is set —
and `restore-clickhouse.sh --local`, both scripts under the shell and the
applets given with `--script-shell` / `--script-path` (busybox, for what the
Alpine pod runs). It seeds with `tests.fixtures.scale_seed`, merges that bulk
load, and lands `--daily-runs` runs on top through the ingest transform — one
unmerged part per run in each table, all of the same size, controls rows
included: the shape that `deduplicate_files` collapsed. It fingerprints both
stores (Postgres row counts of every table plus MD5 over `assets`,
`asset_identifiers`, `tenants`, `users`; ClickHouse `count()` and
`sum(cityHash64(*))` per table, `FINAL`), and after the restore boots the API,
signs in and reads the tenant's assets back. With `--nats-url` it also runs
the two JetStream legs: a run published through `INGEST` *after* the
ClickHouse backup, which the restore loses and the replay brings back, and a
JetStream whose three streams are deleted and recreated by the API. It is
destructive by design and refuses to start without `--destroy-and-restore`.

```bash
CLICKHOUSE_PASSWORD=… CLICKHOUSE_BACKUP_PASSWORD=… AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… \
python3 scripts/dr-drill.py --destroy-and-restore \
  --postgres-url postgresql://postgres@localhost:5432/shapo_drill \
  --clickhouse-client "clickhouse client" --clickhouse-port 9000 --clickhouse-http-port 8123 \
  --clickhouse-pid "$(pgrep -f 'clickhouse server' | head -n 1)" \
  --s3-endpoint http://127.0.0.1:9000 --s3-bucket drill-backups \
  --script-shell "busybox ash" --script-path /path/to/busybox-applets \
  --nats-url nats://127.0.0.1:4222 --assets 10000 --out drill.json
```

The server needs the ConfigMap's `users.xml` (for `shapoclyack_backup`) in its
`users.d`.

### Recorded: 2026-09-24, 10k assets

The drill as first recorded passed with the manifest bug in it: it merged the
whole seed before the backup and wrote no controls rows, so no two parts were
alike and nothing was deduplicated. These runs replace it. With the backup
script as it was then, today's drill fails at the restore's dry run
(exit 6, `listed=3 readable=1` per table).

**Environment.** One Linux container, 4 vCPU shared with about ten other
workloads (load average 4.5–8.4 during the runs), 15 GiB RAM. PostgreSQL 16.13
with `fsync=off`, `synchronous_commit=off`, `full_page_writes=off` — restore
times are therefore optimistic against real disks. ClickHouse 24.8.14.39
(single binary) with the ConfigMap's `users.xml` merged over the image's.
Both scripts under busybox 1.36.1 `ash` with busybox applets only. S3
emulated by moto 5.2.3 on localhost — no network, no real object-store
latency. NATS 2.10.29. Not kind, not a cluster: no scheduling, image pulls or
PVC provisioning are in these numbers.

**Data.** `scale_seed --assets 10000`: 10,000 assets, 13,558 identifiers in
Postgres (everything else near-empty: one tenant, one user). ClickHouse:
69,991 seeded rows merged into one part per table, three daily runs of 50
hosts on top (parts of 12 / 100 / 50 rows in controls / open ports /
vulnerabilities), and the drill's run A — 70,639 rows, four equal-sized parts
per table plus the merged one. The dump is 848 KB, the ClickHouse backup
829 KB in 144 files. A real installation of 10k assets also has findings,
jobs, audit history and run artifacts, so these sizes are a floor, not an
estimate.

Three runs, all verified (fingerprints equal, manifest counts equal to the
restored counts, API served 10,000 assets, `/api/health` `postgres` and
`clickhouse` ok, run B 0 → 100 rows by replay, three streams recreated). Wall
seconds / CPU seconds of the processes the drill started / ClickHouse server
CPU seconds:

| Phase | Run 1 | Run 2 | Run 3 | Median wall |
|---|---|---|---|---:|
| `pg_dump` + SHA-256 | 0.34 / 0.12 / — | 0.26 / 0.12 / — | 0.31 / 0.12 / — | 0.31 |
| ClickHouse backup (CronJob script) | 2.10 / 0.34 / 0.23 | 1.99 / 0.34 / 0.24 | 2.21 / 0.35 / 0.23 | 2.10 |
| Postgres restore: `pg_restore` + migrate | 1.54 / 0.91 / — | 1.19 / 0.79 / — | 1.70 / 0.82 / — | 1.54 |
| ClickHouse restore, `--dry-run` | 0.46 / 0.22 / 0.07 | 0.32 / 0.17 / 0.06 | 0.66 / 0.19 / 0.08 | 0.46 |
| ClickHouse restore | 3.21 / 0.85 / 0.30 | 2.03 / 0.77 / 0.27 | 3.42 / 0.88 / 0.32 | 3.21 |
| API boot → assets served | 4.43 / 3.07 / — | 3.48 / 3.10 / — | 4.87 / 3.27 / — | 4.43 |
| **RTO, all four in sequence** | 9.65 | 7.02 | 10.64 | **9.65** |
| **RTO, console path** (Postgres + API) | 5.98 | 4.67 | 6.57 | **5.98** |

- `pg_restore` alone took 0.37–0.63 s; the rest of the Postgres row is the
  migrate step on an already-current schema (0.79–1.03 s).
- The ClickHouse backup's wall time is bounded by the 1 s status poll, not by
  the work (0.23–0.24 s of server CPU, up from 0.11 s before: the files are no
  longer deduplicated, and the parts check reads `.backup`).
- INGEST replay: the API was ready in 2.6–6.9 s, and ClickHouse matched its
  pre-disaster fingerprint 1.6–2.3 s later.
- JetStream re-creation: all three streams present with their configured
  limits once the API was ready (3.0–4.6 s).
- The two ingest phases and the replay phase take ~15–25 s of wall time each
  in the raw output; most of that is the API's own shutdown with a NATS
  connection open, after the measured work is done.
- Postgres server CPU is not in the table (its backends are not the drill's
  children).

A single 50k-asset run (no JetStream legs, same machine, same shape): dump
3.47 MB, ClickHouse backup 4.01 MB / 350,416 rows in 114 files, `pg_restore`
0.83 s, ClickHouse restore 2.07 s, RTO 7.7 s in sequence and 5.3 s on the
console path.

Checked outside the drill, on the same server and under busybox: a restore
interrupted with `SIGINT` while it polled exits 130 and leaves merges running
(`OPTIMIZE … FINAL` succeeds afterwards); a restore into a server first booted
by an `init.sql` with one more column succeeds with one `schema_drift` line;
a second backup started while one is `CREATING_BACKUP` exits with
`reason=backup_in_flight`, and `KILL QUERY` on the running one's `query_id`
ends it as `BACKUP_CANCELLED`; the `shapoclyack_backup` grants allow exactly
what the job does and refuse the rest (§ The backup).

**RPO in this drill** is zero by construction — nothing wrote between the
backup and the wipe except the run the replay recovered. The achievable RPO is
the schedule's: up to 24 h for Postgres and for ClickHouse from its backup,
and for ClickHouse down to the stream's retention when `INGEST` survives.

### On kind or the Arch stand

Not run for this change — there is no cluster in the environment it was made
in. The sequence, with the objects from this repository:

```bash
# Source: a stand with shapoclyack-backup and shapoclyack-clickhouse-backup-s3
# pointing at a bucket (MinIO is fine).
kubectl -n network-scan create job --from=cronjob/shapoclyack-postgres-backup   pg-drill
kubectl -n network-scan create job --from=cronjob/shapoclyack-clickhouse-backup ch-drill
kubectl -n network-scan logs job/ch-drill            # backup_success … url=…

# Target: the isolated namespace (Postgres + API + a lab-sized ClickHouse, no
# NATS, no backups). kind's local-path has no snapshots, so there is no
# artifact claim to create first; anywhere that has them, step 2 of
# § Full restore comes before this apply.
kubectl create namespace shapoclyack-restore
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
kind with MinIO in-cluster that is the cluster network. The source ClickHouse
restarts once on the upgrade that brings this job: its StatefulSet gains the
`shapoclyack_backup` user's password variable.
