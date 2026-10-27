# Disposable operator recovery drill

`scripts/operator-acceptance-drill.py` exercises operator control-plane recovery
in newly created containers and an internal Docker network. Container/network
names include a fresh random task prefix. It never connects to an existing
console, database or language model, publishes no host ports, and removes only
its own containers, volumes and network. PostgreSQL data uses bounded 512-MiB
tmpfs, avoiding persistent test volumes and disk-pressure interference.

Pass an already installed immutable application image ID containing the normal
Python dependencies and an immutable PostgreSQL image reference. The application
source is copied from Git-listed `api/`, `scanner/` and `agent/` files to a
read-only snapshot before migrations. The JSON report records its digest,
commit, dirty state and image identities; concurrent checkout edits cannot
change running drill containers. Symlinks in the source snapshot and existing
report files are refused.

```console
python scripts/operator-acceptance-drill.py \
  --app-image sha256:<installed-application-image-id> \
  --postgres-image postgres:16-alpine@sha256:<installed-image-digest> \
  --report /tmp/new-operator-drill-report.json
```

The drill uses a fixed-response provider and synthetic published observations.
It checks queued cancellation without inference; API and worker restart with
durable results and idempotent submission; running cancellation without result
publication; SIGKILL recovery without automatic replay; custom-format `pg_dump`
restore into a second fresh database and a separate artifact copy; schema
downgrade/re-upgrade while traffic is stopped; feature disable while ordinary
scan submission still queues through the normal control plane; and personal
session/task deletion.

For crash recovery the test explicitly expires the killed worker's lease in
its private database. This accelerates the grace period and is recorded in
the report. It does not measure production recovery time after a real lease
timeout. Schema rollback is to `0100_asset_groups` with no nonreserved effect
evidence; this does not override the migration's refusal to discard real
confirmed-action evidence. PostgreSQL restore prepares the required cluster
roles with normal migrations before restoring the database.

Timing fields measure this disposable fixture. They do not establish production
RPO/RTO, real model cancellation/restart, model quality, vendor-feed acceptance,
or a physical NVIDIA GPU profile. Real Mac runtime and frozen quality acceptance
are independent gates. No scanner executor is started; the feature-disable
test proves job admission, with no network scan executed.
