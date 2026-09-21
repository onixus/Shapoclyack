# High availability

`k8s/shapoclyack/overlays/prod-ha` is the profile for an installation that must
survive a node going away ([#335](https://github.com/onixus/Shapoclyack/issues/335)).
It is a different overlay from `overlays/prod`, not a flag on it, because the
two make opposite choices: `prod` pins one API replica to a scanner node so an
RWO volume can be shared with the scan Jobs, and this one spreads replicas
across nodes and therefore cannot.

This page is the prerequisite list and the honest boundary of what the overlay
buys. **Rendered as-is the overlay is not appliable** — it carries three
placeholders that must be replaced first. That is deliberate: a default that
half-works is worse than a value that fails with the name of the thing it needs.

## What the overlay does

| Change | File | Why |
|---|---|---|
| API `replicas: 2`, HPA to 6 at 70% CPU | `api-ha-patch.yaml`, `api-hpa.yaml` | One replica means every node drain, rollout and eviction is an outage |
| `podAntiAffinity` + `topologySpreadConstraints` | `api-ha-patch.yaml` | Two replicas on one node survive a pod failure but not a node failure |
| API PDB `maxUnavailable: 1` (inherited from base) | `base/api-pdb.yaml` | Serialises voluntary disruptions: at N replicas it keeps N-1 available, which `minAvailable: 1` would not — that would let five of six be evicted at once |
| NATS PDB `maxUnavailable: 1`, NATS anti-affinity | `nats-pdb.yaml`, `nats-ha-patch.yaml` | Three broker pods the scheduler may stack on one node are one failure domain, and a parallel drain of two nodes costs the JetStream quorum |
| NATS 3-node JetStream cluster, streams `R3` | `nats-ha-patch.yaml`, `nats-ha-configmap-patch.yaml`, `OCTO_NATS_STREAM_REPLICAS=3` | A single broker pod loses every queued job offer with its node |
| Route port 6222 opened between NATS pods | `nats-cluster-networkpolicy-patch.yaml` | Base's NetworkPolicy denies it, so the cluster silently never forms |
| `OCTO_NATS_URL` and `OCTO_CLICKHOUSE_URL` filled in | `api-ha-patch.yaml` | Base leaves both empty — they are opt-in sidecars there |
| Postgres: in-cluster StatefulSet, Services, NetworkPolicy, backup CronJob and dev Secret removed; URL from a Secret | `postgres-delete-*.yaml`, `api-ha-patch.yaml` | The in-cluster Postgres is one pod with one PVC and no failover |
| `OCTO_DB_POOL_SIZE` / `OCTO_DB_MAX_OVERFLOW` / `OCTO_DB_POOL_TIMEOUT` set | `api-ha-patch.yaml` | The pool is per replica; the server's `max_connections` is not |

Apply order is the usual one:

```bash
kubectl apply -k k8s/shapoclyack/overlays/prod-ha
```

### Kubernetes 1.27+

The API's hostname spread constraint sets `nodeTaintsPolicy: Honor` and
`nodeAffinityPolicy: Honor`. Both default to `Ignore`, under which a node that
`kubectl drain` has cordoned still counts as a topology domain — so the evicted
pod's replacement has nowhere to go without pushing the skew past 1 and stays
`Pending` for the whole maintenance window. The fields are silently pruned by
older API servers, which puts that behaviour back.

## Prerequisites

### Somewhere both API pods can reach the artifacts

This is the hard one. Scan artifacts — run directories, screenshots, generated
reports, the input files a job hands its executor — used to be files on the
`scanner-data` PVC, mounted by the API Deployment, the scan Job and the
CronJob. Base requests `ReadWriteOnce`, and an RWO volume attaches to **one
node at a time**, so a second API replica scheduled on another node sits in
`ContainerCreating` with a `Multi-Attach error for volume` event until the
first pod goes away.

Since [#336](https://github.com/onixus/Shapoclyack/issues/336) there are two
ways to satisfy that, and **exactly one of them is enabled** in
`overlays/prod-ha/kustomization.yaml`.

#### Object storage (`artifacts-s3-patch.yaml`)

The better answer where S3, MinIO, Ceph RGW or any other S3-compatible gateway
is available: there is no shared filesystem at all, so there is no storage
class to find and no multi-attach to get right, and the artifacts outlive the
cluster that produced them. Set `OCTO_ARTIFACT_BACKEND=s3` and a bucket; the
patch wires the rest from a `shapoclyack-artifacts` Secret
(`examples/artifacts-s3.secret.example.yaml`). Each pod keeps a node-local
working copy of the runs it is asked about, on an `emptyDir` — a cache, whose
loss costs a re-fetch and nothing else.

Two things to decide when you enable it:

* **Presigned downloads are off.** The API streams every artifact itself, which
  always works. Turning them on (`OCTO_ARTIFACT_PRESIGN_ENABLED=true`) answers a
  download with a redirect to a short-lived signed URL, so the bytes never pass
  through the API — but the console downloads through XHR, so the redirect is a
  cross-origin request the browser blocks unless the **bucket is configured to
  send CORS headers** for the console's origin. An in-cluster MinIO reachable
  only from inside the cluster cannot serve such a download at all. Worth doing
  for large reports on a public bucket; not something to switch on blind.
* **No bucket lifecycle rule.** Run retention (`OCTO_RUN_RETENTION_DAYS`)
  already prunes artifacts through the API, which knows what the console is
  still listing. A second expiry policy in the bucket does not, and would
  delete runs out from under it.

Moving an existing installation into a bucket is a copy, not a cutover:

```bash
kubectl -n network-scan exec deploy/shapoclyack-api -- \
  python3 scripts/migrate-artifacts.py --dry-run
```

It copies and deletes nothing, skips what is already there, and is safe to
re-run and safe to run while the API is serving. Check the console lists the
runs and reports you expect before removing the volume.

#### ReadWriteMany storage (`pvc-rwx-patch.yaml`)

Enabled by default, because it is what this overlay has always carried and an
upgrade should not switch an installation's storage backend on its own. It
requests `ReadWriteMany` and leaves the class name as
`REPLACE-WITH-YOUR-RWX-STORAGE-CLASS`. Replace it with a class your cluster
actually has — CephFS, AWS EFS, Azure Files, GCP Filestore, NFS, Portworx
shared volumes. A wrong name binds to the wrong backend silently; an unknown
one leaves the PVC `Pending` with a `storageclass not found` event, which is
why it is not guessed here. `storageClassName` is immutable on an existing PVC,
so this is a decision made at install time, not migrated into later.

**With neither, this overlay cannot be applied.** There is no third path that
keeps both the replicas and the artifacts.

### External Postgres

The overlay deletes `base/postgres/` — a single pod with a single PVC, no
replica, no failover, no automatic restore. Bring your own:

* **AWS RDS / Aurora PostgreSQL, Cloud SQL, Yandex Managed PostgreSQL** —
  multi-AZ, snapshots and PITR come with the service.
* **CloudNativePG** — an in-cluster operator with real replicas, failover and
  Barman backups. The right answer if the database has to stay in the cluster.
* **Patroni** — where an existing HA Postgres estate is already run this way.

What the API needs on the other end: a `shapoclyack` database, a role with
`CREATE` on it (the `migrate` init container runs Alembic on every rollout),
and the URL in a Secret:

```bash
kubectl -n network-scan create secret generic shapoclyack-postgres-external \
  --from-literal=url='postgresql+psycopg://octo:PASSWORD@db.example.internal:5432/shapoclyack?sslmode=verify-full&sslrootcert=/etc/ssl/postgres-ca/ca.crt'
```

See `k8s/shapoclyack/examples/postgres-external.secret.example.yaml`, or use
ExternalSecrets (`examples/externalsecret.example.yaml`) so the password does
not pass through shell history. The Secret is a prerequisite, not part of the
overlay: applying without it leaves the pods in `CreateContainerConfigError`
naming `shapoclyack-postgres-external`.

If your provider's certificate does not chain to a public root — RDS, Cloud
SQL and CloudNativePG all mint or publish their own — you also need the CA
inside the pod. `postgres-ca-patch.yaml` in the overlay mounts it; it is
commented out of `kustomization.yaml` by default, because an installation whose
database uses a public CA has nothing to mount and would only gain a Secret it
must create. Uncomment it, create `shapoclyack-postgres-ca` from the bundle, and
keep `sslrootcert=/etc/ssl/postgres-ca/ca.crt` in the URL. Without one of those
two the `migrate` init container exits with
`root certificate file "/etc/ssl/postgres-ca/ca.crt" does not exist` and the pod
sits in `Init:CrashLoopBackOff`.

`?sslmode=verify-full` is not decoration — without any `sslmode=` libpq
negotiates TLS opportunistically and accepts whatever certificate it is handed,
and a `prod` start says so in the log. `verify-full` also checks the hostname,
so the name in the URL must be in the certificate's SAN, and `sslrootcert=`
must point at a CA bundle mounted into the API pod. Mounting it is described in
[operations.md § Transport encryption](operations.md#transport-encryption).

**Backups move with the database.** The nightly `pg_dump` CronJob is deleted
with the Service it pointed at, so
[operations.md § Backup and disaster recovery](operations.md#backup-and-disaster-recovery)
now describes the provider's tooling — RDS snapshots plus PITR, CloudNativePG's
Barman objectstore — and the restore drill has to be rehearsed there. An
installation that applies this overlay and configures nothing on the other side
has **no backups at all**.

### NATS route password

`nats-ha-configmap-patch.yaml` ships the clustered `nats.conf` with the literal
`replace-me-with-a-shared-route-password` in four places. Replace all four with
the same value before applying. It cannot come from the environment the way the
user passwords do: `nats-server` expands `$VAR` only when it is the whole value,
and the route URLs embed the password mid-token.

The route port is its own trust boundary — anything that completes a route
handshake joins the cluster and sees every subject, whatever the per-user
permissions say. Keep this ConfigMap out of anywhere a plain manifest is
world-readable, or move NATS to `nkeys`/operator mode.

### One `OCTO_MASTER_KEY` for every replica

The integration secrets in Postgres are encrypted under a key-encryption key
read from the environment at startup ([#310](https://github.com/onixus/Shapoclyack/issues/310)),
and every replica of this Deployment reads the same `shapoclyack-api-users`
Secret — so the requirement is met by construction here, and broken the moment
a replica is given a key of its own. The failure is not an obvious one: the
console lists and edits those subscriptions from every replica, because the read
path holds no key, and only the webhook deliveries that happen to land on the
odd replica dead-letter with `SecretDecryptionError`
([operations.md](operations.md#when-a-row-cannot-be-decrypted)) — a tenant
losing some of its notifications and none of the others.

Rotation ([operations.md](operations.md#rotating-the-kek)) is for the same
reason one Secret and one rollout rather than a per-pod step:
`OCTO_MASTER_KEY_PREVIOUS` has to be on every replica before any of them starts
writing under the new key, or a row written by an already-rolled pod is one an
un-rolled pod cannot read.

### metrics-server

The HPA reads `metrics.k8s.io`. Without a provider it reports `unknown` for the
CPU metric and never scales — it does not fall back to `minReplicas` and does
not scale down, so a cluster missing metrics-server keeps whatever replica count
it has rather than losing capacity. Check with `kubectl top pods -n network-scan`.

### A NetworkPolicy-enforcing CNI

Not required, but assumed: `base/networkpolicy-datastores.yaml` and the route
rule this overlay adds are inert under a CNI that ignores NetworkPolicy. They
were never a substitute for the credentials on each service.

## Connection pool sizing

`OCTO_DB_POOL_SIZE` (default 5) and `OCTO_DB_MAX_OVERFLOW` (default 10) are
**per API process**, while `max_connections` on the server is one shared budget.
Scaling the API multiplies the left side and not the right, and the failure is
not graceful: every replica starts refusing connections at the same moment.

The overlay sets `10 + 5`, which at the HPA ceiling of 6 replicas is 90
connections, plus one short-lived connection per `migrate` init container during
a rollout. That fits a managed instance's default (an RDS `db.t3.medium` allows
roughly 340). Before raising either number — or `maxReplicas` — raise
`max_connections` on the server, or put pgbouncer in front of it.

`OCTO_DB_POOL_TIMEOUT` (default 30s) bounds the wait for a free connection: a
saturated pool then fails a request with a cause instead of hanging it.

Not every connection in that pool is available to a request. Each leader-elected
worker holds one for the life of the process: the schedule dispatcher, the
report dispatcher, the software-match worker, the SLA escalation worker and the
inbound ticket-sync poller each keep one open for a session-scoped Postgres
advisory lock (`api/services/leader_lock.py`), because that is what makes
leadership end the instant the leader does. So the useful width of the pool is
`pool_size + max_overflow` minus the number of those workers that are enabled,
and a total that small leaves a worker unable to take its lock at all — it
would simply never run, in every replica, with nothing in the logs.
`api/settings.py` floors the total at four (`MIN_DB_CONNECTIONS`) for that
reason; size it well above the floor, not at it.

The values are read in `api/settings.py` and applied in `api/db/engine.py`,
which `create_app()` configures before the first session is opened — the engine
is a lazy singleton, so sizing that arrived later would apply to nobody.

## Rolling upgrade without 5xx

The pieces that make a rollout non-disruptive landed with
[#331](https://github.com/onixus/Shapoclyack/issues/331) and live in
`base/api-deployment.yaml`; with two replicas they finally have something to
work with:

* `strategy.rollingUpdate.maxUnavailable: 0` / `maxSurge: 1` — the replacement
  pod is Ready before the old one is taken down.
* `readinessProbe` on `/readyz`, which fails only on Postgres — a replica
  without its database can serve nothing, and it leaves the Service instead of
  being restarted. ClickHouse, the artifact bucket, NATS and the outbox backlog
  are checked and reported but deliberately do **not** fail the probe: each of
  them is shared by every replica (and ClickHouse is one pod with no PDB, see
  [below](#what-this-overlay-does-not-give-you)), so letting one decide
  readiness would take *both* API replicas out of the Service at once. Such a
  replica answers `/readyz` with 200 and `"status": "degraded"`, and
  `/api/health` says which check failed. NATS stopped being a blocking check
  with the outbox described in
  [What a NATS outage costs](#what-a-nats-outage-costs).
* `livenessProbe` on `/livez`, dependency-free on purpose: a Postgres outage
  must not restart every replica at once.
* `startupProbe` — up to 150s for a cold start against a busy database, during
  which neither probe above runs.
* `lifecycle.preStop: sleep 5` and `terminationGracePeriodSeconds: 45` —
  endpoint removal and `SIGTERM` are dispatched concurrently, so without the
  pause the process starts shutting down while proxies still route to it.
* PDB `maxUnavailable: 1` (`base/api-pdb.yaml`, inherited unpatched) — bounds
  *voluntary* disruption (drains, evictions), which the rollout strategy does
  not. At N replicas it keeps N-1 available; `minAvailable: 1` would allow five
  of six to go at once.

What is still a brief interruption:

* **Migrations.** The `migrate` init container runs `python -m api.db.migrate`
  under a Postgres advisory lock before any replica starts, so replicas queue
  rather than migrate concurrently. A migration that rewrites a large table
  still blocks the rollout for its duration — this is why
  [operations.md § Upgrade and rollback](operations.md#upgrade-and-rollback)
  insists on expand/contract.
* **In-flight scans.** `OCTO_ALLOW_SCAN_START=true` runs scan work inside the
  API process. A replica terminating mid-scan loses that run; the job is
  re-claimed after its lease expires, it is not lost, but it restarts rather
  than resumes.

## What a NATS outage costs

The matrix the 2026-09-18 architecture review asked for before deciding whether
the broker should keep failing `/readyz`. Read from the code: `nats_bus` and
every caller of it — `jobs._publish_job_offer`, `results_ingest`,
`asset_events`, `audit_events`, `endpoint_inventory`, `ch_ingest_worker`,
`webhook_worker`, `audit_syslog_forwarder`.

| Capability | With NATS unreachable | Why |
| --- | --- | --- |
| Sign-in, RBAC, tenants, users, sessions | **Works** | Postgres only; the bus is not in the path |
| Every read of assets, findings, runs, reports, schedules, policies | **Works** | Served from Postgres and the artifact store |
| Starting a scan (`POST /api/scans`) | **Works** | The job row is committed first; the offer is published after it and is only a notification. A failed publish is logged and the job stays `queued` |
| A sensor picking up work | **Works, slower** | `POST /api/agent/jobs/claim` is HTTP and takes the job under a row lock; JetStream only tells a sensor to claim *sooner*. A sensor with `OCTO_NATS_URL` set falls back to that claim every `NATS_FALLBACK_CLAIM_SECONDS` (60s, `agent/worker.py`), so with the broker gone dispatch latency is bounded by one minute rather than by the poll interval |
| Sensor registration, heartbeats, lease renewal, cancellation | **Works** | HTTP and Postgres throughout |
| Uploading results (`POST /api/agent/jobs/{id}/results`) | **Works** | Archive is extracted, artifacts published, assets and findings updated, job finished — all without the broker |
| The analytical (ClickHouse) projection of a new run | **Degrades — recovered** | The refused publish is written to `nats_outbox` by the last step of the run's publication (`run_publisher._publish_to_bus`) and republished when the broker returns. The run itself, its artifacts and its Postgres projections are published without waiting for that. The backlog is the `ingest_backlog` check and `octo_nats_outbox_backlog` |
| Asset lifecycle events, and the webhooks/notifications fed by them | **Degrades — not recovered** | `asset_events.publish_events` counts the failure as `skipped` and moves on. The changes are in `diff.json` and in Postgres; the notifications for that run are not sent later |
| Audit events to a SIEM over `events.audit.>` | **Degrades — recovered by the other source** | The rows are committed and readable via `GET /api/audit`; the publish is skipped. `OCTO_AUDIT_SYSLOG_SOURCE=db` forwards without the broker at all |
| Endpoint inventory submissions | **Works, event skipped** | The snapshot is stored; the `endpoint_inventory_accepted` event is fail-soft |
| Webhook delivery of already-queued events, including DLQ replay | **Works** | The queue is Postgres rows and the dispatcher needs no broker |
| Replaying events from the stream after recovery | **Works** | JetStream retains `INGEST` for 7d and `EVENTS` for 30d; a consumer that was down resumes at its cursor |

Nothing in the first block needs the bus, which is why NATS is **not** in
`health.BLOCKING_CHECKS` any more. Blocking on it meant one broker outage took
every API replica out of its Service simultaneously — they share one broker —
and what the installation lost was not "dispatch" but sign-in, the console, the
sensor fleet's heartbeats and the ability to see that anything was wrong.

The row that made the old policy defensible is the ingest one: a publish lost
with the broker is lost for good, and availability then hides a permanent hole
in analytics. That is what `nats_outbox` (migration `0059`) is for, and the two
are a single decision — **do not put NATS back into `BLOCKING_CHECKS` without
also removing the outbox, and do not remove the outbox while NATS is
advisory.** The unrecovered backlog is reported as the `ingest_backlog` check
on `/readyz` and `/api/health`, and as `octo_nats_outbox_backlog`; draining it
is [operations.md § NATS outbox](operations.md#nats-outbox).

The recording is done where the publication ends. An accepted run is published
from a durable `run_publications` row (migration `0058`), and the bus hop is
that row's last step; it now publishes *or* records, so neither the run's
artifacts nor its Postgres projections wait on the broker, and the message is
not lost when the broker refuses it. The one configuration in which it still is
is `OCTO_NATS_OUTBOX_ENABLED=false`: nothing durable is written, and the
publication itself then fails and retries like any other, ending `dead` for an
operator rather than silently.

One row is *not* recovered: asset events and the notifications they feed — P1
of the same review ("успешное задание не гарантирует актуальность всех
проекций"), deliberately out of scope here. This section is the honest
statement of what a broker outage costs today, not a claim that it costs
nothing.

Background workers are safe across replicas by construction, not by luck: the
scheduler dispatcher, the report dispatcher, the software-match worker, the SLA
escalation worker and the inbound ticket-sync poller take a
Postgres advisory lock (`api/services/leader_lock.py`), webhook delivery claims
rows `FOR UPDATE`, and the ClickHouse ingest worker is a durable JetStream
consumer. `tests/test_multi_replica_load.py` is the regression suite for that.

## What this overlay does not give you

Naming these is the point of the page.

* **ClickHouse is a single StatefulSet pod.** Losing it loses the analytics
  store — not the control plane, which is Postgres, and not the raw run
  artifacts, which are files. This is why it is an advisory readiness check and
  not a blocking one (`api/services/health.py`): a dependency with one replica
  and no PDB must not be able to unready the two that do have both. A real
  ClickHouse cluster (Keeper, sharded or replicated tables) is out of scope
  here; nothing in this repository sets one up, and
  `base/clickhouse/init-local.sql` creates non-replicated tables.
* **Artifacts on a shared filesystem are still the default here.** Object
  storage ([#336](https://github.com/onixus/Shapoclyack/issues/336)) shipped and
  is the better answer, but `pvc-rwx-patch.yaml` is what this overlay enables
  out of the box — switching is a decision, not an upgrade. Note also that run
  keys are flat (`runs/<run_id>`): per-tenant prefixes, which is what would let
  a bucket policy enforce the isolation the API enforces in code, are
  [#311](https://github.com/onixus/Shapoclyack/issues/311).
* **Disaster recovery beyond Postgres is unproven.**
  [#333](https://github.com/onixus/Shapoclyack/issues/333) tracks a rehearsed
  restore of ClickHouse, artifacts and JetStream state. Only the Postgres drill
  in [operations.md](operations.md#backup-and-disaster-recovery) has been run —
  and this overlay hands even that to the managed provider.
* **No multi-cluster or multi-region story.** Zone spread is best-effort
  (`whenUnsatisfiable: ScheduleAnyway`) because a single-zone cluster would
  otherwise leave every pod after the first unschedulable.
* **NATS transport is not encrypted by this overlay.** TLS on the client port
  exists ([#309](https://github.com/onixus/Shapoclyack/issues/309) /
  [#359](https://github.com/onixus/Shapoclyack/issues/359):
  `examples/nats-tls-configmap-patch.yaml`, `OCTO_NATS_TLS_*` on the API and
  the sensors — see [operations.md § NATS TLS](operations.md#nats-tls)), but
  it is opt-in and this overlay does not enable it; the route port `:6222` has
  no TLS at all. Without that patch keep `:4222` and `:6222` on the cluster
  network.
* **The scan Job and CronJob are unchanged, relative to `base`.** They are batch
  work with their own retry semantics; running two of them is not availability.
  Note that this overlay is **not** a superset of `overlays/prod`: it does not
  carry that overlay's `hostNetwork: true` + `workload=scanner` patches for the
  Job and CronJob. An installation moving from `prod` to `prod-ha` that scans
  from the host network must copy `overlays/prod/job-hostnetwork-patch.yaml` and
  `overlays/prod/cronjob-hostnetwork-patch.yaml` into `overlays/prod-ha/` and add
  them to `patches:` — kustomize will not load a patch file from outside its
  own root. Left out silently, the scan Jobs move to the pod network and return
  quieter results with no error.
* **ClickHouse and the scan workload have no HPA.** Only the API scales.

## Migrating an existing install

`kubectl apply -k` onto a namespace that already runs `overlays/prod` or
`overlays/dev` **fails part-way**, and the half that applied stays applied.
Two fields in this overlay are immutable on an object that already exists, and
the API server rejects the change rather than rolling anything:

| Object | Field | Base | prod-ha |
|---|---|---|---|
| `pvc/scanner-data` | `spec.accessModes`, `spec.storageClassName` | `ReadWriteOnce`, default class | `ReadWriteMany`, your RWX class |
| `sts/shapoclyack-nats` | `spec.podManagementPolicy` | `OrderedReady` (default) | `Parallel` |

A green-field namespace has neither problem. For an existing one, do both
migrations first, in a maintenance window — this is not a live migration and
there is no version of it that is:

```bash
NS=network-scan

# 1. Artifacts: the RWO claim cannot be widened, it has to be replaced — so
#    copy its contents out while a pod still mounts it. A PVC delete is not
#    reversible unless the PV's reclaim policy is Retain; check that first.
kubectl -n "$NS" exec deploy/shapoclyack-api -- \
  tar -C /app/scanner -cf - output state > artifacts.tar
kubectl -n "$NS" scale deploy/shapoclyack-api --replicas=0
kubectl -n "$NS" delete pvc scanner-data

#    Recreate just the claim — the rest of the overlay comes in step 3, and
#    applying it now would hit the NATS problem below. Same shape the overlay
#    renders (`kubectl kustomize .../prod-ha` to check), with your RWX class:
kubectl -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: scanner-data
spec:
  accessModes: [ReadWriteMany]
  storageClassName: YOUR-RWX-STORAGE-CLASS
  resources:
    requests:
      storage: 20Gi
EOF
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Bound pvc/scanner-data --timeout=5m

#    Restore into the new volume, then scale back up.
kubectl -n "$NS" scale deploy/shapoclyack-api --replicas=1
kubectl -n "$NS" exec -i deploy/shapoclyack-api -- \
  tar -C /app/scanner -xf - < artifacts.tar

# 2. NATS: recreate the StatefulSet object, keep the pod and its PVC.
#    --cascade=orphan leaves nats-0 running and nats-data-shapoclyack-nats-0 intact; the
#    new StatefulSet adopts the pod by name on the next apply.
kubectl -n "$NS" delete statefulset shapoclyack-nats --cascade=orphan

# 3. Now the overlay applies as a whole.
kubectl apply -k k8s/shapoclyack/overlays/prod-ha
```

`podManagementPolicy: Parallel` is not cosmetic and is why step 2 exists at
all: under the default `OrderedReady`, pod N+1 is not created until pod N is
Ready, and a NATS pod that has to reach a JetStream meta leader cannot get
there alone (verified: `nats-1` sits at `0/1` forever and `nats-2` is never
created). The narrower readiness probe this repository now uses
(`/healthz?js-server-only=true`, `base/nats/statefulset.yaml`) removes that
particular cause, but "should now bootstrap under `OrderedReady`" has not been
re-verified on a real three-node cluster, and an unverified claim here costs an
outage. The field stays, and so does this section.

## Verifying the profile

`k8s/scripts/validate-kustomize.sh` renders this overlay in CI (Jenkins stage
`Kustomize`), which catches a patch that does not build — an unresolvable
path, a malformed `$patch: delete`, a merge that produces invalid YAML. It does
not validate against the cluster's schema and it cannot catch anything that
needs a running cluster: a dangling reference to a deleted object, an RWX class
that does not exist, a NATS cluster that fails to form.

`tests/test_multi_replica_load.py` is the concurrency regression suite and runs
in the normal `pytest` stage against the CI Postgres. It simulates replicas
in-process; **it is not run against a rendered `prod-ha` cluster in CI**, and it
cannot be, because the CI environment is kind with no RWX StorageClass and no
external Postgres — the two prerequisites above. Rehearse the profile by hand on
a cluster that has them:

```bash
# 1. Prerequisites in place (RWX class, external Postgres Secret, route password).
kubectl apply -k k8s/shapoclyack/overlays/prod-ha
kubectl -n network-scan rollout status deploy/shapoclyack-api

# 2. Replicas are actually on different nodes.
kubectl -n network-scan get pods -l app.kubernetes.io/component=api \
  -o custom-columns=POD:.metadata.name,NODE:.spec.nodeName

# 3. JetStream formed a cluster and the streams are R3. The nats:2.10-alpine
#    image carries no `nats` CLI, so ask the monitoring endpoint, which needs
#    no credentials and is not exposed outside the pod network.
kubectl -n network-scan exec sts/shapoclyack-nats -- \
  wget -qO- 'http://127.0.0.1:8222/jsz?streams=1'
#    Expect "cluster" with three peers, and every stream's "replicas": 3.
#    For the CLI's own output, run it from a box image instead:
kubectl -n network-scan run natsbox --rm -it --restart=Never \
  --image=natsio/nats-box:latest -- \
  nats --server nats://shapoclyack-nats:4222 \
      --user api --password "$(kubectl -n network-scan get secret shapoclyack-nats \
        -o jsonpath='{.data.api_password}' | base64 -d)" stream report

# 4. The HPA can read metrics (not <unknown>).
kubectl -n network-scan get hpa shapoclyack-api

# 5. A drain evicts one replica and not both.
kubectl drain "$NODE" --ignore-daemonsets --delete-emptydir-data
kubectl -n network-scan get pdb shapoclyack-api

# 6. A rollout serves throughout. Run this against /readyz from outside the
#    cluster while restarting, and expect zero non-200s.
kubectl -n network-scan rollout restart deploy/shapoclyack-api
```

Record the result of steps 5 and 6 the way the restore drill is recorded in
[operations.md](operations.md#backup-and-disaster-recovery): an HA profile
nobody has drained a node under is a claim, not a capability.
