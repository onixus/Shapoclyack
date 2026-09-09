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
| PDB `minAvailable: 1` | `api-pdb-patch.yaml` | Serialises voluntary disruptions so two nodes cannot be drained at once |
| NATS 3-node JetStream cluster, streams `R3` | `nats-ha-patch.yaml`, `nats-ha-configmap-patch.yaml`, `OCTO_NATS_STREAM_REPLICAS=3` | A single broker pod loses every queued job offer with its node |
| Route port 6222 opened between NATS pods | `nats-cluster-networkpolicy-patch.yaml` | Base's NetworkPolicy denies it, so the cluster silently never forms |
| `OCTO_NATS_URL` and `OCTO_CLICKHOUSE_URL` filled in | `api-ha-patch.yaml` | Base leaves both empty — they are opt-in sidecars there |
| Postgres: in-cluster StatefulSet, Services, NetworkPolicy, backup CronJob and dev Secret removed; URL from a Secret | `postgres-external-patch.yaml` | The in-cluster Postgres is one pod with one PVC and no failover |
| `OCTO_DB_POOL_SIZE` / `OCTO_DB_MAX_OVERFLOW` / `OCTO_DB_POOL_TIMEOUT` set | `api-ha-patch.yaml` | The pool is per replica; the server's `max_connections` is not |

Apply order is the usual one:

```bash
kubectl apply -k k8s/shapoclyack/overlays/prod-ha
```

## Prerequisites

### ReadWriteMany artifact storage (or #336)

This is the hard one. Scan artifacts are files on the `scanner-data` PVC,
mounted by the API Deployment, the scan Job and the CronJob. Base requests
`ReadWriteOnce`, and an RWO volume attaches to **one node at a time** — so a
second API replica scheduled on another node sits in `ContainerCreating` with a
`Multi-Attach error for volume` event until the first pod goes away.

`pvc-rwx-patch.yaml` therefore requests `ReadWriteMany` and leaves the class
name as `REPLACE-WITH-YOUR-RWX-STORAGE-CLASS`. Replace it with a class your
cluster actually has — CephFS, AWS EFS, Azure Files, GCP Filestore, NFS,
Portworx shared volumes. A wrong name binds to the wrong backend silently; an
unknown one leaves the PVC `Pending` with a `storageclass not found` event,
which is why it is not guessed here.

**Without RWX storage this overlay cannot be applied.** The other option is
[#336](https://github.com/onixus/Shapoclyack/issues/336), which moves artifacts
to object storage and removes the shared filesystem from the picture; until it
lands there is no third path that keeps both the replicas and the artifacts.
`storageClassName` is immutable on an existing PVC, so this is a decision made
at install time, not migrated into later.

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
* `readinessProbe` on `/readyz`, which checks Postgres and, where configured,
  NATS and ClickHouse. A replica that cannot serve leaves the Service instead of
  being restarted.
* `livenessProbe` on `/livez`, dependency-free on purpose: a Postgres outage
  must not restart every replica at once.
* `startupProbe` — up to 150s for a cold start against a busy database, during
  which neither probe above runs.
* `lifecycle.preStop: sleep 5` and `terminationGracePeriodSeconds: 45` —
  endpoint removal and `SIGTERM` are dispatched concurrently, so without the
  pause the process starts shutting down while proxies still route to it.
* PDB `minAvailable: 1` — bounds *voluntary* disruption (drains, evictions),
  which the rollout strategy does not.

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

Background workers are safe across replicas by construction, not by luck: the
scheduler dispatcher, the report dispatcher and the software-match worker take a
Postgres advisory lock (`api/services/leader_lock.py`), webhook delivery claims
rows `FOR UPDATE`, and the ClickHouse ingest worker is a durable JetStream
consumer. `tests/test_multi_replica_load.py` is the regression suite for that.

## What this overlay does not give you

Naming these is the point of the page.

* **ClickHouse is a single StatefulSet pod.** Losing it loses the analytics
  store — not the control plane, which is Postgres, and not the raw run
  artifacts, which are files. A real ClickHouse cluster (Keeper, sharded or
  replicated tables) is out of scope here; nothing in this repository sets one
  up, and `base/clickhouse/init-local.sql` creates non-replicated tables.
* **Artifacts still live on a shared filesystem.**
  [#336](https://github.com/onixus/Shapoclyack/issues/336) — object storage — is
  the fix; RWX is the workaround this overlay depends on.
* **Disaster recovery beyond Postgres is unproven.**
  [#333](https://github.com/onixus/Shapoclyack/issues/333) tracks a rehearsed
  restore of ClickHouse, artifacts and JetStream state. Only the Postgres drill
  in [operations.md](operations.md#backup-and-disaster-recovery) has been run —
  and this overlay hands even that to the managed provider.
* **No multi-cluster or multi-region story.** Zone spread is best-effort
  (`whenUnsatisfiable: ScheduleAnyway`) because a single-zone cluster would
  otherwise leave every pod after the first unschedulable.
* **NATS transport is not encrypted.** Still
  [#309](https://github.com/onixus/Shapoclyack/issues/309) /
  [#359](https://github.com/onixus/Shapoclyack/issues/359); a 3-node cluster
  does not change it. Keep `:4222` and `:6222` on the cluster network.
* **The scan Job and CronJob are unchanged.** They are batch work with their own
  retry semantics; running two of them is not availability.

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

# 3. JetStream formed a cluster and the streams are R3.
kubectl -n network-scan exec sts/shapoclyack-nats -- \
  nats --user api --password "$NATS_API_PASSWORD" stream report

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
