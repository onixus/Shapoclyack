# Shapoclyack — Kubernetes

This guide deploys Shapoclyack with Kustomize. For architecture, configuration,
and operational context, start at [../docs/README.md](../docs/README.md).

Primary cluster runtime for **shapoclyack-0.40-0806+**. Default control plane is the **all-in-one**
image with Web UI scan start enabled.

| Image | Tag | Role |
|-------|-----|------|
| `ghcr.io/onixus/shapoclyack-aio` | `shapoclyack-0.40-0806` | API + UI + scanner (**default** Deployment / Job / CronJob) |
| `ghcr.io/onixus/shapoclyack-scanner` | `shapoclyack-0.40-0806` | Scanner-only (lighter Job/CronJob alternative) |
| `ghcr.io/onixus/shapoclyack-api` | `shapoclyack-0.40-0806` | Thin API + UI (results-only overlay) |

Also see root [README.md](../README.md) and [CHANGELOG.md](../CHANGELOG.md).

For local labs, prefer `scripts/dev-up.sh` at the repo root — it builds the
all-in-one image, loads it into a [kind](https://kind.sigs.k8s.io/) cluster,
and applies `overlays/kind-dev`. Set `OVERLAY=kind-enrichment` for real
enrichment data; with `OVERLAY` unset the script keeps whatever the cluster
already runs, so a rebuild cannot silently strip enrichment from the API.
Tear down with `scripts/dev-down.sh`.

### A note on NET_RAW/NET_ADMIN and `allowPrivilegeEscalation`

**Default path (Phase 4–5):** service enrichment is **Pulse** + Nuclei, not
nmap NSE. Caps still matter for:

| Binary | Why caps |
|--------|----------|
| **naabu** | SYN / host discovery |
| **pulse** | SYN mode and OS fingerprint (connect mode needs no raw caps) |
| **nmap** | Optional — not in the default `shapoclyack-scanner`/`-aio` images (`backend: nmap\|hybrid` only); local `docker build` defaults to `INSTALL_NMAP=1` unless overridden, see below |
| **fping** | ICMP discovery |

Raw sockets are granted via file capabilities baked into the image at build
time (`setcap`, see `Dockerfile`). Any pod running them as a non-root user
needs `allowPrivilegeEscalation: true` alongside
`capabilities.add: [NET_RAW, NET_ADMIN]` — setting `allowPrivilegeEscalation:
false` (a common hardening default) sets `no_new_privs`, which silently
blocks those file capabilities from taking effect on exec, regardless of what
`capabilities.add` lists. This is a Linux capabilities interaction, not a
Docker-vs-Kubernetes difference — it affected both runtimes equally before
being fixed (see `job.yaml`, `cronjob.yaml`, `api-deployment.yaml`,
`agents/agent-deployment.yaml`, all of which correctly set it `true`). Don't
"fix" it back to `false` on any manifest that runs naabu/pulse/nmap
directly.

**Published images are Nmap-free by default** — `ghcr.io/onixus/shapoclyack-{scanner,aio}:latest`
(and versioned tags) are built with `INSTALL_NMAP=0`; no Nmap binary, NSE data,
or `nmap-vulners`/Vulscan scripts, so the Nmap Public Source License's
redistribution terms don't apply to those artifacts (see
[issue #97](https://github.com/onixus/Shapoclyack/issues/97)). A separate
`-nmap` tag (`shapoclyack-{scanner,aio}:latest-nmap`) is published for anyone
who explicitly wants classic NSE — review NPSL before redistributing that tag
further.

A local `docker build` still defaults to `INSTALL_NMAP=1` unless you pass the
build-arg explicitly:

```bash
docker build -f Dockerfile --build-arg INSTALL_NMAP=0 -t shapoclyack-scanner:pulse-only .
```

NSE stage skips cleanly if someone still sets `backend: nmap` against a
Nmap-free image.

## Layout

```
k8s/shapoclyack/
├── base/                 # namespace, SA, PVC, NATS, ClickHouse, Job, CronJob, aio API
├── base/nats/            # JetStream StatefulSet + Services + ConfigMap
├── base/clickhouse/      # Analytics StatefulSet + Services + ConfigMap (50Gi PVC)
├── base/config/k8s.yaml  # scanner ConfigMap source
├── base/agents/          # optional agent Deployment + VPA (not in default base)
├── base/enrichment/      # optional GeoIP/EPSS/KEV/CVSS4 component: RWX PVC + daily refresh CronJob + patches
├── overlays/dev/         # smaller resources, --mode safe
├── overlays/prod/        # hostNetwork + scanner node pool
├── overlays/api-readonly/# thin shapoclyack-api image, OCTO_ALLOW_SCAN_START=false
├── overlays/agents/      # remote agents (topology spread + VPA) + API agent-mode
├── overlays/enrichment/  # real GeoIP/EPSS/KEV/CVSS4 data, hot-reloaded, no restart needed
├── overlays/kind-enrichment/ # kind-dev + enrichment, with the PVC dropped to RWO for local-path
└── examples/             # Secrets / Ingress / agent / NATS patches + ServiceMonitor
```

### NATS JetStream

Base includes `shapoclyack-nats` under `base/nats/` (ConfigMap + StatefulSet + headless/client Services).
API/agent stay HTTP-only until you set:

```bash
OCTO_NATS_URL=nats://shapoclyack-nats-client:4222
```

Example patches: `examples/nats-api-patch.yaml`, `examples/nats-agent-patch.yaml`.

Subjects: `jobs.scan` (work-queue stream `JOBS`), `ingest.raw_results` (stream
`INGEST`), `events.asset.{tenant_id}.{kind}` (stream `EVENTS`).

**Asset events (Phase 10.2):** after every successful run the API publishes the
run's `diff.json` events — `new_asset`, `new_open_port`, `new_cve`,
`cert_expiring` — plus `decommissioned_host` when an operator decommissions an
asset. Subscribe per tenant with `events.asset.acme.>` or across tenants by kind
with `events.asset.*.new_cve`. The stream is `LIMITS` retention, not
`WORK_QUEUE`: one event is meant to reach several independent consumers, so a
webhook bridge does not consume it away from a ticket bridge. Publishing is
best-effort — a broker outage costs notifications, not data, since the events
stay in the run's `diff.json`. Turn it off with `OCTO_ASSET_EVENTS_ENABLED=false`
without disabling job dispatch or result ingest on the same broker.

**Webhook fan-out (Phase 10.3):** the API's own consumer of that stream is the
durable pull consumer `octo-webhook-fanout` on `events.asset.>`, which turns
matching events into `webhook_deliveries` rows; a dispatcher thread in every
replica then delivers them (claims via `FOR UPDATE SKIP LOCKED`, so replicas
divide the queue). Only queueing is on the broker path — the HTTP call is not —
so a slow receiver shows up as pending rows, not as JetStream lag. With
`OCTO_WEBHOOK_DISPATCH_ENABLED=false` a replica keeps the API surface but sends
nothing, which is how you confine outbound traffic to pods that have egress.
Watch `octo_webhook_delivery_queue{status="dead"}` for the dead-letter queue and
`octo_nats_consumer_pending{consumer="octo-webhook-fanout"}` for fan-out lag.
See [../docs/configuration.md](../docs/configuration.md) for the full
`OCTO_WEBHOOK_*` set.

**Retention:** streams are bounded by default (`JOBS` max age 24h, `INGEST` max
age 7d / max bytes 10GiB, `EVENTS` max age 30d / max bytes 1GiB) so a stalled
agent, disabled ClickHouse worker or absent event consumer can't grow JetStream
storage without limit. Override on the API deployment:
`OCTO_NATS_JOBS_MAX_AGE_SECONDS`, `OCTO_NATS_INGEST_MAX_AGE_SECONDS`,
`OCTO_NATS_INGEST_MAX_BYTES`, `OCTO_NATS_EVENTS_MAX_AGE_SECONDS`,
`OCTO_NATS_EVENTS_MAX_BYTES`. Limits apply to existing streams on API restart
(via JetStream `update_stream`), not just first creation.

`EVENTS` also sets a 24h JetStream duplicate window
(`OCTO_NATS_EVENTS_DEDUPE_SECONDS`): event ids are derived from
tenant+run+kind+host+port+CVE, so a results upload retried after a network
timeout republishes the same ids and JetStream drops them. The window is longer
than JetStream's 2-minute default because that is shorter than the gap between
an upload and its retry.

**HA:** base runs a single NATS pod (fine for dev/lab). The cluster config is
already in `base/nats/configmap.yaml` — apply `examples/nats-ha-patch.yaml`
to scale to 3 replicas for a real quorum, and set `OCTO_NATS_STREAM_REPLICAS=3`
on the API so streams replicate R3 instead of staying single-copy. Each
replica requests its own 5Gi PVC (3 nodes = 15Gi total, not shared).

### ClickHouse

Base includes `shapoclyack-clickhouse` under `base/clickhouse/` (50Gi PVC).
Client DNS: `shapoclyack-clickhouse-client:8123` (HTTP) / `:9000` (native).

First-boot schema via `/docker-entrypoint-initdb.d/init.sql` (ConfigMap):
- `shapoclyack.shapoclyack_vulnerabilities` (`ReplacingMergeTree`, ORDER BY `tenant_id, asset_ip, cve_id`)
- `shapoclyack.shapoclyack_open_ports` (`ReplacingMergeTree`, ORDER BY `tenant_id, target_ip, port`)

Enable API ingest worker:

```bash
OCTO_NATS_URL=nats://shapoclyack-nats-client:4222
OCTO_CLICKHOUSE_URL=http://shapoclyack-clickhouse-client:8123
OCTO_CH_INGEST_ENABLED=true
```

Example patch: `examples/clickhouse-ingest-api-patch.yaml`.

### Postgres (PRIMARY_DB — Phase 7)

Base includes `shapoclyack-postgres` under `base/postgres/` (10Gi PVC). Client
DNS: `shapoclyack-postgres-client:5432`. **Unlike NATS/ClickHouse, this is not
opt-in** — the tenant store (`api/services/tenants.py`) and the cross-run
asset inventory (`api/services/assets.py`) both live here, so the API fails
fast on startup if `OCTO_POSTGRES_URL` is empty.

An `initContainer` on the API Deployment runs `alembic upgrade head` before
any replica starts (migrations aren't safely idempotent across N concurrently
starting replicas the way ClickHouse's `CREATE TABLE IF NOT EXISTS` init-SQL
is). Dev-only password `shapoclyack-dev-postgres-change-me` is generated by the
base `secretGenerator` — replace it before any real deployment, same as the
API JWT secret.

`GET /api/assets`, `GET /api/assets/{asset_id}` expose the cross-run
registry; run-scoped endpoints under `/api/runs/*` are unaffected.

### Metrics scraping (Prometheus)

The API serves `GET /metrics` on the same port as everything else (`8080`,
Service `shapoclyack-api`, named port `http`). There is **no Prometheus in this
repository** — bring your own. Two wiring options, both already in the tree:

| You run | Wiring | Action |
|---|---|---|
| An annotation-based scrape config (`kubernetes-pods` job) | `prometheus.io/scrape,port,path` on the API pod template in `base/api-deployment.yaml` | none — already applied |
| Prometheus Operator / kube-prometheus-stack | `examples/servicemonitor.example.yaml` | `kubectl -n network-scan apply -f …`, and set a label your `serviceMonitorSelector` matches |

The ServiceMonitor lives in `examples/` because it needs the
`monitoring.coreos.com/v1` CRDs, which base does not install; applying base on a
cluster without the operator must not fail. The pod annotations are inert when
nothing scrapes them.

Bare `scrape_configs` instead of either of the above:

```yaml
- job_name: shapoclyack-api
  metrics_path: /metrics
  kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names: [network-scan]
  relabel_configs:
    - source_labels: [__meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
      action: keep
      regex: shapoclyack-api;http
```

`/metrics` is **unauthenticated** by design (standard Prometheus practice —
restrict at the network layer, not app auth). `examples/ingress.example.yaml`
does not expose it; keep it that way, and reach it in a lab with
`kubectl -n network-scan port-forward svc/shapoclyack-api 8080:8080`.

Series reference and alert thresholds: [docs/slo.md](../docs/slo.md) and the
observability section of [docs/operations.md](../docs/operations.md).

### Upgrading a cluster deployed before the `octo-man` → `shapoclyack` rename

Resource names, labels, and the Postgres database name all carried the old
product name. Renaming them creates *new* objects, so an existing deployment
needs one migration pass:

```bash
# 1. Rename the database (no active connections; scale the API to 0 first).
kubectl -n network-scan scale deploy/octo-man-api --replicas=0
kubectl -n network-scan exec sts/octo-man-postgres -- \
  psql -U octo -d postgres -c 'ALTER DATABASE octo_man RENAME TO shapoclyack;'

# 2. Apply the renamed manifests, then remove the old objects.
kubectl apply -k k8s/shapoclyack/overlays/prod
kubectl -n network-scan delete deploy/octo-man-api sts/octo-man-postgres \
  sts/octo-man-nats sts/octo-man-clickhouse --cascade=orphan
```

`--cascade=orphan` keeps the PVCs; re-point the renamed StatefulSets at them
before deleting anything if your StorageClass does not retain volumes. The
namespace (`network-scan`), the `OCTO_*` environment variables, the `octo`
database user, and the `octo_*` Prometheus metric names are unchanged — only
the product name moved.

A self-hosted (non-Kubernetes) installation needs nothing: the sqlite default
falls back to an existing `scanner/state/octo_man.db` when the new
`shapoclyack.db` is absent.

### MSSP tenancy (Phase 2)

- Admin: `POST /api/tenants`, `POST /api/tenants/{id}/provisioning-keys`
- Agent: `POST /api/auth/agent/token` with provisioning key → short-lived JWT
- Env: `OCTO_AGENT_PROVISIONING_KEY` (preferred) or legacy `OCTO_AGENT_TOKEN` (`tenant_id=default`)
- Examples: `networkpolicy-agent.example.yaml`, `externalsecret.example.yaml`

## Quick start (pull release images)

### 1. Namespace + scan targets

```bash
kubectl create namespace network-scan --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic scan-targets -n network-scan \
  --from-file=ranges.txt=./scanner/inputs/ranges.txt \
  --from-file=domains.txt=./scanner/inputs/domains.txt \
  --from-file=ports.txt=./scanner/inputs/ports.txt \
  --from-file=ports_udp.txt=./scanner/inputs/ports_udp.txt
```

Or edit [`examples/scan-targets.secret.example.yaml`](shapoclyack/examples/scan-targets.secret.example.yaml).

### 2. API / alert secrets

```bash
# Edit defaults first — demo JWT/users are for labs only
kubectl apply -f k8s/shapoclyack/examples/api-secrets.example.yaml
```

Base kustomization also generates a **dev-only** `shapoclyack-api` JWT secret
(`shapoclyack-dev-secret-change-me`). Replace it before any real deployment.

### 3. Apply overlay

**Dev** (aio API with UI job start, smaller CPU/RAM, Job `--mode safe`):

```bash
kubectl apply -k k8s/shapoclyack/overlays/dev
# re-run a finished one-shot Job:
kubectl -n network-scan delete job network-scan --ignore-not-found
kubectl apply -k k8s/shapoclyack/overlays/dev
```

**Prod** (nodes labeled `workload=scanner`, taint `scanner=true:NoSchedule`):

```bash
kubectl apply -k k8s/shapoclyack/overlays/prod
```

**Results-only API** (thin image, no local scan start):

```bash
kubectl apply -k k8s/shapoclyack/overlays/api-readonly
```

### 4. Dashboard

```bash
kubectl -n network-scan port-forward svc/shapoclyack-api 8080:8080
# http://localhost:8080  — demo users: viewer / operator / admin (*-change-me)
```

Or apply [`examples/ingress.example.yaml`](shapoclyack/examples/ingress.example.yaml).

Default RBAC:

| Role | Access |
|------|--------|
| `viewer` | List/read runs, summaries, diffs, vulns, artifacts |
| `operator` | Viewer + start/list scan jobs / agents via API |
| `admin` | Operator access plus tenant provisioning and configuration administration |

Default aio Deployment sets **`OCTO_ALLOW_SCAN_START=true`** so operators start scans from
the Jobs page. Scheduled scans can still use `Job` / `CronJob`. Remote agents remain optional
(see **overlays/agents** below, or `examples/agent-*.yaml`).

### Optional: scanner agents (topology spread + VPA)

Agents are **not** in the default `base` kustomization (they need an agent token and
usually `OCTO_JOB_EXECUTION_MODE=agent`). Enable with:

```bash
# Requires: Secret shapoclyack-agent, VPA CRDs, and preferably NATS
kubectl apply -k k8s/shapoclyack/overlays/agents
```

| Manifest | Behavior |
|----------|----------|
| `base/agents/agent-deployment.yaml` | Replicas 2 (overlay → 3); zone + hostname `topologySpreadConstraints`; NATS URL wired |
| `base/agents/agent-vpa.yaml` | VPA `updateMode: Auto` for CPU/RAM under burst scan load |
| Overlay patches | API `OCTO_JOB_EXECUTION_MODE=agent` + NATS URL |

Standalone example: `shapoclyack/examples/agent-deployment.example.yaml`.

### Optional: real GeoIP / EPSS / KEV / CVSS4 data

The committed enrichment files (`scanner/data/{geoip,epss,kev,cvss4}/`) are tiny seed
stubs baked into every image, not production feeds — without this overlay, EPSS/KEV
score only a handful of hardcoded CVEs and GeoIP only resolves 5 hardcoded IPs. Enable
with:

```bash
# Requires a StorageClass supporting ReadWriteMany (see pvc.yaml)
kubectl apply -k k8s/shapoclyack/overlays/enrichment

# On a local kind cluster instead — same thing, but the PVC drops to RWO
# because kind only ships the RWO local-path provisioner:
kubectl apply -k k8s/shapoclyack/overlays/kind-enrichment
```

| Manifest | Behavior |
|----------|----------|
| `base/enrichment/pvc.yaml` | `enrichment-data` RWX PVC (2Gi) shared by every replica |
| `base/enrichment/cronjob.yaml` | Daily 03:00 UTC `scripts/fetch-enrichment.sh` refresh into the PVC |
| `base/enrichment/*-patch.yaml` | API gets a cold-start `fetch-enrichment` initContainer + read-only volume mount + `OCTO_EPSS_DATABASE`/`OCTO_KEV_DATABASE`/`OCTO_GEOIP_DATABASE`/`OCTO_CVSS4_DATABASE`/`OCTO_ENRICHMENT_RELOAD_SECONDS`; the weekly scan CronJob gets the volume + GeoIP/CVSS4 env |

`base/enrichment/` is a kustomize **Component**, pulled in under `components:` rather
than `resources:` — that is what lets both overlays reuse the same two patches.

The API re-checks the EPSS/KEV files' mtimes at most once per
`OCTO_ENRICHMENT_RELOAD_SECONDS` (default 60s) and reloads in place when the daily
CronJob rewrites them — no pod restart needed. GeoIP source is automatic: MaxMind
GeoLite2-City if `Secret shapoclyack-geoip` / key `maxmind_license_key` is set, else
keyless DB-IP City Lite.

The CVSS4 refresh calls the NVD API, which throttles anonymous callers to 5 req/30s —
slow enough that an unkeyed refresh can hit the job's `activeDeadlineSeconds` and leave
the seed stub in place. Set a key to get 50 req/30s:

```bash
kubectl create secret generic shapoclyack-nvd \
  --from-literal=nvd_api_key=<your-key> -n network-scan
```

This is deliberately separate from the NVD key stored through the config API
(`enrichment.cvss4.nvd_api_key`): that value is only exported into the environment of a
running scan process (`scanner/main.py`), so it never reaches the enrichment fetch. An
operator-set `NVD_API_KEY` also wins over the stored config value by design.

### 5. Observe / resume

```bash
kubectl -n network-scan get jobs,cronjobs,deploy,pods,pvc,svc
kubectl -n network-scan logs -f job/network-scan
kubectl apply -f k8s/shapoclyack/base/job-resume.yaml
```

Artifacts: PVC `scanner-data` → `output/` and `state/` subPaths.

## Optional: build images yourself

```bash
docker build -t ghcr.io/onixus/shapoclyack-aio:local -f Dockerfile.allinone .
docker build -t ghcr.io/onixus/shapoclyack-scanner:local -f Dockerfile .
docker build -t ghcr.io/onixus/shapoclyack-api:local -f Dockerfile.api .
# kind load docker-image … / k3d image import … / push to your registry
# then patch image names in the overlay or kustomize images: transformer
```

## Validate

```bash
./k8s/scripts/validate-kustomize.sh
```
