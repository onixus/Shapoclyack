# Octo-man — Kubernetes

Primary cluster runtime for **shapoclyack-0.33+**. Default control plane is the **all-in-one**
image with Web UI scan start enabled.

| Image | Tag | Role |
|-------|-----|------|
| `ghcr.io/onixus/shapoclyack-aio` | `shapoclyack-0.33` | API + UI + scanner (**default** Deployment / Job / CronJob) |
| `ghcr.io/onixus/shapoclyack-scanner` | `shapoclyack-0.33` | Scanner-only (lighter Job/CronJob alternative) |
| `ghcr.io/onixus/shapoclyack-api` | `shapoclyack-0.33` | Thin API + UI (results-only overlay) |

Also see root [README.md](../README.md) and [CHANGELOG.md](../CHANGELOG.md).

For local labs, prefer `docker compose up` at the repo root.

## Layout

```
k8s/octo-man/
├── base/                 # namespace, SA, PVC, NATS, ClickHouse, Job, CronJob, aio API
├── base/nats/            # JetStream StatefulSet + Services + ConfigMap
├── base/clickhouse/      # Analytics StatefulSet + Services + ConfigMap (50Gi PVC)
├── base/config/k8s.yaml  # scanner ConfigMap source
├── base/agents/          # optional agent Deployment + VPA (not in default base)
├── overlays/dev/         # smaller resources, --mode safe
├── overlays/prod/        # hostNetwork + scanner node pool
├── overlays/api-readonly/# thin shapoclyack-api image, OCTO_ALLOW_SCAN_START=false
├── overlays/agents/      # remote agents (topology spread + VPA) + API agent-mode
└── examples/             # Secrets / Ingress / agent / NATS enable patches
```

### NATS JetStream

Base includes `octo-man-nats` under `base/nats/` (ConfigMap + StatefulSet + headless/client Services).
API/agent stay HTTP-only until you set:

```bash
OCTO_NATS_URL=nats://octo-man-nats-client:4222
```

Example patches: `examples/nats-api-patch.yaml`, `examples/nats-agent-patch.yaml`.

Subjects: `jobs.scan` (work-queue stream `JOBS`), `ingest.raw_results` (stream `INGEST`).

**Retention:** streams are bounded by default (`JOBS` max age 24h, `INGEST` max
age 7d / max bytes 10GiB) so a stalled agent or disabled ClickHouse worker
can't grow JetStream storage without limit. Override on the API deployment:
`OCTO_NATS_JOBS_MAX_AGE_SECONDS`, `OCTO_NATS_INGEST_MAX_AGE_SECONDS`,
`OCTO_NATS_INGEST_MAX_BYTES`. Limits apply to existing streams on API restart
(via JetStream `update_stream`), not just first creation.

**HA:** base runs a single NATS pod (fine for dev/lab). The cluster config is
already in `base/nats/configmap.yaml` — apply `examples/nats-ha-patch.yaml`
to scale to 3 replicas for a real quorum, and set `OCTO_NATS_STREAM_REPLICAS=3`
on the API so streams replicate R3 instead of staying single-copy. Each
replica requests its own 5Gi PVC (3 nodes = 15Gi total, not shared).

### ClickHouse

Base includes `octo-man-clickhouse` under `base/clickhouse/` (50Gi PVC).
Client DNS: `octo-man-clickhouse-client:8123` (HTTP) / `:9000` (native).

First-boot schema via `/docker-entrypoint-initdb.d/init.sql` (ConfigMap):
- `shapoclyack.shapoclyack_vulnerabilities` (`ReplacingMergeTree`, ORDER BY `tenant_id, asset_ip, cve_id`)
- `shapoclyack.shapoclyack_open_ports` (`ReplacingMergeTree`, ORDER BY `tenant_id, target_ip, port`)

Enable API ingest worker:

```bash
OCTO_NATS_URL=nats://octo-man-nats-client:4222
OCTO_CLICKHOUSE_URL=http://octo-man-clickhouse-client:8123
OCTO_CH_INGEST_ENABLED=true
```

Example patch: `examples/clickhouse-ingest-api-patch.yaml`.

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

Or edit [`examples/scan-targets.secret.example.yaml`](octo-man/examples/scan-targets.secret.example.yaml).

### 2. API / alert secrets

```bash
# Edit defaults first — demo JWT/users are for labs only
kubectl apply -f k8s/octo-man/examples/api-secrets.example.yaml
```

Base kustomization also generates a **dev-only** `octo-man-api` JWT secret
(`octo-man-dev-secret-change-me`). Replace it before any real deployment.

### 3. Apply overlay

**Dev** (aio API with UI job start, smaller CPU/RAM, Job `--mode safe`):

```bash
kubectl apply -k k8s/octo-man/overlays/dev
# re-run a finished one-shot Job:
kubectl -n network-scan delete job network-scan --ignore-not-found
kubectl apply -k k8s/octo-man/overlays/dev
```

**Prod** (nodes labeled `workload=scanner`, taint `scanner=true:NoSchedule`):

```bash
kubectl apply -k k8s/octo-man/overlays/prod
```

**Results-only API** (thin image, no local scan start):

```bash
kubectl apply -k k8s/octo-man/overlays/api-readonly
```

### 4. Dashboard

```bash
kubectl -n network-scan port-forward svc/octo-man-api 8080:8080
# http://localhost:8080  — demo users: viewer / operator / admin (*-change-me)
```

Or apply [`examples/ingress.example.yaml`](octo-man/examples/ingress.example.yaml).

Default RBAC:

| Role | Access |
|------|--------|
| `viewer` | List/read runs, summaries, diffs, vulns, artifacts |
| `operator` | Viewer + start/list scan jobs / agents via API |
| `admin` | Same as operator (reserved for future admin APIs) |

Default aio Deployment sets **`OCTO_ALLOW_SCAN_START=true`** so operators start scans from
the Jobs page. Scheduled scans can still use `Job` / `CronJob`. Remote agents remain optional
(see **overlays/agents** below, or `examples/agent-*.yaml`).

### Optional: scanner agents (topology spread + VPA)

Agents are **not** in the default `base` kustomization (they need an agent token and
usually `OCTO_JOB_EXECUTION_MODE=agent`). Enable with:

```bash
# Requires: Secret octo-man-agent, VPA CRDs, and preferably NATS
kubectl apply -k k8s/octo-man/overlays/agents
```

| Manifest | Behavior |
|----------|----------|
| `base/agents/agent-deployment.yaml` | Replicas 2 (overlay → 3); zone + hostname `topologySpreadConstraints`; NATS URL wired |
| `base/agents/agent-vpa.yaml` | VPA `updateMode: Auto` for CPU/RAM under burst scan load |
| Overlay patches | API `OCTO_JOB_EXECUTION_MODE=agent` + NATS URL |

Standalone example: `octo-man/examples/agent-deployment.example.yaml`.

### 5. Observe / resume

```bash
kubectl -n network-scan get jobs,cronjobs,deploy,pods,pvc,svc
kubectl -n network-scan logs -f job/network-scan
kubectl apply -f k8s/octo-man/base/job-resume.yaml
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
