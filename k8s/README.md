# Octo-man — Kubernetes

Primary cluster runtime for **v0.3.2.1+**. Default control plane is the **all-in-one**
image with Web UI scan start enabled.

| Image | Tag | Role |
|-------|-----|------|
| `ghcr.io/onixus/octo-man-aio` | `0.3.2.1` | API + UI + scanner (**default** Deployment / Job / CronJob) |
| `ghcr.io/onixus/octo-man-scanner` | `0.3.2.1` | Scanner-only (lighter Job/CronJob alternative) |
| `ghcr.io/onixus/octo-man-api` | `0.3.2.1` | Thin API + UI (results-only overlay) |

Also see root [README.md](../README.md) and [CHANGELOG.md](../CHANGELOG.md).

For local labs, prefer `docker compose up` at the repo root.

## Layout

```
k8s/octo-man/
├── base/                 # namespace, SA, PVC, Job, CronJob, aio API Deployment/Service
├── base/config/k8s.yaml  # scanner ConfigMap source
├── overlays/dev/         # smaller resources, --mode safe
├── overlays/prod/        # hostNetwork + scanner node pool
├── overlays/api-readonly/# thin octo-man-api, OCTO_ALLOW_SCAN_START=false
└── examples/             # Secrets / Ingress / agent samples
```

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
(`examples/agent-mode-api-patch.yaml`, `agent-deployment.example.yaml`).

### 5. Observe / resume

```bash
kubectl -n network-scan get jobs,cronjobs,deploy,pods,pvc,svc
kubectl -n network-scan logs -f job/network-scan
kubectl apply -f k8s/octo-man/base/job-resume.yaml
```

Artifacts: PVC `scanner-data` → `output/` and `state/` subPaths.

## Optional: build images yourself

```bash
docker build -t ghcr.io/onixus/octo-man-aio:local -f Dockerfile.allinone .
docker build -t ghcr.io/onixus/octo-man-scanner:local -f Dockerfile .
docker build -t ghcr.io/onixus/octo-man-api:local -f Dockerfile.api .
# kind load docker-image … / k3d image import … / push to your registry
# then patch image names in the overlay or kustomize images: transformer
```

## Validate

```bash
./k8s/scripts/validate-kustomize.sh
```
