# Octo-man — Kubernetes

Primary runtime for **v0.3.0+**. Images are built with Docker; orchestration is
**Kubernetes + kustomize** (docker-compose is retired).

| Image | Tag | Role |
|-------|-----|------|
| `ghcr.io/onixus/octo-man` | `0.3.0` | Scanner pipeline (`Job` / `CronJob`) |
| `ghcr.io/onixus/octo-man-api` | `0.3.0` | FastAPI + React dashboard |

Also see root [README.md](../README.md) and [CHANGELOG.md](../CHANGELOG.md).

## Layout

```
k8s/octo-man/
├── base/                 # namespace, SA, PVC, Job, CronJob, API Deployment/Service
├── base/config/k8s.yaml  # scanner ConfigMap source (cluster-tuned rates, vuln-offline)
├── overlays/dev/         # smaller resources, --mode safe
├── overlays/prod/        # hostNetwork + scanner node pool
└── examples/             # Secrets / Ingress samples
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

**Dev** (smaller CPU/RAM, `--mode safe`):

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
| `operator` | Viewer + start/list scan jobs via API |
| `admin` | Same as operator in v0.3.0 (reserved for future admin APIs) |

Scan start from the API image stays **off** (`OCTO_ALLOW_SCAN_START=false`): use the
Kubernetes `Job` / `CronJob` for scans; the UI reads results from the shared PVC.

### 5. Observe / resume

```bash
kubectl -n network-scan get jobs,cronjobs,deploy,pods,pvc,svc
kubectl -n network-scan logs -f job/network-scan
kubectl apply -f k8s/octo-man/base/job-resume.yaml
```

Artifacts: PVC `scanner-data` → `output/` and `state/` subPaths.

## Optional: build images yourself

```bash
docker build -t ghcr.io/onixus/octo-man:local -f Dockerfile .
docker build -t ghcr.io/onixus/octo-man-api:local -f Dockerfile.api .
# kind load docker-image … / k3d image import … / push to your registry
# then patch image names in the overlay or kustomize images: transformer
```

## Workload map

| Capability | Kubernetes object |
|---|---|
| One-shot scan | `Job/network-scan` |
| Scheduled / delta scan | `CronJob/network-scan-scheduled` |
| Resume interrupted run | `job-resume.yaml` (manual apply) |
| API + dashboard | `Deployment/octo-man-api` + `Service` |

## Storage note

`scanner-data` defaults to `ReadWriteOnce`. API + scan Jobs must land on the same node
(prod overlay pins both to `workload=scanner`), or switch the PVC to `ReadWriteMany`
when your StorageClass supports it.

## Validate manifests

```bash
./k8s/scripts/validate-kustomize.sh
```
