# Octo-man — Kubernetes

Primary deployment path for Octo-man. Images are still built with Docker/`docker build`,
but runtime orchestration is **Kubernetes + kustomize** (docker-compose is retired).

Images (release `v0.3.0`):
- Scanner: `ghcr.io/onixus/octo-man:0.3.0`
- API + dashboard: `ghcr.io/onixus/octo-man-api:0.3.0`

## Layout

```
k8s/octo-man/
├── base/                 # namespace, SA, PVC, Job, CronJob, API Deployment/Service
├── base/config/k8s.yaml  # scanner config ConfigMap source
├── overlays/dev/         # smaller resources, safe mode
├── overlays/prod/        # hostNetwork + scanner node pool
└── examples/             # Secrets / Ingress samples
```

## Quick start

### 1. Targets Secret

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
# Edit examples/api-secrets.example.yaml then:
kubectl apply -f k8s/octo-man/examples/api-secrets.example.yaml
```

Base kustomization already generates a **dev-only** `octo-man-api` JWT secret
(`octo-man-dev-secret-change-me`). Override it in real environments.

### 3. Build / push images (still Docker)

```bash
docker build -t ghcr.io/onixus/octo-man:local -f Dockerfile .
docker build -t ghcr.io/onixus/octo-man-api:local -f Dockerfile.api .
# push or load into your cluster (kind load / k3d image import / registry)
```

### 4. Apply

**Dev**

```bash
kubectl apply -k k8s/octo-man/overlays/dev
# re-run a one-shot Job after it finishes:
kubectl -n network-scan delete job network-scan --ignore-not-found
kubectl apply -k k8s/octo-man/overlays/dev
```

**Prod** (nodes labeled `workload=scanner`, taint `scanner=true:NoSchedule`)

```bash
kubectl apply -k k8s/octo-man/overlays/prod
```

### 5. Dashboard access

```bash
kubectl -n network-scan port-forward svc/octo-man-api 8080:8080
# open http://localhost:8080
```

Or apply [`examples/ingress.example.yaml`](octo-man/examples/ingress.example.yaml).

### 6. Observe / resume

```bash
kubectl -n network-scan get jobs,cronjobs,deploy,pods,pvc,svc
kubectl -n network-scan logs -f job/network-scan
kubectl apply -f k8s/octo-man/base/job-resume.yaml
```

Artifacts live on PVC `scanner-data` under `output/` and `state/` subPaths.

## Scheduling model

| Compose (retired) | Kubernetes |
|---|---|
| `docker compose run scanner` | `Job/network-scan` |
| `scheduler` service / cron | `CronJob/network-scan-scheduled` |
| `api` service | `Deployment/octo-man-api` + `Service` |

## Storage note

`scanner-data` defaults to `ReadWriteOnce`. API + scan Jobs must schedule on the same
node (prod overlay pins both to `workload=scanner`), or switch the PVC to `ReadWriteMany`
if your StorageClass supports it.

## Validate manifests

```bash
./k8s/scripts/validate-kustomize.sh
```
