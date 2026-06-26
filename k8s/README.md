# Network Scan CLI — Kubernetes

Манифесты и конфигурация для запуска [Octo-man](https://github.com/onixus/Octo-man) в Kubernetes.  
**Всё, что относится к K8s, хранится в этом репозитории (Shapoclyack), не в Octo-man.**

Образ: `ghcr.io/onixus/octo-man`

## Структура

```
k8s/network-scan-cli/
├── base/config/k8s.yaml         # конфиг сканера для кластера
├── base/                        # namespace, SA, PVC, Job, CronJob
├── overlays/dev/                # меньше ресурсов, режим safe
├── overlays/prod/               # hostNetwork, taints, scanner node pool
├── examples/                    # пример Secret с целями
└── base/job-resume.yaml         # шаблон Job с --resume (вручную)
```

## Быстрый старт

### 1. Secret с целями

```bash
kubectl create namespace network-scan --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic scan-targets -n network-scan \
  --from-file=ranges.txt=./ranges.txt \
  --from-file=domains.txt=./domains.txt \
  --from-file=ports.txt=./ports.txt
```

Или отредактировать и применить [`examples/scan-targets.secret.example.yaml`](network-scan-cli/examples/scan-targets.secret.example.yaml).

### 2. GHCR (если образ приватный)

```bash
kubectl create secret docker-registry ghcr-pull \
  -n network-scan \
  --docker-server=ghcr.io \
  --docker-username=<USER> \
  --docker-password=<TOKEN>

# Добавить в patch overlay:
# spec.template.spec.imagePullSecrets: [{ name: ghcr-pull }]
```

### 3. Применить манифесты

**Dev** (overlay-сеть, малые ресурсы):

```bash
kubectl apply -k k8s/network-scan-cli/overlays/dev
kubectl delete job network-scan -n network-scan --ignore-not-found
kubectl apply -k k8s/network-scan-cli/overlays/dev
```

**Prod** (hostNetwork на выделенных нодах):

```bash
# Ноды должны иметь label workload=scanner и taint scanner=true:NoSchedule
kubectl apply -k k8s/network-scan-cli/overlays/prod
```

### 4. Наблюдение

```bash
kubectl -n network-scan get jobs,pods,pvc
kubectl -n network-scan logs -f job/network-scan
```

### 5. Resume после сбоя

```bash
# Отредактировать run-id в job-resume.yaml при необходимости
kubectl apply -f k8s/network-scan-cli/base/job-resume.yaml
```

Артефакты: PVC `scanner-data` → `output/` и `state/` (subPath).

## Проверка манифестов локально

```bash
./k8s/scripts/validate-kustomize.sh
# или вручную:
kubectl kustomize k8s/network-scan-cli/overlays/dev
kubectl kustomize k8s/network-scan-cli/overlays/prod
```

## Связанные документы

- [План и риски](../plans/network-scan-cli-kubernetes.md)
- [AGENTS.md](../AGENTS.md) — для AI-агентов
- Исходный код сканера: https://github.com/onixus/Octo-man
