# Shapoclyack

Репозиторий планов, **Kubernetes-манифестов** и эксплуатационной документации для проектов [onixus](https://github.com/onixus).  
Исходный код приложений здесь **не хранится**.

## Для AI-агентов

См. **[AGENTS.md](AGENTS.md)**:

- исходники сканера — в [Octo-man](https://github.com/onixus/Octo-man);
- **манифесты K8s и все доработки под Kubernetes — в Shapoclyack** (`k8s/`).

## Kubernetes

| Ресурс | Описание |
|--------|----------|
| [k8s/README.md](k8s/README.md) | Runbook: деплой, resume, secret |
| [k8s/network-scan-cli/](k8s/network-scan-cli/) | Kustomize: base + overlays `dev` / `prod` |

```bash
kubectl apply -k k8s/network-scan-cli/overlays/dev   # тест
kubectl apply -k k8s/network-scan-cli/overlays/prod  # hostNetwork + scanner nodes
```

## Планы

| План | Описание |
|------|----------|
| [network-scan-cli-kubernetes.md](plans/network-scan-cli-kubernetes.md) | Архитектура, риски, roadmap |

## Связанные репозитории

| Проект | GitHub | Назначение |
|--------|--------|------------|
| Octo-man (Network Scan CLI) | https://github.com/onixus/Octo-man | Исходный код, Docker-образ, CI образа |
| Shapoclyack | https://github.com/onixus/Shapoclyack | K8s-манифесты, планы (этот репо) |
