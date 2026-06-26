# Пометки для AI-агента

Этот репозиторий (**Shapoclyack**) — планы, архитектура, **Kubernetes-манифесты** и эксплуатационная документация для проектов onixus.  
Исходный код приложений здесь **не хранится**.

## Разделение ответственности

| Что | Где |
|-----|-----|
| Python-код сканера, Dockerfile, docker-compose, unit/e2e в Docker | **Octo-man** |
| K8s-манифесты, k8s-конфиг, overlays, runbook, k8s CI | **Shapoclyack** (этот репо) |
| Планы и ADR | **Shapoclyack** → `plans/` |

**Не добавлять** `k8s/` и Kubernetes-конфиги в Octo-man — они живут только здесь.

---

## Исходный проект: Network Scan CLI (Octo-man)

| Что | Где |
|-----|-----|
| **GitHub (исходники)** | https://github.com/onixus/Octo-man |
| **Локальный клон** | `/Users/onixus/Git/network-scan-cli` |
| **Имя каталога на диске** | `network-scan-cli` (≠ имя репозитория на GitHub) |
| **Контейнерный образ (GHCR)** | `ghcr.io/onixus/octo-man` |
| **Docker-эталон запуска** | `docker-compose.yml` в Octo-man |

### Ключевые пути в Octo-man (только для чтения / ссылок)

```
network-scan-cli/                 # локальный клон Octo-man
├── scanner/                      # Python-пайплайн
├── Dockerfile                    # образ для K8s Job
├── docker-compose.yml            # эталон capabilities и volumes
└── tests/e2e/, tests/load/       # тесты в docker-сети
```

---

## Kubernetes-артефакты в Shapoclyack

| Что | Путь |
|-----|------|
| Runbook | [`k8s/README.md`](k8s/README.md) |
| Манифесты (Kustomize) | [`k8s/network-scan-cli/`](k8s/network-scan-cli/) |
| Конфиг сканера для кластера | [`k8s/network-scan-cli/base/config/k8s.yaml`](k8s/network-scan-cli/base/config/k8s.yaml) |
| План и риски | [`plans/network-scan-cli-kubernetes.md`](plans/network-scan-cli-kubernetes.md) |

```
Shapoclyack/
├── k8s/network-scan-cli/
│   ├── base/config/k8s.yaml
│   ├── base/                   # Job, CronJob, PVC, namespace
│   ├── overlays/dev/
│   ├── overlays/prod/
│   └── examples/
├── plans/
└── .github/workflows/          # k8s-валидация / e2e (если есть)
```

---

## Что делать агенту

1. **Манифесты, overlays, k8s.yaml, NetworkPolicy, k8s CI** — править в **Shapoclyack**.
2. **Код сканера, Dockerfile, pytest, docker e2e** — править в **Octo-man** (`network-scan-cli`).
3. При изменении CLI-флагов или путей в образе — обновить манифесты **здесь**, сверяясь с `scanner/main.py` в Octo-man.
4. Образ всегда тянуть из GHCR: `ghcr.io/onixus/octo-man` (сборка — в Octo-man CI).
5. Доработки **только для удобства K8s** (например, логи в stdout) — по согласованию: код в Octo-man, манифесты/доки здесь.

### Связанные документы

- [`plans/network-scan-cli-kubernetes.md`](plans/network-scan-cli-kubernetes.md) — архитектура, риски, roadmap
- [`k8s/README.md`](k8s/README.md) — как деплоить
