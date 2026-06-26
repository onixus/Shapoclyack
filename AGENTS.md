# Пометки для AI-агента

Этот репозиторий (**Shapoclyack**) — хранилище планов, архитектурных решений и контекста для проектов onixus.  
Здесь **нет исходного кода** приложений; код живёт в отдельных репозиториях.

## Исходный проект: Network Scan CLI (Octo-man)

| Что | Где |
|-----|-----|
| **GitHub (канонический remote)** | https://github.com/onixus/Octo-man |
| **Локальный клон (рабочая копия)** | `/Users/onixus/Git/network-scan-cli` |
| **Имя каталога на диске** | `network-scan-cli` (папка ≠ имя репозитория на GitHub) |
| **Контейнерный образ (GHCR)** | `ghcr.io/onixus/octo-man` |
| **Основной README** | https://github.com/onixus/Octo-man/blob/master/README.md |
| **Русская документация** | https://github.com/onixus/Octo-man/blob/master/README.ru.md |

### Ключевые пути в исходниках

```
network-scan-cli/
├── scanner/                    # Python-пакет пайплайна
│   ├── main.py                 # entrypoint: python -m scanner.main
│   ├── config/default.yaml     # конфиг по умолчанию
│   └── pipeline/               # этапы: resolve, discover, ports, nse, report
├── Dockerfile                  # образ с nmap, naabu, dnsx, setcap NET_RAW
├── docker-compose.yml          # эталон запуска (capabilities, limits, volumes)
├── bench/                      # локальный бенчмарк discovery в docker
└── tests/e2e/, tests/load/     # e2e и нагрузочные тесты в docker-сети
```

### Что делать агенту

1. **Планы и ADR** — хранить и править **здесь**, в `Shapoclyack/plans/`.
2. **Код сканера, Dockerfile, k8s-манифесты** — реализовывать в **Octo-man** (`network-scan-cli`), не в Shapoclyack.
3. При ссылке на «исходный проект» / «сканер» — иметь в виду **Octo-man**, не Shapoclyack.
4. Актуальный план миграции в Kubernetes: [`plans/network-scan-cli-kubernetes.md`](plans/network-scan-cli-kubernetes.md).

### Связанные планы в этом репозитории

- [`plans/network-scan-cli-kubernetes.md`](plans/network-scan-cli-kubernetes.md) — развёртывание сканера в Kubernetes
