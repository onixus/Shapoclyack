# Shapoclyack

Shapoclyack — self-hosted платформа для обнаружения внешней поверхности атаки,
инвентаризации активов и управления уязвимостями. В одном проекте объединены
сетевой сканер, FastAPI control plane, распределённые агенты, аналитика и
операторский Web UI на Next.js.

[English](README.md) · [Карта документации](docs/README.md) ·
[Kubernetes](k8s/README.md) · [Changelog](CHANGELOG.md) ·
[Roadmap](ROADMAP.md) · [Security](.github/SECURITY.md)

> Используйте платформу только для систем, владельцем которых вы являетесь или
> на тестирование которых у вас есть явное разрешение.

## Возможности

| Область | Что реализовано |
|---|---|
| Discovery | CIDR/IP/FQDN, DNS, CT-логи, ASN, облачные ресурсы, мониторинг доменов |
| Сканирование | TCP/UDP, сервисы и ОС, NSE, Nuclei |
| Обогащение | CVSS v4, EPSS, CISA KEV, GeoIP, ASN, TLS posture, fingerprinting |
| Инвентарь | Активы между прогонами, идентификаторы, владелец, критичность, lifecycle, ПО endpoints |
| Эксплуатация | Jobs, schedules, diff, alerts, reports, remote agents, resume |
| Платформа | JWT RBAC, multi-tenancy, PostgreSQL, ClickHouse, NATS JetStream |
| Развёртывание | Docker Compose all-in-one или Kubernetes/Kustomize |

Конвейер сканирования:

```text
цели → resolve → discovery → hostnames → ports → NSE/Nuclei → enrich → report
```

## Быстрый старт

Требуются Docker с Compose plugin и не менее 4 ГБ свободной памяти.

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack
docker compose up --build
```

Откройте <http://localhost:8080>:

```text
operator / operator-change-me
```

Перед публикацией сервиса за пределами тестового контура замените demo-пароли и
JWT secret. Для постоянного хранения tenants и asset inventory подключите
PostgreSQL:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.postgres.yml \
  --profile postgres \
  up --build
```

Для распределённых агентов и аналитики добавьте NATS и ClickHouse:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.postgres.yml \
  -f docker-compose.nats.yml \
  -f docker-compose.clickhouse.yml \
  --profile postgres \
  --profile nats \
  --profile clickhouse \
  up --build
```

Подготовка целей, выбор профиля и проверка первого прогона описаны в
[Getting started](docs/getting-started.md).

## Интерфейс

Web UI включает:

- дашборд текущей экспозиции и исторический trend;
- постоянный инвентарь и карточку актива;
- граф поверхности атаки;
- jobs, runs, findings и отчёты;
- tenants и парк удалённых агентов;
- статус компонентов и безопасные overrides конфигурации.

Актуальные снимки и воспроизводимая процедура их обновления находятся в
[docs/ui.md](docs/ui.md).

## Что читать дальше

| Задача | Документ |
|---|---|
| Установка и первый скан | [Getting started](docs/getting-started.md) |
| Архитектура и потоки данных | [Architecture](docs/architecture.md) |
| Профили и параметры | [Configuration](docs/configuration.md) |
| API, JWT и роли | [API and RBAC](docs/api-and-rbac.md) |
| Эксплуатация, resume, артефакты | [Operations](docs/operations.md) |
| Kubernetes | [k8s/README.md](k8s/README.md) |
| Разработка и тесты | [Development](docs/development.md) |
| Диагностика | [Troubleshooting](docs/troubleshooting.md) |

## Структура репозитория

| Путь | Назначение |
|---|---|
| `scanner/` | Discovery, сканирование, enrichment, diff и отчёты |
| `api/` | FastAPI, auth, БД, scheduling и ingest |
| `agent/` | Удалённый worker для выполнения jobs |
| `web-next/` | Next.js 14 Web UI со static export |
| `recon/` | Основа Go-worker для discovery |
| `k8s/octo-man/` | Kubernetes base, overlays и examples |
| `bench/` | Локальный benchmark discovery |
| `tests/` | Unit, integration, load и e2e тесты |

## Релиз и образы

Документация привязана к релизу
[`shapoclyack-0.36-0723`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.36-0723).

| Образ | Роль |
|---|---|
| `ghcr.io/onixus/shapoclyack-aio` | API, Web UI и scanner |
| `ghcr.io/onixus/shapoclyack-api` | API и Web UI |
| `ghcr.io/onixus/shapoclyack-scanner` | Scanner и agent runtime |

В production фиксируйте release tag и не используйте `latest`.

## Безопасность

Правила disclosure, поддерживаемые версии и рекомендации по hardening:
[`.github/SECURITY.md`](.github/SECURITY.md). Лицензии встроенных компонентов:
[docs/third-party.md](docs/third-party.md).
