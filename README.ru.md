# Shapoclyack

**Self-hosted платформа обнаружения внешней поверхности атаки и управления уязвимостями.**

[![Release](https://img.shields.io/github/v/release/onixus/Shapoclyack?label=release&color=2b7489)](https://github.com/onixus/Shapoclyack/releases/latest)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://github.com/onixus/Shapoclyack/blob/main/requirements.txt)
[![Deploy](https://img.shields.io/badge/deploy-Kubernetes%20%2F%20Kustomize-326ce5)](k8s/README.md)
[![Images](https://img.shields.io/badge/images-ghcr.io-181717)](https://github.com/onixus?tab=packages&repo_name=Shapoclyack)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

Сетевой сканер со стадийным конвейером, FastAPI control plane, распределённые
агенты, инвентарь активов, переживающий отдельные прогоны, обогащение и
аналитика, операторская консоль на Next.js — разворачивается как одно
Kubernetes-приложение или как единый all-in-one контейнер.

**[English](README.md)** · [Быстрый старт](docs/getting-started.md) ·
[Карта документации](docs/README.md) · [Kubernetes](k8s/README.md) ·
[Changelog](CHANGELOG.md) · [Roadmap](ROADMAP.md) ·
[Security](.github/SECURITY.md)

> [!WARNING]
> Сканирование затрагивает чужие машины. Используйте платформу только для
> систем, владельцем которых вы являетесь или на тестирование которых у вас
> есть явное разрешение. Свежая установка намеренно не сканирует ничего, пока
> админ не одобрит область сканирования для тенанта.

## Возможности

| Область | Что реализовано |
|---|---|
| Discovery | CIDR/IP/FQDN, DNS, CT-логи, ASN, облачные ресурсы, мониторинг доменов |
| Сканирование | TCP/UDP, сервисы и ОС, NSE, Nuclei |
| Обогащение | CVSS v4, EPSS, CISA KEV, GeoIP, ASN, TLS posture, fingerprinting |
| Инвентарь | Активы между прогонами, идентификаторы, владелец, критичность, lifecycle, ПО endpoints |
| Управление уязвимостями | Отслеживаемые находки со статусами, SLA и исключениями; риск по NIST SP 800-30; доска ремедиации с механической верификацией и двусторонней синхронизацией тикетов |
| Патчинг endpoints | Установленное ПО сопоставляется с advisories вендоров и группируется в patch gap по пакету — с командой обновления |
| Отчётность | Брендированная фабрика отчётов на тенант (executive, technical, compliance) в PDF, HTML или JSON, с доставкой по расписанию |
| Compliance | Статус контролей PCI DSS 4.0, CIS Controls v8 и ISO/IEC 27001:2022 по данным самого тенанта |
| Adoption | Метрики результата по тенанту — подтверждённые закрытия, соблюдение SLA, время до исправления, покрытие владельцами и сканами, время до первой ценности, возраст overlay-данных обогащения |
| Эксплуатация | Jobs, schedules, diff, alerts, reports, remote agents, resume |
| Платформа | JWT RBAC, OIDC SSO, service tokens, multi-tenancy, PostgreSQL, ClickHouse, NATS JetStream |
| Развёртывание | Kubernetes/Kustomize (kind для локальной разработки) |

Конвейер сканирования:

```text
цели → resolve → discovery → hostnames → ports → NSE/Nuclei → enrich → report
```

## Быстрый старт

Требуются Docker (для сборки/загрузки образов), [kind](https://kind.sigs.k8s.io/)
и `kubectl`, не менее 4 ГБ свободной памяти.

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack
scripts/dev-up.sh
```

Скрипт поднимает локальный кластер kind, собирает all-in-one образ, загружает
его в кластер и применяет `k8s/shapoclyack/overlays/kind-dev` (API, PostgreSQL,
NATS, ClickHouse, Job/CronJob сканера).

Откройте <http://127.0.0.1:8080>:

```text
operator / operator-change-me
```

Используйте `127.0.0.1`, а не `localhost`: kind публикует NodePort только по
IPv4, а на macOS `localhost` сначала резолвится в `::1`, и соединение
отвергается.

Свежая установка не сканирует ничего, пока администратор не утвердит область
сканирования для тенанта — см. [шаг 6 в Getting started](docs/getting-started.md#6-approve-a-scanning-scope).

Перед публикацией сервиса за пределами тестового контура замените demo-пароли и
JWT secret (`k8s/shapoclyack/examples/api-secrets.example.yaml`).

Остановить кластер:

```bash
scripts/dev-down.sh
```

Подготовка целей, выбор профиля и проверка первого прогона описаны в
[Getting started](docs/getting-started.md).

## Интерфейс

Web UI включает:

- обзор риска, дашборд экспозиции и исторический trend;
- центр уязвимостей и доску ремедиации;
- постоянный инвентарь и карточку актива;
- инвентарь endpoints, сопоставление ПО с CVE и patch gaps;
- граф поверхности атаки и карту гео;
- jobs, runs, findings, отчёты и фабрику отчётов;
- статус compliance по выбранному фреймворку;
- метрики adoption: находки закрываются и проверяются — или только производятся;
- tenants и парк удалённых агентов;
- wordlists, service tokens, статус компонентов и безопасные overrides
  конфигурации.

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
| Отчёты и compliance | [Reports and compliance](docs/reports-and-compliance.md) |
| Жизненный цикл уязвимости | [Vulnerability lifecycle](docs/vulnerability-lifecycle.md) |
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
| `k8s/shapoclyack/` | Kubernetes base, overlays и examples |
| `bench/` | Локальный benchmark discovery |
| `tests/` | Unit, integration, load и e2e тесты |

## Релиз и образы

Документация привязана к релизу
[`shapoclyack-0.43-0828`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.43-0828).

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
