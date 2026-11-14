# Shapoclyack

Self-hosted платформа обнаружения внешней поверхности атаки и управления рисками уязвимостей (EASM · CAASM · RBVM).

[English](README.md) · [Документация](docs/README.md) · [Wiki](docs/wiki/README.md) · [Roadmap](ROADMAP.md) · [История изменений](CHANGELOG.md)

Документация описывает исходники `main` (`f01c2b6a`, после PR #644). Актуальный пререлиз — [`shapoclyack-0.49-1111-rc1`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.49-1111-rc1) от 2026-11-11, см. [заметки к пререлизу](docs/releases/0.49-1111-rc1.md) (предыдущий стабильный релиз — [`shapoclyack-0.48-1021`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.48-1021), [заметки](docs/releases/0.48-1021.md)). Для установки релиза сверяйтесь с документацией его тега и [границами версий](docs/README.md#version-scope).

## Возможности платформы

- **Активы и история:** находки, владельцы и история устранения привязаны к подтверждённой идентичности актива, включая L2-обнаружение и нативные периметровые наблюдения RDP X.224 (`octo.perimeter_observation.v1`). [Правила корреляции](docs/asset-identity.md).
- **Проверка устранения и кампании:** адрес и порт проверяются детекторами, которые нашли уязвимость, а однотипные проблемы объединяются в агрегированные проблемы и кампании устранения (`/api/problems`, `/api/remediation-campaigns`). Закрытый тикет сам по себе не подтверждает устранение. [Жизненный цикл и SLA](docs/vulnerability-lifecycle.md), [проблемы и кампании устранения](docs/remediation-campaigns.md).
- **Нативное зондирование Pulse v1.5.0:** 60+ неаутентифицированных read-only проверок на базе плагинов Rhai (фазы 1–9) для инфраструктурных, веб- и ICS/SCADA-сервисов (Modbus, EtherNet/IP, S7, SMB, NTP, DNS, Cassandra, MSSQL, Oracle TNS, RMI, EPMD, iSCSI, DRDA, GIOP) с поддержкой схемы отчётов Pulse v3 (и обратной совместимостью с v2). [Бэкенд Pulse](docs/pulse-backend.md).
- **Patch gaps и БДУ ФСТЭК:** пакеты сопоставляются с бюллетенями дистрибутивов с учётом бэкпортов, сборки Windows — с MSRC, а также выполняется маппинг угроз БДУ ФСТЭК России и формирование отчётности по 187-ФЗ. [Сопоставление ПО и CVE](docs/software-cve-matching.md), [сертификация и требования ФСТЭК](docs/fstec-certification.ru.md).
- **Риск с бизнес-контекстом:** вероятность и ущерб — отдельные оси; зрелость эксплойта задаёт ограничения вероятности. [Модель риска](docs/risk-scoring.md).
- **AI-оператор (опционально):** поддержка локальных моделей и внешних провайдеров (`local`, `xai`, `openrouter`, `omnirouter`, `openai_compatible`) со строгой проверкой публичных эндпоинтов и read-only MCP. [Архитектура AI-оператора](docs/local-operator.md), [провайдеры AI-оператора](docs/local-operator-providers.md).
- **Распределённое сканирование:** сенсоры получают задания по исходящим соединениям NATS JetStream или HTTPS. [Сетевые требования](docs/network-requirements.md).

Машинно подтверждённое закрытие требует доказательства, что каждый детектор повторил проверку. При недостаточном покрытии находка возвращается в `FIXING`. Закрытие недоступного порта как `endpoint_unreachable` сохраняет `machine_verified = false`. [Сквозной пример](docs/demo-remediation-loop.md).

## Быстрый старт

Выберите профиль. Команды ниже выполняются из корня проверенной копии проекта.

| Задача | Руководство | Требования |
|---|---|---|
| Один Linux-сервер, готовые образы | [Установка без сборки](docs/server-install.ru.md) | Python 3.9+, Docker Engine, Compose v2, HTTPS reverse proxy |
| Локальная оценка со сборкой | [Getting started](docs/getting-started.md) | Docker, kind, kubectl, OpenSSL, от 4 ГБ свободной RAM; доступ к релизам Pulse (`v1.5.0`) |
| Кластерное развёртывание | [Kubernetes / Kustomize](k8s/README.md), [Helm](docs/helm.md) | Кластер, registry, секреты и хранилища выбранного профиля |

Подготовка серверной установки и запуск:

```bash
sudo python3 scripts/install-server.py prepare --url https://scan.example.test
# Проверьте /opt/shapoclyack/compose.json, затем запустите установку:
sudo python3 scripts/install-server.py start
```

`prepare` создаёт конфигурацию и секреты без Docker. `start` скачивает образы, делает дамп PostgreSQL, выполняет миграции (включая `0097`–`0106` до головы схемы `0106_saml_session_binding`) и ждёт readiness; на это время API останавливается. Руководство описывает перенос одного файла установщика, настройку TLS, начальные учётные данные, резервирование и обновление.

Синхронизация вынесенных из образов плагинов Rhai для Pulse, базы угроз БДУ ФСТЭК и настройка L2-лимитов таблицы соседей:

```bash
./scripts/fetch-pulse-plugins.sh
python3 scripts/fetch-bdu-threats.py
sudo ./scripts/neigh-table-limits.sh
```

Локальный стенд:

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack
scripts/dev-up.sh
curl --fail --cacert .dev-tls/ca.crt https://127.0.0.1:8080/api/health
```

Добавьте `.dev-tls/ca.crt` в доверенные сертификаты браузера и откройте **https://127.0.0.1:8080**. Учётные записи стенда и первый скан описаны в [Getting started](docs/getting-started.md). Удаление стенда: `scripts/dev-down.sh`.

Сканируйте только разрешённую инфраструктуру. Свежая установка не выполняет сканы до утверждения области сканирования администратором тенанта.

## Документация и Wiki

| Задача | Источник |
|---|---|
| Ролевые сценарии, процессы ИБ и план внедрения на 12 недель | [Корпоративная Wiki](docs/wiki/README.md) |
| Архитектура и потоки данных | [Архитектура](docs/architecture.md) |
| Агрегированные проблемы и кампании устранения (`/api/problems`, `/api/remediation-campaigns`) | [Проблемы и кампании устранения](docs/remediation-campaigns.md) |
| Тенанты, RBAC, MFA, OIDC, SAML SLO (с привязкой сессий), SCIM и сервисные токены | [API и RBAC](docs/api-and-rbac.md) |
| Версии API, экспорт CSV/NDJSON и Python-клиент | [API v1 и SDK](docs/api-versioning.md) |
| Отчёты, комплаенс 187-ФЗ, маппинг угроз БДУ ФСТЭК и подписанные пакеты доказательств | [Отчёты](docs/reports-and-compliance.md), [пользовательский комплаенс](docs/custom-compliance.md), [ФСТЭК / БДУ](docs/fstec-certification.ru.md) |
| AI-оператор, локальный вывод, провайдеры `xai` / `openai_compatible` и MCP | [AI-оператор](docs/local-operator.md), [провайдеры AI-оператора](docs/local-operator-providers.md), [MCP](docs/mcp.md) |
| Консоль управления APEX (единые вкладки навигации, доска 1440px, тёмная/светлая темы) | [Web UI](docs/ui.md), [дизайн-система консоли](docs/console-design-system.md) |
| Сенсоры, агенты, плагины Pulse, мониторинг и резервирование | [Эксплуатация](docs/operations.md), [конфигурация](docs/configuration.md) |
| Статус поставки и оставшиеся работы | [Enterprise roadmap](ROADMAP.md#enterprise-readiness-review-epic-370) |
| Полный каталог руководств | [docs/README.md](docs/README.md) |

**Сенсор** запускает сканы (`agent/worker.py`, API-ресурс `agents`, `agent_kind = scanner`). **Агент** Lariska собирает инвентаризацию внутри хоста (`agent_kind = endpoint`) и не получает задания сканирования.

Исходники wiki и её sidebar проходят ревью в этом репозитории. Локальная подготовка страниц GitHub Wiki без публикации:

```bash
scripts/publish-wiki.sh --output /tmp/shapoclyack-wiki
```

Порядок сопровождения и публикации: [документация](docs/documentation-maintenance.md).

## Разработка и тестирование

Python 3.11/3.12, Node.js 26+. Установка зависимостей и проверки с PostgreSQL/NATS описаны в [руководстве разработчика](docs/development.md).

```bash
scripts/ci-lint.sh
python -m pytest tests/test_server_installer.py tests/test_agent_install_pins.py -q
```

Это проверки установщиков; полный CI требует отдельных тестовых PostgreSQL и NATS.

Карта каталогов находится в [английской версии README](README.md#repository-layout).

## Релизы и образы

Актуальный пререлиз: [shapoclyack-0.49-1111-rc1](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.49-1111-rc1) ([заметки](docs/releases/0.49-1111-rc1.md), Pulse `v1.5.0`, схема БД `0106_saml_session_binding`, миграции `0097`–`0106`). Предыдущий стабильный релиз: [shapoclyack-0.48-1021](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.48-1021) ([заметки](docs/releases/0.48-1021.md)). Полная история изменений — в [CHANGELOG.md](CHANGELOG.md).

| Образ | Содержимое |
|---|---|
| `ghcr.io/onixus/shapoclyack-aio` | API, Web UI и сканер (включает патч `nuclei` с `go-jose/v4` `v4.1.6` против CVE-2026-116587) |
| `ghcr.io/onixus/shapoclyack-api` | API и Web UI |
| `ghcr.io/onixus/shapoclyack-scanner` | Сканер и сенсор (`python -m agent`, включает патч `nuclei` с `go-jose/v4` `v4.1.6`) |

В production фиксируйте проверенный `tag@sha256:<digest>`. Значения по умолчанию в установщиках закреплены по digest (контрольные суммы бинарных сборок Pulse `v1.5.0` зафиксированы в `scripts/pulse-pinned.sha256`). [Контракт релиза](docs/release-contract.md) описывает проверку артефактов.

## Лицензия и безопасность

Проект распространяется под [Apache 2.0](LICENSE). Условия зависимостей — в [сторонних лицензиях](docs/third-party.md), порядок раскрытия уязвимостей и поддерживаемые версии — в [политике безопасности](.github/SECURITY.md).

Образы используют нативный движок Pulse (`v1.5.0`) и не содержат бинарных файлов Nmap или скриптов NSE (публикуются только три образа: `scanner`, `api`, `aio`; последний релиз с тегом `-nmap` — `0.47-1009-rc1`). Продукт больше не запускает Nmap: любая конфигурация с бэкендом Nmap или параметром `nmap_timing` отклоняется при загрузке, а плагины Rhai управляются отдельно от слоёв контейнера через `scripts/fetch-pulse-plugins.sh` в `service_probe.pulse.plugins_dir`. Что заменено, как читаются старые прогоны и какие разрывы остались — в [Migrating off Nmap](docs/nmap-migration.md) (на английском).
