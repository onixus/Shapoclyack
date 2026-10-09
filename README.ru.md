# Shapoclyack

Self-hosted платформа обнаружения внешней поверхности атаки и управления рисками уязвимостей (EASM · CAASM · RBVM).

[English](README.md) · [Документация](docs/README.md) · [Wiki](docs/wiki/README.md) · [Roadmap](ROADMAP.md) · [История изменений](CHANGELOG.md)

Документация описывает исходники `main`, включая изменения после релиза
`shapoclyack-0.46-0922`. Для установки релиза сверяйтесь с документацией его
тега и [границами версий](docs/README.md#version-scope). Для подготовленного
кандидата см. [заметки 0.47-1009-rc1](docs/releases/0.47-1009-rc1.md).

## Возможности платформы

- **Активы и история:** находки, владельцы и история устранения привязаны к подтверждённой идентичности актива. [Правила корреляции](docs/asset-identity.md).
- **Проверка устранения:** адрес и порт проверяются детекторами, которые нашли уязвимость. Закрытый тикет сам по себе не подтверждает устранение. [Жизненный цикл и SLA](docs/vulnerability-lifecycle.md).
- **Patch gaps:** пакеты сопоставляются с бюллетенями дистрибутивов с учётом бэкпортов, сборки Windows — с MSRC. [Сопоставление ПО и CVE](docs/software-cve-matching.md).
- **Риск с бизнес-контекстом:** вероятность и ущерб — отдельные оси; зрелость эксплойта задаёт ограничения вероятности. [Модель риска](docs/risk-scoring.md).
- **Распределённое сканирование:** сенсоры получают задания по исходящим соединениям NATS JetStream или HTTPS. [Сетевые требования](docs/network-requirements.md).

Машинно подтверждённое закрытие требует доказательства, что каждый детектор
повторил проверку. При недостаточном покрытии находка возвращается в `FIXING`.
Закрытие недоступного порта как `endpoint_unreachable` сохраняет
`machine_verified = false`. [Сквозной пример](docs/demo-remediation-loop.md).

## Быстрый старт

Выберите профиль. Команды ниже выполняются из корня проверенной копии проекта.

| Задача | Руководство | Требования |
|---|---|---|
| Один Linux-сервер, готовые образы | [Установка без сборки](docs/server-install.ru.md) | Python 3.9+, Docker Engine, Compose v2, HTTPS reverse proxy |
| Локальная оценка со сборкой | [Getting started](docs/getting-started.md) | Docker, kind, kubectl, OpenSSL, от 4 ГБ свободной RAM; доступ к релизам Pulse |
| Кластерное развёртывание | [Kubernetes / Kustomize](k8s/README.md) | Кластер, registry, секреты и хранилища выбранного профиля |

Подготовка серверной установки и запуск:

```bash
sudo python3 scripts/install-server.py prepare --url https://scan.example.test
# Проверьте /opt/shapoclyack/compose.json, затем запустите установку:
sudo python3 scripts/install-server.py start
```

`prepare` создаёт конфигурацию и секреты без Docker. `start` скачивает образы,
делает дамп PostgreSQL, выполняет миграции и ждёт readiness; на это время API
останавливается. Руководство описывает перенос одного файла установщика,
настройку TLS, начальные учётные данные, резервирование и обновление.

Локальный стенд:

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack
scripts/dev-up.sh
curl --fail --cacert .dev-tls/ca.crt https://127.0.0.1:8080/api/health
```

Добавьте `.dev-tls/ca.crt` в доверенные сертификаты браузера и откройте
**https://127.0.0.1:8080**. Учётные записи стенда и первый скан описаны в
[Getting started](docs/getting-started.md). Удаление стенда: `scripts/dev-down.sh`.

Сканируйте только разрешённую инфраструктуру. Свежая установка не выполняет
сканы до утверждения области сканирования администратором тенанта.

## Документация и Wiki

| Задача | Источник |
|---|---|
| Ролевые сценарии, процессы ИБ и план внедрения на 12 недель | [Корпоративная Wiki](docs/wiki/README.md) |
| Архитектура и потоки данных | [Архитектура](docs/architecture.md) |
| Тенанты, RBAC, MFA, OIDC, SCIM и сервисные токены | [API и RBAC](docs/api-and-rbac.md) |
| Отчёты, комплаенс и подписанные пакеты доказательств | [Отчёты](docs/reports-and-compliance.md), [пользовательский комплаенс](docs/custom-compliance.md) |
| Текущие экраны и рабочие процессы | [Web UI](docs/ui.md) |
| Сенсоры, агенты, мониторинг и резервирование | [Эксплуатация](docs/operations.md) |
| Статус поставки и оставшиеся работы | [Enterprise roadmap](ROADMAP.md#enterprise-readiness-review-epic-370) |
| Полный каталог руководств | [docs/README.md](docs/README.md) |

**Сенсор** запускает сканы (`agent/worker.py`, API-ресурс `agents`,
`agent_kind = scanner`). **Агент** Lariska собирает инвентаризацию внутри хоста
(`agent_kind = endpoint`) и не получает задания сканирования.

Исходники wiki и её sidebar проходят ревью в этом репозитории. Локальная
подготовка страниц GitHub Wiki без публикации:

```bash
scripts/publish-wiki.sh --output /tmp/shapoclyack-wiki
```

Порядок сопровождения и публикации: [документация](docs/documentation-maintenance.md).

## Разработка и тестирование

Python 3.11/3.12, Node.js 26+. Установка зависимостей и проверки с PostgreSQL/NATS
описаны в [руководстве разработчика](docs/development.md).

```bash
scripts/ci-lint.sh
python -m pytest tests/test_server_installer.py tests/test_agent_install_pins.py -q
```

Это проверки установщиков; полный CI требует отдельных тестовых PostgreSQL и NATS.
Карта каталогов находится в [английской версии README](README.md#repository-layout).

## Релизы и образы

Документированный релиз: [shapoclyack-0.46-0922](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.46-0922).
Изменения исходников после него — в `Unreleased` [CHANGELOG.md](CHANGELOG.md).

| Образ | Содержимое |
|---|---|
| `ghcr.io/onixus/shapoclyack-aio` | API, Web UI и сканер |
| `ghcr.io/onixus/shapoclyack-api` | API и Web UI |
| `ghcr.io/onixus/shapoclyack-scanner` | Сканер и сенсор (`python -m agent`) |

В production фиксируйте проверенный `tag@sha256:<digest>`. Значения по умолчанию
в установщиках закреплены по digest. [Контракт релиза](docs/release-contract.md)
описывает проверку артефактов.

## Лицензия и безопасность

Проект распространяется под [Apache 2.0](LICENSE). Условия зависимостей — в
[сторонних лицензиях](docs/third-party.md), порядок раскрытия уязвимостей и
поддерживаемые версии — в [политике безопасности](.github/SECURITY.md).

Образы используют Pulse и не содержат Nmap/NSE (последний релиз с тегом
`-nmap` — `0.47-1009-rc1`). Nmap подпадает под NPSL; если он нужен, установите
свой рядом с сенсором: [Using your own Nmap](docs/nmap-external.md) (на английском).
