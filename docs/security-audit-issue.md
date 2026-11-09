# Security Audit: что в заметке было неверно (3 Issues)

> Разбор заметки против `main` на `5ee0ad1`. Ниже не план «внедрить исходные
> критерии приёмки»: часть из них описывает код, которого нет, или чинит не ту
> ветку. Для каждого пункта — что в коде уже есть и какой остаток настоящий.

---

## Issue #1 — [HIGH] `verify=False` при HTTPS-подтверждении subdomain takeover

**Компонент:** `scanner/pipeline/takeover.py`
**Место:** `_confirm_all`, клиент с `verify=False` (около строки 430)

`verify=False` в коде есть, и docstring модуля (строки 30–38) прямо говорит,
зачем: у незанятого имени у провайдера нет сертификата на это имя. MITM на
этом запросе может подменить тело и сдвинуть вердикт в любую сторону. Это
реальный зазор.

**Что в рекомендации неверно.** Продолжать проверку только при
`CERTIFICATE_UNKNOWN` / unknown-ca и помечать hostname mismatch как
inconclusive — это наоборот.

Обычный ответ провайдера на чужое имя — сертификат публичного CA на *своё*
имя. OpenSSL в этом случае отвечает `CERTIFICATE_VERIFY_FAILED` с
`Hostname mismatch`, а не unknown-ca. Если считать mismatch inconclusive,
стадия перестаёт видеть как раз ту страницу, ради которой HTTPS-запрос
существует. unknown-ca как раз не отличает провайдера с частным CA от MITM,
и по нему нельзя принимать «vulnerable».

**Что делать, если HTTPS-подтверждение остаётся.**

1. Проверять цепочку по системному trust store.
2. Не требовать, чтобы имя в сертификате совпало с именем жертвы. Совпадение
   цепочки с публичным CA и чужое имя — это сертификат провайдера; тело такого
   ответа можно сверять с отпечатком.
3. Цепочка, которая не сошлась (unknown-ca, обрыв handshake), не даёт
   вердикт vulnerable по HTTPS-телу. Остаются DNS NXDOMAIN и ответ на порту 80.
4. Не оставлять unconditional `verify=False` и не помечать непроверенное тело
   флагом `tls_verified: false`, если этот флаг всё ещё кормит положительный
   finding.

**Критерий приёмки:** положительный takeover по HTTPS берётся только из тела,
полученного при проверке цепочки; hostname mismatch при доверенной цепочке
по-прежнему доходит до сверки отпечатка; unknown-ca и обрыв handshake сами по
себе не дают `vulnerable`.

---

## Issue #2 — [HIGH] Прод уже отказывается стартовать; дыра — пароль бэкапа ClickHouse

**Компоненты:** `api/settings.py`, `charts/shapoclyack/templates/validate.yaml`,
`k8s/shapoclyack/base/kustomization.yaml`

Исходная заметка описывает отсутствие проверок, которые уже стоят в
`_validate_production` (не `_strict_problems`). `OCTO_ENV` по умолчанию
`prod` (`_resolve_env`). При `OCTO_ENV=prod` старт бросает
`InsecureConfigurationError`, если:

- `OCTO_POSTGRES_URL` пуст (тогда подставляется локальный SQLite) или явно
  указывает на SQLite;
- `OCTO_JWT_SECRET` пуст или равен `DEFAULT_JWT_SECRET`
  (`shapoclyack-dev-secret-change-me`), в том числе когда этот литерал лежит
  в `OCTO_JWT_SECRET_PREVIOUS`;
- `OCTO_POSTGRES_URL`, `OCTO_CLICKHOUSE_URL` или `OCTO_NATS_URL` содержат
  литерал из `DEFAULT_DATA_PLANE_SECRETS`;
- в CORS есть `*` (см. Issue #3).

Оверлей `prod-ha` не рендерит sqlite URL: workload'ы ссылаются на Secret через
`secretKeyRef`.

Helm уже отказывает в рендере. `templates/validate.yaml` вызывает `fail`,
если пусты `existingSecrets.api`, `postgres`, `clickhouse`, `clickhouseBackup`
или `nats`, и при этом не включены `devPlaceholders` и
`externalSecrets.enabled`. Ключ JWT — `existingSecrets.api` (в Secret поле
`jwt_secret`), а не `existingSecrets.jwt`. `devPlaceholders=true` — явный
путь для одноразового стенда; API при этом всё равно требует `OCTO_ENV=dev`,
иначе `_validate_production` не пустит те же плейсхолдеры.

**Настоящий остаток.** Пароль `shapoclyack-dev-clickhouse-backup-change-me`
(литерал в `k8s/shapoclyack/base/kustomization.yaml` и в Secret чарта
`shapoclyack-clickhouse-backup`) не входит в `DEFAULT_DATA_PLANE_SECRETS`.
Его и некуда подставить в эту проверку: `_shipped_data_plane_secrets` смотрит
только три URL, а пароль бэкапа живёт в CronJob и в API не приходит. Прод-API
может стартовать, пока бэкап ClickHouse всё ещё на опубликованном пароле.

**Что делать.**

1. Ловить этот литерал в рендере прод-оверлея и чарта (kustomize/helm), а не
   описывать `_validate_production` как отсутствующую.
2. Не переименовывать ключ в `existingSecrets.jwt` и не заставлять
   `required` ронять `devPlaceholders=true`: этот флаг и есть документированный
   выход для стенда, а прод закрывает API отдельно.

**Критерий приёмки:** рендер `prod-ha` и helm template без
`devPlaceholders` не содержат `shapoclyack-dev-clickhouse-backup-change-me`.
Пустой `existingSecrets.api` по-прежнему валит рендер. `devPlaceholders=true`
по-прежнему рендерится и по-прежнему не стартует API при `OCTO_ENV=prod`.

---

## Issue #3 — [MEDIUM] Wildcard CORS в проде уже отказ старта, не 403

**Компонент:** `api/settings.py` (`load_settings`), проверка в
`_validate_production`

Незаданная, пустая и `"*"` переменная `OCTO_API_CORS` становятся
`cors_origins=["*"]` (дефолт аргумента `os.environ.get` и ветка `or ["*"]`,
плюс дефолт поля `Settings`). Это так.

Дальше заметка расходится с кодом.

- Отказ делает `_validate_production` (~1744), не `_strict_problems`. Любой
  список, в котором есть `"*"`, при `OCTO_ENV=prod` не даёт процессу
  стартовать. Wildcard достижим только при `OCTO_ENV=dev`.
- `CORSMiddleware` в `api/app.py` создаётся с `allow_credentials=True`.
  Starlette на preflight с origin вне списка отвечает **400**, не 403.

Менять дефолт на пустой список — отдельное ужесточение dev-стенда, а не
закрытие прода. Прод это состояние и так не запускает.

**Критерий приёмки, если дефолт всё же меняют:** процесс с `OCTO_ENV=prod` и
`OCTO_API_CORS=*` по-прежнему не стартует; dev-compose, которому нужен
wildcard, задаёт его явно; чужой credentialed preflight получает 400.
Критерий «403 на preflight» этому стеку не соответствует.

---

## Сводка

| # | Что было в заметке | Что в коде |
|---|---|---|
| 1 | mismatch = inconclusive, продолжать только unknown-ca | mismatch — нормальный сертификат провайдера; unknown-ca не доказательство |
| 2 | нет проверки SQLite, JWT и Helm-секретов; ключ `existingSecrets.jwt` | `_validate_production` и `validate.yaml` это уже закрывают; ключ — `existingSecrets.api`; не закрыт пароль бэкапа ClickHouse |
| 3 | дефолт `*` надо убрать, иначе прод открыт; preflight 403 | прод с `*` не стартует; preflight вне списка — 400 |

Порядок, если брать остаток: пароль бэкапа ClickHouse, затем дизайн HTTPS-
подтверждения takeover (цепочка да, имя жертвы нет). Смена дефолта CORS прода
не закрывает.
