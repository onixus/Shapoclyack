# Модуль «Профиль организации» (org_profile)

Проектный документ. Описывает **планируемое** поведение; ничего из этого ещё не
реализовано. Соглашения по языку: файл на русском по образцу `README.ru.md`;
при переводе в официальную документацию — английская версия в `docs/`.

## Задача

По одному входному домену:

1. определить **владельца** (организацию-регистранта и связанные идентификаторы);
2. найти **совместные домены** — остальные домены той же организации;
3. прогнать по ним **скан**;
4. выдать **краткую сводку состояния** в виде матрицы контролей:

| Контроль | Статус | Влияние |
| --- | --- | --- |
| DNS структура | требуется проверка | среднее |
| TLS сертификаты | требуется проверка | среднее |
| Почтовая защита | требуется проверка | высокое |
| Технологии сайта | требуется проверка | среднее |
| Открытые сервисы | требуется проверка | высокое |
| Утечки учетных данных | требуется проверка | критическое |

## Что уже есть в репозитории

Модуль не строится с нуля — три из шести контролей уже покрыты работающими
стадиями, и переиспользование обязательно (дублирование HTTP/DNS-клиентов по
хостам прямо запрещено докстрингом `fingerprint.py`).

| Контроль | Источник данных | Состояние |
| --- | --- | --- |
| TLS сертификаты | `scanner/pipeline/tls_posture.py` (+ `cert_names.py`, `tls_probe.py`) | **есть**, нужен только маппинг в контроль |
| Технологии сайта | `scanner/pipeline/fingerprint.py` (CDN/WAF/CMS) | **есть**, покрытие сигнатур сознательно неполное |
| Открытые сервисы | `ports.py` → `pulse_probe.py` / `nse.py` → `nuclei_scan.py` | **есть** |
| DNS структура | `resolve.py`, `hostnames.py`, `domain_monitor.py` (typosquat + dangling CNAME) | **частично** — нет гигиены зоны (NS/SOA/CAA/DNSSEC/AXFR/wildcard) |
| Почтовая защита | только `alerts.py::check_dkim_record` — самопроверка отправителя, не аудит цели | **нет** |
| Утечки учётных данных | — | **нет** |
| Владелец | `asn_discovery.py` (RIPEstat: ASN и префиксы), `cloudflare` импорт зон | **частично** — нет RDAP-регистранта домена |
| Совместные домены | `hostnames.py` (CT по домену), `cert_names.py` (SAN) | **частично** — нет атрибуции по организации |

Переиспользуемая инфраструктура: стадии/чекпойнты (`main.py::_run_stage`,
`checkpoint.py`), тайминги (`stage_timing.py`), конфиг на pydantic
(`config_schema.py`), артефакты в `output_dir`, выдача через
`GET /runs/{id}/artifacts/...`, ClickHouse-ингест (`ch_transform.py`),
интенты сканирования (`api/services/scan_intents.py`), риск-модель
NIST SP 800-30 (`api/services/nist_risk.py`).

## Архитектура

Модуль — это **набор стадий существующего пайплайна плюс агрегатор**, а не
отдельный сервис. Работает внутри обычного run'а, пишет обычные артефакты,
ходит через обычный `jobs`/`runs` API.

```text
seed domain
   ├─ owner        → ownership.json          (RDAP домена/IP, ASN-org, cert O)
   ├─ related      → related_domains.json    (кандидаты + evidence + confidence)
   │                    └─ (по умолчанию НЕ расширяет scope — см. «Граница»)
   ├─ dns_hygiene  → dns_hygiene.json        (NS/SOA/CAA/DNSSEC/wildcard/AXFR)
   ├─ mail_posture → mail_posture.json       (MX/SPF/DMARC/DKIM/MTA-STS/TLS-RPT)
   ├─ [существующий пайплайн: resolve → discovery → ports → probe → nuclei
   │   → tls_posture → fingerprint]
   ├─ leaks        → credential_leaks.json   (провайдерный плагин, off by default)
   └─ controls     → controls.json + раздел в summary.md/summary.json
```

Порядок в `main.py::_run_pipeline_body`: `owner` и `related` — рядом с `ct`/`asn`
(до `resolve`, т.к. могут влиять на scope); `dns_hygiene`/`mail_posture` — после
`resolve` (как `domain_monitor`, чтобы видеть финальный список FQDN);
`controls` — последним, после `report`, т.к. читает артефакты всех остальных.

### Новые файлы

| Путь | Роль |
| --- | --- |
| `scanner/pipeline/ownership.py` | RDAP домена + IP/ASN, сбор идентификаторов владельца |
| `scanner/pipeline/related_domains.py` | поиск совместных доменов, оценка уверенности |
| `scanner/pipeline/dns_hygiene.py` | контроль «DNS структура» |
| `scanner/pipeline/mail_posture.py` | контроль «Почтовая защита» |
| `scanner/pipeline/credential_leaks.py` | контроль «Утечки», провайдерный интерфейс |
| `scanner/pipeline/controls.py` | матрица контролей и итоговая сводка |
| `tests/test_ownership.py` и т.д. | по файлу на модуль, моки `httpx`/DNS как в `test_asn_discovery.py` |

## Стадия 1 — владелец (`ownership.py`)

Пассивно, только публичные keyless-источники, fail-soft на каждый вызов —
та же посадка, что у `asn_discovery.py`.

**Источники и что берём:**

- **RDAP домена** (bootstrap IANA → `rdap.org` как fallback): регистратор,
  организация-регистрант (`entities[].vcardArray` роли `registrant`/`administrative`),
  abuse-email, даты регистрации/истечения, статусы (`clientTransferProhibited` и т.п.),
  флаг DNSSEC, список NS. Учитываем реальность: у большинства зон регистрант
  скрыт GDPR/privacy-прокси — тогда организация остаётся `null`, и это
  фиксируется как `redacted`, а не как «нет данных».
- **RDAP IP / ASN**: организация владельца адресного блока. Уже частично
  делает `asn_discovery.py` через RIPEstat — переиспользуем его вывод, не
  добавляем второй клиент.
- **TLS-сертификат**: поле `O=` из subject. `tls_posture.py` уже разбирает
  subject; нужен только доступ к разобранному `cert`.

**Выход `ownership.json`:**

```json
{
  "seed_domain": "example.com",
  "identifiers": [
    {"kind": "org_name",   "value": "Example Holding LLC", "source": "rdap_domain",  "confidence": 0.9},
    {"kind": "abuse_email","value": "abuse@example.com",   "source": "rdap_domain",  "confidence": 0.9},
    {"kind": "asn_org",    "value": "AS64500 EXAMPLE-AS",  "source": "ripestat",     "confidence": 0.6},
    {"kind": "cert_org",   "value": "Example Holding LLC", "source": "tls_cert",     "confidence": 0.7}
  ],
  "registrar": "…", "created": "…", "expires": "…",
  "registrant_status": "public|redacted|unknown",
  "nameservers": ["ns1.…"],
  "truncated": false, "errors": []
}
```

`identifiers` — вход для стадии 2. `confidence` — не выдумка: фиксированные
веса по источнику, задокументированные в модуле (RDAP-регистрант надёжнее,
чем ASN-организация, которая у хостера принадлежит хостеру, а не клиенту).

## Стадия 2 — совместные домены (`related_domains.py`)

Самая рискованная часть модуля: ошибка атрибуции означает скан чужой
инфраструктуры. Поэтому — **findings-only по умолчанию**, ровно как
`cloud_discovery.py` и `domain_monitor.py`.

**Источники (каждый opt-in, каждый со своим капом):**

| Источник | Механика | Ложные срабатывания |
| --- | --- | --- |
| `cert_san` | домены из SAN уже собранных сертификатов | низкие; общий сертификат у SaaS-хостинга — да |
| `ct_org` | crt.sh по `O=` организации (расширение уже существующего CT-клиента в `hostnames.py`) | средние; тёзки организаций |
| `reverse_ns` | домены на тех же NS | **высокие**, если NS публичные → жёсткий фильтр `excluded_ns_providers` (Cloudflare, Route53, GoDaddy, …); без фильтра источник бесполезен |
| `reverse_mx` | домены на том же MX | то же: исключаем Google/Microsoft/Yandex 365 |
| `asn` | домены, резолвящиеся в префиксы ASN организации | высокие на shared-хостинге; применять только если ASN-org совпал с org_name |
| `reverse_whois` | коммерческий API по регистранту/email | зависит от вендора; ключ в конфиге, выключено по умолчанию |

**Правило уверенности:** кандидат считается `confirmed`, если его подтверждают
**≥2 независимых источника** или один источник с весом ≥ `min_confidence`
(по умолчанию 0.6). Каждый кандидат несёт `evidence[]` с указанием источника и
конкретного факта («SAN сертификата `*.example.net` на 203.0.113.10»), чтобы
оператор мог оспорить вывод — тот же принцип объяснимости, что в `nist_risk.py`.

**Граница безопасности (обязательна к реализации):**

- `merge_into_scope: false` по умолчанию — найденные домены **не** сканируются
  в этом же run'е;
- при `auto_merge: true` мержатся только `confirmed` и не больше
  `max_merged_domains` (жёсткий кап, как `max_total_ips` в `asn_discovery.py`),
  превышение → `truncated: true`, а не тихое расширение;
- продвижение домена в scope вручную — отдельное действие оператора в UI/API
  (`POST /runs/{id}/related-domains/{domain}/promote`, роль operator+), которое
  добавляет цель, но **не запускает** скан само;
- в артефакт и в UI пишется дисклеймер: атрибуция вероятностная, ответственность
  за авторизацию скана — на операторе (перекликается с предупреждением в
  `README.md`).

## Стадия 3 — DNS структура (`dns_hygiene.py`)

Проверки по каждому домену в scope (не по каждому FQDN — контроль зонального
уровня):

- **NS**: количество, разнесённость по ASN/провайдерам (единственный NS или все
  NS в одной AS → finding `ns_single_point`), расхождение NS в зоне и у
  регистратора (`lame delegation`);
- **SOA**: наличие, вменяемые `refresh`/`expire`, соответствие MNAME списку NS;
- **DNSSEC**: наличие DS у родителя и RRSIG в зоне; `ds_without_rrsig` —
  отдельный finding (сломанная цепочка хуже отсутствия DNSSEC);
- **CAA**: наличие записи и её узость (`issue ";"` vs открытая);
- **wildcard**: резолв заведомо несуществующего лейбла → `wildcard_a_record`
  (важно: обесценивает брутфорс-поддомены, о чём должен знать оператор);
- **AXFR**: попытка трансфера зоны у каждого NS. **Активная проверка, opt-in**
  (`axfr_probe: false` по умолчанию) — единственная в модуле, выходящая за
  рамки обычного DNS-запроса;
- **dangling CNAME / typosquat**: **не реализуем заново** — контроль ссылается
  на findings из `domain_monitor.py` и включает их в свой статус.

## Стадия 4 — почтовая защита (`mail_posture.py`)

Полностью DNS-based, единственное исключение — HTTP-запрос политики MTA-STS.

- **MX**: наличие; `null MX` (RFC 7505) — домен явно не принимает почту;
- **SPF**: наличие ровно одной записи (две = ошибка по RFC 7208), механизм
  `all` (`-all` / `~all` / `?all` / `+all` — последний критичен), число
  DNS-lookup ≤ 10, `ptr`-механизм как deprecated;
- **DMARC** (`_dmarc.<domain>` TXT): наличие, политика `p=` (`none` →
  мониторинг без защиты), `sp=` для поддоменов, `pct<100`, наличие `rua`;
- **DKIM**: перебор распространённых селекторов (`default`, `google`,
  `selector1`, `selector2`, `k1`, `mail`, `dkim`, `s1`, `s2`) — только TXT-запросы,
  список настраиваемый. Отсутствие ответа = «селектор не найден», **не**
  «DKIM отсутствует»: селекторы произвольны, и модуль обязан это честно
  сообщать (тот же принцип, что «no expectation, no finding» в `cert_names.py`);
- **MTA-STS**: `_mta-sts` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt`
  (режим `enforce`/`testing`/`none`), **TLS-RPT** (`_smtp._tls`);
- **Правило для доменов без почты**: домен без MX обязан иметь `SPF -all` и
  `DMARC p=reject`, иначе его можно подделывать — самый частый и самый дешёвый
  в исправлении finding, поэтому выделен отдельно.

## Стадия 5 — утечки учётных данных (`credential_leaks.py`)

Выключено по умолчанию, работает через провайдерный интерфейс:

```python
class LeakProvider(Protocol):
    def domain_breaches(self, domain: str) -> LeakReport: ...
```

- **Провайдер по умолчанию — HIBP Breached Domain Search**: требует API-ключ
  **и** подтверждённого владения доменом на стороне HIBP. Это не ограничение,
  а фича — внешняя проверка авторизации;
- дополнительные провайдеры (DeHashed, LeakCheck, внутренний индекс дампов)
  подключаются реализацией того же протокола;
- **без ключа статус контроля — `not_checked`**, никогда `ok`.

**Обращение с данными (жёсткие правила):**

- в артефакт пишутся **агрегаты**: число затронутых учёток, перечень
  breach-источников с датами, флаг «в утечке были пароли/хеши»;
- сами пароли и хеши **не сохраняются никогда**;
- локальные части адресов маскируются (`j***@example.com`) в артефакте;
- полный список адресов доступен только через отдельный API-эндпоинт под
  правом уровня operator+ и не попадает ни в PDF-отчёт, ни в webhook-payload
  (см. существующую границу доставки вебхуков, коммит `b68796b`).

## Стадия 6 — сводка (`controls.py`)

Читает артефакты всех стадий и строит матрицу. Форма записи:

```json
{
  "control": "mail_protection",
  "title": "Почтовая защита",
  "status": "ok | weak | fail | not_checked | error",
  "impact": "critical | high | medium | low",
  "coverage": {"checked": 12, "total": 15},
  "findings_by_severity": {"critical": 0, "high": 4, "medium": 2},
  "top_findings": [{"id": "dmarc_policy_none", "domain": "…", "detail": "…"}],
  "evidence": ["mail_posture.json"],
  "why": "у 4 из 15 доменов DMARC в режиме p=none"
}
```

**Правила вывода статуса** (одинаковые для всех контролей, чтобы таблица
читалась однородно):

- `fail` — есть хотя бы один finding severity `critical`/`high`;
- `weak` — только `medium`/`low`;
- `ok` — проверка выполнена, findings нет;
- `not_checked` — стадия выключена, нет ключа или нет данных → **это статус
  «требуется проверка» из исходной таблицы**;
- `error` — стадия упала (fail-soft: run не падает, контроль честно красный).

Отсутствие данных **никогда** не даёт `ok`. Это главный инвариант модуля.

**Влияние (`impact`)** — фиксированный вес контроля, ровно как в исходной
таблице: DNS — среднее, TLS — среднее, почта — высокое, технологии — среднее,
открытые сервисы — высокое, утечки — критическое. Веса живут константой в
`controls.py`, не в конфиге (иначе матрица перестаёт быть сравнимой между
организациями).

**Итоговый уровень** считается не суммой весов, а через уже имеющуюся таблицу
NIST SP 800-30 Table I-2 из `api/services/nist_risk.py`: статус контроля →
ось likelihood, фиксированный impact → ось impact. Переиспользование даёт
объяснимую формулировку («High, потому что …») и не плодит второй риск-движок.

**Выход:** `controls.json`, раздел в `summary.md` (та самая таблица), поле
`controls` в `summary.json`, блок в PDF (`pdf_report.py`).

## Конфигурация

Новая секция в `scanner/config/default.yaml`, классы — в `config_schema.py`
рядом с `DomainMonitorConfig`:

```yaml
org_profile:
  enabled: false
  seed_domains: []            # пусто → base_domains_from_fqdns(scope)
  ownership:
    enabled: true
    timeout_seconds: 10
  related_domains:
    enabled: true
    sources: [cert_san, ct_org, reverse_ns, reverse_mx]
    excluded_ns_providers: [cloudflare.com, awsdns, googledomains, …]
    max_candidates: 500
    min_confidence: 0.6
    merge_into_scope: false
    auto_merge: false
    max_merged_domains: 25
  dns_hygiene:
    enabled: true
    axfr_probe: false         # единственная активная проверка
  mail_posture:
    enabled: true
    dkim_selectors: [default, google, selector1, selector2, k1, mail]
    mta_sts_http: true
  credential_leaks:
    enabled: false
    provider: hibp
    api_key: ""
    reveal_identifiers: false
  controls:
    enabled: true
```

## API и UI

**API** (`api/schemas.py`, `api/routes/runs.py`):

- `ControlItem`, `OrgProfileSummary` в схемах;
- `GET /runs/{id}/controls` → матрица;
- `GET /runs/{id}/org-profile` → владелец + связанные домены (пагинация через
  `_pagination.py`);
- `POST /runs/{id}/related-domains/{domain}/promote` → добавить в цели
  (operator+, без автозапуска скана);
- `GET /runs/{id}/leaks/identifiers` → полные адреса, отдельное право;
- новый интент `org_profile` в `api/services/scan_intents.py` — включает
  стадии модуля поверх обычного пайплайна (по образцу `inventory`/`vuln`);
- ClickHouse: таблица `controls` в `ch_transform.py` — тренд контроля во
  времени («почта была fail, стала weak»).

**UI** (`web-next/src/`):

- `components/run/controls-matrix.tsx` + `controls-matrix.test.tsx` (тесты рядом
  с компонентом — уже принятая в репозитории практика);
- вкладка «Контроли» на `/runs/[id]` — таблица с раскрытием в findings;
- страница `/org-profile` — владелец, дерево связанных доменов с evidence и
  кнопкой «добавить в scope»;
- на дашборде — плитка со сводным уровнем.

## Порядок поставки

| Этап | Содержание | Почему в этом порядке |
| --- | --- | --- |
| **M1** | `ownership.py` + RDAP + конфиг + тесты | фундамент для стадии 2, ни от чего не зависит |
| **M2** | `mail_posture.py` + `dns_hygiene.py` | два недостающих контроля с лучшим отношением ценности к цене — чистый DNS, без активного трафика |
| **M3** | `controls.py` + сводка + API + UI-матрица | **сводка появляется раньше, чем все контроли готовы**: незакрытые честно показываются как «требуется проверка» — ровно исходная таблица |
| **M4** | `related_domains.py` + promote-flow | самая рискованная часть, делается на устоявшемся фундаменте |
| **M5** | `credential_leaks.py` + RBAC-гейт | зависит от внешнего вендора и юридического решения по хранению |

После M3 продукт уже отвечает на вопрос «в каком состоянии домен», по одному
домену. M4 расширяет ответ на всю организацию.

## Риски и границы

| Риск | Митигация |
| --- | --- |
| Ошибка атрибуции → скан чужой инфраструктуры | findings-only по умолчанию, ручное продвижение в scope, жёсткие капы, дисклеймер в артефакте |
| `reverse_ns`/`reverse_mx` на публичных провайдерах взрывают scope | обязательный фильтр `excluded_ns_providers`; без него источник отключён |
| AXFR — активное действие | opt-in, выключено по умолчанию |
| Rate limit RDAP / crt.sh | кэш в `state_dir`, backoff, fail-soft per-call (как в `asn_discovery.py`) |
| Приватность данных об утечках | агрегаты, маскирование, RBAC-гейт, исключение из PDF и вебхуков |
| Скрытый GDPR-регистрант | статус `redacted` вместо молчаливого «нет владельца» |
| Дублирование существующей логики | typosquat/dangling — ссылка на `domain_monitor.py`; TLS/технологии/сервисы — маппинг существующих findings, без новых HTTP-клиентов |

## Открытые вопросы

1. Коммерческий reverse-WHOIS: включать ли вендорный источник в M4 или оставить
   интерфейс без реализации до появления бюджета/договора.
2. Хранить ли идентификаторы из утечек вообще — вариант «только счётчики,
   никаких адресов» юридически чище и почти не теряет ценности.
3. Считать ли `org_profile` отдельным интентом или флагом поверх `full` —
   влияет на форму `StartScanRequest` и на планировщик.
