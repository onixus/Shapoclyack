# Модуль «Профиль организации» (org_profile)

Проектный документ. **Все этапы M1 (`ownership.py`), M2 (`dns_hygiene.py`, `mail_posture.py`), M3 (`controls.py`, API, Web UI), M4 (`related_domains.py`, promote-flow, API, Web UI) и M5 (`credential_leaks.py`, RBAC-гейт, API) полностью реализованы и протестированы**. Соглашения по языку: файл на русском по
поведение. Соглашения по языку: файл на русском по
образцу `README.ru.md`; при переводе в официальную документацию — английская
версия в `docs/`.

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

## Стадия 1 — владелец (`ownership.py`) — реализовано (M1)

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
  "registrant_status": "public|redacted|natural_person|unidentified|unknown",
  "nameservers": ["ns1.…"],
  "truncated": false, "errors": []
}
```

`identifiers` — вход для стадии 2. `confidence` — не выдумка: фиксированные
веса по источнику, задокументированные в модуле (RDAP-регистрант надёжнее,
чем ASN-организация, которая у хостера принадлежит хостеру, а не клиенту).

### Что вошло в M1

Реализовано: `scanner/pipeline/ownership.py` (RDAP домена) и
`scanner/pipeline/safe_http.py` (исходящий HTTPS сканера). Стадия `ownership`
врезана в `main.py` рядом с `ct`/`asn`, до `resolve`, с чекпойнтом и таймером.

**Не вошло в M1:** идентификаторы `asn_org` и `cert_org`. `asn_org` берётся из
вывода `asn_discovery.py`, `cert_org` — из subject сертификата, который
разбирает `tls_posture.py` намного позже в пайплайне; оба добавляются вместе с
M2/M3, когда появится агрегатор, читающий чужие артефакты. В M1
`identifiers[]` содержит только `org_name`, `registrar` и `abuse_email` из
источника `rdap_domain` с весами 0.9 / 0.8 / 0.7 (константа `_CONFIDENCE`).

**Конфиг** — `org_profile.ownership` в `scanner/config/default.yaml`:

| Параметр | Дефолт | Смысл |
| --- | --- | --- |
| `enabled` | `false` | стадия opt-in, как все стадии модуля |
| `domains` | `[]` | пусто = базовые домены из входных FQDN (`base_domains_from_fqdns`) |
| `max_domains` | `50` | кап на число доменов, которым уйдёт RDAP-запрос |
| `timeout_seconds` | `15` | таймаут одного запроса (весь бюджет hop'а, включая редиректы) |
| `deadline_seconds` | `300` | общий дедлайн стадии — проверяется и между доменами, и перед каждой попыткой запроса, и таймаут одного запроса им подрезается |

**Семантика `truncated`.** Флаг ставится в двух случаях и оба логируются с
именем параметра, который нужно поднять: сид-список длиннее `max_domains`
(лишние домены не опрашиваются) и исчерпание `deadline_seconds` (оставшиеся
домены не опрашиваются). Тихого усечения нет: в `ownership.json` всегда видно
`seed_domains` и фактически опрошенный `domains`.

**Статусы домена** — инвариант «отсутствие данных никогда не даёт `ok`»:

| `status` | `reason` | Когда |
| --- | --- | --- |
| `ok` | `null` | RDAP-объект получен и разобран |
| `not_checked` | `rdap_not_found` | сервер ответил 404 — объекта нет |
| `error` | `rdap_unavailable` | транспорт/HTTP-ошибка после ретраев |
| `error` | `rdap_blocked_target` | адрес RDAP-сервера не прошёл валидацию `safe_http` |

**Статусы регистранта** (`registrant_status`) — модуль различает «скрыто»,
«человек» и «ничего нет», а не сваливает их в один `null`:

| Значение | Когда |
| --- | --- |
| `public` | получено имя организации: поле `org`, либо `fn` при явном `kind: org` |
| `redacted` | реестр замаскировал поле (RFC 9537 `redacted[]`, remark «REDACTED FOR PRIVACY» или маркер в значении) |
| `natural_person` | регистрант объявлен как `kind: individual` — имя намеренно не записывается |
| `unidentified` | регистрант есть, но ничего в нём не опознаётся как организация (голый `fn` без `kind`) |
| `unknown` | сущности с ролью `registrant` в объекте нет вообще |

`fn` без `kind: org` **не** используется как `org_name`. Это осознанный
false-negative: у домена частного лица `fn` — это имя человека, а контракт
модуля запрещает писать его на диск. Реестры, кладущие название компании в
`fn` без `kind`, теряют идентификатор — потерять идентификатор дешевле, чем
записать имя физлица с весом 0.9.

**Что пишется на диск.** `ownership.json` и `ownership_findings.txt` содержат
только `org_name`, `registrar`, `abuse_email`, даты, статусы, флаг DNSSEC и NS.
Сырой блок `entities[]` / vCard — адрес, телефон, имя физлица, tech/admin —
разбирается в памяти и не сохраняется (тест
`test_ownership_never_persists_the_raw_contact_block`). Оба файла — **класс
ограниченного артефакта** в API (`is_restricted_artifact`, operator+), см.
`docs/api-and-rbac.md`. В `pdf_report.py`, в ClickHouse и в webhook-payload
стадия ничего не проводит.

**Исходящий HTTPS.** `safe_http.py` — второй экземпляр границы из
`api/services/integrations/delivery.py` (`scanner/` не импортирует `api/`):
только https, запрет userinfo, отказ, если хоть один A/AAAA не `is_global`,
TCP на провалидированный IP при SNI и проверке сертификата по DNS-имени,
кап тела 256 KiB, один wall-clock дедлайн на всю цепочку, до 3 редиректов с
повторной валидацией каждого `Location`. Проверка сертификата и пиннинг не
настраиваются. Прокси из окружения игнорируются (`http.client`, не `httpx`).
Bootstrap IANA кэшируется в `state_dir` — на 50k активов это один запрос к
IANA вместо одного на домен. У кэша есть TTL в сутки (столько же, сколько IANA
отдаёт в `max-age`), потому что `state_dir` не всегда пер-ран: при
`runtime.per_run_output: false` это общий `state_base`, и кэш без TTL был бы
записан один раз и считался бы верным вечно — новый TLD или переехавший
RDAP-сервер реестра не подхватился бы никогда, а такие домены молча уходили бы
на `rdap.org`.

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
  добавляет цель, но **не запускает** скан само; продвинуть можно только
  синтаксически валидный домен, который этот run действительно нашёл как
  кандидата (`related_domains.json`), иначе `400` — `promoted_domains.txt`
  построчно задаёт scope будущего скана, и произвольное значение из URL туда
  попасть не должно;
- в артефакт и в UI пишется дисклеймер: атрибуция вероятностная, ответственность
  за авторизацию скана — на операторе (перекликается с предупреждением в
  `README.md`).

## Стадия 3 — DNS структура (`dns_hygiene.py`) — реализовано (M2)

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

## Стадия 4 — почтовая защита (`mail_posture.py`) — реализовано (M2)

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

### Что вошло в M2

Реализовано: `scanner/pipeline/dns_hygiene.py`, `scanner/pipeline/mail_posture.py`
и общая обёртка над dnsx `scanner/pipeline/dnsx.py` (семь типов записей на две
стадии — механика одного вызова живёт в одном месте, а тонкие именованные
обёртки остаются в стадиях, потому что именно их подменяют тесты). Обе стадии
врезаны в `main.py` **после `resolve`**, рядом с `domain_monitor`, с чекпойнтом
и таймером; обе findings-only и scope не расширяют.

**Не вошло в M2** и почему:

- **`ds_without_rrsig`** — честно не определяется. У dnsx 1.2.3 нет флага
  DS/RRSIG, `dnspython` в зависимостях нет и добавлять его нельзя. Сломанная
  цепочка неотличима от отсутствия DNSSEC, а выдать догадку за факт — прямое
  нарушение инварианта модуля. DNSSEC берётся из RDAP-флага
  `secureDNS.delegationSigned`, который уже собрал M1: источник назван явно,
  `source: "rdap_registry"`. Флаг `AD` от резолвера не используется вовсе — это
  мнение резолвера, а не проверенная цепочка.
- **Разнесённость NS по ASN** — ASN-запросов стадия не делает. Концентрация
  считается по родительскому домену NS и по префиксу их адресов (/24 для v4,
  /48 для v6), поле `ns_diversity.source` так и называется:
  `ns_parent_domain_and_ip_prefix`. Слабый источник, названный слабым, лучше
  сильного названия у слабого источника.
- **Расхождение NS с регистратором** (`lame delegation` в узком смысле) — в M2
  реализован только вариант «NS не резолвится» (`ns_lame_delegation`). Сверка с
  NS-списком регистратора — это чтение чужого артефакта, и она уезжает в M3
  вместе с агрегатором.
- **Typosquat и dangling CNAME** — как и планировалось, заново не реализуются;
  M3 сошлётся на findings `domain_monitor.py`.
- **Матрица контролей** — M3. M2 пишет только findings с полями `kind`,
  `severity`, `domain` (форма как в `tls_posture.py`).

**Конфиг** — `org_profile.dns_hygiene` и `org_profile.mail_posture`:

| Параметр | Дефолт | Смысл |
| --- | --- | --- |
| `dns_hygiene.enabled` | `false` | стадия opt-in |
| `dns_hygiene.domains` | `[]` | пусто = `base_domains_from_fqdns` от scope |
| `dns_hygiene.max_domains` | `50` | кап на число доменов стадии |
| `dns_hygiene.timeout_seconds` | `15` | таймаут одного вызова dnsx |
| `dns_hygiene.retries` | `1` | ретраи вызова dnsx |
| `dns_hygiene.deadline_seconds` | `300` | общий дедлайн стадии |
| `dns_hygiene.axfr_probe` | `false` | **активная** проверка, см. ниже |
| `dns_hygiene.axfr_timeout_seconds` | `10` | таймаут одной попытки трансфера |
| `mail_posture.enabled` | `false` | стадия opt-in |
| `mail_posture.domains` | `[]` | пусто = `base_domains_from_fqdns` от scope |
| `mail_posture.max_domains` | `50` | кап на число доменов стадии |
| `mail_posture.timeout_seconds` | `15` | таймаут одного вызова dnsx |
| `mail_posture.retries` | `1` | ретраи вызова dnsx |
| `mail_posture.deadline_seconds` | `300` | общий дедлайн стадии |
| `mail_posture.dkim_selectors` | `[default, google, selector1, selector2, k1, mail]` | ≤ 20 записей, каждая — DNS-лейбл `[a-z0-9-]{1,63}` |
| `mail_posture.mta_sts_http` | `true` | единственный HTTP-запрос модуля |
| `mail_posture.mta_sts_timeout_seconds` | `10` | таймаут запроса политики |

Жёсткие капы живут константами в коде, а не в конфиге — их нельзя поднять
из YAML: `dns_hygiene.MAX_NS_PER_DOMAIN` = 10, `dns_hygiene.WILDCARD_PROBE_LABELS`
= 2, `mail_posture.MAX_MX_PER_DOMAIN` = 10, `mail_posture.MAX_DKIM_QUERIES` = 500,
`mail_posture.SPF_MAX_LOOKUPS` = `SPF_MAX_DEPTH` = 10.

**Семантика `truncated`** — та же, что в M1: флаг ставится там, где данные
сознательно недобраны, и каждый случай логируется с именем параметра, который
нужно поднять. В M2 таких случаев пять:

1. сид-список длиннее `max_domains` (обе стадии);
2. домен публикует больше `MAX_NS_PER_DOMAIN` NS — лишние не проверяются
   (`nameservers_truncated` у домена);
3. домен публикует больше `MAX_MX_PER_DOMAIN` MX;
4. `домены × dkim_selectors` превышает `MAX_DKIM_QUERIES` — DKIM проверяется
   для первых `MAX_DKIM_QUERIES / len(selectors)` доменов, остальные получают
   `dkim.status: not_checked`, `reason: selector_budget_exhausted`;
5. дедлайн стадии исчерпан до AXFR-пробы очередного NS.

Ни один из этих случаев не превращается в `ok`: недобранные данные видны в
артефакте как `not_checked` с причиной.

**Источники данных, названные явно:**

| Что | Источник | Поле |
| --- | --- | --- |
| DNSSEC | RDAP-объект домена из `ownership.json` (M1) | `dnssec.source: "rdap_registry"` |
| Концентрация NS | родительский домен NS + префикс адреса | `ns_diversity.source: "ns_parent_domain_and_ip_prefix"` |
| NS, SOA, CAA, MX, TXT, wildcard | `dnsx` | — |
| Политика MTA-STS | HTTPS через `safe_http.py` | `mta_sts.policy` |

Если `ownership` выключен, DNSSEC — это `not_checked` с
`reason: "no_rdap_secure_dns"`, а не «DNSSEC нет».

**AXFR — единственная активная проверка модуля.** Три обязательных гейта:

1. **конфигурационный:** `axfr_probe: false` по умолчанию, и флаг сознательно
   недоступен нигде, кроме файла конфига. Его нет в `EDITABLE_PATHS`
   (`api/services/config_override.py`), потому что оверрайды там
   установочно-широкие, а не пер-тенантные — платформенный admin включил бы
   AXFR разом для сканов всех тенантов. И его нет в `StartScanRequest`, потому
   что это перенесло бы решение об активной проверке на роль `operator`,
   которая запускает скан, а не отвечает за авторизацию цели;
2. **runtime по scope:** пробуются только домены сид/scope самого run'а
   (`base_domains_from_fqdns`), никогда — кандидаты атрибуции из M4;
3. **по адресу NS:** каждый адрес NS обязан пройти
   `safe_http.is_public_address`. NS-запись пишет сканируемая сторона, поэтому
   `ns1.target.example → 10.0.0.5` превращает пробу в TCP/53-коннект по
   внутренней сети агента. Проверка одна на весь сканер — та же функция, что
   валидирует адреса исходящего HTTPS.

**Зона не попадает ни в лог, ни в артефакт.** `utils.run_command` логирует
командную строку и stdout ребёнка в общий лог run'а, а stdout успешного
трансфера — это вся зона цели; `scan.log` переживает артефакты и не входит в
класс ограниченного доступа. Поэтому проба ходит в `subprocess` напрямую, без
`-o`, держит вывод в памяти и записывает только факт трансфера и число записей
(`{"nameserver": …, "status": "open", "records": N}`).

**MTA-STS — единственный HTTP в M2.** `https://mta-sts.<domain>/.well-known/mta-sts.txt`
запрашивается только через `safe_http.py`: адрес валидируется и пиннится,
`max_redirects=0` (RFC 8461 §3.3 прямо запрещает следовать 3xx при получении
политики — и редирект здесь же является примитивом, нужным для SSRF), кап тела
64 KiB. Тело сверх капа — это `status: "error"`, `reason: "policy_too_large"`, а
не «политика распарсена наполовину». `httpx`/`urllib`/`requests` в модуле не
используются.

**DKIM и инвариант «нет данных ≠ ok».** Селекторы произвольны, поэтому
«ни один известный селектор не ответил» — это `dkim.status: "not_checked"`,
`reason: "no_known_selector"`, и **никакого finding**. Утверждение «у домена нет
DKIM» модуль сделать не может и не делает.

**Findings M2:**

| `kind` | `severity` | Когда |
| --- | --- | --- |
| `axfr_open` | critical | NS отдал зону |
| `spf_all_permissive` | critical | `+all` |
| `ns_missing` | high | у домена нет NS |
| `soa_missing` | high | нет SOA |
| `spf_missing`, `spf_multiple_records` | high | нет SPF / их больше одного (permerror по RFC 7208 §4.5) |
| `dmarc_missing`, `dmarc_policy_none`, `dmarc_policy_invalid` | high | нет DMARC / `p=none` / `p` отсутствует или не распознан |
| `no_mx_domain_spoofable` | high | домен без MX (или с `null MX`) без `SPF -all` **и** `DMARC p=reject` |
| `ns_single_point`, `ns_lame_delegation` | medium | один NS или один провайдер / NS не резолвится |
| `dnssec_absent` | medium | RDAP говорит `delegationSigned: false` |
| `wildcard_a_record` | medium | все пробные лейблы резолвятся |
| `spf_all_neutral`, `spf_too_many_lookups`, `spf_include_cycle` | medium | `?all`/нет `all`, > 10 DNS-lookup, цикл `include:` |
| `dmarc_policy_quarantine`, `dmarc_subdomain_policy_none`, `dmarc_pct_partial`, `dmarc_multiple_records` | medium | — |
| `mta_sts_policy_unreachable` | medium | TXT есть, политика не получена |
| `soa_mname_not_in_ns`, `soa_timers_out_of_range` | low | MNAME вне списка NS, таймеры вне RFC 1912 §2.2 |
| `caa_missing`, `caa_wildcard_unrestricted` | low | нет CAA / есть `issue`, но нет `issuewild` |
| `spf_ptr_mechanism` | low | механизм `ptr` (deprecated) |
| `dmarc_no_rua` | low | нет отчётного адреса |
| `dkim_key_revoked` | low | селектор есть, `p=` пустой |
| `mta_sts_missing`, `mta_sts_mode_not_enforce`, `tls_rpt_missing` | low | — |

**Цикл `include:` останавливается, а не фиксируется постфактум.** Обход —
BFS с visited-set и потолком глубины `SPF_MAX_DEPTH`, один вызов dnsx на
уровень; `a.example include:b.example` / `b.example include:a.example`
завершается на втором визите и даёт finding `spf_include_cycle`.

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
  dns_hygiene:            # реализовано в M2, полный список параметров выше
    enabled: false
    axfr_probe: false         # единственная активная проверка
  mail_posture:           # реализовано в M2, полный список параметров выше
    enabled: false
    dkim_selectors: [default, google, selector1, selector2, k1, mail]
    mta_sts_http: true
  credential_leaks:
    enabled: false
    provider: hibp
    api_key: ""
    # false: на диск пишутся только маскированные идентификаторы; полные
    # адреса в credential_leaks_identifiers.json не сохраняются вовсе
    reveal_identifiers: false
  controls:
    enabled: true
```

## API и UI

**API** (`api/schemas.py`, `api/routes/runs.py`):

- `ControlItem`, `OrgProfileSummary` в схемах;
- `GET /runs/{id}/controls` → матрица;
- `GET /runs/{id}/org-profile` → владелец + связанные домены (пагинация через
  `_pagination.py`); блок `ownership` отдаётся только operator+, как и сам
  `ownership.json` в `_RESTRICTED_ARTIFACTS` — для viewer он `null`, а
  `ownership_restricted: true` объясняет, что это ограничение доступа, а не
  отсутствие данных;
- `POST /runs/{id}/related-domains/{domain}/promote` → добавить в цели
  (operator+, без автозапуска скана);
- `GET /runs/{id}/leaks/identifiers` → полные адреса, отдельное право; при
  `reveal_identifiers: false` возвращает `revealed: false` и `withheld_reason`
  вместо адресов — они не пишутся на диск;
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
| **M1** ✅ | `ownership.py` + `safe_http.py` + RDAP + конфиг + тесты | фундамент для стадии 2, ни от чего не зависит |
| **M2** ✅ | `mail_posture.py` + `dns_hygiene.py` | два недостающих контроля с лучшим отношением ценности к цене |
| **M3** ✅ | `controls.py` + сводка + API + UI-матрица | матрица контролей, NIST SP 800-30 риск, API, вкладка в UI |
| **M4** ✅ | `related_domains.py` + promote-flow | поиск совместных доменов (SAN, CT, NS, MX), promote API и UI |
| **M5** ✅ | `credential_leaks.py` + RBAC-гейт | поиск утечек (HIBP/провайдеры), маскирование, RBAC-гейт для идентификаторов |

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
| Регистрант — физлицо, его имя утекает в артефакт как `org_name` | `fn` берётся только при `kind: org`; иначе `natural_person`/`unidentified` и `org_name: null` |
| Дублирование существующей логики | typosquat/dangling — ссылка на `domain_monitor.py`; TLS/технологии/сервисы — маппинг существующих findings, без новых HTTP-клиентов |

## Открытые вопросы

1. Коммерческий reverse-WHOIS: включать ли вендорный источник в M4 или оставить
   интерфейс без реализации до появления бюджета/договора.
2. Хранить ли идентификаторы из утечек вообще — вариант «только счётчики,
   никаких адресов» юридически чище и почти не теряет ценности.
3. Считать ли `org_profile` отдельным интентом или флагом поверх `full` —
   влияет на форму `StartScanRequest` и на планировщик.
