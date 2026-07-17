# Octo-man (документация на русском)

Основной README: [README.md](README.md).  
Этот файл — эксплуатационные рекомендации на русском.

| | |
|---|---|
| **Релиз** | **[shapoclyack-0.33](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.33)** |
| **Образы** | `ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.33` (+ `shapoclyack-scanner` / `shapoclyack-api`) |
| **Runtime** | All-in-one (`docker compose`) или Kubernetes ([k8s/README.md](k8s/README.md)) |
| **История** | [CHANGELOG.md](CHANGELOG.md) |
| **Roadmap** | [ROADMAP.md](ROADMAP.md) — MSSP / Enterprise (NATS, tenancy, ClickHouse, …) |

## Назначение

Контейнеризированный пайплайн разведки больших сетей + API/дашборд:
- вход: `CIDR + IP + FQDN`
- этапы: `resolve → discovery → hostnames → ports → NSE (версии/ОС + CVE)`
- выход: `JSON/JSONL/CSV` + сводка `Markdown/HTML` (+ diffs, alerts)
- управление: Kubernetes Job/CronJob и UI на `:8080`

## All-in-one (по умолчанию)

```bash
docker compose up --build
# UI: http://localhost:8080 — operator / operator-change-me
# Запуск сканов из Jobs включён (OCTO_ALLOW_SCAN_START=true)
```

## Kubernetes

Полная инструкция: [k8s/README.md](k8s/README.md). Base/dev используют образ **aio**
с управлением сканами из Web UI.

```bash
docker build -t ghcr.io/onixus/shapoclyack-aio:local -f Dockerfile.allinone .
kubectl apply -k k8s/octo-man/overlays/dev
kubectl -n network-scan port-forward svc/octo-man-api 8080:8080
```

Тонкий API без локальных сканов: `overlays/api-readonly`.

## Phase 2: API, дашборд и RBAC

Роли: `viewer` (чтение прогонов), `operator` (jobs + агенты), `admin` (зарезервировано).  
Демо-пользователи: `viewer` / `operator` / `admin` с паролями `*-change-me` — сразу смените.
Секрет JWT: `OCTO_JWT_SECRET` / Secret `octo-man-api`.

Удалённые агенты (фаза 3): `OCTO_JOB_EXECUTION_MODE=agent`, `OCTO_AGENT_TOKEN`, воркер
`python -m agent`. Подробности и примеры k8s — в README (EN) и
`k8s/octo-man/examples/agent-*.yaml`.

## Быстрый старт

### 1) Сборка образов

```bash
docker build -t ghcr.io/onixus/shapoclyack-scanner:local -f Dockerfile .
docker build -t ghcr.io/onixus/shapoclyack-api:local -f Dockerfile.api .
```

### 2) Подготовка входов и деплой

Заполните `scanner/inputs/{ranges,domains,ports}.txt`, создайте Secret `scan-targets`, затем:

```bash
kubectl apply -k k8s/octo-man/overlays/dev
kubectl -n network-scan logs -f job/network-scan
```

### 3) Локальный one-shot без кластера (опционально)

```bash
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/scanner:/app/scanner" ghcr.io/onixus/shapoclyack-scanner:local \
  --config scanner/config/default.yaml --mode balanced
```

### 4) Возобновление после прерывания

```bash
kubectl apply -f k8s/octo-man/base/job-resume.yaml
```

### 5) L1-скан, затем NSE

`--skip-nse` на первом Job, затем `job-resume.yaml` / `--resume`.  
Или `runtime.skip_nse: true` в конфиге.

### 6) Инкрементальный (delta) discovery

CronJob уже передаёт `--delta`. Для one-shot добавьте флаг в args Job или локальный `docker run … --delta`.
**Не** используйте delta на первом скане / после смены диапазонов.

## Валидация конфигурации

YAML проверяется при старте через **Pydantic** (`scanner/pipeline/config_schema.py`):
неверные ключи, ссылки на несуществующие профили, выход за диапазоны — ошибка с кодом `2`.

## Каталоги на каждый прогон

При `runtime.per_run_output: true` (по умолчанию):

- `scanner/output/runs/<run_id>/` — артефакты и `run_meta.json`
- `scanner/state/runs/<run_id>/` — checkpoint
- `scanner/state/latest_run.json` — указатель на последний `run_id`

`run_id` — UTC-метка времени или `--run-id`. `per_run_output: false` — плоская схема как раньше.

## Коды выхода

| Код | Значение |
|-----|----------|
| `0` | Успех |
| `1` | Неожиданная внутренняя ошибка |
| `2` | Ошибка валидации конфигурации |
| `3` | Нет валидных целей после проверки входа |
| `4` | Сбой внешнего инструмента после ретраев |
| `130` | Прерывание (Ctrl+C) |

## Логирование и лимиты

- Ротация логов: `pipeline.log` с `log_max_bytes` / `log_backup_count` в `runtime:`.
- Kubernetes Job/CronJob: requests/limits `4–8 CPU` / `4–8Gi` (overlay `dev` снижает лимиты).

## Рекомендации по профилям и rate-limit

Ниже стартовые значения для `discover_rate` / `port_rate`.  
Увеличивайте постепенно, контролируя нагрузку, потери и срабатывания IDS/IPS.

| Размер цели | Режим | Рекомендованный стартовый rate |
|---|---|---|
| `/24` | `safe` | `500-1000` pps |
| `/16` | `balanced` | `2000-4000` pps |
| `/16` (агрессивно) | `fast` | `5000-8000` pps |
| `>/16` (батчами) | `balanced/fast` | `3000-7000` pps на воркер |

Практика:
- Для первой разведки используйте `top-100` или `top-1000`, а не полный `1-65535`.
- Запускайте NSE только по найденным `host:port`, не по всей подсети.
- Делите большие диапазоны на части и запускайте контролируемо (batch/window).

## Рекомендованный процесс для больших сетей

1. **Нормализация целей**: валидация `CIDR/IP/FQDN`.
2. **Resolve**: FQDN → IP через `dnsx`.
3. **Discovery (wave-1)**: определение живых хостов побатчево; при **disjoint** батчах — параллельно. Probe ladder: ICMP → TCP SYN → naabu (`probe_order`).
4. **Discovery (wave-2, adaptive)**: догон пропущенных хостов в scope (если `discovery.adaptive.enabled`).
5. **Hostname enrichment**: forward-имена из DNS + reverse PTR через `dnsx` → `hostnames.json`.
6. **Fast ports**: быстрый проход по `top-ports`/custom ports (побатчево).
7. **Verify (опционально)**: повторный ping живых хостов без открытых портов (`discovery.verify`).
8. **NSE/Nmap** (можно отложить через `--skip-nse`): углубление по найденным `host:port` — версии сервисов, **ОС (`-O`)**, **CVE (`vuln`/`vulners`/`vulscan`)**. Параллельный пул nmap.
9. **Отчёты**: JSON/CSV + сводка с ОС, hostname и уязвимостями.
10. **Diff отчётов** (фаза 1): сравнение с предыдущим прогоном → `diff.json` / `diff.md`.
11. **Оповещения** (фаза 1, опционально): Slack / Telegram через `--notify` или `alerts.enabled`.
12. **DefectDojo** (фаза 3, опционально): Generic Findings Import через `--export-defectdojo` или `defectdojo.enabled`.
13. **PDF-отчёт** (фаза 3): executive `summary.pdf` при `reporting.pdf_summary` (по умолчанию включено).

Двухфазный режим: `--skip-nse` → `--resume` (L1, затем enrichment).  
Инкрементальный режим: `--delta` после baseline (см. выше).

### Diff отчётов

По умолчанию (`reporting.diff.enabled: true`) после отчётов сравниваются живые хосты,
открытые порты и CVE с предыдущим `run_id` из `latest_run.json`:

```bash
# diff пишется автоматически между прогонами Job/CronJob
```

Отключить: `--no-diff`.

### Оповещения Slack / Telegram

Secret `octo-man-alerts` + `--notify` на Job, либо `alerts.enabled: true` в YAML.
`alerts.on_diff_only: true` — слать только при изменениях в diff.

### Экспорт в DefectDojo (фаза 3)

Отправляет `vulnerabilities.json` в DefectDojo как **Generic Findings Import**
(`POST /api/v2/reimport-scan/`).

```bash
export OCTO_DEFECTDOJO_URL="https://defectdojo.example.com"
export OCTO_DEFECTDOJO_API_KEY="your-api-token"
python -m scanner.main --config scanner/config/default.yaml --mode balanced --export-defectdojo
```

Либо `defectdojo.enabled: true` в YAML. Артефакты: `defectdojo_findings.json` (payload),
`defectdojo.json` (статус). Ошибка DD не валит скан.

В API: `"export_defectdojo": true` в теле `POST /api/jobs`.
Цели скана можно задать полями `ranges` / `domains` / `ports` / `ports_udp`
(или формой на странице Jobs; UDP — при `ports.protocol: udp|tcp_udp`).

### PDF бизнес-отчёт (фаза 3)

При `reporting.pdf_summary: true` (по умолчанию) после отчётов и diff пишется `summary.pdf`:
KPI, severity, топ-сервисы, таблица приоритетных findings, дельта к прошлому прогону.
Настройки: `pdf_title`, `pdf_org_name`, `pdf_max_vulnerabilities`. Отключить: `pdf_summary: false`.

### Планировщик задач

В кластере — `CronJob/network-scan-scheduled`. Локально: `python -m scanner.scheduler --once`.

## Батчинг и возобновление (resume)

Большие диапазоны разбиваются на независимые батчи, чтобы единый запуск `naabu`/`nmap`
не упирался в глобальный таймаут, сбой одного батча не валил весь скан, а `--resume`
переделывал только незавершённое.

- IPv4-сети крупнее `batching.ipv4_prefix` дробятся на батчи `/ipv4_prefix`
  (например, `/16` → 16 × `/20`). Одиночные IP, IPv6 и мелкие сети группируются по
  `batching.max_targets_per_batch`.
- Discovery и port-scan идут **побатчево** (опционально **параллельно** через
  `runtime.discover_concurrency` / `runtime.ports_concurrency`); живые хосты и открытые
  порты инкрементально агрегируются в `alive_ips.txt` / `open_ports.txt`. Каждый
  параллельный naabu использует `discover_rate` / `port_rate` профиля — суммарный
  сетевой шум ≈ `rate × concurrency`.
- Этап NSE/OS чекпойнтится **по хостам** — `--resume` пропускает уже отсканированные.
- Прогресс — в `scanner/state/runs/<run_id>/checkpoint.json` (или плоский
  `scanner/state/checkpoint.json` при `per_run_output: false`): флаги стадий + множества
  элементов (id батчей `discover` / `discover-wave2` / `discover-refresh` /
  `discover-hostnames`, батчи `ports`, хосты `nse`). Запись потокобезопасна и атомарна по элементу.

Настройка/отключение — секция `batching:` в `scanner/config/default.yaml`
(`enabled`, `ipv4_prefix`, `max_targets_per_batch`). Меньший `ipv4_prefix` — более
дробный resume ценой большего числа запусков инструментов.

## Настройка discovery

Секция `discovery:` в конфиге:

```yaml
discovery:
  profile: auto              # auto | fast | balanced | thorough | custom
  skip_discovery: false       # true — считать входные IP живыми (load test)
  skip_known_alive: true      # не сканировать уже найденные alive в следующих батчах
  disjoint_batches: true      # параллельный discover, если батчи не пересекаются
  adaptive:
    enabled: true             # wave-2 — догон пропущенных хостов
    min_gap: 1
    wave2_rate: 800           # опционально; по умолчанию ≈ discover_rate / 4
  exclude_alive: []
  exclude_last_octets: []     # напр. [0, 255]
  verify:
    enabled: false            # повторный ping alive без открытых портов
  icmp:
    enabled: false            # fping pre-filter (крупные CIDR)
  tcp_probe:
    enabled: false            # SYN probe на типовых портах
    ports: [80, 443, 22]
  probe_order: [icmp, tcp, naabu]
  hostnames:
    forward: true
    reverse: true
  seed_alive_file: ""         # предзаполнение alive (CMDB/DHCP)
  delta:
    enabled: false
    previous_run_dir: ""      # по умолчанию — последний per-run output
    refresh_rate: 0.1         # доля known-alive для повторного probe
```

**Presets** (`discovery.profile: auto` маппится из `runtime.mode` — `safe`→thorough, `balanced`→balanced, `fast`→fast):

| Preset | Wave2 | Verify | ICMP | PTR | discover_rate |
|--------|-------|--------|------|-----|---------------|
| fast | skip если coverage ≥95% | off | off | off | ×1.5 |
| balanced | gap ≥ min_gap | off | off | forward only | ×1 |
| thorough | gap ≥ min_gap | on | on | forward+reverse | ×0.75 |

`profile: custom` — значения из YAML без переопределения preset.

Для **firewall-heavy** сетей включите `tcp_probe` (и при необходимости `icmp`), чтобы хосты
без ICMP всё равно находились через TCP/80 или /443. Счётчики по методам — в `discovery_stats.json`.

**Disjoint** батчи (напр. `/22` → четыре `/24`) идут параллельно с `discover_concurrency`.
Пересекающиеся батчи — последовательно с `skip_known_alive`.

## Протокол сканирования (TCP / UDP / TCP+UDP)

Секция `ports:` в конфиге:

```yaml
ports:
  protocol: tcp        # tcp | udp | tcp_udp
  top_udp_ports: 100
  udp_probes: true     # naabu -uP
  custom_ports_file: scanner/inputs/ports.txt
  custom_udp_ports_file: scanner/inputs/ports_udp.txt
```

- **`tcp`** (по умолчанию) — naabu top/custom TCP → nmap `-sV` (+ `-O` при включении).
- **`udp`** — naabu `-p u:…` с `-uP` → nmap `-sU -sV` (OS detection для UDP отключён).
- **`tcp_udp`** — оба прохода; в `open_ports.txt` записи `host:port/tcp` и `host:port/udp`.

Checkpoint NSE: ключи `host/tcp` и `host/udp`. XML — в `nmap/tcp/` и `nmap/udp/`.

## Параллелизм и таймауты NSE

- `runtime.discover_concurrency` / `runtime.ports_concurrency` — число параллельных
  батчей naabu на этапах discovery и port-scan (по умолчанию `4`). `1` — строго
  последовательно. Эффективный pps ≈ `rate × concurrency`.
- `runtime.nse_concurrency` / `profiles.<name>.nse_concurrency` — число одновременно запускаемых процессов nmap. Увеличивайте под мощность хоста и допустимый сетевой шум.
- `runtime.nse_hosts_per_scan` — число хостов в одном процессе nmap (по умолчанию `8`). Меньше
  стартов nmap; checkpoint по-прежнему **по хостам**. `1` — один хост на процесс, как раньше.
- `runtime.nse_max_rate` / `profiles.<name>.nse_max_rate` — глобальный бюджет пакетов/сек на этап NSE/OS. Делится между параллельными процессами nmap (каждый получает `nse_max_rate / nse_concurrency` через `nmap --max-rate`). `0` — без ограничения (полагаемся на тайминг-шаблон). Так совокупный шум скана остаётся ограниченным независимо от уровня параллелизма.
- `runtime.nse_timeout_seconds` — таймаут nmap на один хост (отдельно от глобального `timeout_seconds`; максимум **600** с / 10 мин).
- `runtime.skip_nse` / флаг `--skip-nse` — пропустить NSE (L1: discover + ports + отчёты); затем `--resume` для обогащения.
- `nse_profiles.<name>.os_detection: true` включает `nmap -O --osscan-guess`. Требует raw-сокетов (`NET_RAW`/`NET_ADMIN` в Job/CronJob securityContext).

Артефакты по ОС и уязвимостям: `scanner/output/os_findings.json`, `scanner/output/script_findings.json`, `scanner/output/vulnerabilities.json`, `scanner/output/vulnerabilities.csv`.

## Проверка уязвимостей

Этап NSE выполняет проверку уязвимостей в зависимости от профиля `nse_profiles`:

- `vuln` — категория Nmap `vuln` **+ `vulners`**: сопоставление версий сервисов (`-sV`) с CVE через API vulners.com. Привязан к `balanced`/`fast`. **Требует исходящего доступа в интернет**.
- `vuln-offline` — категория `vuln` **+ `vulscan`**: офлайн-сопоставление CVE по локальным базам (интернет не нужен).
- `service_specific` — точечные скрипты (`http-*`, `ssl-cert`, `smb-*`, `ssh-*`, `dns-*`) без OS detection.
- `baseline` — только неинтрузивные `default,safe` (используется в `safe`).

Скрипты `nmap-vulners` и `vulscan` ставятся в образ на этапе сборки (`Dockerfile`, версии пинуются через build-args `NMAP_VULNERS_REF` / `VULSCAN_REF`).

Находки структурируются: для каждого `CVE` извлекается `cvss` и вычисляется `severity` (`critical >= 9.0`, `high >= 7.0`, `medium >= 4.0`, `low > 0`, иначе `unknown`). Скрипты со `State: VULNERABLE` без CVE тоже фиксируются (severity `unknown`). Список отсортирован по убыванию критичности.

## Когда выбирать `safe` / `balanced` / `fast`

- `safe`: чувствительная среда, есть риск деградации сети.
- `balanced`: рабочий режим по умолчанию для регулярных прогонов.
- `fast`: допустим повышенный шум и нужно сократить общее время скана.

## Полезные проверки

- Smoke-тест:

```bash
./scripts/smoke.sh
```

- Быстрый нагрузочный прогон по **вашей сети** (вне CI):

```bash
./scripts/load-test.sh 10.0.0.0/16
```

- **Синтетический load test** в docker (как в CI) — N контейнеров-мишеней, без интернета:

```bash
docker build -t network-scan-cli:ci .
tests/load/run.sh network-scan-cli:ci --hosts 16
tests/load/run.sh network-scan-cli:ci --hosts 32 --config tests/load/config-heavy.yaml \
  --run-id local-heavy --resume-test
```

Переиспользуемый composite action: `.github/actions/synthetic-load-test` (опциональная сборка
образа, artifact с метриками, summary в job).

| Запуск | Хосты | Конфиг | Resume |
|--------|------:|--------|--------|
| CI (каждый PR) | 16 | `tests/load/config.yaml` | нет |
| Workflow `Load test` (вручную) | 32 | `tests/load/config-heavy.yaml` | да |
| Workflow `Load test` (cron) | 32 | heavy | нет |
| `workflow_call` | задаёт вызывающий | задаёт вызывающий | задаёт вызывающий |

Переменные окружения для `tests/load/run.sh`: `CHECKPOINT_TIMEOUT_SEC`, `SCAN_TIMEOUT_SEC`,
`KEEP_WORK=1` (отладка, не удалять temp-директорию).

Ручной тяжёлый прогон: **Actions → Load test → Run workflow**.

- **Бенчмарк discovery** (локальная docker-лаборатория):

```bash
bench/up.sh [alive] [target_count] [cidr|list]   # поднять сеть + nginx-мишени
bench/run-discovery.sh [alive] [target_count]    # прогон с metrics JSON
bench/run-realistic.sh [alive]                   # preset: 400 alive, balanced, лимиты Docker
bench/down.sh                                    # снести сеть и контейнеры
```

Конфиги: `scanner/config/discovery-bench.yaml`, `discovery-bench-realistic.yaml`;
входы — `scanner/inputs/bench/`. Переменные — `bench/env.defaults` (`BENCH_SUBNET`,
`BENCH_CONFIG`, `BENCH_DOCKER_LIMITS=1` для `--memory 8g`). Метрики:
`scanner/output/bench/<run_id>-metrics.json`.

- Модульные тесты чистых функций и парсеров (валидация входа, группировка портов,
  разбор `host:port` с IPv6, режимы TCP/UDP, adaptive discovery и coverage tracker,
  деление rate-budget, сборка команды nmap, извлечение сервисов/ОС/CVE с CVSS и severity,
  валидация схемы конфига, per-run каталоги, проверка load-test результатов):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check scanner api tests
```

## Контейнерные образы (GHCR) и CI

- CI (`.github/workflows/ci.yml`) на каждый push в `main` и PR: `ruff`, `pytest` (3.11/3.12),
  сборка web-дашборда, проверка kustomize, job `image` (smoke, e2e, load×16, Trivy, SBOM).
- E2E (`tests/e2e/run.sh`): целевой `nginx:alpine` в приватной docker-сети, офлайн-конфиг,
  проверка alive / порт `80` / сервис / артефакты отчёта.
- Trivy: неблокирующий отчёт + гейт на **устранимые CRITICAL**; при публикации — SBOM + SLSA.
- Публикация (`.github/workflows/docker-publish.yml`) — мультиарх `linux/amd64` + `linux/arm64`
  для **обоих** образов по тегу `v*`, релизу или `workflow_dispatch`.
- Образы: `shapoclyack-aio` (по умолчанию), `shapoclyack-scanner`, `shapoclyack-api`.

```bash
docker pull ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.33
docker pull ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.33
docker pull ghcr.io/onixus/shapoclyack-api:shapoclyack-0.33
```

Подробности и полный пример запуска — в [README.md](README.md#container-image-ghcr).

### Воспроизводимые сборки (пины)

Образ запинен сквозно — пересборка байт-в-байт и защита от подмены апстрима/MITM:

- **Базовый образ** — по мультиарх **index digest** (`python:3.12-slim@sha256:...`).
- **dnsx / naabu** — по версии **и** по **sha256** на каждую арку (build-args
  `*_SHA256_AMD64/ARM64`); архив проверяется через `sha256sum -c` при сборке.
- **nmap-vulners / vulscan** — по конкретным **коммитам** (`NMAP_VULNERS_REF`, `VULSCAN_REF`).

Обновление пина: возьмите новый digest (`docker manifest inspect`), sha256 из checksum-файла
релиза и коммит (`git ls-remote ... HEAD`), затем обновите соответствующие `FROM @sha256` /
`ARG` в `Dockerfile`. Digest заморожен, поэтому периодически переустанавливайте его, чтобы
получать обновления безопасности базового образа.

## Артефакты вывода

При `runtime.per_run_output: true` (по умолчанию) файлы лежат в `scanner/output/runs/<run_id>/`:

- `run_meta.json`, `hostnames.json`, `discovery_stats.json`, `discovery_delta.json` (при `--delta`)
- `alive_ips.txt`, `alive_hosts.json` (alive + hostname)
- `open_ports.txt`, `findings.*`, `summary.{json,md,html}`
- `vulnerabilities.json`, `os_findings.json`, `script_findings.json`
- `nmap/*`, `logs/pipeline.log`

Полный список — в [README.md](README.md#output-artifacts).

## Эксплуатационные замечания

- Сканируйте только сети, где есть официальное разрешение.
- Высокий PPS может влиять на стабильность сети и вызывать алерты SIEM/IDS.
- Если Docker недоступен (`docker.sock`), запустите Docker Desktop/daemon.
- Для production желательно сохранять историю `scanner/output/summary.json` и сравнивать тренды по запускам.

## Лицензии

Собственный код проекта (пакет `scanner/`, `scripts/`, конфиги и документация)
**пока без лицензии**. До добавления лицензии действует копирайт по умолчанию, и права на
распространение у третьих лиц отсутствуют — добавьте лицензию (например, `MIT` или
`Apache-2.0`) в корень репозитория перед публикацией.

Образ контейнера **включает сторонние инструменты**, каждый под своей лицензией. Python-код
лишь вызывает их как отдельные исполняемые файлы / NSE-скрипты («простое объединение»),
поэтому не является производной работой от них. Однако **распространение собранного образа**
должно соответствовать всем перечисленным ниже лицензиям.

### Инструменты времени выполнения (внутри образа)

| Компонент | Версия | Лицензия | Примечание |
|---|---|---|---|
| Nmap | пакет Debian | Nmap Public Source License (NPSL) v0.95 | кастомная, производная GPLv2, с ограничениями на коммерческое/OEM-распространение — см. <https://nmap.org/npsl/> |
| naabu | `2.6.1` | MIT | ProjectDiscovery |
| dnsx | `1.2.3` | MIT | ProjectDiscovery |
| nmap-vulners | `NMAP_VULNERS_REF` | GPL-3.0 | NSE-скрипт поиска CVE |
| vulscan | `VULSCAN_REF` | GPL-3.0 | NSE-скрипт + локальные базы CVE |

### Базовый образ и пакеты ОС (`python:3.12-slim`, Debian)

| Компонент | Лицензия |
|---|---|
| Python (CPython) | PSF License Agreement |
| ca-certificates (набор CA Mozilla) | MPL-2.0 |
| curl | curl license (в стиле MIT/X11) |
| git | GPL-2.0 |
| jq | MIT |
| unzip (только на этапе сборки, удаляется из финального образа) | Info-ZIP License |

### Python-зависимости

| Пакет | Лицензия | Назначение |
|---|---|---|
| PyYAML | MIT | runtime |
| pydantic | MIT | runtime |
| pytest | MIT | dev/тесты |
| ruff | MIT | dev/линт |

### Замечания по соответствию

- В образе присутствуют компоненты под **GPL-3.0** (`nmap-vulners`, `vulscan`) и Nmap под **NPSL**.
  При распространении образа предоставляйте соответствующий исходный код или письменное
  предложение по требованиям GPL и соблюдайте условия NPSL (в частности, ограничения на
  коммерческое/OEM-распространение; для таких случаев у Nmap Project есть отдельная OEM-лицензия).
- Сканер управляет инструментами через subprocess / NSE и не линкуется с ними статически,
  поэтому ваш собственный код может использовать другую лицензию.
- Эта сводка носит информационный характер и **не является юридической консультацией**;
  перед распространением сверяйтесь с полными текстами лицензий каждого компонента.
