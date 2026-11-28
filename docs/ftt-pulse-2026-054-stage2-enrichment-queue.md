# ФТТ: S4 — Stage2 enrichment queue (отложенное обогащение)

## 1. Паспорт требования
- **Идентификатор**: FTT-PULSE-2026-054
- **Инициатор / Автор**: Архитектор ИБ
- **Ответственный за реализацию**: Сеньор разработки
- **Ответственный за автоматизацию проверок**: Инженер DevSecOps
- **Статус**: Реализовано (ожидает ревью / приемки ИБ)
- **Связанные**: FTT-PULSE-2026-052 (S1/S3/sharding), FTT-PULSE-2026-053 (S2 KEDA),
  ADR 0008, ADR 0009, ADR 0010, ADR 0011, ADR 0012,
  [throughput-okr-10k.md](throughput-okr-10k.md)
- **Репозиторий**: shapoclyack (control plane + post-publication fan-out)

## 2. Границы доверия и потоки данных (Data Flow & Trust Boundaries)

- **Точки входа/выхода**:
  - Operator `POST /api/jobs` with `stage2_enrichment=true` on a Stage1 intent
    (`inventory` / `inventory_services`) → persisted in `jobs.scan_options`.
  - After Stage1 succeeds and the run is published: read `open_ports.txt` from
    the published run directory (trusted after admission + sensor upload fence).
  - Fan-out creates N claimable Stage2 jobs (`intent=enrichment`) offered on
    the existing NATS job-offer path; sensors claim via
    `FOR UPDATE SKIP LOCKED` (same trust boundary as ordinary agent jobs).
- **Уровни доверия**:
  - Trusted: Stage1 job row after admission; published run artifacts under the
    tenant's run ref; Stage2 `scan_options` written only by the control plane.
  - Semi-trusted: operator `stage2_enrichment` flag and Stage1 targets (scope-
    checked at admission).
  - Untrusted: raw endpoint lines inside `open_ports.txt` until parsed and
    re-admitted as Stage2 target lines (scope re-checked by `start_scan`).
- **Диаграмма**:
  ```
  [Stage1 job: inventory(_services) + stage2_enrichment]
        |
        v
  [sensor claim → discover/ports/(light Pulse)]
        |
        v
  [results upload → run published]
        |
        v
  [run_completion STAGE2 step]
        |  open_ports.txt → unique hosts
        |  partition → N jobs (≤64)
        v
  [Stage2 jobs: intent=enrichment, stage2_of=<parent>]
        |
        v
  [NATS offer → claim SKIP LOCKED → TLS/plugins/nuclei]
  ```

## 3. Моделирование угроз (STRIDE Analysis)

| Угроза (STRIDE) | Описание вектора атаки | Требование к защите (Контрмера) |
|---|---|---|
| **S** (Spoofing) | Подделка Stage2 job от имени другого tenant / parent | Stage2 создаётся только control plane из published parent; `tenant_id` / `agent_group` / `surface` наследуются; claim path без изменений |
| **T** (Tampering) | Клиент пишет `stage2_of` / `stage2_group_id` в request | Поля Stage2 meta только через `_stage2_meta` на сервере; не из body `StartScanRequest` |
| **R** (Repudiation) | Нельзя связать Stage2 с Stage1 | `scan_options.stage2_of`, `stage2_of_run_id`, `stage2_group_id` на каждом sibling; audit через job rows |
| **I** (Information Disclosure) | Секреты / полные target lists в метриках или логах | Gauge `octo_jobs_stage2_queued` — только счётчик; overlay без `SECRET_PATHS`; error notes без сырого open_ports dump |
| **D** (Denial of Service) | Взрыв Stage2 jobs с плотного estate | Caps: ≤64 Stage2 shards/group, ≤10 000 hosts fan-out, empty open_ports → no jobs; agent mode only; publication mark предотвращает double fan-out |
| **E** (Elevation of Privilege) | Stage2 обходит scope / поднимает fragile policy | Каждый child проходит полный `admit_scan` + scope; recursion запрещена (`stage2_enrichment` false на Stage2; jobs with `stage2_of` не фан-аутят дальше) |

## 4. Функциональные требования (Functional Requirements)

- **FR-01**: `StartScanRequest.stage2_enrichment` (bool, default false) хранится в
  `scan_options` Stage1 и входит в idempotency digest.
- **FR-02**: После успешной публикации Stage1 run control plane извлекает
  уникальные хосты из `open_ports.txt` и ставит в очередь Stage2 jobs с
  `intent=enrichment` (TLS posture + Pulse plugins + nuclei).
- **FR-03**: Stage2 jobs — durable Postgres rows + NATS offer; claim path =
  существующий `claim_job` (`SKIP LOCKED`), без нового протокола.
- **FR-04**: Хосты партиционируются round-robin в ≤ `MAX_STAGE2_SHARDS` (64)
  непустых jobs; группа связана через `stage2_group_id` / `stage2_index` /
  `stage2_count` / `stage2_of`.
- **FR-05**: Fan-out только при `execution=agent`, `status=succeeded`, флаге
  Stage1, и отсутствии `stage2_of` на parent (no recursion). Local mode
  отказывается от Stage2 (как sharding).
- **FR-06**: Intent `enrichment` в vocabulary intents; Stage2 jobs
  `quota_exempt=True` (платформенный follow-on после оплаченного Stage1).
- **FR-07**: Метрика `octo_jobs_stage2_queued` — число queued jobs с
  `scan_options.stage2_group_id` (cluster scrape gauge).
- **FR-08**: Idempotency: `publication_marks` step `stage2` — повторная
  публикация не создаёт вторую группу.

## 5. Требования по информационной безопасности (Security Requirements)

- **SEC-01 (Scope isolation)**: Каждый Stage2 job проходит admission/scope
  заново; цели — только хосты, наблюдавшиеся Stage1 в published artifacts.
- **SEC-02 (Resource bounds)**: Жёсткие caps на shards и hosts; best-effort
  hook не роняет terminal outcome Stage1 при ошибке fan-out.
- **SEC-03 (No secret leakage)**: Stage2 `scan_options` / overlay без секретов;
  метрики без tenant/target labels.
- **SEC-04 (AuthN/AuthZ)**: Claim/lease/ingest fence без ослабления; Stage2
  наследует `agent_group` parent'а.
- **SEC-05 (No recursion / Amplification)**: Stage2 jobs не ставят
  `stage2_enrichment`; parent с `stage2_of` не фан-аутит.

## 6. Критерии приемки ИБ (Security Acceptance Criteria / DoD)

1. [ ] Юнит-тесты: parse hosts, partition, should_enqueue guards, no-recursion,
   caps, enrichment intent overlay paths ⊆ OVERLAY_PATHS v4.
2. [ ] Метрика `octo_jobs_stage2_queued` в scrape catalogue / tests.
3. [ ] ruff + точечный pytest зелёные на затронутых suites.
4. [ ] FTT/ADR/throughput-okr согласованы.
5. [ ] Протокол приемки ИБ (§4.2 AGENTS.md) подписан Архитектором ИБ.
