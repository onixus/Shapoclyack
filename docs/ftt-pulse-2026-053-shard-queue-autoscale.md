# ФТТ: S2 — глубина очереди шардов и KEDA/HPA для scanner-executor

## 1. Паспорт требования
- **Идентификатор**: FTT-PULSE-2026-053
- **Инициатор / Автор**: Архитектор ИБ
- **Ответственный за реализацию**: Сеньор разработки
- **Ответственный за автоматизацию проверок**: Инженер DevSecOps
- **Статус**: Реализовано (ожидает ревью / приемки ИБ)
- **Связанные**: FTT-PULSE-2026-052 (S1/S3/sharding), ADR 0009, ADR 0010, ADR 0011,
  [throughput-okr-10k.md](throughput-okr-10k.md)
- **Репозиторий**: shapoclyack (метрика control plane + манифесты k8s)

## 2. Границы доверия и потоки данных (Data Flow & Trust Boundaries)

- **Точки входа/выхода**:
  - DB scrape на `GET /metrics`: `jobs.status`, `jobs.scan_options.shard_group_id`
    (trusted после admission).
  - Prometheus scrape → KEDA Prometheus trigger → HPA → scale StatefulSet
    `shapoclyack-scanner-executor` в `network-scan-executor`.
- **Уровни доверия**:
  - Trusted: строки jobs после admission/claim path; значения gauge после SQL.
  - Semi-trusted: URL Prometheus и пороги ScaledObject (операторский конфиг).
  - Untrusted: внешний доступ к `/metrics` без сетевого ограничения или без
    `OCTO_METRICS_TOKEN` — не новый риск; scaling не читает цели скана.
- **Диаграмма**:
  ```
  [shard_count create] --> [N queued Jobs + shard_group_id]
        |                         |
        v                         v
  [octo_jobs_shard_queued]   [octo_jobs_queued]
        \                         /
         \---- Prometheus ----/
                   |
                   v
           [KEDA ScaledObject]
                   |
                   v
      [HPA → StatefulSet scanner-executor]
                   |
                   v
           [claim FOR UPDATE SKIP LOCKED]
  ```

## 3. Моделирование угроз (STRIDE Analysis)

| Угроза (STRIDE) | Описание вектора атаки | Требование к защите (Контрмера) |
|---|---|---|
| **S** (Spoofing) | Подделка метрик / чужой Prometheus → ложный scale-out | Trigger бьёт во внутренний Prometheus; `OCTO_METRICS_TOKEN` + NetworkPolicy на API; overlay не открывает новый Ingress |
| **T** (Tampering) | Манипуляция `scan_options` для накрутки `shard_queued` | Метрика читает только persisted jobs после admission; клиент не пишет `shard_group_id` напрямую |
| **R** (Repudiation) | Нельзя объяснить, почему выросло число реплик | Series в каталоге observability; ScaledObject/HPA events в k8s audit |
| **I** (Information Disclosure) | Метрика утекает scope/targets | Gauge — только счётчики; без tenant/target labels (cluster-wide) |
| **D** (Denial of Service) | Взрыв реплик executor → NIC/FD/DB | `maxReplicaCount` ≤ 25; PDB `maxUnavailable: 1`; порог ≥ 1 queued job на реплику |
| **E** (Elevation of Privilege) | ScaledObject в чужом namespace / RBAC KEDA шире нужного | ScaledObject только в `network-scan-executor`; scaleTargetRef = существующий StatefulSet; без новых capabilities на pod |

## 4. Функциональные требования (Functional Requirements)

- **FR-01**: API экспортирует cluster-wide gauge `octo_jobs_shard_queued` —
  число jobs со `status=queued` и непустым `scan_options.shard_group_id`.
- **FR-02**: `octo_jobs_queued` / `octo_jobs_running` сохраняют прежнюю семантику;
  shard gauge считается в том же scrape-snapshot TTL.
- **FR-03**: Overlay `k8s/shapoclyack/overlays/executor-keda` (поверх `agents`)
  содержит KEDA `ScaledObject` на StatefulSet `shapoclyack-scanner-executor`
  с Prometheus triggers по `max(octo_jobs_shard_queued)` и `max(octo_jobs_queued)`,
  `threshold=1`, `minReplicaCount≥1`, `maxReplicaCount≤25`.
- **FR-04**: Манифесты остаются opt-in (нужны CRD KEDA); `kubectl kustomize`
  рендерит overlay без установленного оператора.
- **FR-05**: Документация (FTT, ADR 0011, observability) описывает формулу и
  placeholder `PROMETHEUS_URL`.

## 5. Требования по информационной безопасности (Security Requirements)

- **SEC-01 (Изоляция)**: Autoscaling не расширяет scope сенсора и не меняет
  claim/lease trust boundary.
- **SEC-02 (Ресурсы)**: Жёсткий потолок реплик; scale-down stabilization, чтобы
  не thrash’ить enrollment/leases.
- **SEC-03 (Метрики)**: Без high-cardinality / PII labels на новых series.
- **SEC-04 (Секреты)**: Token для Prometheus (если `OCTO_METRICS_TOKEN`) только
  через KEDA `TriggerAuthentication` / Secret; не в git.
- **SEC-05 (Apply safety)**: Overlay не входит в `prod`/`prod-ha` по умолчанию —
  apply без KEDA CRD не ломает базовые профили.

## 6. Критерии приемки ИБ (Security Acceptance Criteria / DoD)

1. [ ] Юнит-тесты: shard gauge в snapshot/collector; non-shard queued не
   увеличивает `octo_jobs_shard_queued`.
2. [ ] `docs/observability.md` и `tests/test_observability_assets.py` согласованы
   с новой series.
3. [ ] `kubectl kustomize k8s/shapoclyack/overlays/executor-keda` успешен;
   ScaledObject в `network-scan-executor`, target = StatefulSet executor.
4. [ ] ruff / точечный pytest зелёные на затронутых suites.
5. [ ] Протокол приемки ИБ (§4.2 AGENTS.md) подписан Архитектором ИБ.
