# ФТТ: Stage2 — KEDA/HPA на глубине очереди enrichment (`octo_jobs_stage2_queued`)

## 1. Паспорт требования
- **Идентификатор**: FTT-PULSE-2026-058
- **Инициатор / Автор**: Архитектор ИБ
- **Ответственный за реализацию**: Сеньор разработки
- **Ответственный за автоматизацию проверок**: Инженер DevSecOps
- **Статус**: Реализовано (ожидает ревью / приемки ИБ)
- **Связанные**: FTT-PULSE-2026-053 (S2 KEDA), FTT-PULSE-2026-054 (S4 Stage2
  queue), ADR 0011, ADR 0012, ADR 0015, [throughput-okr-10k.md](throughput-okr-10k.md)
- **Репозиторий**: shapoclyack (`overlays/executor-keda` + docs)
- **Стек**: поверх #684 / `cursor/s4-stage2-enrichment-queue-6501` (метрика
  уже экспортируется)

## 2. Границы доверия и потоки данных (Data Flow & Trust Boundaries)

- **Точки входа/выхода**:
  - Scrape gauge `octo_jobs_stage2_queued` (FTT-054) — число `queued` jobs с
    `scan_options.stage2_group_id` (trusted после admission / Stage2 fan-out).
  - Prometheus → KEDA Prometheus trigger → HPA → scale StatefulSet
    `shapoclyack-scanner-executor` в `network-scan-executor`.
- **Уровни доверия**:
  - Trusted: persisted Stage2 jobs после control-plane fan-out.
  - Semi-trusted: `PROMETHEUS_URL`, порог Stage2 trigger (операторский конфиг).
  - Untrusted: внешний `/metrics` без NetworkPolicy / token — не новый риск;
    scaling не читает цели скана.
- **Диаграмма**:
  ```
  [Stage1 inventory publish + stage2_enrichment]
            |
            v
  [N queued Stage2 jobs + stage2_group_id]
            |
            v
  [octo_jobs_stage2_queued] ----+
  [octo_jobs_shard_queued]  ----+--> Prometheus --> KEDA ScaledObject
  [octo_jobs_queued]        ----+                       |
                                                        v
                                         [HPA → scanner-executor]
                                                        |
                                                        v
                                              [claim SKIP LOCKED]
  ```

## 3. Моделирование угроз (STRIDE Analysis)

| Угроза (STRIDE) | Описание вектора атаки | Требование к защите (Контрмера) |
|---|---|---|
| **S** (Spoofing) | Подделка PromQL / чужой Prometheus → ложный scale-out | Trigger → внутренний Prometheus; `OCTO_METRICS_TOKEN` + NetworkPolicy на API; overlay без нового Ingress |
| **T** (Tampering) | Клиент пишет `stage2_group_id` чтобы накрутить gauge | Поле сервер-only (FTT-054); scrape читает только persisted jobs |
| **R** (Repudiation) | Нельзя объяснить scale-out после Stage2 fan-out | Series в observability; ScaledObject/HPA events |
| **I** (Information Disclosure) | Метрика утекает tenant/targets | Cluster-wide counter без labels |
| **D** (Denial of Service) | Dense Stage2 fan-out → взрыв реплик | `maxReplicaCount` ≤ 25 (общий потолок S2); PDB; opt-in overlay |
| **E** (Elevation of Privilege) | Отдельный Stage2 pool с шире RBAC | **Не** вводим отдельный Deployment/ScaledObject в этом FTT — тот же StatefulSet claim path |

## 4. Функциональные требования (Functional Requirements)

- **FR-01**: Overlay `k8s/shapoclyack/overlays/executor-keda` добавляет
  Prometheus trigger `max(octo_jobs_stage2_queued)` с `threshold=1` и
  `activationThreshold=1` наряду с shard/queued triggers (FTT-053).
- **FR-02**: Hand-apply example
  `examples/executor-keda-scaledobject.example.yaml` зеркалит тот же trigger.
- **FR-03**: `scaleTargetRef` остаётся StatefulSet
  `shapoclyack-scanner-executor` — Stage2 drain через существующий claim path
  (ADR 0012); отдельный enrichment Deployment **не** вводится.
- **FR-04**: `maxReplicaCount` ≤ 25; `minReplicaCount` ≥ 1; поведение
  scale-up/down без изменений относительно FTT-053.
- **FR-05**: Документация (FTT-058, ADR 0015, observability, throughput OKR)
  описывает Path B scale signal и независимость порога Stage2.
- **FR-06**: Topology test проверяет наличие Stage2 metricName + query в
  отрендеренном ScaledObject.

## 5. Требования по информационной безопасности (Security Requirements)

- **SEC-01 (Изоляция)**: Autoscaling не расширяет scope сенсора и не меняет
  claim/lease trust boundary Stage2 (FTT-054 SEC-*).
- **SEC-02 (Ресурсы)**: Общий потолок реплик S2; Stage2 trigger не поднимает
  `maxReplicaCount` выше 25 без отдельного capacity review.
- **SEC-03 (Метрики)**: Без новых high-cardinality labels.
- **SEC-04 (Секреты)**: `PROMETHEUS_URL` / TriggerAuthentication — как в
  FTT-053; секреты не в git.
- **SEC-05 (Apply safety)**: Overlay остаётся opt-in; не входит в
  `prod`/`prod-ha` по умолчанию.

## 6. Критерии приемки ИБ (Security Acceptance Criteria / DoD)

1. [ ] `kubectl kustomize k8s/shapoclyack/overlays/executor-keda` содержит
   trigger `octo_jobs_stage2_queued` / `max(octo_jobs_stage2_queued)`.
2. [ ] `tests/test_k8s_topology.py` — Stage2 metric в expected set.
3. [ ] ADR 0015 + обновления ADR 0011/0012 согласованы; S6 по-прежнему
   parked/rejected как OKR primary.
4. [ ] ruff не затронут (docs/YAML); точечный pytest topology зелёный.
5. [ ] Протокол приемки ИБ (§4.2 AGENTS.md) подписан Архитектором ИБ.
