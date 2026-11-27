# ФТТ: Throughput OKR — ADR acceptance pack + S6 reject

## 1. Паспорт требования
- **Идентификатор**: FTT-PULSE-2026-059
- **Инициатор / Автор**: Архитектор ИБ
- **Ответственный за реализацию**: Сеньор разработки
- **Ответственный за автоматизацию проверок**: Инженер DevSecOps
- **Статус**: Реализовано (ожидает merge / подпись приемки)
- **Связанные**: ADR 0009–0016, FTT-052…058, [throughput-okr-10k.md](throughput-okr-10k.md),
  [security-acceptance-throughput-okr.md](security-acceptance-throughput-okr.md)
- **Репозиторий**: shapoclyack (`docs/adr/`, FTT, pytest index gate)
- **База**: `main` (standalone acceptance pack; не redo S1–S5 / Measure code)

## 2. Границы доверия и потоки данных (Data Flow & Trust Boundaries)

- **Точки входа/выхода**: только документация ADR/FTT и тест, читающий
  `docs/adr/*.md`. Нет сетевого I/O, нет изменения claim/lease, KEDA или
  scanner defaults в этом срезе.
- **Уровни доверия**:
  - Trusted: committed ADR markdown в git.
  - Semi-trusted: ссылки на sibling PR/FTT (могут отставать до merge).
  - Untrusted: внешние URL issue tracker — только citation.
- **Диаграмма**:
  ```
  [Implemented FTTs 052–058 + Measure 055]
            |
            v
  [FTT-059 acceptance pack] ---> [ADR 0009–0015 Accepted]
                              |-> [ADR 0016 Rejected (S6)]
                              |-> [IB protocol + pytest index]
  ```

## 3. Моделирование угроз (STRIDE Analysis)

| Угроза (STRIDE) | Описание вектора атаки | Требование к защите (Контрмера) |
|---|---|---|
| **S** (Spoofing) | Подделка «Accepted» без владельца | Статус именует `onixus` + дату; merge PR = подпись владельца |
| **T** (Tampering) | Расхождение README ↔ файл ADR | `tests/test_throughput_adr_acceptance.py` сверяет статусы |
| **R** (Repudiation) | Неясно, что принято | Матрица ADR↔FTT↔PR в этом FTT + IB protocol |
| **I** (Information Disclosure) | Утечка целей/estate в acceptance | Запрет live target lists; только docs/fixture citations |
| **D** (Denial of Service) | «Acceptance» как оправдание privilege expansion (S6) | ADR 0016 Rejected — S6 не OKR primary |
| **E** (Elevation of Privilege) | Acceptance меняет runtime trust boundary | Этот FTT **не** меняет код сенсора/API/K8s |

## 4. Функциональные требования (Functional Requirements)

- **FR-01**: ADR **0009** → **Accepted** (модель OKR 10 k hosts/h).
- **FR-02**: ADR **0010–0015** → **Accepted** (S1/S3/sharding, S2 KEDA,
  S4 Stage2 queue, product defaults, S5 heuristics, Stage2 KEDA Path B).
- **FR-03**: ADR **0016** → **Rejected** — S6 (eBPF/XDP / masscan-class /
  SHM / WASM) не является primary path к OKR.
- **FR-04**: `docs/adr/README.md` индексирует 0009–0016 с итоговыми статусами.
- **FR-05**: `docs/throughput-okr-10k.md` build order отмечает shipped slices
  и паркует S6 со ссылкой на ADR 0016.
- **FR-06**: IB protocol
  [security-acceptance-throughput-okr.md](security-acceptance-throughput-okr.md)
  консолидирует DoD по FTT-052…059.
- **FR-07**: Pytest gate проверяет наличие файлов и согласованность
  Accepted/Rejected для throughput ADR pack.

## 5. Требования по информационной безопасности (Security Requirements)

- **SEC-01**: Acceptance pack не расширяет scope сканирования, claim path,
  overlay v4 или `maxReplicaCount`.
- **SEC-02**: Не вводит privileged/hostNetwork манифесты (см. ADR 0016).
- **SEC-03**: Не коммитит live estate paths / target lists.
- **SEC-04**: Статус *Accepted* не отменяет SEC-* sibling FTT — IB protocol
  остаётся обязательным чек-листом перед релизом образа.

## 6. Критерии приемки ИБ (Security Acceptance Criteria / DoD)

1. [x] ADR 0009–0015 содержат **Accepted** + `onixus, 2026-11-27`.
2. [x] ADR 0016 содержит **Rejected** и явно исключает S6 как OKR primary.
3. [x] README index согласован с файлами (pytest).
4. [x] throughput-okr-10k.md ссылается на FTT-059 / ADR 0016.
5. [x] IB protocol опубликован.
6. [ ] Подпись Архитектора ИБ в протоколе после merge sibling code PRs
      (#681–#688 / GenDec #56) — tracker task у координатора.

## 7. Матрица принятия (evidence)

| ADR | Slice | FTT | Sibling evidence |
|---|---|---|---|
| 0009 | OKR model | 055 + 059 | Measure harness; analysis doc |
| 0010 | S1 + S3 + sharding | 052 | GenDec #56; Shapoclyack #681 |
| 0011 | S2 KEDA shard depth | 053 | #682 |
| 0012 | S4 Stage2 queue | 054 | #684 |
| 0013 | Product defaults | 056 | #686 |
| 0014 | S5 heuristics | 057 | #687 |
| 0015 | Stage2 KEDA Path B | 058 | #688 |
| 0016 | Reject S6 | 059 | this pack |

## 8. Вне скоупа

- Merge sibling feature PRs / pin GenDec Pulse image.
- Live-estate packet benches (Measure `runs-dir` остаётся операторским).
- Dedicated Stage2 Deployment / raising `maxReplicaCount` > 25.
- Реализация S6 в любом виде.
