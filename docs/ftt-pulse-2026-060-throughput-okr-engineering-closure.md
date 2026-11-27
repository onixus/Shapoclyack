# ФТТ: Throughput OKR — engineering closure (no further code P0)

## 1. Паспорт требования
- **Идентификатор**: FTT-PULSE-2026-060
- **Инициатор / Автор**: Архитектор ИБ / Tech Lead
- **Ответственный за реализацию**: координатор релиза (human merge + IB)
- **Ответственный за автоматизацию проверок**: Инженер DevSecOps (CI на sibling PRs)
- **Статус**: Реализовано (docs checklist; ожидает human actions)
- **Связанные**: FTT-052…059, ADR 0009–0016, [throughput-okr-10k.md](throughput-okr-10k.md),
  [throughput-okr-closure-checklist.md](throughput-okr-closure-checklist.md),
  [security-acceptance-throughput-okr.md](security-acceptance-throughput-okr.md) (sibling #689)
- **Репозиторий**: shapoclyack (`docs/` + pytest gate)
- **База**: `main` (standalone; не redo S1–S5 / Measure / KEDA / ADR pack)

## 2. Границы доверия и потоки данных

- **Точки входа/выхода**: только документация и тест наличия чек-листа.
  Нет изменений scanner/API/K8s/runtime image digests в этом срезе.
- **Уровни доверия**:
  - Trusted: committed checklist markdown.
  - Semi-trusted: номера sibling PR (#681–#689, GenDec #56) — могут
    меняться до merge; checklist перечисляет intent merge order.
  - Untrusted: live estate paths — **запрещены** в git.
- **Диаграмма**:
  ```
  [S1–S5 + Measure + Product defaults + Stage2 KEDA + ADR pack]
                         |
                         v
            [FTT-060 engineering CLOSED]
                         |
         +---------------+---------------+
         v               v               v
   merge stack     Pulse image pin    Architect IB
   bottom-up       (operator/CI)      sign-off
                   live Measure
  ```

## 3. Моделирование угроз (STRIDE)

| Угроза (STRIDE) | Описание | Контрмера |
|---|---|---|
| **S** | «Closed» без владельца merge | Checklist требует human merge + IB подпись |
| **T** | Изобретение нового P0 (S6 / privilege) | Явный non-goal; ADR 0016 Rejected |
| **R** | Неясный порядок merge | Bottom-up stack в checklist |
| **I** | Commit live targets / runs-dir | Запрет; только operator action вне git |
| **D** | Closure как оправдание hostNetwork/XDP | SEC-01: no privilege manifests |
| **E** | Docs PR меняет trust boundary runtime | Этот FTT **не** меняет код сенсора |

## 4. Функциональные требования

- **FR-01**: Зафиксировать, что **engineering P0 program** по
  [throughput-okr-10k.md](throughput-okr-10k.md) **закрыт** — S1–S5,
  Measure harness, product defaults, Stage2 KEDA, ADR acceptance shipped
  as PRs; S6 Rejected.
- **FR-02**: Опубликовать
  [throughput-okr-closure-checklist.md](throughput-okr-closure-checklist.md)
  с открытыми **human** действиями (не новый feature scope).
- **FR-03**: Обновить build-order в `throughput-okr-10k.md`: указать
  engineering closed → human closure path.
- **FR-04**: Pytest gate проверяет наличие checklist и обязательных секций.
- **FR-05**: **Не** пинить Pulse image digest без release artifact; pin —
  human/CI после merge GenDec train.

## 5. Требования по ИБ

- **SEC-01**: Closure docs не добавляют privileged / hostNetwork / XDP.
- **SEC-02**: Не коммитит live estate / `runs-dir` содержимое.
- **SEC-03**: Не ослабляет sibling SEC-* (FTT-052…059); IB protocol
  остаётся обязательным до runtime release.
- **SEC-04**: Image pin (когда выполняется) — digest-only, существующий
  hardening path; вне scope этого docs PR.

## 6. Критерии приемки (DoD)

1. [x] Checklist enumerates merge stack bottom-up (#681→#682→#684→#688).
2. [x] Checklist lists parallel main-based PRs (#685–#687, #689, this).
3. [x] Checklist lists IB sign-off + live Measure + Pulse image pin.
4. [x] Explicit non-goal: no S6 / no invented enrichment P0.
5. [x] `tests/test_throughput_okr_closure.py` passes.
6. [ ] Human merges + Architect IB signature — **tracker task** (parent).
