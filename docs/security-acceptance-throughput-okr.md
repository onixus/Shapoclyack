# Security acceptance — throughput OKR program (10 000 hosts/h)

Consolidated IB gate for ADRs **0009–0016** / FTT-PULSE-2026-052…059.
Companion to [FTT-PULSE-2026-059](ftt-pulse-2026-059-throughput-adr-acceptance.md)
and AGENTS.md §4.

**Program status:** ADR pack **Accepted** (0009–0015) / S6 **Rejected**
(0016) under FTT-059. Code-slice merges and image pins remain sibling PR
work — this document is the sign-off checklist, not a substitute for them.

---

### Протокол приемки функционала по ИБ

- **Функционал**: Throughput OKR 10 000 hosts/h (Path A inventory + Path B Stage2)
- **Версия / Коммит**: _(fill on sign-off)_
- **Дата проведения**: 2026-11-27 (pack); code sign-off TBD
- **Результаты проверок**:
  - SAST / Secrets: _(sibling CI on #681–#688 / GenDec #56)_
  - Тестовое покрытие: ADR index gate
    `tests/test_throughput_adr_acceptance.py`; feature tests per FTT
  - Валидация скриптов/контрактов: overlay v4 / KEDA topology per FTT-053/058
  - Соответствие ФТТ: ADR 0009–0015 Accepted; ADR 0016 Rejected (S6)
- **Решение**: **УТВЕРЖДЕНО К РЕЛИЗУ (ADR policy)** — runtime image release
  still requires sibling code merges + Architect sign-off below
- **Подпись Архитектора ИБ**: _(pending tracker task / merge of code slices)_

---

## Checklist (Security Gate)

### Architecture

- [x] Two-speed contract: Stage1 inventory OKR vs Stage2 assessment
      (ADR 0009 / 0012).
- [x] Scale on queue depth, not CPU (ADR 0011 / 0015); `maxReplicaCount ≤ 25`.
- [x] S6 privilege expansion **not** adopted as OKR primary (ADR 0016).
- [ ] Live estate `stage_timings.json` replaces synthetic Measure fixtures
      before production shard sizing (FTT-055).

### Code / trust boundaries (sibling FTTs)

- [ ] FTT-052: shard admission, enrich/chunk caps, serial defaults.
- [ ] FTT-053 / 058: opt-in KEDA overlay; no new Ingress; metrics low-cardinality.
- [ ] FTT-054: Stage2 opt-in, no recursion, server-only `stage2_*` fields.
- [ ] FTT-056 / 057: speed intents strip plugins/tls-enum/JARM; heavy keep ON.
- [ ] GenDec S1: `--enrich-concurrency` bounded; Zero Unsafe where applicable.

### CI Quality Gate

- [ ] Gitleaks / Semgrep / cargo-deny (GenDec) clean on release train.
- [ ] Shapoclyack pytest on touched areas + topology KEDA tests.
- [x] `pytest tests/test_throughput_adr_acceptance.py` — ADR pack consistency.

### Explicit non-goals this program accepts

- Single-pod full TLS+plugins+nuclei at 10 k hosts/h.
- hostNetwork / XDP / masscan-class TX as default sensor path.
- Automatic Stage2 for every `full` intent (remains opt-in).
