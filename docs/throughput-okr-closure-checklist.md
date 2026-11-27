# Throughput OKR — engineering closure checklist

**Program:** 10 000 hosts/hour ([throughput-okr-10k.md](throughput-okr-10k.md),
ADR 0009).
**Gate:** [FTT-PULSE-2026-060](ftt-pulse-2026-060-throughput-okr-engineering-closure.md).
**Verdict (engineering):** **CLOSED** — no further meaningful code P0 on the
OKR path. S6 remains **Rejected** (ADR 0016 / FTT-059). Remaining work is
**human / operator / release**, not new scanner features.

Companion IB protocol (sibling ADR acceptance pack #689):
[security-acceptance-throughput-okr.md](security-acceptance-throughput-okr.md).

---

## 1. Engineering slices already delivered (do not redo)

| Slice | Evidence (open PR / merged) | FTT / ADR |
|---|---|---|
| Measure harness | [#685](https://github.com/onixus/Shapoclyack/pull/685) | FTT-055 |
| Product defaults (speed intents) | [#686](https://github.com/onixus/Shapoclyack/pull/686) | FTT-056 / ADR 0013 |
| S1 enrich concurrency (GenDec) | GenDec #56 (merged) | FTT-052 / ADR 0010 |
| S3 chunk overlap + sharding | [#681](https://github.com/onixus/Shapoclyack/pull/681) | FTT-052 / ADR 0010 |
| S2 shard-queue KEDA | [#682](https://github.com/onixus/Shapoclyack/pull/682) | FTT-053 / ADR 0011 |
| S4 Stage2 enrichment queue | [#684](https://github.com/onixus/Shapoclyack/pull/684) | FTT-054 / ADR 0012 |
| S5 heuristics | [#687](https://github.com/onixus/Shapoclyack/pull/687) | FTT-057 / ADR 0014 |
| Stage2 KEDA Path B | [#688](https://github.com/onixus/Shapoclyack/pull/688) | FTT-058 / ADR 0015 |
| ADR acceptance + S6 Reject | [#689](https://github.com/onixus/Shapoclyack/pull/689) | FTT-059 / ADR 0016 |
| Engineering closure (this doc) | this PR | FTT-060 |

**Explicit non-goals (do not invent):**

- S6 eBPF/XDP / masscan-class TX / in-pod SHM / WASM plugins as OKR primary.
- Single-pod full TLS+plugins+nuclei at 10 k hosts/h.
- New enrichment engine P0 beyond shipped S1–S5 / Stage2 path.

---

## 2. Open human actions (required for program close)

### A. Merge stack bottom-up (superseded by one rollup)

Do **not** merge the stacked train separately — that re-runs PR Gate for days.
The dependency chain is already combined, bottom-up, in the rollup branch
`feat/throughput-okr-rollup` (one PR to `main`):

1. [x] **#681** `cursor/s1-s3-sharding-throughput-6501` → included in the rollup
2. [x] **#682** `cursor/s2-shard-queue-keda-d4ac` → included (was based on `#681`)
3. [x] **#684** `cursor/s4-stage2-enrichment-queue-6501` → included (was based on `#682`)
4. [x] **#688** `cursor/stage2-keda-enrichment-6501` → included (was based on `#684`)

### B. Parallel `main`-based docs/feature PRs

Included in the same rollup (conflicts with the stack resolved there):

5. [x] **#685** Measure estate baseline harness
6. [x] **#686** Product defaults — speed intents
7. [x] **#687** S5 throughput heuristics
8. [x] **#689** ADR acceptance pack (0009–0015 Accepted; 0016 Rejected)
9. [x] **#690** FTT-060 closure checklist
10. [x] **#679** unpublished screenshot worker kept out of a default install

### C. Release / operator (outside feature invent)

10. [ ] **GenDec Pulse image pin** — rebuild/pin sensor image (or
      `scripts/install-pulse.sh` / digest pin) that includes GenDec
      `--enrich-concurrency` from merged GenDec #56. **Do not invent a
      digest in this docs PR.**
11. [ ] **Live-estate Measure calibration** — operator runs Measure harness
      with real `runs-dir` / `stage_timings.json` (FTT-055); replace
      synthetic fixtures before production shard sizing. **No live targets
      in git.**
12. [ ] **Architect IB sign-off** — complete checkboxes and signature in
      [security-acceptance-throughput-okr.md](security-acceptance-throughput-okr.md)
      on the **merged** code train (fill commit SHA + date). Parent creates
      tracker task.

---

## 3. Done when

- [ ] Merge stack A + parallel B landed on `main` (or explicitly superseded).
- [ ] Pulse image pin (C10) published for the release train.
- [ ] At least one calibrated estate Measure artifact reviewed (C11) —
      stored outside public git if it contains targets.
- [ ] IB protocol signed (C12).
- [ ] No open engineering P0 filed against this OKR except regressions /
      bugfixes.

Until then: **engineering closed / release open**.
