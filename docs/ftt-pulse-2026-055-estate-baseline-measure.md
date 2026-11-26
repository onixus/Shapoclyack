# FTT-PULSE-2026-055: Representative estate baseline (Measure)

| | |
|---|---|
| **ID** | FTT-PULSE-2026-055 |
| **Author** | Security Architect / throughput OKR |
| **Implementer** | Senior development |
| **Automation** | DevSecOps (pytest on fixtures; no live packets in CI) |
| **Status** | Implemented (harness + fixture baselines) |
| **Related** | [throughput-okr-10k.md](throughput-okr-10k.md), [ADR 0009](adr/0009-scan-throughput-okr.md), [scan-performance.md](scan-performance.md) |

## 1. Scope

Repeatable **measurement** of estate-scale scan throughput from artifacts a
sensor already writes — not product default changes, not S1/S3/S2/S4
implementation.

| In scope | Out of scope |
|---|---|
| Parse `stage_timings.json` → wall, `top_stages`, hosts/hour | Changing default YAML / intents |
| Pulse `stats.l4_complete` vs `stats.complete` | GenDec `--enrich-concurrency` (S1) |
| L4 vs enrichment wall split from `stats.elapsed_ms` + pulse stage | Chunk concurrency / sharding / Stage2 (S3/S2/S4) |
| Cohorts: `inventory`, `inventory_services`, `enrichment`, `full` | Live packet benches in CI |
| Calibrate `scripts/throughput_okr_model.py` from baselines | ADR 0009 owner acceptance (citations only) |

## 2. Trust boundaries

| Input | Trust | Rule |
|---|---|---|
| Operator `runs/` directories | Semi-trusted | Read-only; no target lists committed |
| Committed fixture baselines | Trusted (synthetic) | Marked `synthetic`; RFC 5737 / loopback only |
| Pulse `pulse/raw.json` stats | Untrusted shape | Missing keys → `null` fields, never invent completeness |

No network I/O in the harness. No secrets in argv or committed JSON.

## 3. STRIDE (measure path only)

| Threat | Countermeasure |
|---|---|
| **T** Tampered timings | Schema checks; refuse non-dict / non-numeric durations |
| **I** Target disclosure | Docs forbid committing live estate paths; fixtures use docs addresses |
| **D** Huge runs-dir | Stream per run; skip synthetic/`--resume` like `scale_measure runs-dir` |
| **R** Unreproducible claim | Every report carries `environment` + git commit + fixture digest |

## 4. Functional requirements

- **FR-01**: Given a run directory with `alive_hosts.json` + `stage_timings.json`,
  emit `hosts`, `pipeline_wall_sec`, `hosts_per_hour`, `top_stages`.
- **FR-02**: When `pulse/raw.json` has `stats`, emit `l4_complete`, `complete`,
  `pulse_elapsed_ms` (L4 wall per Pulse contract), and
  `enrichment_wall_sec ≈ max(0, pulse_stage_sec − elapsed_ms/1000)`.
- **FR-03**: Cohort label is an explicit CLI/metadata field
  (`inventory` | `inventory_services` | `enrichment` | `full`), not inferred
  from incomplete stage lists alone.
- **FR-04**: Fixture pack under
  `docs/benchmarks/throughput-okr-estate-baseline/` reproduces a stable
  summary JSON used to calibrate the Little’s-law model.
- **FR-05**: `python3 scripts/throughput_okr_model.py --calibration <summary.json>`
  prints model vs measured hosts/h for the same cohorts.

## 5. Security requirements

- **SEC-01**: Harness is read-only against operator paths; writes only to
  `--out` the operator names.
- **SEC-02**: No subprocess scanners; no `eval` of JSON values.
- **SEC-03**: Fixture hosts stay in documentation / loopback ranges.

## 6. Acceptance (DoD)

1. [x] Unit tests for hosts/h, L4/enrich split, completeness, malformed input.
2. [x] Fixture baseline summary regenerates bit-stable under the harness.
3. [x] Docs link Measure → harness → ADR 0009 citation section.
4. [x] Product defaults unchanged in this slice.
