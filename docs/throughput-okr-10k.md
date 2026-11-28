# Throughput OKR: 10 000 hosts/hour

Analysis of why estate-scale full scans take hours, which bottlenecks
survive measurement against the code, and which solution hypotheses
reach the OKR on Kubernetes/Linux. Companion to
[scan-performance.md](scan-performance.md) and
[ADR 0009](adr/0009-scan-throughput-okr.md).

**OKR:** 10 000 hosts / hour ≈ **2.78 hosts/s**.

**Method:** hypothesis → analysis → verification → confirm/revise;
≤3 iterations per cycle. Evidence is file citations and Little’s-law
models; run `stage_timings.json` on a real estate before sizing shards.

---

## Architecture (current)

```text
Job (one claim) ──► sensor pod ──► pipeline
  discover / naabu ports
       │
       ▼
  pulse_probe: chunks of 64 hosts, SERIAL process loop
       │  Pulse L4: parallel (-c, --host-parallel)
       │  enrichment: SERIAL (version → TLS/JARM/enum → plugins)
       ▼
  nuclei / reports …
```

| Layer | Parallel today? | Default levers |
|---|---|---|
| Naabu / discover | Yes (batch workers) | `port_rate`, `ports_concurrency` |
| Pulse L4 | Yes (`buffer_unordered` + semaphore) | `-c`, `--rate`, `--host-parallel`, `--adaptive` |
| Pulse TLS / version / plugins | **No** — plain `for` loops | `tls_posture.enumerate_ciphers`, `plugins` |
| Pulse chunks (adapter) | **No** — one subprocess at a time | `chunk_hosts=64` |
| Estate across pods | **Different jobs only** | executor replicas; no auto-shard |

---

## Bottleneck hypotheses

### H1 — Serial TLS/version enrichment dominates Pulse wall clock

| Iter | Action | Result |
|---|---|---|
| 1 | Trace `main.rs` post-L4 path | version → TLS → scripts; L4 already parallel |
| 2 | Check concurrency primitives in enrich | none; JARM = 10 probes/endpoint; `--tls-enum` ≤30 s/endpoint; Shapoclyack defaults enable plugins + cipher enum |
| 3 | Throughput math | **PARTIALLY CONFIRMED** — owns ~90–98% of Pulse stage when TLS opens are common; irrelevant for sparse/no-open cohorts |

Order-of-magnitude (enrichment-bound, 1 TLS open/host, serial):

| Path | ≈ hosts/h |
|---|---|
| No enum, healthy (~1–4 s/host) | 900–3600 |
| With `--tls-enum` (~5–35 s/host) | 100–700 |
| + plugins dense | ≪ 500 |

**10 k/h fails** whenever TLS enrichment stays in-band and serial.

### H2 — Serial Pulse chunks + one job per sensor

| Iter | Action | Result |
|---|---|---|
| 1 | Read `pulse_probe.py` chunk loop + claim path | serial `_probe_chunk`; one job per agent |
| 2 | Model hosts/h ≈ `host_parallel × 3600 / T_wave` | hp=8 needs \(T_{wave} ≲ 2.9\) s without plugins to clear OKR |
| 3 | K8s replicas | parallelize **jobs**, not chunks of one job → **CONFIRMED** |

Raising `chunk_hosts` alone saves process-start overhead (minutes at 10 k
hosts), not an order of magnitude.

### H3 — L4 window alone blocks the OKR

| Iter | Action | Result |
|---|---|---|
| 1 | \(pps = \min(R, c/t_{eff})\) | default connect silent ≈ 625 pps |
| 2 | 10 k × top-100 vs 1–1024 | top-100 &lt;1 h if concurrency does not collapse; 1–1024 without `-D` fails under normal ceilings |
| 3 | Adaptive floor 16 on silence | can drop to ~20 pps → **REVISED** |

**L4 is the limiter for naive wide inventory without discovery / after
adaptive collapse.** For product “full” scans (Pulse on known opens),
enrichment and orchestration dominate.

---

## Solution hypotheses

### S1 — Parallel Pulse enrichment (`--enrich-concurrency`)

**CONFIRM.** Highest ROI engine change in GenDec.

- Touch: `tls_probe.rs`, `fingerprint.rs`, optional `script.rs`, `cli.rs`;
  pass-through in `pulse_probe.py` / schema / `default.yaml`.
- Uplift: ~2–3.5× on enrichment-heavy Pulse wall at E=8; keep shared
  rate + FD budget; fragile/OT stay at E=1.

### S2 — Control-plane job sharding + executor scale-out

**CONDITIONAL CONFIRM** — required for reliable estate OKR.

- Fan-out on create → N claimable shards; merge on completion
  (FTT-052 / ADR 0010).
- Scale pods on **queued shard depth** (HPA/KEDA), not CPU —
  `octo_jobs_shard_queued` + `overlays/executor-keda` (FTT-053 / ADR 0011);
  Stage2 enrichment depth `octo_jobs_stage2_queued` is an explicit Path B
  trigger on the same overlay (FTT-058 / ADR 0015).
- If one sensor full ≈ 400–800 hosts/h → need N ≈ 13–25 for assessment;
  inventory mid-tier ≈ 2–5 k/h/sensor → N ≈ 2–5.

### S3 — Overlap Pulse processes + mid-tier intent

**CONFIRM** chunk concurrency; **REJECT** “only raise `host_parallel`”
(fast already 32; L4 underfills after naabu). **CONDITIONAL** new
intent `inventory_services` (banner on, plugins/tls-enum/nuclei off).

### S4 — Two-tier / deferred enrichment

**CONFIRM** as primary product shape for the OKR.

- Stage1: discover + ports (+ optional light banner) → inventory SLO.
- Stage2: open endpoints as claimable work → TLS/plugins/CVE/nuclei
  pods scale under load (screenshot-worker pattern, ADR 0008;
  KEDA on `octo_jobs_stage2_queued` — FTT-058 / ADR 0015).

### S5 — Heuristics (not ML-first)

**CONFIRM heuristics; REJECT ML-first.** **Shipped** in
[FTT-057](ftt-pulse-2026-057-heuristics-s5.md) /
[ADR 0014](adr/0014-throughput-heuristics-s5.md).

- Historical∪top-N ports, skip JARM/tls-enum unless risk/intent requires,
  shorten silence timeouts after RST evidence.
- ML port models later if labeled history exists — not blocking.

### S6 — eBPF/XDP, masscan-class TX, in-pod SHM, WASM plugins

**REJECT as OKR primary** — recorded in
[ADR 0016](adr/0016-reject-s6-ebpf-masscan-okr.md) (FTT-059 acceptance pack).
Pulse SYN already ~10 k+ pps class for Stage1; privilege and hardening cost
dominate. Revisit only if Stage1 PPS (not enrichment) remains the measured
wall after S4–S5.

---

## Paths that hit 10 000 hosts/h

Assumptions: Linux sensor, top-100 or known opens, mixed RTT, no fragile
policy. Numbers are models — validate with `stage_timings.json`.

### A — Inventory / mid-tier (L4 + banner)

| Lever | Action |
|---|---|
| Intent | `inventory` (ports-only) or new `inventory_services` |
| S3 | `pulse_chunk_concurrency=2–4` when Pulse runs |
| S1 | optional enrich concurrency for version probes |
| S2 | 2–4 executor replicas or auto-shards |

**Expected:** ~3–8 k hosts/h per strong sensor; **2–4 pods → ≥10 k**.

### B — Full TLS + plugins (+ nuclei)

| Lever | Action |
|---|---|
| S1 + S3 | ~5–10× vs today’s serial Pulse path — often still &lt;10 k alone |
| S2 / S4 | **Required** — N≈15–30 shards or Stage2 pod pool |
| Nuclei | Keep behind `vuln`/`full` schedule; do not fold into inventory OKR |

**Expected single pod:** hundreds of hosts/h with tls-enum+plugins.
**Reliable 10 k assessed hosts/h:** horizontal Stage2, not one process.

---

## Recommended build order

1. **Measure** a representative estate: `stage_timings.json` + Pulse
   `stats.l4_complete` vs full complete — **harness shipped** (FTT-055 / #685);
   live calibration remains an **operator** action (stand `runs-dir` before production shard sizing).
2. **Ship mid-tier intent + turn off default cipher-enum/plugins for
   speed intents** — **shipped** (FTT-056 / ADR 0013 / #686).
3. **GenDec `--enrich-concurrency`** (S1) — **shipped** (GenDec #56 / FTT-052).
4. **Adapter `pulse_chunk_concurrency`** (S3) — **shipped** (#681 / FTT-052 /
   ADR 0010).
5. **Job sharding + KEDA/HPA on queue depth** (S2) — **shipped** (FTT-053 /
   ADR 0011 / #682). **Stage2 enrichment jobs** (S4) — **shipped** (FTT-054 /
   ADR 0012 / #684). **Stage2 KEDA Path B trigger** — **shipped** (FTT-058 /
   ADR 0015 / #688).
6. Heuristics S5 — **shipped** (FTT-057 / ADR 0014 / #687). **S6 Rejected**
   as OKR primary ([ADR 0016](adr/0016-reject-s6-ebpf-masscan-okr.md) / FTT-059).
7. **ADR acceptance pack** — **shipped** (FTT-059): ADRs 0009–0015 Accepted;
   ADR 0016 Rejected; IB protocol in
   [security-acceptance-throughput-okr.md](security-acceptance-throughput-okr.md).
8. **Engineering closure** — FTT-060: no further code P0; open human actions in
   [throughput-okr-closure-checklist.md](throughput-okr-closure-checklist.md)
   (single rollup PR instead of the stacked train, Pulse image pin, live Measure, IB sign-off).

---

## Simulation helper

```bash
python3 scripts/throughput_okr_model.py
python3 scripts/throughput_okr_model.py \
  --calibration docs/benchmarks/throughput-okr-estate-baseline/calibration.json
```

Prints hosts/hour under the models above for default / balanced / fast
and for enrichment serial vs parallel, then (with `--calibration`) the
Measure medians. It does not send packets.

---

## Measure harness

```bash
# Synthetic pack (CI / ADR citations)
python3 scripts/throughput_okr_measure.py fixtures

# Stand runs (read-only); cohort is an explicit label
python3 scripts/throughput_okr_measure.py runs-dir "$OCTO_OUTPUT_DIR/runs" \
  --cohort inventory_services --out /tmp/midtier.json

# Same entry via scale_measure
python3 -m tests.fixtures.scale_measure okr-baseline \
  docs/benchmarks/throughput-okr-estate-baseline/fixtures
```

Per run the harness reports `hosts_per_hour`, `top_stages`, Pulse
`l4_complete` / `complete`, and enrichment share
(`1 − l4_wall / pulse_stage`). Cohort roll-ups feed
`calibration.json` for the model below.

| Fixture cohort | Median hosts/h | Notes |
|---|---|---|
| inventory | 5000 | Ports-only; Path A needs ≥2 sensors for OKR |
| inventory_services | 4000 | Enrich share ~75% of Pulse stage |
| enrichment | 200 | L4 complete even when full `complete` false |
| full | 125 | Nuclei appears in `top_stages` |

