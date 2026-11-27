# ADR 0009: Throughput model for the 10 000 hosts/hour OKR

| | |
|---|---|
| **Status** | **Accepted** — onixus, 2026-11-27 ([FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md) acceptance pack) |
| **Date** | 2026-11-26 |
| **Related** | [scan-performance.md](../scan-performance.md), [throughput-okr-10k.md](../throughput-okr-10k.md), [FTT-PULSE-2026-055](../ftt-pulse-2026-055-estate-baseline-measure.md), [FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md), [scale-profile.md](../scale-profile.md), ADR 0003, ADR 0008, ADR 0010–0016 |

## Context

Estate-scale “full” scans (Pulse service probe with banners, TLS posture,
plugins, CVE/OS) take hours on large host sets. The product OKR is
**10 000 hosts per hour** on Kubernetes under Linux, with dynamic pod
management allowed.

Measured architecture facts (code, not benches):

1. **Pulse L4 is parallel**; post-L4 enrichment is **serial**
   (`fingerprint.rs`, `tls_probe.rs`, `script.rs`). Default Shapoclyack
   enables plugins and `tls_posture.enumerate_ciphers` → `--tls-enum`
   (`scanner/config/default.yaml`).
2. The Pulse adapter runs **one chunk at a time**
   (`scanner/pipeline/pulse_probe.py` serial `for` over `chunk_hosts=64`)
   with `--host-parallel` default **8** (profiles raise this; it only
   paces L4 host waves, not enrichment).
3. A sensor claims **one job** at a time (`agent/worker.py`).
   `FOR UPDATE SKIP LOCKED` gives concurrent agents **different jobs**,
   not shards of one job (`api/services/job_control.py`,
   `docs/architecture.md`). Executor StatefulSet replicas do not
   auto-shard an estate; API has HPA, executor does not.
4. `intent=inventory` already skips Pulse/nuclei for ports-only speed
   (`docs/scan-performance.md`). There is no mid-tier “L4 + banner,
   no TLS/plugins” intent today.

Companion analysis with hypothesis cycles, throughput models, and ranked
options: [throughput-okr-10k.md](../throughput-okr-10k.md).

## Decision drivers

- Hit **10 000 hosts/h** for an inventory / service-discovery outcome
  without requiring privileged XDP/masscan by default.
- Keep assessment-grade completeness (TLS enum, plugins, nuclei) available
  without pretending it shares the same single-pod wall clock as inventory.
- Fit existing claim/lease control plane and hardened K8s sensors
  (prefer queue depth scale-out over hostNetwork privilege expansion).
- Prefer work elimination and stage separation over raw PPS increases
  (see [scan-performance.md](../scan-performance.md)).

## Options

| ID | Option | Hits inventory OKR? | Hits full-assessment OKR on one pod? |
|---|---|---|---|
| A | Only raise `-c` / `host_parallel` / `chunk_hosts` | Unreliable; enrichment still serial | No |
| B | Parallelize Pulse enrichment (`--enrich-concurrency`) | Helps mid-tier | Partial (~2–3.5×) |
| C | Overlap Pulse chunk processes on one sensor | Helps | Partial |
| D | Two-tier: Stage1 inventory job; Stage2 enrichment queue + dynamic pods | **Yes** (Stage1) | Stage2 scales with pods |
| E | Auto-shard one estate into N claimable jobs + executor HPA/KEDA | **Yes** with N | **Yes** with larger N |
| F | ML port prediction / eBPF-XDP / in-pod SHM mesh | Optional later | Not primary |

## Recommendation

**Adopt a two-speed product contract (D + E), with engine parallelism (B+C)
as accelerators — not as the sole path.**

1. **Define OKR on Stage1 inventory throughput** (alive hosts + open ports,
   optionally light banner). Schedule assessment enrichment as Stage2
   work items claimed by enrichment-capable pods (pattern already used
   by the isolated screenshot worker, ADR 0008).
2. **Add control-plane sharding** so one estate can become N claimable
   sub-jobs; scale `scanner-executor` (and/or enrichment workers) on
   **queued shard / endpoint depth**, not CPU alone.
3. **Ship Pulse `--enrich-concurrency`** (bounded semaphore + shared
   rate) and adapter `pulse_chunk_concurrency` for single-sensor speed.
4. **Add a mid-tier intent** (working name `inventory_services`): Pulse
   banner on; plugins / tls-enum / nuclei off — between today’s
   `inventory` and `full`.
5. **Heuristics before ML**: historical∪top-N ports, skip JARM/tls-enum
   unless risk/intent requires them, silence-timeout shortening after
   RST. Defer ML models and XDP/masscan unless Stage1 PPS is the
   measured limiter after D–E.

Default shipped YAML should stop treating `enumerate_ciphers: true` and
`plugins: true` as the only path for every large job; speed profiles and
intents must be able to turn them off without dropping banners.

## Consequences

- Operators get an honest split: “hosts inventoried / hour” vs
  “hosts fully assessed / hour”.
- K8s gains a reason to run many scanner/enrichment pods on one estate.
- Pulse remains the service-probe engine; GenDec gains enrichment
  parallelism; Shapoclyack gains adapter concurrency + job fan-out.
- Full TLS+plugins+nuclei on one pod will still miss 10 k/h on dense
  estates — that is accepted and solved by sharding / Stage2, not by
  denying the measurement.

## Not decided here

- Exact shard size, merge schema, or parent/child job API fields.
- Whether Stage2 enrichment is the same `scanner-executor` image or a
  dedicated enrichment Deployment (screenshot-worker precedent).
- Changes to Nuclei scheduling beyond existing intent severity gates.
- GenDec release train / FTT identifiers for `--enrich-concurrency`
  (separate Pulse FTT).
- Product default YAML / intent shipping (Measure does not change defaults).

## Acceptance evidence

Accepted under [FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md).
Measure artifacts that grounded the decision:

| Citation | Path / command |
|---|---|
| Measure FTT | [FTT-PULSE-2026-055](../ftt-pulse-2026-055-estate-baseline-measure.md) |
| Analysis | [throughput-okr-10k.md](../throughput-okr-10k.md) |
| Fixture baseline README | [benchmarks/throughput-okr-estate-baseline](../benchmarks/throughput-okr-estate-baseline/README.md) |
| Calibration coefficients | `docs/benchmarks/throughput-okr-estate-baseline/calibration.json` |
| Harness | `python3 scripts/throughput_okr_measure.py fixtures` |
| Model + calibration | `python3 scripts/throughput_okr_model.py --calibration docs/benchmarks/throughput-okr-estate-baseline/calibration.json` |
| L4 vs enrich contract | Pulse `stats.elapsed_ms` = L4; adapter `pulse` stage = L4+enrich (`scanner/pipeline/pulse_probe.py`, GenDec report) |
| Completeness | `stats.l4_complete` vs `stats.complete` in `pulse/raw.json` |

Fixture medians (synthetic, order-of-magnitude): inventory **5000**/h,
inventory_services **4000**/h, enrichment **200**/h, full **125**/h —
supporting Path A (horizontal inventory) and Path B (Stage2 / shards for
assessment) without claiming a live estate measurement.
