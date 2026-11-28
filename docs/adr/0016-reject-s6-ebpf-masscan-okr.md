# ADR 0016: Reject S6 (eBPF/XDP, masscan-class TX, in-pod SHM, WASM) as OKR primary

| | |
|---|---|
| **Status** | **Rejected** — onixus, 2026-11-27 (as 10 000 hosts/h OKR primary; [FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md)) |
| **Date** | 2026-11-27 |
| **Related** | [ADR 0009](0009-scan-throughput-okr.md), [throughput-okr-10k.md](../throughput-okr-10k.md), [FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md) |

## Context

Throughput OKR analysis ([throughput-okr-10k.md](../throughput-okr-10k.md)
hypothesis **S6**) considered privileged high-PPS paths:

- eBPF/XDP or masscan-class transmit for Stage1 discovery
- In-pod shared-memory meshes between scanner stages
- WASM plugin sandboxes replacing or wrapping Rhai

Pulse SYN already reaches ~10 k+ pps class for Stage1 inventory. After
S4–S5 (Stage2 enrichment queue, heuristics) the measured wall for the
OKR is enrichment and orchestration, not Stage1 packet rate
([ADR 0009](0009-scan-throughput-okr.md)).

## Decision drivers

- Hit **10 000 hosts/h** without expanding the sensor privilege / hostNetwork
  surface by default.
- Prefer work elimination and stage separation (accepted ADRs 0009–0015)
  over raw PPS increases.
- Keep hardening cost and ops complexity proportional to measured need.

## Options

| Option | Notes |
|---|---|
| Adopt S6 as OKR primary | Privilege + hardening dominate; wrong bottleneck after S4–S5 |
| Park S6 until Stage1 PPS is the measured wall (this ADR) | Matches ADR 0009 recommendation #5 |
| Ship a privileged opt-in overlay now | Premature; no live-estate PPS failure after S4–S5 |

## Decision

**Reject S6 as the primary path to the 10 000 hosts/h OKR.**

Revisit only if a representative estate `stage_timings.json` (Measure /
[FTT-PULSE-2026-055](../ftt-pulse-2026-055-estate-baseline-measure.md)) shows
Stage1 discovery PPS — not enrichment or queue depth — remains the wall
after ADRs 0010–0015 are in production.

## Consequences

- Product and ops continue on Path A (inventory + shards/KEDA) and Path B
  (Stage2 enrichment queue + `octo_jobs_stage2_queued` KEDA).
- No hostNetwork / CAP_NET_RAW expansion is implied by the throughput OKR.
- A future ADR may supersede this rejection with measured Stage1 PPS evidence;
  until then S6 stays out of the build order.
