# ADR 0011: Executor autoscaling on shard / job queue depth (S2)

- **Status**: Proposed (implementation under FTT-PULSE-2026-053; owner acceptance pending)
- **Date**: 2026-11-26
- **Related**: [FTT-PULSE-2026-053](../ftt-pulse-2026-053-shard-queue-autoscale.md),
  [ADR 0010](0010-throughput-s1-s3-sharding.md), [ADR 0009](0009-scan-throughput-okr.md),
  [throughput-okr-10k.md](../throughput-okr-10k.md)

## Context

ADR 0010 landed claimable job shards (`shard_count`) but left KEDA scaling
formulas undecided. Path A of the 10 k hosts/h OKR needs 2–4 executor pods; Path
B needs larger N. CPU-based HPA (API pattern in `overlays/prod-ha`) is the wrong
signal for scanners: a queued shard spends almost no CPU until claimed.

## Decision drivers

- Scale on **queued claimable work**, not CPU.
- Preserve StatefulSet identity / enrollment (`shapoclyack-scanner-executor`).
- Cap replica explosion (DoS / NIC).
- Keep CRD-dependent objects opt-in (same reason as monitoring / VPA).

## Options

| Option | Notes |
|---|---|
| HPA on CPU/memory only | Misses idle backlog; rejected for S2 |
| prometheus-adapter + External metric HPA | Works; more cluster plumbing |
| KEDA ScaledObject (Prometheus trigger) | Creates HPA; queue PromQL is first-class |
| Fixed replicas in `overlays/agents` | Manual; no OKR elasticity |

## Recommendation

Ship **KEDA ScaledObject** (opt-in overlay `executor-keda`) targeting the
executor StatefulSet, triggered by:

- `max(octo_jobs_shard_queued)` — queued jobs that carry `shard_group_id`
- `max(octo_jobs_queued)` — all queued jobs (non-sharded backlog)

with `threshold: "1"` (≈ one replica per waiting job), `minReplicaCount: 1`,
`maxReplicaCount: 25`. Expose `octo_jobs_shard_queued` from the API scrape
snapshot alongside existing queue gauges.

## Consequences

- Operators install KEDA + point `PROMETHEUS_URL` before applying the overlay.
- Scale-out enrolls new executor ordinals; scale-down must respect PDB and lease
  expiry (existing behaviour).
- Automatic Stage2 enrichment pools remain out of scope (S4).

## Not decided here

- Host-weighted shard sizing.
- Per-tenant scale ceilings.
- Whether Stage2 enrichment uses the same StatefulSet image.
