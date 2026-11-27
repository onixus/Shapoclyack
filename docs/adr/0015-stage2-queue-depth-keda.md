# ADR 0015: Stage2 enrichment queue-depth KEDA trigger (Path B)

| | |
|---|---|
| **Status** | **Proposed** — implementation under FTT-PULSE-2026-058; owner acceptance pending |
| **Date** | 2026-11-27 |
| **Related** | [FTT-PULSE-2026-058](../ftt-pulse-2026-058-stage2-queue-keda.md), [ADR 0011](0011-executor-queue-depth-autoscale.md), [ADR 0012](0012-stage2-enrichment-queue.md), [ADR 0009](0009-scan-throughput-okr.md), [throughput-okr-10k.md](../throughput-okr-10k.md) |

## Context

ADR 0012 shipped Stage2 as claimable `intent=enrichment` jobs on the existing
scanner-executor claim path and exported `octo_jobs_stage2_queued`. ADR 0011
wired KEDA to `octo_jobs_shard_queued` and `octo_jobs_queued`, and explicitly
deferred Stage2 as a ScaledObject trigger.

Stage2 jobs are also counted by `octo_jobs_queued`, so the generic trigger
already scales the fleet when enrichment backlog exists. Path B of the 10 k
hosts/h OKR still needs an **explicit** Stage2 scale signal so operators can:

1. See enrichment backlog as a first-class autoscaling input.
2. Tune Stage2 threshold independently of shard / generic queue depth
   (enrichment wall clock ≫ inventory).
3. Keep Path B scale intent intact if the generic queued trigger is later
   narrowed or removed.

## Decision drivers

- Close the deferred wiring in ADR 0011 / ADR 0012 without inventing a new
  worker protocol or image.
- Preserve `maxReplicaCount ≤ 25` and opt-in overlay apply safety.
- Prefer work on the existing executor fleet over a Stage2-only Deployment
  until measurement proves a separate pool is required.
- Leave S6 (eBPF/XDP / masscan-class TX) rejected as OKR primary.

## Options

| Option | Notes |
|---|---|
| Rely only on `octo_jobs_queued` | Already scales; Path B intent opaque; threshold coupled |
| Add `octo_jobs_stage2_queued` trigger to existing ScaledObject (this ADR) | Explicit Path B; same claim path; independent threshold |
| Dedicated Stage2-only StatefulSet + ScaledObject | Larger ops surface; deferred until pool split is justified |
| Fixed high replica count | Manual; no elasticity |

## Recommendation

**Add `max(octo_jobs_stage2_queued)` as a third Prometheus trigger on the
existing opt-in `overlays/executor-keda` ScaledObject** (and the hand-apply
example), with `threshold: "1"` matching the S2 defaults.

Do **not** introduce a separate Stage2 Deployment or ScaledObject in this
decision. Keep Stage2 on the scanner-executor claim path (ADR 0012).

## Consequences

- Path B scale-out is documented and independently tunable.
- Operators still install KEDA + set `PROMETHEUS_URL` before apply.
- Replica ceiling remains the S2 capacity review boundary (25).
- A future Stage2-only pool can supersede this ADR without changing the
  job contract or the gauge.

## Not decided here

- Separate Stage2-only executor pool / Deployment image.
- Host-weighted Stage2 partition skew (still ADR 0012).
- Automatic Stage2 for every `full` intent.
- Raising `maxReplicaCount` past 25.
- Accepting ADR 0009 / promoting sibling throughput ADRs (acceptance pack).
