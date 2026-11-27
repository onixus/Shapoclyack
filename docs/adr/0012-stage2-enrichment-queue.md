# ADR 0012: Stage2 enrichment queue (S4)

| | |
|---|---|
| **Status** | **Proposed** — implementation under FTT-PULSE-2026-054; owner acceptance pending |
| **Date** | 2026-11-26 |
| **Related** | [FTT-PULSE-2026-054](../ftt-pulse-2026-054-stage2-enrichment-queue.md), [throughput-okr-10k.md](../throughput-okr-10k.md), ADR 0008, ADR 0009, ADR 0010, ADR 0011 |

## Context

Full TLS/plugins/nuclei assessment cannot share the Stage1 inventory wall clock
on dense estates (ADR 0009 Path B). ADR 0010 shipped in-band accelerators and
claimable *target* shards; ADR 0011 scales executors on shard queue depth.
Neither automatically schedules assessment after a fast inventory.

ADR 0008 already established the pattern: heavy work (browser capture) is
claimable opt-in work outside the critical inventory path. Stage2 applies the
same product shape to Pulse enrichment.

## Decision drivers

- Hit inventory OKR on Stage1 while keeping assessment available as horizontal
  claimable work.
- Reuse the existing job claim / lease / NATS offer path — no new worker
  protocol.
- Preserve admission, scope, and overlay trust boundaries.
- Cap fan-out so a dense estate cannot amplify into unbounded jobs.

## Options

| Option | Notes |
|---|---|
| Only raise in-band `--enrich-concurrency` | Helps mid-tier; fails Path B alone |
| Dedicated enrichment Deployment (new image) | Screenshot-worker precedent; larger ops surface |
| Stage2 as claimable jobs on scanner-executor (this ADR) | Same image/claim path; scales with S2 KEDA depth |

## Recommendation

**Ship Stage2 as opt-in claimable jobs on the existing scanner-executor fleet.**

1. Operator sets `stage2_enrichment=true` on a Stage1 job (`inventory` /
   `inventory_services`).
2. On successful run publication, the control plane reads `open_ports.txt`,
   partitions unique hosts, and enqueues Stage2 jobs with `intent=enrichment`.
3. Stage2 jobs carry `stage2_of` / `stage2_group_id` metadata (server-written
   only), are `quota_exempt`, and do not recurse.
4. Export `octo_jobs_stage2_queued` for KEDA triggers alongside
   `octo_jobs_shard_queued` — wired on the existing executor ScaledObject in
   [ADR 0015](0015-stage2-queue-depth-keda.md) / FTT-058.

## Consequences

- Inventory SLO and assessment completeness become honest separate queues.
- Executors that already claim ordinary jobs also drain Stage2 work.
- Operators must opt in; default behaviour is unchanged.
- A dedicated enrichment Deployment remains possible later without changing
  the job contract.
- Path B scale-out can follow Stage2 backlog explicitly (ADR 0015), not only
  via the generic `octo_jobs_queued` trigger.

## Not decided here

- Automatic Stage2 for every `full` intent (kept opt-in).
- Host-weighted (vs round-robin) Stage2 partition skew.
- A separate KEDA ScaledObject / Deployment for Stage2-only pools (metric +
  same-fleet trigger shipped; dedicated pool still deferred — ADR 0015).
- Whether Stage2 should consume parent `open_ports.txt` as a pinned ports
  input instead of rediscovering (future adapter seam).
