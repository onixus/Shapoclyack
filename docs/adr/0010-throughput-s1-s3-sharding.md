# ADR 0010: Throughput path — S1 parallel enrichment, S3 chunk overlap, job sharding

- **Status**: Proposed (implementation landed under FTT-PULSE-2026-052; owner acceptance pending)
- **Date**: 2026-11-26
- **Related**: [FTT-PULSE-2026-052](https://github.com/onixus/GenDec/blob/main/docs/requirements/FTT-PULSE-2026-052.md), [scan-performance.md](../scan-performance.md)

## Context

Full in-band Pulse enrichment (JARM / tls-enum / plugins) on one sensor cannot
reach a 10 000 hosts/h assessment OKR when TLS opens are common. L4 inventory
can. The product needs:

1. **S1** — in-process parallel TLS enrichment in GenDec (`--enrich-concurrency`).
2. **S3** — overlapping Pulse chunks (`chunk_concurrency`) and a mid-tier intent
   (`inventory_services`) that keeps banners/services without tls-enum/plugins/nuclei.
3. **Sharding** — claimable job partitions so HPA/KEDA-scaled sensors share one estate.

## Decision drivers

- Preserve existing claim/lease and admission trust boundaries.
- Cap concurrency (enrich ≤ 64, chunk ≤ 8, shards ≤ 64).
- Keep serial defaults (`*=1`) so upgrades do not change behaviour.

## Options

| Option | Notes |
|---|---|
| Raise `-c` / nuclei rate alone | Saturated NIC/ACL; completeness drops |
| Two-tier Stage1/Stage2 queue only | Necessary for full TLS path; complementary |
| S1+S3+sharding (this ADR) | Immediate wall-clock gains; works with current job claim |

## Recommendation

Ship S1 in GenDec, S3 + sharding in Shapoclyack under FTT-PULSE-2026-052.
Stage2 enrichment queue (canvas S4) remains a follow-up.

## Consequences

- `POST /api/jobs` accepts `shard_count`; returns shard 0 with `scan_options.shard_*`.
- `shard_count` requires `job_execution_mode=agent` (local fan-out is refused).
- Sibling shards are persisted with `_defer_dispatch` and offered to NATS only
  after the whole group exists; the parent idempotency digest is stored on insert.
- Overlapped Pulse chunks split `--rate` / `-c` by `chunk_concurrency`; crash /
  timeout breakers trip as futures complete (`as_completed`), not after the wave.
- Intent vocabulary grows by `inventory_services`.
- Pulse adapter records `chunk_concurrency` / `enrich_concurrency` in `raw.json`.

## Not decided here

- Exact shard sizing for a given estate (operator-chosen `shard_count`).
- Host-weighted (vs line round-robin) partition skew.

KEDA / queue-depth executor scale-out is decided in
[ADR 0011](0011-executor-queue-depth-autoscale.md) (FTT-PULSE-2026-053).
Automatic Stage2 enrichment enqueue after Stage1 inventory is decided in
[ADR 0012](0012-stage2-enrichment-queue.md) (FTT-PULSE-2026-054).
