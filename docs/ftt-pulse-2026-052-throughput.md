# FTT-PULSE-2026-052 (Shapoclyack companion)

Full FTT lives in GenDec: `docs/requirements/FTT-PULSE-2026-052.md`.

This repository implements:

| Piece | Location |
|---|---|
| S3 `chunk_concurrency` / `enrich_concurrency` | `scanner/pipeline/config_schema.py`, `pulse_probe.py` |
| Intent `inventory_services` | `api/services/scan_intents.py` |
| Job sharding (`shard_count`) | `api/services/job_sharding.py`, `job_submission.py`, `api/schemas.py` |
| ADR | `docs/adr/0010-throughput-s1-s3-sharding.md` |

S2 (queue-depth metric + KEDA/HPA): [FTT-PULSE-2026-053](ftt-pulse-2026-053-shard-queue-autoscale.md),
[ADR 0011](adr/0011-executor-queue-depth-autoscale.md).

S4 (Stage2 enrichment queue): [FTT-PULSE-2026-054](ftt-pulse-2026-054-stage2-enrichment-queue.md),
[ADR 0012](adr/0012-stage2-enrichment-queue.md).
