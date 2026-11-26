# FTT-PULSE-2026-052 (Shapoclyack companion)

Full FTT lives in GenDec: `docs/requirements/FTT-PULSE-2026-052.md`.

This repository implements:

| Piece | Location |
|---|---|
| S3 `chunk_concurrency` / `enrich_concurrency` | `scanner/pipeline/config_schema.py`, `pulse_probe.py` |
| Intent `inventory_services` | `api/services/scan_intents.py` |
| Job sharding (`shard_count`) | `api/services/job_sharding.py`, `job_submission.py`, `api/schemas.py` |
| ADR | `docs/adr/0010-throughput-s1-s3-sharding.md` |
