# Throughput OKR — representative estate baseline (Measure)

Synthetic, repeatable pack for [FTT-PULSE-2026-055](../../ftt-pulse-2026-055-estate-baseline-measure.md)
and [ADR 0009](../../adr/0009-scan-throughput-okr.md) acceptance citations.

These fixtures are **not** a live estate. Hostnames use `.invalid`. Numbers are
chosen to match the order-of-magnitude models in
[throughput-okr-10k.md](../../throughput-okr-10k.md) so CI can lock the harness
without sending packets. Replace with stand `stage_timings.json` before sizing
production shards.

## Cohorts

| Cohort | What it models | Fixture hosts/h | Pulse L4 vs enrich |
|---|---|---|---|
| `inventory` | Ports-only Stage1 | 5000 | no Pulse stage |
| `inventory_services` | Mid-tier banners | 4000 | L4 180s / enrich share 75% |
| `enrichment` | Assessment Pulse (TLS/plugins) | 200 | enrich share ≈98%; one partial `complete=false` |
| `full` | Pulse + nuclei | 125 | enrich share ≈98%; nuclei in `top_stages` |

None of the single-sensor fixture medians clear **10 000 hosts/h** alone —
Path A needs ≥2 inventory sensors; Path B needs Stage2 / shards (ADR 0009).

## Layout

```text
fixtures/<cohort>/<run>/
  stage_timings.json      # synthetic marker: tests.fixtures.throughput_measure
  alive_hosts.json
  summary.json            # throughput_cohort / intent
  throughput_meta.json
  pulse/raw.json          # when Pulse ran (stats.l4_complete / complete / elapsed_ms)
baseline.summary.json     # harness output (stable environment stub)
calibration.json          # seconds/host coefficients for throughput_okr_model.py
```

## Reproduce

```bash
python3 -m tests.fixtures.throughput_measure fixtures \
  docs/benchmarks/throughput-okr-estate-baseline \
  --out /tmp/okr-baseline.json

python3 -m tests.fixtures.scale_measure okr-baseline \
  docs/benchmarks/throughput-okr-estate-baseline/fixtures

python3 scripts/throughput_okr_measure.py fixtures

python3 scripts/throughput_okr_model.py \
  --calibration docs/benchmarks/throughput-okr-estate-baseline/calibration.json
```

On a stand (read-only against real runs):

```bash
python3 scripts/throughput_okr_measure.py runs-dir "$OCTO_OUTPUT_DIR/runs" \
  --cohort inventory --out /tmp/inventory-baseline.json
```

Do not commit live target lists or production run directories.
