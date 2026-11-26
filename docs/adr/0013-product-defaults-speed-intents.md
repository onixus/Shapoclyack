# ADR 0013: Product defaults — speed intents without cipher-enum / plugins

| | |
|---|---|
| **Status** | **Accepted** (implements ADR 0009 recommendation #4 + build-order #2) |
| **Date** | 2026-11-26 |
| **Related** | [ADR 0009](0009-scan-throughput-okr.md), [FTT-PULSE-2026-056](../ftt-pulse-2026-056-product-defaults-speed-intents.md), [scan-performance.md](../scan-performance.md) |

## Context

Shipped `scanner/config/default.yaml` enables Pulse Rhai plugins and
`tls_posture.enumerate_ciphers` for every job that runs the service probe.
That is correct for assessment (`full` / Stage2 enrichment) and wrong as the
silent default for large inventory-style work: tls-enum and plugins dominate
Pulse wall-clock (ADR 0009).

S1/S3/S2/S4 and Measure land concurrency and measurement elsewhere
(For Review). This ADR ships only the **product intent contract**.

## Decision

1. **Speed intents** (`inventory`, `inventory_services`) always overlay
   `service_probe.pulse.plugins: false` and
   `tls_posture.enumerate_ciphers: false`.
2. **`inventory_services`** is the mid-tier: Pulse banners/services on,
   nuclei off, no plugins / tls-enum (between ports-only inventory and full).
3. **Heavy intents** (`enrichment`, `full`, `vuln`, `delta`, `org_profile`)
   explicitly overlay plugins + enumerate_ciphers **on** so assessment stays
   complete even if YAML defaults change later.
4. **Legacy** (no intent) keeps YAML defaults — no surprise for operators who
   omit intent.
5. Stage2 **queue fan-out** and S3 chunk overlap remain separate PRs; this
   slice only defines the enrichment / mid-tier **config contract**.

## Consequences

- Operators can schedule hourly `inventory` / `inventory_services` without
  paying tls-enum + plugin budgets.
- Weekly `full` and Stage2 `enrichment` jobs keep assessment-grade Pulse work.
- Merge with #681 may add `chunk_concurrency` on `inventory_services`; merge
  with #684 may attach Stage2 enqueue — overlays here stay compatible.
