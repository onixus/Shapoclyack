# FTT-PULSE-2026-056: Product defaults — speed intents without cipher-enum / plugins

| | |
|---|---|
| **ID** | FTT-PULSE-2026-056 |
| **Author** | Security Architect / throughput OKR |
| **Implementer** | Senior development |
| **Automation** | DevSecOps (pytest on intent resolution; no live packets) |
| **Status** | Implemented |
| **Related** | [ADR 0009](adr/0009-scan-throughput-okr.md), [throughput-okr-10k.md](throughput-okr-10k.md), [scan-performance.md](scan-performance.md), FTT-052 / FTT-054 / FTT-055 (For Review — not redone here) |

## 1. Scope

Ship the **product contract** from ADR 0009 build-order item 2: speed-oriented
intents must not inherit assessment-grade Pulse plugins or `--tls-enum`
(cipher enumeration). Assessment intents keep those heavy stages on.

| In scope | Out of scope |
|---|---|
| Intent overlays: plugins / `enumerate_ciphers` OFF for speed intents | GenDec `--enrich-concurrency` (S1 / GenDec#56) |
| Mid-tier `inventory_services` (banners on; plugins/tls-enum/nuclei off) | Adapter `chunk_concurrency` / S3 overlap (#681) |
| Explicit ON for `full` / `vuln` / `delta` / `org_profile` / `enrichment` | Job sharding / KEDA (#681–#682) |
| Docs + UI vocabulary for the new intents | Stage2 enrichment **queue fan-out** (#684) |
| Unit tests for the OFF/ON contract | Flipping global `default.yaml` for legacy no-intent jobs |

Legacy jobs (no `intent`) keep shipped YAML defaults (`plugins: true`,
`enumerate_ciphers: true`) so assessment operators who omit intent are
unchanged. Intents own the speed vs heavy split.

## 2. Trust boundaries

| Input | Trust | Rule |
|---|---|---|
| `StartScanRequest.intent` / schedule intent | Semi-trusted (authenticated operator) | Must be in `INTENTS`; unknown → 4xx |
| Intent `config_extra` merged into job overlay | Trusted (server-authored) | Sensors receive validated overlay only |
| Pulse plugins / tls-enum flags | Untrusted work amplifiers | Speed intents force OFF; heavy intents force ON |

No new network egress. No secrets in overlays.

## 3. STRIDE

| Threat | Countermeasure |
|---|---|
| **S** Spoofed intent | Authn/RBAC on job create; intent enum validated server-side |
| **T** Overlay tampering | Overlay built only from `resolve_scan_options`; agent path signs/validates |
| **I** Accidental assessment load on inventory schedules | Speed intents disable plugins + cipher enum + (where applicable) nuclei |
| **D** DoS via always-on tls-enum/plugins | Product default for speed paths eliminates that wall-clock |
| **E** Escalation via plugin sandbox | Unchanged NetSandbox; speed path simply does not load plugins |

## 4. Functional requirements

- **FR-01**: `inventory` sets `service_probe.pulse.plugins: false` and
  `tls_posture.enumerate_ciphers: false` (in addition to existing skip_nse /
  nuclei-off / top_ports 100).
- **FR-02**: `inventory_services` runs Pulse with banners/services (skip_nse
  false), nuclei off, plugins false, enumerate_ciphers false. No S3
  concurrency knobs in this slice.
- **FR-03**: `enrichment`, `full`, `vuln`, `delta`, and `org_profile` set
  `plugins: true` and `enumerate_ciphers: true` (heavy path). Nuclei floors
  stay as today per intent.
- **FR-04**: UI / API vocabulary accept the new intent names; labels explain
  speed vs assessment.
- **FR-05**: Docs (`scan-performance.md`, ADR 0009 cross-link) describe the
  contract; Measure cohorts already name `inventory_services` / `enrichment`.

## 5. Security requirements

- **SEC-01**: Intent overlays cannot widen plugin `plugins_dir` /
  `plugin_sources` (speed profile rule unchanged).
- **SEC-02**: Turning plugins/tls-enum off never weakens claim/lease,
  sanitization, or audit fields.
- **SEC-03**: Heavy intents do not raise rate/concurrency beyond existing
  profile caps.

## 6. Acceptance (DoD)

1. [x] Unit tests assert speed intents OFF and heavy intents ON for plugins /
   enumerate_ciphers.
2. [x] `inventory_services` and `enrichment` resolve and are accepted by
   request schemas.
3. [x] ruff clean on touched Python.
4. [x] No changes to S1/S3/S2/S4 control-plane or GenDec engine code.
