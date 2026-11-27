# FTT-PULSE-2026-057: Throughput heuristics S5 (not ML-first)

| | |
|---|---|
| **ID** | FTT-PULSE-2026-057 |
| **Author** | Security Architect / throughput OKR |
| **Implementer** | Senior development |
| **Automation** | DevSecOps (pytest on intents + port heuristics; no live packets) |
| **Status** | Implemented |
| **Related** | [ADR 0014](adr/0014-throughput-heuristics-s5.md), [ADR 0009](adr/0009-scan-throughput-okr.md), [throughput-okr-10k.md](throughput-okr-10k.md), [scan-performance.md](scan-performance.md) |

## 1. Scope

Ship OKR **S5 — Heuristics (not ML-first)** from ADR 0009 / throughput model:

1. Inventory port selection = **historical open ports ∪ curated top-N** (never a
   silent default widen to `1–1024`).
2. **Gate JARM / tls-enum** to heavy intents (`full` / `vuln` / `delta` /
   `org_profile`) or explicit overlay flags; inventory forces them off.
3. **Shorten connect / silence timeouts** on speed paths (Pulse `-t` + settle)
   so filtered targets do not burn the assessment-grade 800 ms / 15 s budgets.
4. FTT + tests + docs. **No GenDec engine change** — adapter `-t` already
   bounds silence waits after RST (RST returns immediately; timeout only
   covers silence).

| In scope | Out of scope |
|---|---|
| `ports.heuristic_union` + historical∪top-N writer | GenDec `--enrich-concurrency` (S1 / #56) |
| Intent overlays: JARM / `enumerate_ciphers` / timeouts | Job sharding / KEDA (S2 / #682) |
| Pulse empty-port fallback → curated top-100 (not `1-1024`) | Stage2 enrichment queue (S4 / #684) |
| Overlay v4 paths + unit tests | Mid-tier `inventory_services` product defaults (FTT-056) |
| Docs / ADR 0014 | ML port models; XDP/masscan (S6) |

## 2. Trust boundaries

| Input | Trust | Rule |
|---|---|---|
| Previous run `open_ports.txt` | Semi-trusted (own estate artifacts) | TCP ports only; capped at 4096; excludes applied |
| Intent `config_extra` | Trusted (server-authored) | Sensors receive validated overlay v4 paths only |
| Operator `custom_ports_file` | Semi-trusted | Wins over heuristic union |
| Pulse `-t` / JARM product flag | Trusted work shapers | Speed intents force short timeout + JARM/tls-enum off |

No new network egress. No secrets in overlays.

## 3. STRIDE

| Threat | Countermeasure |
|---|---|
| **S** Spoofed previous opens | Only read from resolved previous run under installation output paths |
| **T** Overlay tampering | Overlay allow-list v4; agent capability gate |
| **I** Accidental full-port / JARM load on inventory | `heuristic_union` + JARM/tls-enum forced off for inventory |
| **D** DoS via long silence waits on dark space | Speed path `timeout_ms=300`, `retry_settle_seconds=3` |
| **E** Escalation via plugins | Unchanged; inventory still `skip_nse` |

## 4. Functional requirements

- **FR-01**: `inventory` sets `ports.heuristic_union: true`, `top_ports: 100`,
  `tls_posture.enumerate_ciphers: false`, `tls_posture.jarm: false`,
  `service_probe.pulse.jarm: false`, `timeout_ms: 300`,
  `retry_settle_seconds: 3`.
- **FR-02**: When heuristic union is on and a previous `open_ports.txt` exists,
  the ports stage scans `historical ∪ top-N` via a generated custom ports
  file. With no history, naabu `-top-ports` remains. Operator custom lists win.
- **FR-03**: `full` / `vuln` / `delta` / `org_profile` force JARM +
  `enumerate_ciphers` **on** (explicit heavy path).
- **FR-04**: Pulse command builder must not use `-p 1-1024` as an empty-ports
  fallback; use curated top-100.
- **FR-05**: Adapter records `adapter.jarm` for audit/resume; does not invent a
  Pulse CLI flag until GenDec exposes one (engine timeouts not required).

## 5. Security requirements

- **SEC-01**: Heuristic union cannot widen past `MAX_HEURISTIC_PORTS` (4096) or
  past exclude_ports / scan policy ceilings.
- **SEC-02**: Turning JARM/tls-enum off never weakens claim/lease, sanitization,
  or audit fields.
- **SEC-03**: Short timeouts only apply via intent/overlay; they do not raise
  rate/concurrency caps.

## 6. Acceptance (DoD)

1. [x] Unit tests for historical∪top-N and inventory/heavy JARM/tls-enum gates.
2. [x] Overlay v4 digest pinned; inventory overlays require `config_overlay.v4`.
3. [x] ruff clean on touched Python.
4. [x] No GenDec / S1–S4 control-plane redo.
