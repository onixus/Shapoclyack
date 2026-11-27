# ADR 0014: Throughput heuristics S5 (historical∪top-N, JARM/tls-enum gates, short silence waits)

| | |
|---|---|
| **Status** | **Accepted** — onixus, 2026-11-27 (implementation in tree; [FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md)) |
| **Date** | 2026-11-26 |
| **Related** | [ADR 0009](0009-scan-throughput-okr.md), [FTT-PULSE-2026-057](../ftt-pulse-2026-057-heuristics-s5.md), [FTT-PULSE-2026-059](../ftt-pulse-2026-059-throughput-adr-acceptance.md), [throughput-okr-10k.md](../throughput-okr-10k.md), [scan-performance.md](../scan-performance.md) |

## Context

The 10 k hosts/hour OKR (ADR 0009) confirms **heuristics before ML** as S5:

- Prefer **historical open ports ∪ top-N** over wide well-known ranges for
  inventory.
- Skip **JARM / tls-enum** unless risk/intent requires them.
- Shorten **silence / connect timeouts** once RST evidence (or speed intent)
  shows waiting longer will not find more opens.

ML port models and eBPF/XDP (S6) stay deferred. GenDec engine changes are
needed only when adapter-level `-t` cannot express the timeout budget — it can.

## Decision

1. **`ports.heuristic_union`** (intent `inventory` forces true): when a previous
   run’s `open_ports.txt` exists, write a per-run custom ports file =
   historical TCP opens ∪ curated top-N (`scanner/pipeline/top_tcp_ports.py`).
   Otherwise keep naabu `-top-ports`. Never use Pulse `-p 1-1024` as a silent
   empty-ports fallback.
2. **JARM / tls-enum product gates** on intents:
   - Speed (`inventory`): both forced **off**.
   - Heavy (`full`, `vuln`, `delta`, `org_profile`): both forced **on**.
   - Explicit overlay flags remain for operators. Adapter records `jarm`;
     Pulse CLI is unchanged until GenDec adds an opt-in switch.
3. **Speed-path timeouts**: inventory sets Pulse `timeout_ms=300` and
   `retry_settle_seconds=3` (vs assessment 800 ms / 15 s). Connect RST still
   completes immediately; the shorter budget only bounds silence/filtered waits.
4. **Overlay v4** carries the new paths so sensors that cannot apply them are
   refused on claim rather than silently ignoring the heuristics.

## Consequences

- Repeat inventory scans stay near top-100 cost while retaining previously
  seen odd ports.
- Assessment jobs keep JARM + cipher enum without relying on YAML alone.
- No GenDec pin bump for S5; optional future `--jarm` / `--no-jarm` can wire
  into the existing adapter flag.
- Mid-tier `inventory_services` / plugin defaults remain FTT-056 territory and
  are not redone here.

## Not decided here

- Exact equality with naabu’s private top-100 table (curated product set).
- GenDec CLI for disabling in-engine JARM during TLS probe.
- Automatic Stage2 enqueue after inventory (S4).
