# Scan performance without more hardware

How to get faster *operator outcomes* from Shapoclyack without adding CPU,
RAM, agents, or packet rate. Companion to [configuration.md](configuration.md),
[slo.md](slo.md), and [scale-profile.md](scale-profile.md).

## Diagnosis first: stage timings

Each pipeline run writes:

```text
<output_dir>/stage_timings.json
```

and a ranked summary line in `pipeline.log`:

```text
stage timings: pipeline_wall=…s stages_sum=…s top=[nuclei=…, ports=…, …]
```

| Field | Meaning |
|---|---|
| `pipeline_wall_sec` | End-to-end wall clock of the process |
| `stages_sum_sec` | Sum of timed stages (can **exceed** wall when pulse+nse run concurrently) |
| `stages[]` | Ordered list with `duration_sec` and `status` (`ok` / `skipped` / `error`) |
| `top_stages` | Slowest successful stages |

Use this file before changing rates or concurrency. The usual ranking on
web-heavy scopes is **nuclei ≫ ports / pulse ≫ discover**.

Load CI also records overall `duration_sec` and `peak_rss_mb` (see
`tests/load/run.sh`). Peak RSS used to always report `0` because the monitor
exited before the scanner container existed; that race is fixed.

## Intents (do less, more often)

Treat scan work as **intent**, not one default full pipeline:

| Intent | Goal | Typical levers |
|---|---|---|
| **inventory** | Alive hosts + open ports + light service ID | `--skip-nse` or Pulse-only, nuclei off / severity floor high, `top_ports` 100 |
| **vuln** | CVE/misconfig signal on known web surface | Nuclei critical+high (optional medium), no full re-discover if scope stable |
| **full** | Assessment-grade completeness | `balanced`/`fast` profile, nuclei medium+, full ports |
| **delta** | Nightly re-check of a known perimeter | `--delta`, seed/previous alive, refresh sample of known hosts |

Existing building blocks (no new runtime required):

- CLI: `--skip-nse`, `--delta`, `--resume`, `--mode safe|balanced|fast`
  (`profiles.test` exists in YAML for smoke overlays but is **not** a
  `--mode` / `runtime.mode` value — use a config file that selects those
  nuclei/port knobs, or overlay `profiles.safe`/`balanced` rates)
- Config: `profiles.*.nuclei`, `runtime.skip_nse`, discovery delta,
  optional custom config with a reduced nuclei/port set (see `profiles.test`
  in `default.yaml` as a template, not a selectable mode)
- Ops: schedule inventory often, full less often; L1 then resume for enrichment

**Product direction (not yet API fields):** expose `intent` on jobs/schedules that
maps to the table above so operators do not hand-edit YAML. Until then, encode
intent in named config overlays or schedule labels.

### Suggested schedule shape (same fleet)

```text
hourly / 4h  → inventory (+ delta discover)
daily        → vuln on open web ports from last inventory
weekly       → full assessment
on-demand    → full or vuln for a ticket
```

Same agents, same packet budget, far less average wall-clock per day.

## Levers that do **not** need more resources

1. **Work elimination** — delta discovery, skip unchanged hosts, nuclei severity
   and `overall_timeout_seconds`, ports list for known assets.
2. **Fail-fast retries** — hard failures (missing tool, 4xx) should not burn
   `retries × timeout`; timeouts should shrink scope, not repeat the same max.
3. **Stage packing** — discover→ports is still a full barrier; streaming by
   batch is a code change that reuses existing `*_concurrency` workers.
4. **Caching** — DNS TTL, previous open ports, banner/cert hash → skip nuclei
   when fingerprint unchanged (future).
5. **Observability** — stage timings (done); OpenTelemetry still open in
   [slo.md](slo.md).

## What *not* to do first

- Raising `nse_concurrency` / nuclei `rate_limit` on a saturated NIC or target
  ACL usually **hurts** completeness for little wall-clock gain.
- Widening Prometheus HTTP buckets to hide p95 > 10 s (API) — that is a
  product/query problem, not a scan problem ([scale-profile.md](scale-profile.md)).

## Validation checklist

After a change aimed at speed:

1. Compare `stage_timings.json` `top_stages` before/after on the same target set.
2. Confirm findings count / severity coverage still matches the **intent** (not full).
3. Load or lab run: `duration_sec` and non-zero `peak_rss_mb` when Docker stats work.
4. Resume still skips finished stages (`status: skipped` in timings).

## Related code

| Path | Role |
|---|---|
| `scanner/pipeline/stage_timing.py` | Timer collector |
| `scanner/main.py` | Wires stages + writes `stage_timings.json` |
| `scanner/config/default.yaml` | Profiles, nuclei, concurrency |
| `tests/load/` | Synthetic multi-host duration gate |
