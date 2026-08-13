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

Treat scan work as **intent**, not one default full pipeline. **Product control
(shipped):** `intent` on `POST /api/jobs` and schedules
(`api/services/scan_intents.py`). Speed profile stays in `mode`
(safe/balanced/fast).

| Intent | Goal | Control plane applies |
|---|---|---|
| **inventory** | Alive hosts + open ports | `--skip-nse`, nuclei off, `top_ports: 100`; optional `delta` |
| **vuln** | High-signal CVE/misconfig | Full probe; nuclei **critical+high** only |
| **full** | Assessment-grade completeness | Default pipeline; nuclei critical/high/medium |
| **delta** | Re-check known perimeter | Full pipeline + forced `--delta` |

Legacy: omit `intent` and use `skip_nse` / `delta` flags (UI: “legacy — manual flags”).

```http
POST /api/jobs
{ "intent": "inventory", "mode": "balanced", "delta": true, "ranges": "10.0.0.0/24" }
```

Persisted as `scan_options.intent` (+ `intent_summary`). Local execution merges
nuclei/top_ports into the job effective config; agent mode still gets CLI flags
but not the nuclei overlay.

### Suggested schedule shape (same fleet)

```text
hourly / 4h  → intent=inventory, delta=true
daily        → intent=vuln
weekly       → intent=full
on-demand    → intent=full or vuln
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
| `api/services/scan_intents.py` | Intent → flags + config overlay |
| `api/schemas.py` | `StartScanRequest.intent`, schedule fields |
| `scanner/pipeline/stage_timing.py` | Timer collector |
| `scanner/main.py` | Wires stages + writes `stage_timings.json` |
| `scanner/config/default.yaml` | Profiles, nuclei, concurrency |
| `tests/load/` | Synthetic multi-host duration gate |
| `tests/test_scan_intents.py` | Intent resolution unit tests |
