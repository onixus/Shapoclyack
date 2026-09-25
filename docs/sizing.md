# Sizing — CPU, memory and volumes by estate size

How much an installation needs for **N assets, M sensors and K scans a day**:
requests and limits for the API, Postgres, ClickHouse, NATS and the sensors,
and how fast each volume grows ([#337](https://github.com/onixus/Shapoclyack/issues/337)).
[scale-profile.md](scale-profile.md) answers how fast the queries are at
1k / 10k / 50k assets; this file answers how much.

> **Where these numbers come from.** Every coefficient below was measured by
> `tests/fixtures/scale_measure.py` on the #337 development container, not on a
> cluster: 4 shared vCPU (load average 3–13 from other jobs throughout), 16 GiB,
> PostgreSQL 16.13 with `fsync=off`/`synchronous_commit=off`/`full_page_writes=off`,
> ClickHouse 24.8.14 with the image's default server configuration plus
> `base/clickhouse/configmap.yaml`, nats-server 2.10.29, Python 3.12.3, commit
> `1ed74b7`, 2026-09-24 (the ClickHouse step re-run with the database attached at
> `05447ad` the same day, for the review of #337). **They are to be confirmed on
> kind and the Arch stand**
> (§ [Re-measuring on a stand](#re-measuring-on-a-stand)); the harness emits the
> same coefficients there, and `scale_sizing.py` regenerates the table from them.
> CPU is reported in CPU-seconds and memory as resident bytes because wall-clock
> on a contended machine is not a property of the software. Even so, repeat runs
> on this box differ (§ [Measured coefficients](#measured-coefficients),
> *Reproducibility*): read the figures to about ±30 %.

## The table

Three representative installations, every asset scanned once a day, three
findings and four open services per asset, 5 API requests a second, two API
replicas, ClickHouse on, a one-year horizon for the stores nothing prunes, and
1.3× headroom. `python -m tests.fixtures.scale_sizing --tiers --markdown`
prints it; `--assets/--sensors/--scans-per-day/--findings-per-asset/…` prints
any other workload.

| | 1,000 assets / 1 sensor / 4 scans/day | 10,000 assets / 3 sensors / 24 scans/day | 50,000 assets / 10 sensors / 100 scans/day |
|---|---:|---:|---:|
| hosts per run | 250 | 417 | 500 |
| API (per replica, agent mode): CPU request / limit | 70m / 1.0 | 70m / 1.0 | 80m / 1.0 |
| API (per replica, agent mode): memory request / limit | 334 MiB / 740 MiB | 334 MiB / 762 MiB | 334 MiB / 774 MiB |
| Sensor (per node): CPU request / limit | n/m / n/m | n/m / n/m | n/m / n/m |
| Sensor (per node): memory request / limit | n/m / n/m | n/m / n/m | n/m / n/m |
| PostgreSQL: CPU request / limit | 250m / 1.9 | 250m / 1.9 | 250m / 1.9 |
| PostgreSQL: memory request / limit | 1.0 GiB / 1.0 GiB | 1.0 GiB / 1.0 GiB | 1.2 GiB / 1.2 GiB |
| PostgreSQL: volume (365 d) | 1.7 GiB | 4.9 GiB | 19.1 GiB |
| ClickHouse: CPU request / limit | n/m / n/m | n/m / n/m | n/m / n/m |
| ClickHouse: memory request / limit | 868 MiB / 1.7 GiB | 868 MiB / 1.7 GiB | 869 MiB / 1.7 GiB |
| ClickHouse: volume (365 d) | 13.4 GiB | 13.4 GiB | 13.4 GiB |
| NATS JetStream (per node): volume | 14.3 GiB | 14.3 GiB | 14.3 GiB |
| Run artifacts (PVC or S3): volume, floor | 624 MiB | 5.4 GiB | 25.8 GiB |

Reading it:

- **The sensor rows are `n/m` on purpose.** Nothing here can run a scan
  (§ [What is not measured here](#what-is-not-measured-here)); the shipped
  500m/512Mi → 2/2Gi and the VPA stand until `runs-dir` measures a stand's real
  runs. What was measured — the report stage alone — costs 0.83 CPU-ms and
  36 KiB of peak memory per host in the run.
- **Postgres grows with scans, not with the estate.** The 50k column's 19.1 GiB
  is 0.3 GiB of estate and 13 GiB of a year's `vulnerability_events`
  (37.5 MiB a day), plus WAL and headroom. Every year kept adds the same again.
  Add `jobs` rows (one per scan, never pruned, row size not measurable here).
- **ClickHouse's volume is its own logs**: 10.3 GiB a year of `system.*_log` at
  the idle rate, against 3.2 MiB of scan data at 50k assets (6.4 MiB with
  the unmerged second copy a rescan lands). Under ingest load the logs grew
  about four times faster; the volume figure is unconfirmed until a stand
  measures a day (§ [What the measurements exposed](#what-the-measurements-exposed), 4).
- **The API rows are agent mode** (sensors scan). In local mode the scan runs
  in the API pod and adds the sensor's footprint to it (§ [API](#api-per-replica-agent-mode)).
- **A stand's table is its own.** `--coefficients stand.json` prints `n/m` for
  what the stand did not measure; `--fill-from-sandbox` fills those cells from
  the figures here and marks each one `†`, with the borrowed coefficients named
  under the table.
- **The NATS volume is what the streams reserve**, the same at every size, and
  more than the shipped 5 Gi (§ [What the measurements exposed](#what-the-measurements-exposed), 1).
- **Artifacts are a floor**: the report stage's files only. Raw tool output
  adds to it; measure a stand's with `runs-dir`.
- **Hosts per run moves the API's memory, not its CPU.** The same 50k estate
  scanned as one run a day needs a 7.3 GiB API memory limit (four concurrent
  ingests of a 50 000-host run), cannot be uploaded by a sensor (the run
  directory passes 512 MiB) and never reaches ClickHouse; as 100 runs of 500
  hosts it needs 774 MiB. Keep runs to a few thousand hosts.

With Lariska endpoint agents (1 500 packages, one snapshot a day, 90-day
snapshot and 365-day change retention) the inventory dominates Postgres; at the
10k tier:

| Endpoint agents | 0 | 100 | 1 000 | 10 000 |
|---|---:|---:|---:|---:|
| PostgreSQL volume (1 year) | 4.9 GiB | 13.5 GiB | 91.7 GiB | 873 GiB |

That is 466 bytes per retained package row — 1.35 billion rows at 10 000
endpoints ([operations.md](operations.md#endpoint-inventory-retention)) — which
is why the collection cadence and `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS`
are sizing decisions, not tuning ones.

## The model

`tests/fixtures/scale_sizing.py` holds every formula below; the table above is
`python -m tests.fixtures.scale_sizing --tiers --markdown`. Inputs are the
workload (N assets, M sensors, K scans a day, and what the operator knows about
the estate); coefficients are the measured per-unit costs in
[§ Measured coefficients](#measured-coefficients). A coefficient nobody measured
prints as `n/m` — it is never filled with a plausible number.

Two derived quantities drive most of it:

- **host scans per day**, `S` — how many host observations all runs make in a
  day. Default: every asset once a day (`S = N`).
- **hosts per run**, `H = S / K`. Projection time, the ingest message and the
  API's memory peak scale with `H`, not with `N`: one scan of the whole estate
  and a hundred scans of a hundredth of it cost the database the same and the
  API very differently.

`h` below is the headroom multiplier (1.3 by default, a policy, not a
measurement); `F` and `P` are findings and open services per asset (3 and 4 in
the fixtures — use your own); `R` is API replicas and `C` concurrent ingests per
replica (`OCTO_AGENT_RESULTS_MAX_CONCURRENT_INGESTS`, 4).

### API (per replica, agent mode)

```text
archive(H)     = archive bytes/run + H × archive bytes/host
memory request = h × (idle RSS + risk-scorer overlays)
memory limit   = h × (idle RSS + scorer + dashboard page
                      + C × (H × (projection RSS/host + transform RSS/host)
                             + archive(H) × (1 + 4/3)))
CPU request    = h × daily CPU-seconds / 86 400 / R, where daily CPU-seconds =
                   R × idle millicores × 86.4
                 + K × projection CPU/run + S × (projection + transform) CPU/host
                 + requests/s × 86 400 × CPU/request
                 + Lariska items/day × CPU/item
CPU limit      = 1 core (one uvicorn process — § What the measurements exposed, 5)
```

The risk scorer's EPSS/KEV/exploit overlays are loaded on the first scoring and
kept; the dashboard's `limit=5000` page is the largest single response. The
upload is read whole and base64'd into the ingest message, hence the
`1 + 4/3` archive copies per concurrent ingest.

These rows are for **agent mode** (`OCTO_JOB_EXECUTION_MODE=agent`): sensors
scan, the API only ingests. In local mode — `overlays/local-scan` only, since
#338 moved the other overlays to a scanner-executor — the scanner runs as a
subprocess of the API pod, and the pod needs the sensor's footprint on top: at
least the report
stage's peak (126 MiB for a 1 000-host run, 444 MiB for 10 000, § 6) plus the
scanning tools, which are not measured here. That is what the shipped 4-core
/ 4 GiB limit is for; the model does not size it.

### PostgreSQL

```text
volume  = h × (N × (bytes/asset + P × bytes/service + F × bytes/finding)
               + S × F × bytes/observation × horizon days      ← vulnerability_events
               + K × bytes/job × horizon days                   ← jobs
               + Lariska rows within their retention windows
               + max_wal_size)
memory  = max(estate tables / 0.25, 1 GiB)                     ← shared_buffers at 25 %
CPU     = request: max(250m, h × (S × (projection + transform) Postgres CPU/host
                                   + requests/s × Postgres CPU/request) / 86 400)
          limit:   max(1 core, h × R × max(projection share, request share) cores)
          projection share = Postgres CPU/host ÷ API CPU/host          (2.9 ÷ 14.3 ms)
          request share    = Postgres CPU/request ÷ API CPU/request    (14.2 ÷ 19.0 ms)
```

"Estate tables" are `assets`, `asset_identifiers`, `asset_os`,
`asset_services` and `vulnerabilities` — what every list page and every
projection touches; the history tables are appended and read by id. The 25 %
share is PostgreSQL's documented starting point for `shared_buffers`. The CPU
limit follows from the API's: a replica drives about one core of Python, and
its backends burn the measured Postgres share of that — the larger of the two
shares, because a list page costs Postgres 0.75 cores per API core where a
projection costs 0.2. The floors are a policy, not a measurement: 250m so the
request never starves autovacuum and checkpoints, one core so a single
backend's query is not throttled. With ClickHouse on, the transform's host
lookups add their Postgres CPU to the request (0.46 ms per host).

### ClickHouse

```text
volume  = h × (2 × N × (F × bytes/vuln row + P × bytes/port row)
               + system-log bytes/hour × 24 × horizon days)
memory  = request h × (idle RSS + tenant-wide query peak), limit twice that
```

The factor 2 is the unmerged copy a rescan lands until the background merge
collapses it (measured: every re-ingest adds exactly one full copy, which
`OPTIMIZE … FINAL` removes). Controls (`shapoclyack_controls`, one row per
control per run, 365-day TTL) are not in the formula: the synthetic runs have
no controls stage, so their row size is unmeasured.

### NATS JetStream (per node)

```text
volume  ≥ h × (OCTO_NATS_INGEST_MAX_BYTES + OCTO_NATS_EVENTS_MAX_BYTES)   (reserved up front)
message    = archive(H) × 4/3 + envelope, or the envelope alone above 4 MB of archive
INGEST content over 7 days = K × 7 × 2 copies × message
```

The envelope is the JSON fields and NATS headers around the archive (409 bytes
measured), and `archive(H)` carries its per-run intercept (73 KiB): at the
1 MiB `max_payload` neither is negligible (§ 2).

The volume is sized by what the streams *reserve*, not by what they hold
(§ What the measurements exposed, 1). Every run is published twice — to
`ingest.results.{tenant}` and to the legacy `ingest.raw_results` — and both
land in `INGEST`. The server's memory was only sampled: nats-server peaked at
44 MiB RSS after the harness's ingest publishes (every stream is file-backed),
well inside the shipped 100m/128Mi → 500m/512Mi; its CPU was not measured.

### Run artifacts (PVC or S3)

```text
volume = h × K × (run-dir bytes/run + H × run-dir bytes/host) × OCTO_RUN_RETENTION_DAYS
```

`run-dir bytes/host` measured here is a floor: only the report stage's files
(§ What is not measured here).

### Sensors

A sensor's CPU and memory are what its scans use, from real runs (`resources`
in `stage_timings.json`, § Re-measuring on a stand):

```text
CPU request  = h × cores a running scan keeps busy (mean of CPU-s ÷ wall-clock over runs)
CPU limit    = h × the busiest run's cores
memory       = request h × largest peak RSS (scan process + its largest tool), limit 1.5× that
daily CPU    = K × CPU-s/run + S × CPU-s/host     → "busy X % of the day" per sensor
```

A scan is bursty: it keeps its cores busy while it runs and nothing in between,
so the request is what a running scan uses, not the daily mean — spreading the
day's CPU over 24 hours would under-request by exactly the idle share. The
daily figure is printed as how much of the day each sensor is busy. Per-run
CPU (the fit's intercept: discovery, report, upload) is kept apart from the
per-host slope. The fit counts **hosts found**, not targets swept: a /16 with
300 live hosts costs its discovery sweep on every address, so `runs-dir`
records the target count beside it for a stand to compare. Resumed runs
(stages skipped from a checkpoint) and runs the harness wrote itself are left
out of the fit. The memory peak holds for runs up to the size it was measured
on; a larger `H` gets a note to re-measure. Here only the report stage could
be driven — its cost is in [§ Measured coefficients](#measured-coefficients),
and it grows with `H` like the API's.

### Lariska endpoint agents

Postgres only: one `endpoint_software_items` row per package per retained
snapshot (90 days), one `endpoint_software_changes` row per changed package
(365 days), one summary row per snapshot (kept). Set `--endpoints` in
`scale_sizing` to include them; the tiers above have none.

## Measured coefficients

The values `scale_sizing.MEASURED` holds, from `scale_measure derive` over the
runs below. Bytes include indexes and TOAST; per-unit figures are slopes across
tiers (1k / 10k / 50k; 1k / 1.85k / 1.9k / 1.95k / 3k / 10k for ClickHouse),
so a fixed per-run or per-process cost lands in the intercept instead of
inflating them — and where an intercept matters (the archive, the run
directory) the model keeps it.

| Coefficient | Value | How |
|---|---:|---|
| Postgres bytes per asset | 722 B | `assets` + `asset_identifiers` (1.35 per asset) + `asset_os`, first projection |
| … per open service | 558 B | `asset_services`, first projection |
| … per finding, steady | 1 246 B | `vulnerabilities`: 730 B written, plus the one round of dead tuples a rescan leaves and `VACUUM` makes reusable |
| … per re-observed finding | 262 B | `vulnerability_events`, second rescan after a `VACUUM` — the growth that never levels off |
| … per Lariska package / change / snapshot | 466 B / 311 B / 963 B | `endpoint_inventory.ingest_snapshot`: 20 × 1 500 packages, and 400 × 20 for the snapshot row |
| Projection CPU per host (API process) | 14.3 ms | `project_published_run`, rescans; first registration 24 ms up to 10k hosts, 29.5 ms at 50k |
| Projection CPU per host (Postgres backends) | 2.9 ms | `/proc` of the backends serving the projection |
| Projection statements per host | 29.3 | rescan; 35.0 on first registration. Exact, the same on any machine |
| Projection memory per host | 7.7 KiB | peak RSS above the process baseline |
| ClickHouse transform CPU / memory per host | 3.22 ms / 18.3 KiB | `ch_transform.transform_ingest_payload` on the run's archive, with the database the ingest worker is given (`api/app.py`) — 0.33 ms without it |
| … its Postgres statements / CPU per host | 4 / 0.46 ms | one asset lookup per host and table; backends' `/proc` |
| Risk-scorer overlays | 100 MiB, 0.4 CPU-s | loaded on a replica's first scoring, kept |
| API idle | 157 MiB, 2 millicores | `python -m api` on the 50k tier, 120 s after a 10 s settle, retro matcher off |
| API CPU per request | 19.0 ms | `api_latency` list routes × concurrency 1/8/32 × 40; 4–21 ms per list page, 66–86 ms `/api/system` |
| Postgres CPU per request | 14.2 ms | same mix, concurrency 1 (74 ms for `/api/vulnerabilities` at 150k findings, 20 ms for `/api/assets`) |
| API memory at the probe's peak | +285 MiB | `VmHWM` over idle after 32 concurrent `limit=5000` dashboard pages (450–505 CPU-ms each) |
| Report stage CPU / memory per host | 0.83 ms / 36.2 KiB | `write_pulse_artifacts` + `build_reports` (sensor side) |
| Run directory per host / per run | 11.4 KiB / 1.2 MiB | report-stage files only — a floor |
| Upload archive per host / per run | 369 B / 73 KiB | the sensor's `tar.gz` of that directory; synthetic JSON compresses 32× |
| Ingest message envelope | 409 B | JSON fields and NATS headers around the base64'd archive |
| ClickHouse bytes per vulnerability / port row | 18.0 B / 3.3 B | `system.parts` after `OPTIMIZE … FINAL`, 10k tier (16.5 / 3.1 at 50k) |
| ClickHouse resident, idle | 667 MiB | `MemoryResident`, image defaults + the shipped config map |
| ClickHouse query memory per row read | 5 B | tenant-wide diff fetch; 1 MiB for 213k port rows at 50k (the 10k tier's probes read 0 — below the tracker's resolution, so not a measurement) |
| ClickHouse `system.*_log` growth | 1.27 MB/hour | idle 1.1-hour window; 4.8 MB/hour over the 4-minute ClickHouse step. **Unconfirmed** — re-measure over a day |
| Lariska ingest CPU per package row | 0.12 ms | API side of `ingest_snapshot` |

The projection itself, per tier (CPU in CPU-seconds; wall-clock left out, the
box was shared):

| Hosts in the run | First registration: API / Postgres CPU, statements | Rescan: API / Postgres CPU, statements | Peak RSS |
|---:|---|---|---:|
| 1 000 | 24.0 s / 4.5 s, 35 016 | 13.9 s / 2.7 s, 29 340 | 198 MiB |
| 10 000 | 237 s / 37.9 s, 350 638 | 141 s / 27.2 s, 293 531 | 259 MiB |
| 50 000 | 1 475 s / 189 s, 1 751 841 | 695 s / 139 s, 1 467 123 | 567 MiB |

A rescan is linear — 13.9 to 14.1 ms of API CPU per host at every tier — and
it is what an estate costs day to day, so it is what the model uses. First
registration (new rows, identifier lookups) costs 24 ms per host up to 10k and
29.5 ms at 50k in one run. Of the peak RSS, ~98 MiB is the interpreter with the
API's modules and ~100 MiB the scorer overlays.

*Reproducibility.* The box was shared, and repeat runs of the same step
differ by more than any rounding: first-registration Postgres CPU at 10k read
37.9 s here and 94.9 s in the review's re-run, `vulnerabilities` bytes per
finding 1 246 and 1 459, the report stage 0.57 and 0.83 ms per host in this
sandbox's two runs, and ClickHouse bytes per vulnerability row 16.5 at 50k and
18.0 at 10k (compression improves with size). Statement counts and row counts
are exact and repeat to the unit; CPU, RSS and on-disk bytes should be read to
about ±30 % and re-measured on the stand that will run the system.

## What the measurements exposed

Measuring the real code paths turned up limits that decide the sizing more than
any coefficient does. None is fixed here — each belongs to the area that owns
it — but the model and the table account for all of them.

### 1. The shipped NATS volume cannot hold the streams the API asks for

JetStream **reserves** a stream's `max_bytes` when the stream is created, and
refuses a stream whose reservation does not fit the server's `max_file`. The API
creates `INGEST` with `OCTO_NATS_INGEST_MAX_BYTES` (default 10 GiB) and `EVENTS`
with `OCTO_NATS_EVENTS_MAX_BYTES` (1 GiB); `base/nats/configmap.yaml` and the
`prod-ha` copy set `max_file: 4G` on a 5 Gi volume. Reproduced against
nats-server 2.10.29 with exactly that `jetstream {}` block:

```text
RuntimeError: JetStream stream INGEST could not be created or read after 8 attempts:
add_stream failed with ServerError: code=500 err_code=10047
description='insufficient storage resources available'
```

`JOBS` is created first and succeeds, then `INGEST` fails, `_connect` raises and
the replica runs with the bus disabled — no JetStream job offers and no
ClickHouse ingest, from the first start of any install that enables NATS with
the shipped config (`prod-ha` does). With `OCTO_NATS_INGEST_MAX_BYTES=2147483648`
the same server reserves 3 GiB and all three streams come up. The rule the
model applies: **`INGEST` + `EVENTS` `max_bytes` ≤ `max_file` < volume size**,
per NATS node (an R3 stream reserves on each of its three peers). Either lower
the two stream caps to fit 4G, or raise `max_file` and the PVC to hold 11 GiB
plus headroom; the API's defaults and the manifests have to agree.

### 2. Runs of more than ~1 900 hosts never reach ClickHouse

The ClickHouse worker reads a run only from the archive the ingest message
carries inline. Three ceilings sit in front of it, and the measured archive
sizes put them far lower than a reader of the settings would guess:

| Hosts in one run | Archive (floor) | Ingest message | What happens (measured) |
|---:|---:|---:|---|
| 1 000 | 424 KiB | 566 KiB | published; ClickHouse gets the rows |
| 1 900 | 761 KiB | 1 015 KiB | published |
| 1 950 | 778 KiB | 1 038 KiB | **refused by NATS**: `nats: maximum payload exceeded` |
| 3 000 | 1.1 MiB | 1.5 MiB | **refused by NATS** |
| 10 000 | 3.6 MiB | 4.8 MiB | archive still inlined (< 4 MB), **refused by NATS** |
| 50 000 | 17.6 MiB | — | **refused by the gateway**: `archive expands to more than 536870912 bytes` |

- nats-server's default `max_payload` is 1 MiB and the shipped `nats.conf`
  does not raise it, while `results_ingest.build_gateway_payload` inlines up
  to 4 MB of archive (5.3 MB of base64). A refused publish goes to the NATS
  outbox, is retried, and ends `dead`: the run is in Postgres and on the
  artifact volume, but never in ClickHouse.
- Over 4 MB the archive is left out of the message and `ch_transform` logs
  `archive not inlined` and inserts nothing.
- Over 512 MiB *expanded* (`results_ingest.MAX_UNCOMPRESSED_BYTES`) a sensor's
  upload is refused outright. At the report-stage floor of 11.4 KiB per host
  that is about 46 000 hosts in one run; real runs, with nmap XML and tool
  logs on top, reach it sooner.

The archive figures are a floor twice over: the run directory holds only what
the report stage writes, and synthetic JSON compresses 32× where real output
will not. The model prints the largest run that still reaches ClickHouse for the
coefficients in use — ((1 MiB − 409 B envelope) × 3/4 − 73 KiB archive
intercept) ÷ 369 B per host, or the 4 MB inline cap if lower; with these,
~1 900 hosts, which the broker confirmed (1 900 published, 1 950 refused; the
per-host slope alone had said ~2 100). The probe is a bare connection's core
publish to `sizing.probe.<pid>`, a subject no stream captures, so measuring
it neither stores a message nor touches a stream's configuration. Until the limits are reconciled,
keep scans that must reach ClickHouse below that on a stand's own measured
archive size (`runs-dir --archive`), and every sensor run well below the
expansion ceiling.

### 3. Postgres grows with every scan, not with the estate

Re-observing a finding appends a `vulnerability_events` row (`observed`), and
nothing prunes that table; one `jobs` row per scan is never pruned either. At a
constant estate the database therefore grows linearly with scans: 262 bytes
per re-observed finding, so with every asset scanned daily and three findings
each, 0.7 MiB a day at 1k assets, 7.5 MiB at 10k and 37.5 MiB at 50k — 13 GiB a
year at the top tier against an estate of 0.3 GiB.
Every other per-scan table either updates in place (`assets`,
`vulnerabilities`, `asset_services`: one round of dead tuples that the next
`VACUUM` makes reusable — measured at 50k, the second rescan after a `VACUUM`
adds no heap to them and under a MiB of index each, `vulnerabilities` even
shrinking by 11 MiB) or has a retention worker (risk snapshots, endpoint
inventory, audit). Per-tenant retention for the tracker's history is #332's; until it
lands, size the volume for the horizon you intend to keep, or budget a manual
prune.

### 4. ClickHouse's own logs outgrow its data

ClickHouse stores what the scans produce compactly — 16.5–18 bytes per
vulnerability row and 3.1–3.3 per port row after merges, so a 50k-asset estate
with four ports and three findings per asset is about 3 MiB (§ Measured
coefficients). The image's default configuration, which
`base/clickhouse/configmap.yaml` merges into rather than replaces, keeps
`metric_log`, `asynchronous_metric_log`, `query_log`, `trace_log`,
`processors_profile_log`, `part_log` and `text_log` with **no TTL**. Measured on
an otherwise idle server: 1.27 MB an hour over a 1.1-hour window — about
10 GiB a year if it held (`metric_log` and `asynchronous_metric_log` are three
quarters of it). Under load it is several times that: 4.8 MB an hour over the
four minutes of this sandbox's ClickHouse step, 5.2 MB in the review's loaded
sample — about 40 GiB a year, 51–55 GiB with the 1.3 headroom, which is more
than the 50 Gi volume. Merges keep recompressing older parts and a busy
installation sits somewhere between the two, so **the ClickHouse volume
figure is unconfirmed**: the table uses the idle rate, and a day-long window
on a stand is the figure to trust. Either way it is the logs, not the scan
data, that fill the volume. A TTL on the `system.*_log` tables (or turning
off the ones nobody reads) belongs in the ClickHouse config map.

### 5. One API replica is one Python process

`python -m api` runs one uvicorn worker: request handling, the run projection
and the ClickHouse transform share one GIL, so a replica turns about one core of
CPU into work however many ingests (`OCTO_AGENT_RESULTS_MAX_CONCURRENT_INGESTS`,
default 4) it admits. Measured under the `api_latency` probe: the busiest
cells kept the process at 0.86–1.00 cores whether 1, 8 or 32 clients were
waiting, and latency took the rest (the dashboard page's p95 went from 1.0 s to
5.3 s to 19.7 s on the shared box). At 14.3 ms of projection and 3.22 ms of
ClickHouse transform per host (the transform with its Postgres lookups, as the
ingest worker runs it), one replica ingests at most ~57 hosts a second. The 4-core limit in `base/api-deployment.yaml`
is for the scanner subprocess of a *local* scan (`OCTO_JOB_EXECUTION_MODE=local`),
which is a separate process; with sensors doing the scanning, more replicas add
ingest capacity and a higher limit does not.

The projection is also statement-bound: 29.3 statements per host on a rescan
(35 on first registration), each a round trip. On the measuring box the
database was on a local socket; across a network each millisecond of
round-trip time adds about 5 minutes to a 10 000-host rescan (293 531
statements) and 24 minutes to a 50 000-host one — time the ingest slot is
held, on top of the CPU.

### 6. Memory follows the size of one run

Three steps hold a whole run in memory: the sensor's report stage (it builds
every report from lists of all hosts, ports and findings), the upload (read
whole, then base64'd into the ingest message) and the ClickHouse transform
(extracts every archive member into memory). Measured peaks for one run:

| Hosts in one run | Report stage (sensor) | ClickHouse transform (API) | Projection (API) |
|---:|---:|---:|---:|
| 1 000 | 126 MiB | 210 MiB | 198 MiB |
| 10 000 | 444 MiB | 405 MiB | 259 MiB |
| 50 000 | 1.83 GiB | 1.11 GiB | 567 MiB |

(Peak RSS of the process doing the step. The report stage starts from a 25 MiB
interpreter; the two API steps from ~98 MiB of modules plus the 100 MiB scorer
overlays. The transform re-run with the database attached peaked at 220 MiB
and 396 MiB for 1 000 and 10 000 hosts.)

So `H`, the hosts per run, sets the API's memory limit (times the concurrent
ingests) and the sensor's; splitting a 50k-host sweep into 50 runs of 1 000
hosts costs the same database work and a fraction of the memory.

## Consistency with the shipped manifests

What `k8s/shapoclyack/base` and `overlays/prod-ha` request, against the model at
the three tiers (rendered with `kubectl kustomize`, 2026-09-24, `main` at
`1ed74b7`). Nothing here edits a manifest — the hardening pass (#338) owns
them — but three of them cannot work as shipped at the sizes they are meant for.

| Workload | Shipped (request → limit; volume) | Model (1k / 10k / 50k tier) | Verdict |
|---|---|---|---|
| NATS | 100m/128Mi → 500m/512Mi; 5 Gi per node, `max_file: 4G` | 14.3 GiB per node | **Cannot work**: the API's streams reserve 11 GiB and are refused (§ 1). Lower `OCTO_NATS_INGEST_MAX_BYTES`/`OCTO_NATS_EVENTS_MAX_BYTES` to fit 4G, or raise `max_file` and the PVC together |
| Run artifacts | `scanner-data` 20 Gi (RWX or S3 in `prod-ha`) | ≥ 0.6 / 5.4 / 25.8 GiB | **Short at 50k** even at the report-stage floor with 30-day retention; enough at 10k if real runs stay under ~3.5× the floor (`runs-dir` will say) |
| PostgreSQL (in-cluster, `base`/`prod`) | 250m/512Mi → 2/2Gi; 10 Gi | 250m / 1 GiB → 1.9 cores / 1 GiB; 1.7 / 4.9 / 19.1 GiB after a year | **Short at 50k**: the volume fills in about 8 months at 50k assets scanned daily (6 with headroom), all of it `vulnerability_events`. Memory request below the model's 1 GiB floor, limit fine. `prod-ha` moves Postgres out of the cluster; the volume figures apply to the managed instance |
| API (agent mode) | 500m/1Gi → 4/4Gi; `prod-ha` 2–6 replicas, HPA at 70 % of 500m | 70–80m / 334 MiB → 1 core / 740–774 MiB (runs of 250–500 hosts) | The 4 GiB limit holds four concurrent ingests of runs up to ~24 000 hosts (the model asks 2.0 GiB at 10 000); **not** 50 000-host runs (7.3 GiB). The request is generous, which is what keeps the HPA from scaling on idle; the limit above one core serves only local-mode scans, whose footprint these rows leave out (§ [API](#api-per-replica-agent-mode), #338) |
| ClickHouse | 500m/2Gi → 4/8Gi; 50 Gi | 868 MiB → 1.7 GiB; 13.4 GiB after a year at the idle log rate | **Unconfirmed.** At the idle rate the volume lasts 4–5 years of its own logs; at the loaded rate (4.8–5.2 MB/h, § 4) it fills within the first year. A day-long window on a stand decides it; a TTL on `system.*_log` settles it either way |
| Sensor (`base/agents`) | 500m/512Mi → 2/2Gi, VPA | n/m | Unconfirmed. The report stage alone peaks at 444 MiB for a 10 000-host run and 1.83 GiB for 50 000, before any scanning tool is counted |
| Scanner Job / CronJob (local scans) | 4/4Gi → 8/8Gi (`dev`: 1/1Gi → 2/2Gi) | n/m | Unconfirmed, same reason |

The HPA's ceiling of six replicas and the 90-connection pool budget in
[high-availability.md](high-availability.md#connection-pool-sizing) are not
contradicted: a replica holds about one core of Python whatever it is asked,
so six replicas put at most about 1.2 cores of projection load on Postgres
(2.9 ms per 14.3 ms) and about 4.5 cores when all six serve list pages
(14.2 ms per 19.0 ms). The latter is what the PostgreSQL CPU limit is sized
from: 1.9 cores at the table's two replicas, 5.8 at six with headroom.

For the kind PoC ([implementation plan](wiki/implementation-plan.md)): the
`kind-dev` overlay requests 1.6 CPU / 4.1 GiB for the long-running services —
the scanner-executor's 500m / 1 GiB among them, which since #338 takes the place
of the 1 CPU / 1 GiB per scan Job — plus 8 GiB of ephemeral storage for the
executor's run directories, and its claims add up to 85 GiB (local-path does
not enforce them). Of the plan's 4 vCPU / 8 GB / 50 GB, only the disk is
supported by these measurements: a 1k-asset PoC writes ~16 GiB of Postgres,
ClickHouse and artifacts in a year (the 1k column), which 50 GB holds. The CPU
and memory are not: `kind-dev`'s API runs in agent mode, but with NATS and
ClickHouse disabled, so neither the API rows nor the ingest path measured here
describe it, and the scan itself is unmeasured.

## Re-measuring on a stand

The harness needs a Postgres database and a ClickHouse it may write to under
`sizing-*` tenants — a stand's own, never production — and, for the ingest
checks, the stand's NATS. Nothing it does contacts a scan target: the run
directories are written by the scanner's report code from synthetic hosts in
`10.0.0.0/8`, and nothing is scanned.

```bash
# 0. A dedicated, migrated database. The harness reports an unmigrated one
#    (with this hint) instead of crashing on it.
createdb -h <postgres> -U <owner> shapoclyack_sizing
export OCTO_POSTGRES_URL=postgresql+psycopg://…/shapoclyack_sizing
alembic -c api/db/alembic.ini upgrade head
export OCTO_CLICKHOUSE_URL=http://default:…@clickhouse:8123
export OCTO_NATS_URL=nats://api:…@nats:4222
W=/var/tmp/sizing
OWN="--i-own-database shapoclyack_sizing"   # the writing steps check it against current_database()

# 1. Postgres: build each tier's run, project it, rescan twice (VACUUM between)
python -m tests.fixtures.scale_measure postgres   --tiers 1000,10000,50000 --work-dir $W $OWN --out pg.json
# 2. ClickHouse + the NATS limits: seeds each tier's assets, ingests its run
#    twice, probes the broker. 1900/1950 bracket the max_payload ceiling.
python -m tests.fixtures.scale_measure clickhouse --tiers 1000,1900,1950,3000,10000,50000 --work-dir $W $OWN --out ch.json
# 3. The API process under the api_latency probe, on the largest tier
python -m tests.fixtures.scale_measure api --tenant sizing-50000 --port 18080 --work-dir $W $OWN --out api.json
# 4. Lariska snapshots
python -m tests.fixtures.scale_measure endpoints --work-dir $W $OWN --out ep.json
# 5. ClickHouse's own logs: two samples, hours apart (a day is better), while
#    the stand does its normal work; the rate is the growth between them.
#    Not read-only: each sample runs SYSTEM FLUSH LOGS.
python -m tests.fixtures.scale_measure ch-system-logs --out logs-0.json
python -m tests.fixtures.scale_measure ch-system-logs --since logs-0.json --out logs.json
# 6. Real scans: bytes per run and per host, and (since #337) sensor CPU and
#    peak RSS from stage_timings.json. Read-only; point it at the run volume
#    ($OCTO_OUTPUT_DIR/runs, /app/scanner/output/runs in the images). prod-ha
#    keeps artifacts in S3 (OCTO_ARTIFACT_BACKEND=s3): copy a sample of run
#    prefixes to local disk first and point it there.
python -m tests.fixtures.scale_measure runs-dir /app/scanner/output/runs --archive --out runs.json
# 7. Real rows: bytes per row from the stand's own database, which has the
#    jobs, evidence and bloat synthetic tiers cannot have. Read-only.
OCTO_POSTGRES_URL=postgresql+psycopg://…/shapoclyack \
python -m tests.fixtures.scale_measure postgres-live --out live.json

python -m tests.fixtures.scale_measure derive pg.json ch.json api.json ep.json logs.json runs.json live.json --out stand.json
python -m tests.fixtures.scale_measure --help   # every command's options
python -m tests.fixtures.scale_sizing --tiers --markdown --coefficients stand.json
# …and with this sandbox's figures filling the gaps, every such cell marked †
python -m tests.fixtures.scale_sizing --tiers --markdown --coefficients stand.json --fill-from-sandbox
```

Where to run it matters, because the steps read `/proc`: a step's own CPU and
peak RSS always, the Postgres backends' CPU only when the database runs on the
same host (otherwise `null`, and the model prints `n/m` for Postgres CPU). On
the Arch stand, run it from a checkout on the host that runs Postgres. On kind,
the images do not ship `tests/`: copy the directory into an API pod, which
reaches all three services with the environment it already has, and run it
there against a *separate* database (Postgres CPU then reads `null`, since the
database is another pod's):

```bash
POD=$(kubectl -n network-scan get pod -l app.kubernetes.io/component=api -o name | head -1)
kubectl -n network-scan cp tests "${POD#pod/}:/tmp/sizing/tests"
# The password stays in the pod: single quotes defer $POSTGRES_PASSWORD to the
# pod's own shell, so it is in neither this command line nor the pod's argv.
kubectl -n network-scan exec "$POD" -- sh -c \
  'cd /tmp/sizing && export PYTHONPATH=/app:/tmp/sizing \
     OCTO_POSTGRES_URL="postgresql+psycopg://octo:${POSTGRES_PASSWORD}@shapoclyack-postgres-client:5432/shapoclyack_sizing" \
   && python -m tests.fixtures.scale_measure postgres --i-own-database shapoclyack_sizing \
        --work-dir /tmp/sizing/w --out /tmp/sizing/pg.json'
```

The writing steps (`postgres`, `clickhouse`, `api`, `endpoints`, `purge`)
need `--i-own-database NAME`, and refuse to run unless it names the database
the URL reaches (`current_database()`). They also refuse a store that is not
theirs: any tenant besides their own `sizing-*` ones (and `scale_seed`'s
`scale-test`) — including the `default` tenant an API creates on startup, once
it owns any row (an asset, a job, an agent, a schedule, …) — any console account that dev
mode did not seed, and ClickHouse rows of any other tenant. That is because
they VACUUM, seed and purge their tenants' rows, and `api` starts an API in dev
mode, which seeds the demo accounts. `--allow-shared-stores` overrides the
second check for a disposable stand, never for production. Store URLs reach
the child processes through the environment, not their command lines. The
`clickhouse` step's broker probe opens its own bare connection and makes a
core publish to `sizing.probe.<pid>`: it creates and reconfigures no stream,
and no stream stores the message. Each step runs its measured work in a child process,
so a peak RSS is that step's own. `runs-dir` is the step that closes
the sensor gap: once a stand has run real scans with this release, its
`stage_timings.json` files carry `resources` — CPU-seconds of the scan and of
the tools it waited for, and their peak RSS — and `derive` turns them into
the sensor's per-host and per-run CPU, the cores a running scan keeps busy,
and its peak RSS with the run size it was seen at. Runs the harness wrote
(marked `synthetic` in their `stage_timings.json`) and resumed runs are
skipped and counted.

Clean up afterwards:

```bash
python -m tests.fixtures.scale_measure purge $OWN                  # every sizing-* row, Postgres and ClickHouse
python -m tests.fixtures.scale_measure purge $OWN --demo-accounts  # …and the accounts `api` seeded
rm -rf "$W"                                                         # the run directories
```

`purge` deletes every row of every `sizing-*` tenant, then the tenants, and
reports what it could not delete. `audit_events` rows are immutable (migration
`0037`) and stay; it counts them. Dropping the dedicated database is the
complete cleanup.

## Disaster recovery at 10k assets

The DR drill at 10k assets the issue also asks for belongs to
[#333](https://github.com/onixus/Shapoclyack/issues/333) (backup and restore
beyond Postgres: artifacts, ClickHouse, JetStream), in
`docs/disaster-recovery.md` on that branch. The volumes it restores are the
ones sized here: at the 10k tier, about 5 GiB of Postgres after a year,
13 GiB of ClickHouse (almost all of it `system.*_log`, which a restore can
skip), at least 4.2 GiB of run artifacts, and 14.3 GiB of JetStream per NATS
node — of which only the unconsumed messages matter.

## What is not measured here

- **The scan itself.** naabu, nmap, nuclei and Pulse need live targets; this
  container has none of them and must not scan anything. Sensor CPU per host,
  sensor peak memory and the raw tool output in a run directory (nmap XML,
  nuclei JSONL, `pipeline.log`, the PDF, `diff.json`) come from `runs-dir` on a
  stand. Until then the sensor rows print `n/m`, the artifact volume is a
  floor, and the shipped sensor values (the scanner-executor's 500m/1Gi
  request and 4/4Gi limit since #338, VPA in `base/agents`) stand unconfirmed.
- **Real data.** Hosts, ports and CVEs are the `scale_seed` estate: three
  findings and four ports per asset, a 2 000-CVE pool, no banners, no CPEs.
  Row sizes in Postgres depend little on content; ClickHouse's compressed
  bytes and every archive size depend on it a lot, and synthetic JSON
  compresses better than real output. Use `--findings-per-asset` /
  `--services-per-asset` for your estate, and `runs-dir --archive` for real
  archive sizes.
- **Durable Postgres writes.** The measuring server ran with `fsync`,
  `synchronous_commit` and `full_page_writes` off. Table and index sizes do not
  depend on that; WAL volume and write latency do, and neither is modelled
  beyond one `max_wal_size` of headroom.
- **Concurrency.** Each ingest was measured alone. Several at once on one
  replica share one core (§ What the measurements exposed, 5); the memory
  formula adds them up, which is the conservative reading.
- **One request mix, not a UI.** API CPU per request is the `api_latency`
  route mix at concurrency 1/8/32 over the 50k tier; a console user generates
  some other mix. `--requests-per-second` is an input for that reason.
- **The retro matcher.** It was off while the API was measured: its first sweep
  on a fresh process re-reads every stored fingerprint (the tiers left
  ~250 000), a one-off that would have been read as idle load. Its cost per
  fingerprint is unmeasured.
- **Controls rows, reports, webhooks, backups.** Not in the synthetic runs or
  not driven: `shapoclyack_controls`, `generated_reports` (365 days),
  `webhook_deliveries` (30 days), `audit_events` (365 days) — `postgres-live`
  reports their bytes per row on a stand. The backup volume is #333's.
- **NATS server CPU**, and ClickHouse CPU beyond the queries timed. Neither
  came close to the shipped requests in anything observed here.
