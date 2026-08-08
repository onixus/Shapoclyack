# Scale profile — 1k / 10k / 50k assets

Results of ROADMAP P3.8: the query paths that grow with asset count, measured
over the P3.7 fixtures (`tests/fixtures/scale_seed.py`). Reproduce with
`tests/fixtures/scale_profile.py` — see [development.md](development.md#scale-fixtures).

## What these numbers are

Wall-clock medians measured **in-process against a local server** (Postgres 16,
ClickHouse 24.3, both in containers on one laptop). No network, no concurrency,
no contention.

They are therefore useful for **comparing shapes** — this query against that
one, before a fix against after — and are **not** a production latency budget.
The durable half of the output is the exact counts: ClickHouse rows/bytes read
(from `system.query_log`) and Postgres statements per call. Those do not depend
on the machine.

> Do not run the test suite against a database holding a fixture.
> `tenants.reset_for_tests()` deletes every asset row, so the tests and the
> fixture need separate databases (or a reseed between them).

## Findings

### 1. `list_assets` issued one query per row (fixed)

The registry page fetched each asset's identifiers in its own `SELECT`, so a
page of N cost N+2 statements. Wall-clock hid it — over a local socket each
round-trip is a fraction of a millisecond — but the dashboard requests
`limit=5000` (`MAX_LIMIT`), which meant **5002 statements and ~1.1 s**, and
every one of those round-trips is paid again over a real network.

Fixed in `api/services/assets.py` by fetching the whole page's identifiers in a
single `IN` query.

| At 50k assets | Before | After | |
|---|---:|---:|---|
| `limit=5000` (dashboard) | 1099.7 ms | **77.0 ms** | 14× |
| `limit=100` (default page) | 27.8 ms | **9.3 ms** | 3× |
| status filter | 21.8 ms | **3.9 ms** | 5.6× |
| statements per call | 5002 / 102 | **3** | — |

The statement count is now constant in page size, which is the part that
matters once the database is not on localhost. Guarded by
`test_list_assets_fetches_page_identifiers_in_one_query`.

### 2. The ClickHouse diff helpers read a tenant's whole history (bounded)

`ch_diff.fetch_tenant_cves` / `fetch_tenant_ports` materialize every row for a
tenant into a Python set, because `compute_clickhouse_diff` is a set
difference.

| At 50k assets | Rows read | Server time | Total |
|---|---:|---:|---:|
| `fetch_tenant_cves` | 182 919 | 5 ms | 129.6 ms |
| `fetch_tenant_ports` | 200 000 | 2 ms | 145.4 ms |
| `compute_clickhouse_diff` | 382 919 | 7 ms | 461.2 ms |

The server is not the problem — 2–5 ms of it. The cost is transferring the rows
and building 350k-element sets in Python. It scales linearly, and it scales
with **history**, not just asset count: these tables accumulate across runs, so
a tenant at a steady 50k assets keeps growing this number every scan.

Nothing in the application calls these helpers yet — the scanner's filesystem
diff is still the default path (ROADMAP Phase 3.4), so this is a latent hazard
rather than a live regression.

Bounded rather than optimized, deliberately. Both helpers now take `max_rows`
(default 500 000) and **raise** when a tenant exceeds it. Truncating would be
worse than failing: a short set makes the diff report every dropped key as
`removed` and every later re-observation as new. `fetch_tenant_ports` also
gained the `since` parameter its CVE counterpart already had, since narrowing
the window is the actual remedy when the cap trips — at 50k assets, `since=7d`
cuts the CVE fetch from 149 930 keys to 35 207.

Making this genuinely cheap means diffing server-side in ClickHouse instead of
in Python. That is a redesign, and speculative while no caller exists; it
belongs with the work that wires the helper up.

### 3. `PARTITION BY` — evaluated, rejected

Both tables are unpartitioned `ReplacingMergeTree`:

| Table | Rows | On disk | Sorting key | Partition key |
|---|---:|---:|---|---|
| `shapoclyack_vulnerabilities` | 182 919 | 3.7 MB | `tenant_id, asset_ip, cve_id` | none |
| `shapoclyack_open_ports` | 200 000 | 0.9 MB | `tenant_id, target_ip, port` | none |

**Recommendation: leave both unpartitioned.**

The obvious candidate, `PARTITION BY toYYYYMM(timestamp)`, is not a tuning
change — it changes what the tables mean. ReplacingMergeTree deduplicates
**within a partition**, so partitioning by month turns "one row per
(tenant, asset, CVE)" into "one row per (tenant, asset, CVE, month)".

Verified directly on ClickHouse 24.3 — the same key written three times across
two months, then `OPTIMIZE TABLE … FINAL`:

| Table | Rows after merge |
|---|---:|
| unpartitioned (current) | **1** |
| `PARTITION BY toYYYYMM(timestamp)` | **2** |

So a vulnerability still present next month would count twice, and the tables
would grow with time instead of converging on current state. `fetch_tenant_cves`
happens to be immune (it builds a `set`), but any `count()` over these tables
would silently change meaning.

The other candidate, partitioning by `tenant_id`, is worse: `tenant_id` is
already the leading column of both sorting keys, so tenant-scoped reads are
efficient without it, and it would produce one part-set per tenant — the small-
parts problem ClickHouse explicitly warns about.

Read amplification does not justify the trade either. Both profiled queries
filter on `tenant_id` and read exactly the rows they return; there is no
partition pruning to win, because there is no scanned-and-discarded set.

If growth needs bounding later, `TTL timestamp + INTERVAL n MONTH` drops old
data without touching dedupe semantics. That is the tool to reach for, not
`PARTITION BY`.

### 4. Identifier search is a sequential scan

`list_assets(q=…)` does `lower(identifier_value) LIKE '%needle%'`. The leading
wildcard makes the index unusable, so it scans `asset_identifiers`: 1.9 ms at
1k → 4.9 ms at 10k → 21.7 ms at 50k, i.e. linear.

Left as is. It is ~20 ms at the top of the supported range, it is a
user-initiated search rather than a page load, and the fix (a `pg_trgm` GIN
index) adds an extension dependency and write amplification for a cost that is
not yet hurting. Recorded here so the next person sees the slope rather than
rediscovering it.

## Full results

`OFFSET` cost is visible but mild — a deep page costs ~1.6× a first page at
50k, since Postgres still walks the skipped rows.

### ClickHouse

| Query | 1k | 10k | 50k |
|---|---:|---:|---:|
| `fetch_tenant_cves` | 7.0 ms | 25.7 ms | 129.6 ms |
| `fetch_tenant_ports` | 7.5 ms | 57.8 ms | 145.4 ms |
| `compute_clickhouse_diff` | 15.6 ms | 90.1 ms | 461.2 ms |

### Postgres (after the fix in finding 1)

| Query | 50k |
|---|---:|
| `list_assets` first page (`limit=100`) | 9.3 ms |
| `list_assets` deep page (`offset=49900`) | 14.8 ms |
| `list_assets` max page (`limit=5000`) | 77.0 ms |
| `list_assets` status filter | 3.9 ms |
| `list_assets` search by IP | 21.7 ms |
| `list_assets` search by FQDN | 19.9 ms |
| `list_assets` search prefix (many hits) | 23.6 ms |
| `list_assets` sort by criticality (unindexed) | 9.0 ms |
| `get_asset` (single) | 1.5 ms |

## What this does not cover

- **No end-to-end API latency.** Services are called in-process; FastAPI
  routing, JSON serialization, auth, and the network are all excluded. The SLO
  in [slo.md](slo.md) for API latency still has no measured basis.
- **No concurrency.** Single-threaded, one query at a time. Connection-pool
  behaviour and lock contention are unmeasured.
- **No UI measurement.** The `web-next` tables were not profiled; finding 1 was
  reached by counting statements on the endpoint they call.
- **No ingest path.** `ch_ingest_worker` throughput at scale is untested.
- **One synthetic tenant.** Everything here is single-tenant; cross-tenant
  interference in shared tables is unmeasured.
