# Configuration

Scanner configuration is YAML-based. The default file is
`scanner/config/default.yaml`; deployments can provide another file through
`OCTO_CONFIG`.

## Configuration order

Effective scanner settings are built from:

1. the selected YAML file;
2. deployment environment variables;
3. installation-wide API overrides for whitelisted editable paths;
4. job-specific options.

API overrides are validated against the full scanner schema before persistence.
Secrets are not exposed or editable from the Web UI.

## Profiles

Use a conservative profile for a new target set and increase concurrency only
after observing coverage, target stability, and network impact.

| Profile | Discovery behavior | Recommended use |
|---|---|---|
| `safe` | Lower rates and conservative external-tool settings | First scan, fragile or remote links |
| `balanced` | Normal rates and staged gap handling | Routine authorized scanning |
| `fast` | Higher rate and reduced secondary work | Controlled, high-capacity environments |
| `thorough` | Verification, ICMP, and fuller hostname work | Deep assessment with a larger window |

Profile names and exact values are defined in the active YAML. Do not treat the
table as a fixed performance guarantee.

## Input contract

| File | Values | Notes |
|---|---|---|
| `scanner/inputs/ranges.txt` | IPv4/IPv6 address or CIDR | One entry per line |
| `scanner/inputs/domains.txt` | FQDN | Normalized and resolved |
| `scanner/inputs/ports.txt` | TCP port or supported range | Optional override |
| `scanner/inputs/ports_udp.txt` | UDP port or supported range | Optional override |

Invalid lines are reported. A run with no valid targets exits with code `3`.

## Protocol selection

TCP is the default. UDP adds materially more time and uncertainty; keep its port
list focused. Combined scans preserve protocol in intermediate and aggregate
results.

```yaml
scan:
  protocol: tcp
```

Supported deployment/job options can select `tcp`, `udp`, or `both`.

## NSE and vulnerability checks

NSE profiles control which scripts run after port discovery. Start with
service-specific and safe checks, then enable broader vulnerability scripts for
authorized targets and a suitable maintenance window.

Nuclei is an optional stage. Template version, severity filters, concurrency,
and rate limits should be pinned in production.

## Discovery modules

Optional modules include:

- CT-log subdomain collection;
- wordlist-based subdomain discovery (built-in list, an operator-set
  `ct.brute_force.wordlist_file` path, or a tenant-uploaded wordlist selected
  per scan — see below);
- Cloudflare zone import;
- ASN/prefix discovery via RIPEstat;
- public cloud-resource candidate checks;
- typosquat and dangling-CNAME monitoring;
- offline ASN and GeoIP enrichment.

Several modules query third-party infrastructure. Enable them deliberately,
keep candidate/concurrency caps, and review their data-handling policies.

### Tenant-uploaded wordlists

Operators can upload custom brute-force dictionaries through the API/UI
(`POST /api/wordlists`, or the **Wordlists** page) instead of baking a file
into the image or a mounted volume. A wordlist is stored per tenant, normalized
to the scanner's on-disk shape (lowercased, de-duplicated, blank/comment lines
dropped), and selected per scan via `StartScanRequest.wordlist_id`. Selecting a
`subdomain` list enables `ct.brute_force` for that scan with the uploaded list;
a `bucket` list enables cloud-storage discovery. This is **local-execution
only** — a remote agent runs its own mounted config and never sees the uploaded
file, so a `wordlist_id` on an agent-mode scan is rejected. Caps:
`OCTO_WORDLIST_MAX_WORDS` (default 50000) and `OCTO_WORDLIST_MAX_BODY_BYTES`
(default 8 MiB).

## Enrichment sources

| Source | Purpose | Typical update |
|---|---|---|
| GeoIP MMDB | Country and city | Provider release cadence |
| ASN MMDB | ASN and organization | Provider release cadence |
| EPSS | Exploit probability | Daily |
| CISA KEV | Known exploitation | Daily |
| CVSS v4 overlay | Score/vector enrichment | With source updates |

The Kubernetes enrichment overlay provides a shared PVC and scheduled refresh.
Placeholder fixture data is suitable only for tests.

### CVSS v4 baseline and refresh

`scanner/data/cvss4/cvss4.json` is committed and baked into every image as the
baseline, then kept current in place — the daily refresh does not rebuild it:

```bash
# Baseline rebuild — pages the whole NVD corpus, run rarely and by hand.
# Set NVD_API_KEY first: it is ~10x faster (50 vs 5 req/30s).
python3 scripts/fetch-cvss4-db.py --full -o scanner/data/cvss4/cvss4.json

# Incremental — what scripts/fetch-enrichment.sh runs daily.
python3 scripts/fetch-cvss4-db.py --last-mod-days 8
```

Every mode merges into the existing file, so a CVE already scored is never
dropped by a later run, and a `--full` rebuild that returns nothing (or fails
mid-way) refuses to publish rather than replacing a good database with an empty
one. `--seed` unions the image's committed baseline into an existing database,
which is how a newer baseline reaches a volume that already has one — the seed
"floor" in `fetch-enrichment.sh` only fires when the file is absent, and an
incremental run only adds recently-modified CVEs.

### NVD API: known traps

Every one of these cost real debugging time. They are the reason the fetcher
looks more defensive than a paging loop ought to.

- **`cvssV4Severity` does not select v4-scored CVEs.** Querying it returns a
  handful of results against a corpus where roughly a third of recent CVEs carry
  `cvssMetricV40`. There is no server-side way to ask for "CVEs with a v4
  score", so `--full` pages the entire corpus and filters client-side.
- **Throttling arrives as a trickle, not a 429.** Under concurrency NVD stops
  sending body bytes without closing the connection or returning an error code.
  Sockets stay `ESTABLISHED` with frozen byte counters. A socket timeout cannot
  catch this — it is per-operation, and the occasional few bytes reset it
  forever — so `_read_bounded()` puts a wall-clock ceiling on the whole body.
  Eight concurrent pages reliably triggered this within about five minutes;
  four is the shipped default.
- **HTTP 503 is routine**, not an outage. It appears mid-run under load and
  clears on backoff, so it is retried like 429 rather than treated as fatal.
- **Deep pagination is slow.** A 2000-CVE page is ~9 MB and takes NVD around
  20 seconds to render, so a serial full rebuild is roughly an hour. Wall-clock
  is dominated by that latency, not by the request rate — an API key raises the
  ceiling from 5 to 50 req/30s but only cuts about a quarter off a serial run.
- **Most older CVEs have no v4 score at all.** `CVE-2014-0160`, `CVE-2021-44228`
  and friends carry only `cvssMetricV31`/`cvssMetricV2`. CVSS v3.x is
  deliberately never substituted, since these scores are consumed downstream as
  genuine v4 — so a fetch restricted to well-known old CVEs returns nothing.
  About 1,900 entries do come from CVEs published before 2024, added
  retroactively by CNAs, which is why `--full` does not skip the older corpus.

## Startup safety: `OCTO_ENV`

The API runs as **`prod`** unless told otherwise, and a `prod` process **refuses
to start** while any of the following is still at its built-in default:

| Refusal | Why |
|---|---|
| `OCTO_JWT_SECRET` (or `API_SECRET_KEY`) unset, empty, or equal to the shipped default | The default is published in this repository, so anyone can mint a valid admin token |
| `OCTO_API_CORS` containing `*` (including when unset, which means `*`) | With credentials in play, any page a logged-in operator visits could call this API with their session. A `*` listed beside real origins is refused too — the wildcard matches everything regardless of what sits next to it |
| **No console account exists** — the `users` table is empty and `OCTO_API_USERS` is unset (checked at startup, once the database is up) | The built-in demo accounts are not seeded in `prod`; their passwords are published in this repository. An install nobody can log into is a failure whether it is reported at startup or discovered at the login form |

The point is that *"forgot to configure"* and *"configured"* must not look alike.
All problems are reported in one message, so fixing them does not take one
redeploy per variable, and the message names variables and never prints values —
it lands in logs and terminals.

```bash
OCTO_ENV=dev
```

`dev` allows every default above and is meant for a laptop, a kind cluster, or
the test suite. The `dev` overlay (`k8s/shapoclyack/overlays/dev`, inherited by
`kind-dev`) sets it; `base` and the `prod` overlay deliberately do not. Any other
value is rejected outright rather than guessed in either direction — a
misspelled `prodution` must not silently disable the checks.

A set `OCTO_AGENT_TOKEN` **warns** rather than refuses: the legacy shared token
still works and maps to `tenant_id=default`, so refusing would break a working
install over a design preference rather than a published credential. Prefer
per-tenant provisioning keys (`POST /api/auth/agent/token`).

The first two are checked in `load_settings()` from the environment alone. The
third needs the database and therefore runs at startup
(`api/services/users.py:bootstrap`) — only the table can tell an installation
with a real admin from one with none.

> Related, not yet covered: `OCTO_POSTGRES_URL` still falls back to local SQLite
> when unset, which is the same fail-open shape as the defaults above.

## Environment variables

Core deployment variables:

| Variable | Purpose |
|---|---|
| `OCTO_ENV` | `prod` (default) or `dev`. `prod` refuses to start on built-in defaults — see [above](#startup-safety-octo_env) |
| `OCTO_CONFIG` | Scanner YAML path |
| `OCTO_OUTPUT_DIR` | Per-run output root |
| `OCTO_STATE_DIR` | Checkpoint and scheduler state |
| `OCTO_JWT_SECRET` | User JWT signing secret. **Required in `prod`**; must be identical across API replicas |
| `OCTO_API_USERS` | **One-time bootstrap only** since #156. Accounts live in the Postgres `users` table; this JSON list is imported on a first start with an empty table and ignored afterwards. Manage accounts through `/api/users` — see [api-and-rbac.md](api-and-rbac.md#console-accounts) |
| `OCTO_API_CORS` | Comma-separated allowed origins. **Must not be `*` in `prod`** |
| `OCTO_POSTGRES_URL` | Primary database connection |
| `OCTO_NATS_URL` | JetStream connection; empty disables NATS |
| `OCTO_CLICKHOUSE_URL` | ClickHouse HTTP connection |
| `OCTO_CH_INGEST_ENABLED` | Enable analytical ingest worker |
| `OCTO_JOB_EXECUTION_MODE` | `local` or `agent` |
| `OCTO_INSTANCE_ID` | Identity of this API replica in the shared job queue; defaults to the hostname. Only local-mode jobs owned by this identity are failed as orphans on startup |
| `OCTO_ALLOW_SCAN_START` | Permit job creation from API/UI |
| `OCTO_ASSET_STALE_DAYS` | Age threshold for stale assets |
| `OCTO_ASSET_EVENTS_ENABLED` | Publish asset-level events to `events.asset.{tenant}.{kind}` after each run (default `true`; inert without `OCTO_NATS_URL`) |
| `OCTO_ASSET_EVENTS_MAX_PER_RUN` | Per-run publish cap (default `1000`); the overflow is logged and counted, and `diff.json` always keeps the full set |

Outbound webhooks (see
[architecture.md](architecture.md#outbound-webhooks)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_WEBHOOKS_ENABLED` | `true` | Register `/api/webhooks` and consume asset events. Off means no subscriptions, no deliveries, no endpoints |
| `OCTO_WEBHOOK_DISPATCH_ENABLED` | `true` | Run the delivery loop in *this* replica. Off keeps the API surface (subscriptions, DLQ, audit trail) while confining outbound HTTP to selected replicas |
| `OCTO_WEBHOOK_MAX_ATTEMPTS` | `6` | Attempts, including the first, before a delivery is dead-lettered |
| `OCTO_WEBHOOK_RETRY_BASE_SECONDS` | `30` | First backoff; doubles per attempt |
| `OCTO_WEBHOOK_RETRY_MAX_SECONDS` | `3600` | Backoff cap |
| `OCTO_WEBHOOK_TIMEOUT_SECONDS` | `10` | Per-request timeout. A receiver needing longer is doing work in the request instead of queueing it |
| `OCTO_WEBHOOK_DISPATCH_INTERVAL_SECONDS` | `5` | How often the due end of the queue is drained |
| `OCTO_WEBHOOK_DISPATCH_BATCH_SIZE` | `50` | Deliveries claimed per tick |
| `OCTO_WEBHOOK_DELIVERY_RETENTION_DAYS` | `30` | Age past which delivered/dead rows are pruned; `0` keeps the audit trail forever. Pending rows are never pruned |
| `OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS` | `false` | Allow webhook URLs resolving to loopback/private/link-local addresses. Needed for an on-cluster receiver; it also removes the SSRF guard, so scope it to installations where operators are trusted with internal reachability |
| `OCTO_WEBHOOK_MAX_SUBSCRIPTIONS_PER_TENANT` | `20` | Bound on how much fan-out one event can cause |

Job leases and the reaper (see [architecture.md](architecture.md#leases)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_JOB_LEASE_SECONDS` | `300` | How long a claimed/running job survives without its executor renewing. Keep it well above the agent heartbeat interval — too low and live scans are requeued under a working agent |
| `OCTO_JOB_MAX_ATTEMPTS` | `3` | Hand-outs a job gets before an expired lease fails it instead of requeueing it |
| `OCTO_JOB_REAPER_ENABLED` | `true` | Run the expiry sweep in this replica. Safe in all replicas; disabling it everywhere means abandoned jobs stay in flight forever |
| `OCTO_JOB_REAPER_INTERVAL_SECONDS` | `60` | Sweep interval |

Recurring-scan dispatcher (see
[architecture.md](architecture.md#schedule-dispatcher-leadership)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_SCHEDULER_DISPATCH_ENABLED` | `true` | Start the dispatcher thread in this replica. Safe to leave on everywhere: only the replica holding the advisory lock dispatches. Disabling it in *every* replica stops recurring scans entirely |

Endpoint inventory (Lariska ingestion):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_ENDPOINT_INVENTORY_ENABLED` | `true` | Register the `/api/endpoint` router at all |
| `OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES` | `15728640` | Hard request-body cap, checked from `Content-Length` before JSON parsing |
| `OCTO_ENDPOINT_INVENTORY_MAX_SOFTWARE_ITEMS` | `5000` | Software entries per snapshot |
| `OCTO_ENDPOINT_INVENTORY_MAX_IDENTIFIERS` | `16` | Hashed platform identifiers per snapshot |
| `OCTO_ENDPOINT_INVENTORY_MAX_LABELS` | `32` | Labels per snapshot |
| `OCTO_ENDPOINT_INVENTORY_MAX_STRING_LENGTH` | `512` | Per-field string bound |
| `OCTO_ENDPOINT_INVENTORY_MAX_SNAPSHOT_AGE_SECONDS` | `86400` | Reject snapshots collected longer ago than this |
| `OCTO_ENDPOINT_INVENTORY_MAX_FUTURE_SKEW_SECONDS` | `300` | Tolerated clock skew on `collected_at` |
| `OCTO_ENDPOINT_INVENTORY_RATE_LIMIT_PER_HOUR` | `12` | Accepted submissions per agent per hour |
| `OCTO_ENDPOINT_STALE_HOURS` | `48` | Age after which a device reports `status: "stale"` |
| `OCTO_ENDPOINT_RETENTION_ENABLED` | `true` | Run the in-process retention sweep |
| `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` | `90` | Age after which a snapshot's software rows are pruned |
| `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` | `365` | Age after which software change events are deleted |
| `OCTO_ENDPOINT_RETENTION_INTERVAL_SECONDS` | `21600` | Sweep interval |
| `OCTO_ENDPOINT_RETENTION_BATCH_SIZE` | `5000` | Rows deleted per statement |

Never commit real URLs containing credentials. Supply them through the platform
secret mechanism.

## Validate before a run

```bash
python -m scanner.main \
  --config scanner/config/default.yaml \
  --validate-config
```

Also render deployment configuration before applying it:

```bash
kubectl kustomize k8s/shapoclyack/overlays/dev >/dev/null
```
