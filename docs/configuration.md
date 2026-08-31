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

Validate a file before using it — the parse runs the same schema the pipeline
does and starts no external tool:

```bash
python -m scanner.main --config scanner/config/default.yaml --validate-config
```

Exit code `0` means the file is accepted; `2` names the failing key.

## Configuration file sections

Every top-level key of the YAML, what it controls, and where it is described in
full. The schema itself is `scanner/pipeline/config_schema.py` (`AppConfig`) —
a wrongly typed or out-of-range value is refused at load, not at the stage that
would have used it. An **unrecognized** key is ignored rather than refused, so a
misspelled key silently keeps the default: validate, then check the effective
value on the System page rather than assuming the file was applied.

| Section | Controls | Detail |
|---|---|---|
| `runtime` | Speed profile, output/state/log directories, timeouts, retries, per-stage concurrency, `skip_nse` | [Profiles](#profiles), [Operations](operations.md) |
| `profiles` | The named speed profiles `runtime.mode` selects | [Profiles](#profiles) |
| `batching` | Splitting a large scope into IPv4-prefix batches | [Scan performance](scan-performance.md), [Architecture](architecture.md) |
| `discovery` | Alive-host discovery: source, discovery profile, CT logs, brute force, Cloudflare, ASN, cloud resources, domain monitoring, delta | [Discovery modules](#discovery-modules), [Scan performance](scan-performance.md) |
| `ports` | Port stage: protocol, port lists, UDP top-N, naabu scan type | [Protocol selection](#protocol-selection) |
| `nse_profiles` | Named NSE script sets a speed profile can reference | [NSE and vulnerability checks](#nse-and-vulnerability-checks) |
| `service_probe` | Service/version detection backend: `pulse` (default), `nmap`, `hybrid`, and shadow comparison | [Pulse backend](pulse-backend.md) |
| `reporting` | Which report formats a run writes (Markdown, HTML, CSV, JSON, PDF) and the PDF's title/org | [Operations](operations.md), [Reports and compliance](reports-and-compliance.md) |
| `enrichment` | CVSS v4, GeoIP and ASN datasets | [Enrichment sources](#enrichment-sources) |
| `fingerprint` | HTTP fingerprinting of already-open web ports | [Scan performance](scan-performance.md) |
| `screenshots` | Viewport PNGs of open web ports | [Web screenshots](#web-screenshots) |
| `nuclei` | Nuclei stage: template directory, severities, caps, rate limit | [NSE and vulnerability checks](#nse-and-vulnerability-checks) |
| `tls_posture` | Certificate expiry, hostname mismatch and TLS findings | [Pulse backend](pulse-backend.md) |
| `org_profile` | Organization profile: ownership, related domains, DNS hygiene, mail posture, credential leaks, controls | [Модуль «Профиль организации»](org-profile-module.ru.md) (RU) |
| `alerts` | Slack, Telegram and SMTP run summaries (`--notify`) | [Operations](operations.md) |
| `defectdojo` | Export of findings to DefectDojo (`--export-defectdojo`) | [Operations](operations.md) |
| `scheduler` | The scanner container's own cron loop, for single-tenant deployments | [Operations](operations.md) |

Tenant-scoped scheduling in the API (`/api/schedules`) is a different mechanism
from `scheduler:` and is the one to use in a multi-tenant install.

## Profiles

There are **two** profile settings, and they are not the same list. Mixing them
up is the usual reason a run behaves unlike the one that was intended.

### Speed profile (`runtime.mode`, `--mode`)

Picks one entry of the YAML's `profiles:` map: probe rates, top-ports count,
timing and the NSE profile to run. Accepted values are `safe`, `balanced`
(default) and `fast`; the shipped `default.yaml` also defines a `test` profile
for the test suite, which `runtime.mode` does not accept.

| `runtime.mode` | Behavior | Recommended use |
|---|---|---|
| `safe` | Lower rates, conservative external-tool settings, baseline NSE | First scan, fragile or remote links |
| `balanced` | Normal rates and staged gap handling | Routine authorized scanning |
| `fast` | Higher rates and reduced secondary work | Controlled, high-capacity environments |

### Discovery profile (`discovery.profile`)

Picks how hard the discovery stage works within the chosen speed profile:
a rate multiplier over it, plus verification, ICMP and reverse-hostname work.
Accepted values are `auto` (default), `fast`, `balanced`, `thorough` and
`custom`.

| `discovery.profile` | Rate vs. speed profile | Verify | ICMP | Reverse DNS |
|---|---|---|---|---|
| `fast` | ×1.5 | no | no | no |
| `balanced` | ×1.0 | no | no | no |
| `thorough` | ×0.75 | yes | yes | yes |
| `custom` | preset not applied — the `discovery.*` keys are used as written | — | — | — |

`auto` derives the preset from `runtime.mode`: `fast` → `fast`,
`balanced` → `balanced`, `safe` → `thorough`. So `safe` is the slower *and*
the more exhaustive setting, which is why it is the right first run.

Exact values are defined in the active YAML
(`scanner/config/default.yaml`) and in `scanner/pipeline/discovery_profiles.py`.
Do not treat the tables as a fixed performance guarantee.

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
ports:
  protocol: tcp        # tcp | udp | tcp_udp
  top_udp_ports: 100
```

`tcp_udp` runs both and keeps the protocol on every port record, in the
intermediate artifacts and in the aggregate.

## NSE and vulnerability checks

NSE profiles control which scripts run after port discovery. Start with
service-specific and safe checks, then enable broader vulnerability scripts for
authorized targets and a suitable maintenance window.

Nuclei is an optional stage. Template version, severity filters, concurrency,
and rate limits should be pinned in production.

## Web screenshots

`screenshots.enabled` (default `false`) takes a viewport PNG of each
already-open web port — the same candidates as `fingerprint`, no new scan.
`max_targets` (50) and `concurrency` (4) cap the work. Capture needs
Playwright + Chromium on the scanner host; without them the stage skips and
writes `skipped_reason: playwright.unavailable`. Playwright is not a
required dependency and is not baked into the default image.

Obvious form fields are covered with a black overlay in the live DOM, then
the screenshot is taken. Unredacted bytes are never written. A name in a
heading is not redacted. That is why PNG access is operator-only and why
the API reaper deletes the files after
`OCTO_SCREENSHOT_RETENTION_DAYS` (see [operations.md](operations.md)).

The System page **Pipeline Stages** tile and the config-override whitelist
expose `screenshots.enabled`. Leave it off until Playwright is installed
and the retention window matches the site's data-handling policy.

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
| GeoIP MMDB | Country, city, and coordinates | Provider release cadence |
| ASN MMDB | ASN and organization | Provider release cadence |
| EPSS | Exploit probability | Daily |
| CISA KEV | Known exploitation | Daily |
| CVSS v4 overlay | Score/vector enrichment | With source updates |

The Kubernetes enrichment overlay provides a shared PVC and scheduled refresh.
Placeholder fixture data is suitable only for tests.

A **City**-edition GeoIP database also yields latitude/longitude, which is what
the [Geo Map](ui.md#geo-map) plots. A Country-edition database is read through
the Country lookup instead (the City query raises against it), so it still
resolves countries and hosts are placed at their country's centroid with the
page saying so; those
coordinates are the registered position of the *network*, never the machine.
The JSON overlay accepts `latitude`/`longitude` (or `lat`/`lon`) per entry for
labs and tests.

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

### Provenance: what the image actually shipped

Every refresh writes `enrichment-manifest.json` next to the data, recording per
dataset where the bytes came from (`source`), the date the feed itself stamped
on them (`updated`), how many entries they hold, and — the field that matters —
`origin`:

| `origin` | Meaning |
|---|---|
| `fetch` | This run pulled the dataset from its source |
| `seed` | The committed baseline, never replaced by a fetch |
| `stale` | A fetch was attempted and failed; the previous data is still in place |
| `missing` | No data at this path at all |

`GET /api/system` reports these alongside `age_days` on every enrichment entry
(`null` for an image built before the manifest existed, or a volume without
one). Set `OCTO_ENRICHMENT_MANIFEST` when the enrichment volume is mounted
somewhere other than `scanner/data/`.

This exists because age alone cannot answer the question operators actually
have. A build whose EPSS fetch returned `403` ships the committed baseline and
is, from outside, identical to one that pulled a fresh corpus — the same file,
in the same place, with a build-time mtime
([#246](https://github.com/onixus/Shapoclyack/issues/246)).

`scripts/fetch-enrichment.sh` exits `0` when everything refreshed, `1` when a
source was unreachable but every required dataset still holds usable data, and
`2` when a required dataset (`cvss4`, `epss`, `kev`, `exploit`) is absent or is
a handful-of-CVEs stub. Only the last is fatal, and only for a release build —
see [operations](operations.md#enrichment-data-in-a-release-build).

## Startup safety: `OCTO_ENV`

The API runs as **`prod`** unless told otherwise, and a `prod` process **refuses
to start** while any of the following is still at its built-in default:

| Refusal | Why |
|---|---|
| `OCTO_JWT_SECRET` (or `API_SECRET_KEY`) unset, empty, or equal to the shipped default | The default is published in this repository, so anyone can mint a valid admin token |
| `OCTO_API_CORS` containing `*` (including when unset, which means `*`) | With credentials in play, any page a logged-in operator visits could call this API with their session. A `*` listed beside real origins is refused too — the wildcard matches everything regardless of what sits next to it |
| `OCTO_POSTGRES_URL` unset (it would fall back to a local SQLite file) or pointing at `sqlite://` | Postgres is a hard dependency, not an opt-in sidecar: tenants, users, assets, jobs, agents and webhook deliveries live there. A per-replica file means a per-replica control plane, and the guarantees the durable control plane rests on — `SELECT … FOR UPDATE SKIP LOCKED` for job claims and leases, advisory locks for scheduler leader election — stop holding without saying so. The file also sits on the pod's ephemeral disk |
| **No console account exists** — the `users` table is empty and `OCTO_API_USERS` is unset (checked at startup, once the database is up) | The built-in demo accounts are not seeded in `prod`; their passwords are published in this repository. An install nobody can log into is a failure whether it is reported at startup or discovered at the login form |
| `OCTO_PUBLIC_BASE_URL` unset, or set to something without an `http(s)://` scheme | It is the URL the agent install snippets tell a target host to fetch the installer from and report to, and it is written into the agent's permanent `OCTO_API_URL`. With no configured value the API would fall back to the request's own `Host` header, letting the caller choose that URL ([#233](https://github.com/onixus/Shapoclyack/issues/233)) |
| `OCTO_POSTGRES_URL`, `OCTO_CLICKHOUSE_URL` or `OCTO_NATS_URL` still carrying a placeholder password from `k8s/shapoclyack/base/kustomization.yaml` | Those literals are as published as the JWT secret; they were unchecked only because they arrive inside a connection URL rather than as a variable of their own. All of them are checked by one rule, so a secret added to `base` later is covered without a new check ([#224](https://github.com/onixus/Shapoclyack/issues/224)) |
| `OCTO_AGENT_TOKEN` set on or after **2027-03-01** | The legacy shared agent token authenticates every agent holding it as `tenant_id=default`. For an MSSP install that is the absence of the tenant isolation every other route enforces, so the deprecation has an end date rather than an open-ended warning ([#224](https://github.com/onixus/Shapoclyack/issues/224)) |

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

Until **2027-03-01** a set `OCTO_AGENT_TOKEN` **warns** rather than refuses, and
the warning names that date. Breaking a working install needs notice, which is
what the date buys; what it does not buy is an indefinite warning nobody acts
on. Migrate before then: mint a per-tenant provisioning key
(`POST /api/tenants/{tenant_id}/provisioning-keys`), re-install the agents with
it so they exchange it for a scoped agent JWT
(`POST /api/auth/agent/token`), then unset the variable.

Everything except the console-account check is decided in `load_settings()`
from the environment alone. That one needs the database and therefore runs at
startup (`api/services/users.py:bootstrap`) — only the table can tell an
installation with a real admin from one with none.

The database refusal distinguishes an unset variable from one set to SQLite,
because those are different mistakes with the same consequence. Under
`OCTO_ENV=dev` the SQLite fallback stays exactly as it was: a laptop and the test
suite must not need a database to start.

## Environment variables

Core deployment variables:

| Variable | Purpose |
|---|---|
| `OCTO_ENV` | `prod` (default) or `dev`. `prod` refuses to start on built-in defaults — see [above](#startup-safety-octo_env) |
| `OCTO_CONFIG` | Scanner YAML path |
| `OCTO_OUTPUT_DIR` | Per-run output root |
| `OCTO_STATE_DIR` | Checkpoint and scheduler state |
| `OCTO_JWT_SECRET` | User JWT signing secret. **Required in `prod`**; must be identical across API replicas |
| `OCTO_JWT_EXPIRE_MINUTES` | Lifetime of a console access token (default `480` — 8 hours). The token is held in browser local storage, so this is how long a copied token stays usable; there is no refresh flow and no server-side revocation, a shorter value is the only bound |
| `OCTO_API_USERS` | **One-time bootstrap only** since #156. Accounts live in the Postgres `users` table; this JSON list is imported on a first start with an empty table and ignored afterwards. Manage accounts through `/api/users` — see [api-and-rbac.md](api-and-rbac.md#console-accounts) |
| `OCTO_API_CORS` | Comma-separated allowed origins. **Must not be `*` in `prod`** |
| `OCTO_PUBLIC_BASE_URL` | The URL this installation is reached at from outside, e.g. `https://shapoclyack.example.com`. **Required in `prod`.** Everything that hands an operator or a target host a link back to the API is built from it: the install one-liner, the container and Kubernetes snippets, and the `OCTO_API_URL` the SSH push writes into `agent.env`. Never taken from the request's `Host` header, which the caller writes. Under `OCTO_ENV=dev` an unset value falls back to the request URL so a laptop needs no extra variable |
| `OCTO_POSTGRES_URL` | Primary database connection. **Required in `prod`** — an unset value or a `sqlite://` URL refuses startup, see [above](#startup-safety-octo_env). Falls back to a local SQLite file only under `OCTO_ENV=dev` |
| `OCTO_NATS_URL` | JetStream connection; empty disables NATS |
| `OCTO_CLICKHOUSE_URL` | ClickHouse HTTP connection |
| `OCTO_CH_INGEST_ENABLED` | Enable analytical ingest worker |
| `OCTO_JOB_EXECUTION_MODE` | `local` or `agent` |
| `OCTO_AGENT_TOKEN` | **Deprecated, refused in `prod` from 2027-03-01.** Legacy shared bearer token for remote agents; every agent holding it is `tenant_id=default`. Use per-tenant provisioning keys instead |
| `OCTO_AGENT_JWT_EXPIRE_MINUTES` | Lifetime of the agent JWT a provisioning key is exchanged for (default `120`). An agent re-exchanges its key when the token expires, so this bounds how long a token lifted off a worker outlives the key being revoked |
| `OCTO_AGENT_STALE_SECONDS` | How long after its last heartbeat an agent is reported `stale` (default `120`). Nothing is stored: the state is computed from `last_seen_at` at read time, so lowering it takes effect on the next request |
| `OCTO_AGENT_RESULTS_MAX_BODY_BYTES` | Hard request-body cap on `POST /api/agent/jobs/{job_id}/results`, read from `Content-Length` before the multipart body is buffered (default `134217728` — 128 MiB). A length-less upload is answered `411` |
| `OCTO_AGENT_DEPLOY_SSH_PORTS` | TCP ports the SSH push deployer and its host-key probe may dial (default `22,2222`, #240). Both open a connection to a host and port taken from the request body, which over an open range makes the probe a port scanner with a tidy response format. Name the port here if your fleet listens elsewhere; `*` restores the full range. A value that is not a port list refuses startup rather than narrowing the list silently |
| `OCTO_AGENT_DEPLOY_ENFORCE_SCAN_SCOPE` | Require a deployment target to sit **inside** the tenant's approved scan scope, not merely outside its denied ranges (default `false`, #240 / #226). Off, the scope's *prohibitions* still apply — a host a tenant was told not to touch is not reachable by SSH from this API either. On is a stricter claim than most fleets can make: an agent on a management host that scans a customer range is the ordinary MSSP shape, and with this set that deployment is refused |
| `OCTO_HSTS_ENABLED` | Send `Strict-Transport-Security` on every response. Defaults to on under `OCTO_ENV=prod` and off under `dev`, since a browser that picks the header up from `http://localhost` pins itself to HTTPS for a year |
| `OCTO_INSTANCE_ID` | Identity of this API replica in the shared job queue; defaults to the hostname. Only local-mode jobs owned by this identity are failed as orphans on startup |
| `OCTO_ALLOW_SCAN_START` | Permit job creation from API/UI |
| `OCTO_SCAN_SCOPE_RESOLVE_CHECK` | Resolve requested scan domains at admission and refuse the ones whose current addresses fall in a range the tenant's approved scope denies (default `true`, #226). Only runs when the scope has deny ranges; a lookup that does not answer within 3s leaves the name checked as a string and is logged. Turn it off only where the API cannot resolve names at all |
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

Report factory (see
[reports-and-compliance.md](reports-and-compliance.md#configuration)). The
report relay is separate from the scanner's alert SMTP on purpose: an alert
goes to an operations channel and a report goes to a customer.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_REPORTS_ENABLED` | `true` | Register `/api/reports`. Off means no report API at all |
| `OCTO_REPORT_DISPATCH_ENABLED` | `true` | Run the scheduled-report loop in *this* replica; leader-locked, so only one replica ever sends |
| `OCTO_REPORT_DISPATCH_INTERVAL_SECONDS` | `60` | Poll interval for due schedules (floored at 5) |
| `OCTO_REPORT_RETENTION_DAYS` | `365` | Age past which generated reports and their files are pruned; `0` keeps them |
| `OCTO_REPORT_SMTP_HOST` | *(empty)* | Relay for emailed reports. Empty means email recipients are recorded as `skipped`, with the reason, rather than silently dropped |
| `OCTO_REPORT_SMTP_PORT` | `25` | Relay port |
| `OCTO_REPORT_SMTP_FROM` | *(empty)* | Envelope sender; required alongside the host |
| `OCTO_REPORT_SMTP_USERNAME` | *(empty)* | Relay username; login is attempted only when set |
| `OCTO_REPORT_SMTP_PASSWORD` | *(empty)* | Relay password |
| `OCTO_REPORT_SMTP_STARTTLS` | `true` | Require an encrypted connection. A relay that refuses fails that recipient rather than sending the report and the relay password in cleartext; set `false` only for a relay that genuinely cannot do TLS |
| `OCTO_REPORT_SMTP_TIMEOUT_SECONDS` | `20` | Per-message budget |

OpenTelemetry (ROADMAP P3). Empty endpoint means no TracerProvider — the
API does not buffer spans nobody will read. Traces are request timing, not
scan observations.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_OTEL_EXPORTER_OTLP_ENDPOINT` | *(empty)* | OTLP HTTP traces URL (`http://collector:4318/v1/traces`). Empty disables tracing |
| `OCTO_OTEL_SERVICE_NAME` | `shapoclyack-api` | `service.name` resource attribute |

Login rate limiting and the auth audit trail (see
[api-and-rbac.md](api-and-rbac.md#login-rate-limiting-and-the-auth-audit-trail)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_LOGIN_RATE_LIMIT_ENABLED` | `true` | Enforce the login limit. Off still records every attempt in `auth_events` — the audit trail is not the limiter |
| `OCTO_LOGIN_RATE_LIMIT_MAX_FAILURES` | `5` | Failed logins allowed per `(username, client IP)` inside the window. A typo budget, not a guessing budget |
| `OCTO_LOGIN_RATE_LIMIT_WINDOW_SECONDS` | `900` | Length of that window. Failures age out of it on their own; nothing unlocks an account by hand |
| `OCTO_LOGIN_RATE_LIMIT_IP_MAX_FAILURES` | `50` | Failures allowed per client IP across *all* usernames, in the same window — what walking a username list looks like. Much looser on purpose: one NAT or office egress address is many legitimate users, and tripping it refuses them too |
| `OCTO_TRUSTED_PROXIES` | *(empty)* | Comma-separated proxy IPs/CIDRs. `X-Forwarded-For` is read **only** when the immediate peer is one of these. Leave empty and every attempt is attributed to the socket peer — set it when the API sits behind an ingress, or the whole installation shares one limiter key |
| `OCTO_AUTH_EVENT_RETENTION_DAYS` | `90` | Age past which `auth_events` rows are pruned; `0` keeps them forever. Rows inside the limiter window are kept regardless, so a short retention cannot weaken the lockout |

Single sign-on (see [api-and-rbac.md](api-and-rbac.md#single-sign-on-oidc)).
SSO stays **off** until the first three are all set:

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_OIDC_ISSUER` | *(empty)* | Provider issuer URL. Its `.well-known/openid-configuration` supplies every endpoint and signing algorithm, so nothing about the provider is configured twice. Must be `https` (plain `http` only for a loopback dev provider) |
| `OCTO_OIDC_CLIENT_ID` | *(empty)* | This installation's client id at the provider |
| `OCTO_OIDC_CLIENT_SECRET` | *(empty)* | Its client secret. Never logged, never returned by any endpoint |
| `OCTO_OIDC_REDIRECT_URI` | *(derived)* | Where the provider sends the browser back. Empty derives `{OCTO_PUBLIC_BASE_URL}/api/auth/oidc/callback` — never the request's own `Host` header, which the client writes |
| `OCTO_OIDC_SCOPES` | `openid email profile` | Scopes requested from the provider |
| `OCTO_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim holding the console username; falls back to `email`, then `sub` |
| `OCTO_OIDC_JIT_PROVISIONING` | `false` | Create a console account for an identity that has none. **Off by default**: with it on, anyone the identity provider will authenticate gets an account |
| `OCTO_OIDC_DEFAULT_ROLE` | `viewer` | Role for a provisioned account when no claim maps to one. The lowest privileged role on purpose — a higher default grants it to everyone the IdP knows. An unrecognised value falls back to `viewer` with a warning |
| `OCTO_OIDC_ROLE_CLAIM` | *(empty)* | Claim holding the caller's groups, e.g. `groups` |
| `OCTO_OIDC_ROLE_MAP` | *(empty)* | JSON object mapping those values to console roles, e.g. `{"vm-admins":"admin","vm-ops":"operator"}`. The **highest** match wins; an unmapped group grants nothing, and an entry naming an unknown role is dropped rather than downgraded. Malformed JSON is logged and ignored rather than refused at startup: this is parsed on every boot whether or not SSO is configured, so a typo here must not stop the whole API |
| `OCTO_OIDC_TENANT_CLAIM` | *(empty)* | Claim naming the tenant a provisioned account is granted membership in |
| `OCTO_OIDC_DEFAULT_TENANT` | `default` | Tenant used when that claim is missing |
| `OCTO_OIDC_CACHE_TTL_SECONDS` | `3600` | Discovery/JWKS cache lifetime. Rotation is also handled out of band: an unknown `kid` forces one refresh before the token is refused |
| `OCTO_OIDC_STATE_TTL_SECONDS` | `600` | How long one authorization request stays valid — it only has to cover a human typing a password at the provider. The record is process-local, so behind more than one replica enable session affinity for `/api/auth/oidc/*`. Pending requests are capped at 10,000 per replica — the login route is unauthenticated, and the oldest are dropped first (an evicted login fails closed and can be retried) |
| `OCTO_OIDC_HTTP_TIMEOUT_SECONDS` | `10` | Per-request timeout for discovery, JWKS and the token exchange |
| `OCTO_OIDC_POST_LOGIN_REDIRECT` | *(empty)* | Where the callback sends the browser once the session exists, with the token in the URL **fragment** (never a query string, which lands in access logs). Empty makes the callback answer with the same JSON body as password login, which is what an API-only install wants; a console install points this at its `/login` page |

Service tokens (see [api-and-rbac.md](api-and-rbac.md#service-tokens)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_SERVICE_TOKENS_ENABLED` | `true` | Register the admin routes. Gates the routes only — an already-issued token keeps authenticating until it is revoked, which is what the revoke endpoint is for |
| `OCTO_SERVICE_TOKEN_DEFAULT_TTL_DAYS` | `90` | Lifetime for a token whose creator named none |
| `OCTO_SERVICE_TOKEN_MAX_TTL_DAYS` | `365` | Ceiling on a requested lifetime. A credential with no expiry is one nobody rotates |
| `OCTO_SERVICE_TOKEN_LAST_USED_INTERVAL_SECONDS` | `300` | How often `last_used_at` may be rewritten. Without it a busy integration turns every request into a write to the hottest row in the table |

Job leases and the reaper (see [architecture.md](architecture.md#leases-and-orphan-recovery)):

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
| `OCTO_ENDPOINT_NATS_EVENTS_ENABLED` | `true` | Publish an `endpoint_inventory_accepted` event to `ingest.endpoint_inventory.{tenant_id}` when a snapshot is accepted (Track D S8). Fail-soft; a no-op without `OCTO_NATS_URL` |
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

Web screenshots (ROADMAP P4.4 / Phase 9.3):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_SCREENSHOT_RETENTION_ENABLED` | `true` | Run the in-process PNG reaper. Safe in every replica; deletes are idempotent |
| `OCTO_SCREENSHOT_RETENTION_DAYS` | `14` | Age after which `runs/*/screenshots/*.png` is unlinked. `0` disables the reaper. `screenshots.json` is never deleted by this worker |
| `OCTO_SCREENSHOT_RETENTION_INTERVAL_SECONDS` | `3600` | Sweep interval (floored at 60) |

Scan run artifact retention (ROADMAP #187):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_RUN_RETENTION_ENABLED` | `true` | Run the in-process scan artifact reaper. Safe in every replica; directory removals are idempotent |
| `OCTO_RUN_RETENTION_DAYS` | `30` | Age after which `output_dir/runs/<run_id>` directories are deleted. `0` disables the reaper |
| `OCTO_RUN_RETENTION_INTERVAL_SECONDS` | `3600` | Sweep interval (floored at 60) |

Risk snapshot retention (#229):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_RISK_SNAPSHOT_RETENTION_ENABLED` | `true` | Run the in-process `risk_score_snapshots` sweep. Safe in every replica; the delete is a range delete |
| `OCTO_RISK_SNAPSHOT_RETENTION_DAYS` | `90` | Age after which risk snapshots are deleted. `0` disables the sweep. Keep at or above the window the trend chart requests |
| `OCTO_RISK_SNAPSHOT_RETENTION_INTERVAL_SECONDS` | `21600` | Sweep interval (floored at 60) |


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
