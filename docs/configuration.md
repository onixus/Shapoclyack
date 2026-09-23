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
only** — a sensor (the remote scanning node, API resource `agents` with
`agent_kind = scanner`) runs its own mounted config and never sees the uploaded
file, so a `wordlist_id` on a scan in `agent` execution mode (i.e. one handed
to a sensor) is rejected. Caps:
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
| Debian Security Tracker | Vendor advisories for software→CVE matching | Daily, **opt-in** |
| Ubuntu USN | Vendor advisories for software→CVE matching | Daily, **opt-in** |

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

### Vendor advisory datasets

The two advisory feeds behind [software→CVE matching](software-cve-matching.md)
sit in the same directory, the same envelope and the same manifest as the
overlays above, and differ in exactly one way: nothing fetches them unless the
installation says so.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_ADVISORY_FETCH_ENABLED` | `false` | Gate on every outbound request for advisory data. With it unset, `api/services/advisories/fetch.py` refuses and `scripts/fetch-enrichment.sh` prints a skip rather than a failure |
| `OCTO_DEBIAN_ADVISORY_DATABASE` | `scanner/data/advisories/debian-advisories.json` | Where the Debian dataset is read from |
| `OCTO_UBUNTU_ADVISORY_DATABASE` | `scanner/data/advisories/ubuntu-advisories.json` | Where the Ubuntu dataset is read from |

```bash
# One dataset, by hand. Exits 3 if the flag is unset — distinct from a failure.
OCTO_ADVISORY_FETCH_ENABLED=true python3 scripts/fetch-advisories.py debian

# Both, as part of the usual refresh (this is what the CronJob runs).
OCTO_ADVISORY_FETCH_ENABLED=true ./scripts/fetch-enrichment.sh
```

In Kubernetes the opt-in is one overlay:

```bash
kubectl apply -k k8s/shapoclyack/overlays/enrichment-advisories
```

That is `overlays/enrichment` plus the `base/enrichment-advisories` component,
which carries two things that belong together: the ConfigMap the CronJob reads
the flag from (through an `optional: true` `configMapKeyRef`, so not applying it
is the default) and the `2Gi` memory limit the Debian tracker parse needs. The
base CronJob stays at `1Gi`, which is what GeoIP/CVSS4/EPSS/KEV need — a cluster
that never took the opt-in must not have its pod rejected by a namespace
`LimitRange` for a dataset it does not fetch.

The API pod's enrichment initContainer deliberately does **not** get the flag.
It would turn a daily download into one per pod start, per replica, per rollout,
and the datasets are on the shared volume the CronJob already refreshes.

The Debian tracker document is around 50 MB, which is why this is a decision
rather than a default: an installation with no egress to
`security-tracker.debian.org` is a supported configuration, and the matcher
answers `unknown` instead of guessing.

The image ships a small committed **seed** of real advisories at both paths.
It is a seed, not a feed: it proves the path works and covers a handful of
packages. The manifest floors (`100000` Debian, `10000` Ubuntu) are sized for
the real feeds, so a build carrying only the seed is recorded `usable: false`
— reported, never fatal, because these datasets are not required.

Those same floors are what `scripts/fetch-advisories.py` refuses to publish
below. A feed answering `200` with a truncated document normalizes to a dozen
statements, and a floor of one would let that replace a corpus; refusing at the
number the manifest already keeps means the fetch and the report use one number.
A refresh that succeeds and still lands under the floor is not silent either —
`origin: fetch` with `usable: false` exits `1` (degraded).

### Provenance: what the image actually shipped

Every refresh writes `enrichment-manifest.json` next to the data, recording per
dataset where the bytes came from (`source`), the date the feed itself stamped
on them (`updated`), how many entries they hold, whether that count clears the
dataset's floor (`usable`), and — the field that matters — `origin`:

| `origin` | Meaning |
|---|---|
| `fetch` | This run pulled the dataset from its source |
| `seed` | The committed baseline, never replaced by a fetch |
| `stale` | A fetch was attempted and failed; the previous data is still in place |
| `missing` | No data at this path at all |

A run that did not *attempt* a dataset — the advisory opt-in being off is the
only way that happens — is a fourth case, and it writes none of these: it keeps
whatever the previous run recorded. That matters because the API pod's
enrichment initContainer runs the same script without the opt-in, so every API
rollout re-inspects datasets the nightly CronJob filled. Rewriting them to
`seed` would make `GET /api/system` report `origin: seed` over four hundred
thousand fetched entries and send an operator to a build log with nothing in it.

`GET /api/system` reports these alongside `age_days` on every enrichment entry
(`null` for an image built before the manifest existed, or a volume without
one). Set `OCTO_ENRICHMENT_MANIFEST` when the enrichment volume is mounted
somewhere other than `scanner/data/`.

`usable` answers the question `entries` leaves open. A dataset that ships with
a seed is present, has a build-time mtime and a non-zero entry count whether it
holds eight advisories or four hundred thousand; only the floor separates them,
and the build is the one that checked it. It reports `null`, not `false`, when
no manifest was found.

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
| `OCTO_POSTGRES_URL` unset (it would fall back to a local SQLite file) or pointing at `sqlite://` | Postgres is a hard dependency, not an opt-in sidecar: tenants, users, assets, jobs, sensors and endpoint Agents (the `agents` table) and webhook deliveries live there. A per-replica file means a per-replica control plane, and the guarantees the durable control plane rests on — `SELECT … FOR UPDATE SKIP LOCKED` for job claims and leases, advisory locks for scheduler leader election — stop holding without saying so. The file also sits on the pod's ephemeral disk |
| **No console account exists** — the `users` table is empty and `OCTO_API_USERS` is unset (checked at startup, once the database is up) | The built-in demo accounts are not seeded in `prod`; their passwords are published in this repository. An install nobody can log into is a failure whether it is reported at startup or discovered at the login form |
| `OCTO_PUBLIC_BASE_URL` unset, or set to something without an `http(s)://` scheme | It is the URL the sensor install snippets tell a target host to fetch the installer from and report to, and it is written into the sensor's permanent `OCTO_API_URL`. With no configured value the API would fall back to the request's own `Host` header, letting the caller choose that URL ([#233](https://github.com/onixus/Shapoclyack/issues/233)) |
| `OCTO_POSTGRES_URL`, `OCTO_CLICKHOUSE_URL` or `OCTO_NATS_URL` still carrying a placeholder password from `k8s/shapoclyack/base/kustomization.yaml` | Those literals are as published as the JWT secret; they were unchecked only because they arrive inside a connection URL rather than as a variable of their own. All of them are checked by one rule, so a secret added to `base` later is covered without a new check ([#224](https://github.com/onixus/Shapoclyack/issues/224)) |
| `OCTO_JWT_SECRET_PREVIOUS` listing the shipped development secret, or repeating the current `OCTO_JWT_SECRET` | A rotation window that trusts a published key is not a rotation; a window that repeats the current key makes a half-finished rotation look finished ([#314](https://github.com/onixus/Shapoclyack/issues/314)) |
| `OCTO_JWT_ALGORITHM` set to anything but `HS256` | This installation holds one shared symmetric secret and no key material, so every other family is either unverifiable here or a token-forgery surface. Refused under `dev` too: an algorithm the build cannot honestly verify is never a local convenience ([#312](https://github.com/onixus/Shapoclyack/issues/312)) |
| `OCTO_AGENT_TOKEN` set on or after **2027-03-01** | The legacy shared agent token authenticates every sensor holding it as `tenant_id=default`. For an MSSP install that is the absence of the tenant isolation every other route enforces, so the deprecation has an end date rather than an open-ended warning ([#224](https://github.com/onixus/Shapoclyack/issues/224)) |
| **`OCTO_MASTER_KEY` unset while secrets are stored at rest** — any `webhook_subscriptions` row carries a secret or a configured header, or any account has enrolled a TOTP seed in `users.mfa_secret` ([#315](https://github.com/onixus/Shapoclyack/issues/315)); checked at startup, once the database is up | Those rows hold somebody else's Jira / ServiceNow / DefectDojo token. Without a key they are written to Postgres as typed, so a dump or a replica hands them over; rows already encrypted cannot be read back at all. An installation with no integrations starts with a warning instead — this refuses "forgot to configure", not "does not use this". That installation is checked again when it stops being one: in `prod`, creating or editing a subscription that carries a secret or a header **is refused** rather than writing the first one as typed — the request fails as a server misconfiguration and the same message goes to the API log ([#310](https://github.com/onixus/Shapoclyack/issues/310)) |

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
(`POST /api/tenants/{tenant_id}/provisioning-keys`), re-install the sensors with
it so they exchange it for a scoped agent JWT
(`POST /api/auth/agent/token`), then unset the variable.

### Transport encryption: what warns instead of refusing

A `prod` process also **warns** — it does not refuse — about two transports it
cannot verify ([#309](https://github.com/onixus/Shapoclyack/issues/309)):

| Warning | Fix |
|---|---|
| `OCTO_POSTGRES_URL` carries no `sslmode=` | libpq then negotiates TLS opportunistically and accepts whatever certificate it is handed, so credentials, tokens and scan results are readable by anything on the path. Append `?sslmode=verify-full&sslrootcert=/etc/ssl/postgres-ca/ca.crt` — see [operations](operations.md#transport-encryption) for mounting the CA |
| `OCTO_REPORT_SMTP_VERIFY_TLS=false` while a relay is configured | Report delivery then encrypts to the relay without verifying its certificate — protection against a passive listener and nobody else. Put the relay's CA in the image's trust store instead |

Both are warnings rather than refusals because, unlike a published default
password, neither value is distinguishable from a deliberate choice: a Postgres
reached over a Unix socket or an operator-owned encrypted link is a legitimate
install, and refusing would break every deployment that upgrades.

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
| `OCTO_OUTPUT_DIR` | Per-run output root. With `OCTO_ARTIFACT_BACKEND=local` (the default) this is where runs and reports live; with `s3` the scanner still writes here and the run is published from it |
| `OCTO_STATE_DIR` | Checkpoint and scheduler state, materialised wordlists, and — on the local backend — job inputs |
| `OCTO_JWT_SECRET` | User JWT signing secret. **Required in `prod`**; must be identical across API replicas |
| `OCTO_JWT_ALGORITHM` | JWT signing algorithm. `HS256` is the only accepted value and the default; anything else **refuses startup** in every environment. It used to be read by `api/core/security.py` alone while `Settings` pinned `HS256` regardless, so setting it changed what half the codebase signed with and nothing that verified ([#312](https://github.com/onixus/Shapoclyack/issues/312)). Widening this is a key-management change (RS256/EdDSA needs key material, a `kid` and a rotation path), not a configuration one |
| `OCTO_AGENT_JWT_SECRET` | Signing secret for **agent** JWTs, separate from `OCTO_JWT_SECRET` ([#312](https://github.com/onixus/Shapoclyack/issues/312)). Optional: when unset it is derived from `OCTO_JWT_SECRET` with HKDF-SHA256, so an upgrade needs no new variable and the two audiences still get different key material. Set it explicitly to rotate the fleet's tokens without invalidating console sessions, or to keep the key an agent host could leak away from the one that signs admin sessions. Must be identical across API replicas; changing it invalidates every agent JWT at once, and sensors (and endpoint Agents) re-exchange their provisioning key within `OCTO_AGENT_JWT_EXPIRE_MINUTES` (immediately, if they meet a `401` before that) |
| `OCTO_MASTER_KEY` | Key-encryption key for the secrets stored in Postgres — the webhook HMAC key and the header values that carry a tracker API token ([#310](https://github.com/onixus/Shapoclyack/issues/310)), and the TOTP seeds in `users.mfa_secret` ([#315](https://github.com/onixus/Shapoclyack/issues/315)). 32 bytes as base64 or hex (`openssl rand -base64 32`); must be identical across API replicas. **Required in `prod`** once any such secret is stored — at startup for the rows already there, and on every write for the rows that come later. Unset, `dev` writes the values as typed with a warning. Replacing it without the step below makes every stored secret unreadable — see [operations.md § Secrets at rest](operations.md#secrets-at-rest) |
| `OCTO_MASTER_KEY_PREVIOUS` | Comma- or space-separated keys that may still **decrypt**, for the overlap window of a rotation. Rows name the key that opens them, so old and new coexist; drop this once `python -m api.db.reencrypt_secrets --rotate` reports nothing left on the old key |
| `OCTO_MASTER_KEY_PROVIDER` | Where the KEK lives: `local` (default, `OCTO_MASTER_KEY`) is the only one implemented. `vault-transit`, `aws-kms` and `gcp-kms` name the interface that exists for them and **refuse startup** — the alternative, falling back to a local key, would be an install that believes it uses a KMS and does not |
| `OCTO_JWT_SECRET_PREVIOUS` | Comma-separated list of **retired** console signing keys, still accepted while the tokens they signed expire ([#314](https://github.com/onixus/Shapoclyack/issues/314)). Nothing is ever signed with one. Without it, rotating `OCTO_JWT_SECRET` signs the whole console out at the moment of the rollout. Empty is the normal state: a rotation adds one entry and the next deploy removes it — see [operations.md](operations.md#rotating-the-jwt-signing-key). Listing the shipped development secret, or repeating the current `OCTO_JWT_SECRET`, **refuses startup** in `prod` |
| `OCTO_AGENT_JWT_SECRET_PREVIOUS` | The same window for the agent key, and consulted **only** when `OCTO_AGENT_JWT_SECRET` is set explicitly. While the agent key is derived, the retired operator keys derive the retired agent keys, so one list rotates both audiences |
| `OCTO_JWT_EXPIRE_MINUTES` | **Absolute** lifetime of a console sign-in (default `480` — 8 hours). Until the refresh-token half of [#314](https://github.com/onixus/Shapoclyack/issues/314) this was the access token's own lifetime; it is now the end of the session family that refresh tokens extend, and refreshing never moves it — eight hours after the password (or the SSO round trip), the user signs in again. The name is kept so an installation that set it keeps the session length it chose. Floored at 1 |
| `OCTO_ACCESS_TOKEN_EXPIRE_MINUTES` | Lifetime of one console access token (default `15`). It is the bearer token in browser local storage, so this is how long a copy lifted out of the browser works on its own; the console renews it through `POST /api/auth/refresh` while the user is active. Capped by what is left of `OCTO_JWT_EXPIRE_MINUTES`. **Behaviour change:** a script that logs in with a password and reuses the token for hours now gets fifteen minutes — call `POST /api/auth/refresh` with the cookie, or (better) use a [service token](api-and-rbac.md#service-tokens). Floored at 1 |
| `OCTO_SESSION_IDLE_MINUTES` | Idle timeout (default `30`; `0` turns it off). A refresh more than this long after the previous one — or after the sign-in — is refused and the session ends. Must be **longer** than `OCTO_ACCESS_TOKEN_EXPIRE_MINUTES`, otherwise startup is refused in every environment: the console refreshes once per access token, so a shorter timeout signs out people who are working. The console itself only refreshes after user activity, so an unattended console is let go when its access token runs out; this value is the server-side bound that holds whatever the client does. See [api-and-rbac.md](api-and-rbac.md#refresh-tokens-and-the-idle-timeout) |
| `OCTO_REFRESH_COOKIE_SECURE` | `Secure` attribute on the refresh-token cookie. Default `true` in `prod`, where `false` **refuses startup**; default `false` in `dev`, like `OCTO_HSTS_ENABLED` — a lab stand reached over plain http at a LAN address (browsers already treat `localhost` as secure) would otherwise never get the cookie back, and every session would end with its first access token |
| `OCTO_API_USERS` | **One-time bootstrap only** since #156. Accounts live in the Postgres `users` table; this JSON list is imported on a first start with an empty table and ignored afterwards. Manage accounts through `/api/users` — see [api-and-rbac.md](api-and-rbac.md#console-accounts) |
| `OCTO_API_CORS` | Comma-separated allowed origins. **Must not be `*` in `prod`** |
| `OCTO_PUBLIC_BASE_URL` | The URL this installation is reached at from outside, e.g. `https://shapoclyack.example.com`. **Required in `prod`.** Everything that hands an operator or a target host a link back to the API is built from it: the install one-liner, the container and Kubernetes snippets, and the `OCTO_API_URL` the SSH push writes into `agent.env`. Never taken from the request's `Host` header, which the caller writes. Under `OCTO_ENV=dev` an unset value falls back to the request URL so a laptop needs no extra variable |
| `OCTO_POSTGRES_URL` | Primary database connection. **Required in `prod`** — an unset value or a `sqlite://` URL refuses startup, see [above](#startup-safety-octo_env). Falls back to a local SQLite file only under `OCTO_ENV=dev` |
| `OCTO_DB_POOL_SIZE` | Connections the SQLAlchemy pool keeps open to Postgres, per API process (default `5`). This is **per replica**: `max_connections` on the server is one shared budget, so a profile that scales the API multiplies this by the replica count — see [high-availability.md](high-availability.md#connection-pool-sizing) ([#335](https://github.com/onixus/Shapoclyack/issues/335)). Floored at 1, and `OCTO_DB_POOL_SIZE + OCTO_DB_MAX_OVERFLOW` is floored at 4 — three connections are held for the life of the process by the leader locks of the schedule dispatcher, the report dispatcher and the software-match worker, so a smaller pool leaves a worker unable to become leader at all. Ignored by the `dev` SQLite fallback, which has no connection queue |
| `OCTO_DB_MAX_OVERFLOW` | Extra connections the pool may open above `OCTO_DB_POOL_SIZE` under load, closed again when returned (default `10`). Counts against the same server budget |
| `OCTO_DB_POOL_TIMEOUT` | Seconds a request waits for a free pooled connection before failing (default `30`, floored at 1). Without a bound, a saturated pool is a request that never returns instead of one that fails with a cause |
| `OCTO_NATS_URL` | JetStream connection; empty disables NATS — and on a network whose only egress is an HTTP proxy, empty is the right value: no proxy carries NATS, and the sensor then polls the HTTP claim instead ([network-requirements.md](network-requirements.md#nats-and-proxies)). `tls://` selects TLS; `wss://` is NATS over WebSocket on 443, which needs `aiohttp` on the agent host. Job offers go to `jobs.scan.{tenant}` and each tenant has its own durable consumer `octo-agents-{tenant}` — see [operations.md](operations.md#per-tenant-job-stream) |
| `OCTO_NATS_TLS_CA` | PEM bundle used to verify the NATS server. Only needed for a privately issued certificate (cert-manager with an in-cluster issuer); a publicly issued one is verified against the system trust store with no variable at all |
| `OCTO_NATS_TLS_CERT` | Client certificate presented to NATS (mTLS). Requires `verify_and_map: true` server-side, with the certificate CN equal to the NATS username |
| `OCTO_NATS_TLS_KEY` | Private key for `OCTO_NATS_TLS_CERT` |
| `OCTO_NATS_TLS_HOSTNAME` | Name the server certificate is verified against, when it differs from the host in `OCTO_NATS_URL` (a broker issued for its in-cluster Service name but dialed by a sensor at a public address). Never a way to skip verification — hostname checking and certificate verification stay on |
| `OCTO_NATS_OUTBOX_*` | The durable record of publications the broker refused, and the reconciler that replays them once it is back. This is what lets NATS be a non-blocking readiness check — see the table under [NATS outbox](#nats-outbox) below and [operations.md](operations.md#nats-outbox) |
| `OCTO_CLICKHOUSE_URL` | ClickHouse HTTP connection; empty disables the client and the ingest worker. TLS follows the **scheme**, not the port — `https://…` connects with certificate verification on any port, anything else is plaintext |
| `OCTO_CH_INGEST_ENABLED` | Enable analytical ingest worker |
| `OCTO_JOB_EXECUTION_MODE` | `local` (the API runs the scanner as a subprocess) or `agent` (jobs are queued for sensors to claim) |
| `OCTO_AGENT_TOKEN` | **Deprecated, refused in `prod` from 2027-03-01.** Legacy shared bearer token for sensors; every sensor holding it is `tenant_id=default`. Use per-tenant provisioning keys instead |
| `OCTO_AGENT_JWT_EXPIRE_MINUTES` | Lifetime of the agent JWT a provisioning key is exchanged for (default `120`). A sensor re-exchanges its key when the token expires, so this bounds how long a token lifted off a sensor host outlives the key being revoked |
| `OCTO_PROVISIONING_KEY_TTL_DAYS` | Days a newly minted provisioning key stays exchangeable (default `90`; `0` mints perpetual keys, [#308](https://github.com/onixus/Shapoclyack/issues/308)). Applied at mint time only — changing it does not move the expiry of a key already handed to an installer, and **keys minted before this variable existed have no expiry and never gain one**. An exchange past `expires_at` answers `401`, the same message as an unknown or revoked key; `GET /api/tenants/{tenant_id}/provisioning-keys` reports `expires_at` and an `expires_soon` flag (14 days) so the ones to rotate can be found |
| `OCTO_AGENT_STALE_SECONDS` | How long after its last heartbeat a sensor is reported `stale` (default `120`). Nothing is stored: the state is computed from `last_seen_at` at read time, so lowering it takes effect on the next request. It also decides the `agent_offline` event ([#349](https://github.com/onixus/Shapoclyack/issues/349)), and there it has a second effect: a sensor is called *recovered*, and its offline alert closed, only after twice this long of unbroken heartbeats. Setting it below twice the sensor's heartbeat interval (60s, `HEARTBEAT_INTERVAL_SECONDS` in `agent/worker.py`) makes every sensor look stale between beats |
| `OCTO_AGENT_MIN_VERSION` | Lowest sensor version allowed to claim jobs (default empty — no floor, [#363](https://github.com/onixus/Shapoclyack/issues/363)). A sensor below it gets `426 Upgrade Required` on `POST /api/agent/jobs/claim` and the reason in its heartbeat response, but keeps registering and heartbeating so it stays visible in the fleet view — which is where the hosts needing an upgrade are found. Versions are ordered the way `dpkg` orders them, so `0.3.2.1` < `0.44-0907` and a `-beta1` of the required release is not below it. A version this installation cannot parse — including a sensor too old to report one — is treated as below any floor |
| `OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS` | Shape the sensor's results upload to this many KiB/s (default `0` — no limit, [#359](https://github.com/onixus/Shapoclyack/issues/359)). Read by the **sensor** (`agent/worker.py`), not the API. The archive is throttled as it is read off disk, so this bounds the wire rate; the bucket holds one second's worth, so a burst up to the rate leaves immediately and only a sustained stream is held back. On a branch office's uplink an unshaped run archive is what makes the site's voice traffic stutter after every scan |
| `OCTO_AGENT_UPLOAD_TIMEOUT` | How long the sensor waits for the API's answer to a results upload, in seconds (default `900`). Read by the **sensor** (`agent/worker.py`), not the API. Separate from `--timeout` because the API answers this one call when it has finished *ingesting*, not when the bytes are in: at the ordinary 60s socket timeout every ingest longer than a minute read as a dead connection, and the client answered it by sending the whole archive again — the site's uplink spent twice over to be told the first copy is still being processed. Keep it at or above the API's `OCTO_JOB_INGEST_LEASE_SECONDS` |
| `OCTO_AGENT_RESULTS_MAX_BODY_BYTES` | Hard request-body cap on `POST /api/agent/jobs/{job_id}/results`, read from `Content-Length` before the multipart body is buffered (default `134217728` — 128 MiB). A length-less upload is answered `411` |
| `OCTO_AGENT_RESULTS_MAX_CONCURRENT_INGESTS` | Result uploads this replica ingests at the same time (default `4`). Ingestion — SQL, the NATS publish, archive extraction, artifact writes, projection updates — is synchronous and runs on a worker thread; this is the ceiling on those threads, and with them on database connections and simultaneous extractions. Raising it past `OCTO_DB_POOL_SIZE` + `OCTO_DB_MAX_OVERFLOW` buys nothing: the extra ingests queue on the connection pool instead |
| `OCTO_AGENT_RESULTS_INGEST_MAX_WAITING` | Uploads allowed to queue for one of those slots (default `8`). This is a **memory** bound, not a fairness knob: a waiting upload is holding its whole archive in RAM, so the worst case in flight is `(concurrent + waiting) × OCTO_AGENT_RESULTS_MAX_BODY_BYTES` — 1.5 GiB at the defaults, if every sensor sent a maximum-size archive at once. Beyond the ceiling an upload is answered `503` with `Retry-After` rather than buffered |
| `OCTO_AGENT_RESULTS_INGEST_WAIT_SECONDS` | How long a queued upload waits for a slot before that same `503` (default `25`; `0` waits indefinitely). Keep it below the sensor's own request timeout, or the answer arrives after the sensor stopped listening and the retry is charged the whole upload again |
| `OCTO_AGENT_DEPLOY_SSH_PORTS` | TCP ports the SSH push deployer and its host-key probe may dial (default `22,2222`, #240). Both open a connection to a host and port taken from the request body, which over an open range makes the probe a port scanner with a tidy response format. Name the port here if your fleet listens elsewhere; `*` restores the full range. A value that is not a port list refuses startup rather than narrowing the list silently |
| `OCTO_AGENT_DEPLOY_ENFORCE_SCAN_SCOPE` | Require a deployment target to sit **inside** the tenant's approved scan scope, not merely outside its denied ranges (default `false`, #240 / #226). Off, the scope's *prohibitions* still apply — a host a tenant was told not to touch is not reachable by SSH from this API either. On is a stricter claim than most fleets can make: a sensor on a management host that scans a customer range is the ordinary MSSP shape, and with this set that deployment is refused |
| `OCTO_HTTPS_PROXY` | Proxy for outgoing `https://` requests, in API **and** sensor ([#359](https://github.com/onixus/Shapoclyack/issues/359)): webhook and ticket delivery, OIDC, advisory feeds, and every call the sensor makes. `[http://][user:pass@]host[:port]` — the proxy URL itself must be `http://`, and no SOCKS. `https://` is refused rather than accepted and downgraded: the hop to the proxy is never wrapped in TLS here, so it would promise an encrypted hop that does not exist while `Proxy-Authorization: Basic` went out in the clear. Falls back to `HTTPS_PROXY`/`https_proxy` when unset; the prefixed name exists so a pod can override a cluster-wide injection meant for something else. HTTPS *through* it is a `CONNECT` tunnel, so the receiver's certificate is still verified against its own name |
| `OCTO_HTTP_PROXY` | The same for `http://` targets; falls back to the **lowercase** `http_proxy` only. Uppercase `HTTP_PROXY` is deliberately **not** read: a CGI-shaped environment derives it from an incoming `Proxy:` request header, so it is the one name an untrusted caller can write (httpoxy) — which is why curl reads only the lowercase spelling too. Only this direction is affected; no request header spells `HTTPS_PROXY` |
| `OCTO_NO_PROXY` | Comma-separated exemptions, falling back to `NO_PROXY`/`no_proxy`. `*` bypasses everything; a bare name matches it and its subdomains (`example.com` covers `api.example.com` but not `notexample.com`); `host:port` pins the port; a CIDR matches an address literal inside it. An exempted webhook keeps the pinned direct dial from #151 |
| `OCTO_CA_BUNDLE` | PEM file **added to** the system trust store — for outgoing HTTPS, the SMTP relay and the NATS connection alike. This is what a TLS-inspecting proxy's internal root goes in; verification is never turned off, and public receivers reached without the inspector keep verifying. A path that does not exist, or a file that is not a PEM bundle, is a hard error rather than a silent fallback to the system store. Read by API and sensor |
| `OCTO_HSTS_ENABLED` | Send `Strict-Transport-Security` on every response. Defaults to on under `OCTO_ENV=prod` and off under `dev`, since a browser that picks the header up from `http://localhost` pins itself to HTTPS for a year |
| `OCTO_API_DOCS` | `enabled` or `disabled` — whether `/docs`, `/redoc` and `/openapi.json` are mounted ([#319](https://github.com/onixus/Shapoclyack/issues/319)). Defaults to `disabled` under `OCTO_ENV=prod` and `enabled` under `dev`: the schema names every route, its parameters and every field an answer carries, which is a map of the installation for anyone who can reach it. Disabled means the routes do not exist, so they answer `404` — or, where the console bundle is served from the same process, its own 404 page. An unrecognised value warns and reads as `disabled` |
| `OCTO_METRICS_TOKEN` | Bearer token `GET /metrics` demands when set; unset leaves the endpoint open. The series name every route, the queue depth and login outcomes, so an installation whose `/metrics` is reachable from outside the cluster should set it — a `prod` start without it logs a warning rather than refusing, since most scrapers run inside. The scraper sends `Authorization: Bearer <token>`; for the Prometheus Operator that is `bearerTokenSecret` in `k8s/shapoclyack/examples/servicemonitor.example.yaml`. The comparison is constant-time |
| `OCTO_INSTANCE_ID` | Identity of this API replica in the shared job queue; defaults to the hostname. Only local-mode jobs owned by this identity are failed as orphans on startup |
| `OCTO_ALLOW_SCAN_START` | Permit job creation from API/UI |
| `OCTO_SCAN_SCOPE_RESOLVE_CHECK` | Resolve requested scan domains at admission and refuse the ones whose current addresses fall in a range the tenant's approved scope denies (default `true`, #226). Only runs when the scope has deny ranges; a lookup that does not answer within 3s leaves the name checked as a string and is logged. Turn it off only where the API cannot resolve names at all |
| `OCTO_ASSET_STALE_DAYS` | Age threshold for stale assets |
| `OCTO_ASSET_EVENTS_ENABLED` | Publish asset-level events to `events.asset.{tenant}.{kind}` after each run (default `true`; inert without `OCTO_NATS_URL`) |
| `OCTO_ASSET_EVENTS_MAX_PER_RUN` | Per-run publish cap (default `1000`); the overflow is logged and counted, and `diff.json` always keeps the full set |

### NATS outbox

A broker outage no longer unreadies an API replica (P2 of the 2026-09-18
architecture review). What it must not do instead is hide the analytical
projection falling behind, which is what the `nats_outbox` table and its
reconciler are for: the ingest message NATS refused is written down and
republished when the broker returns.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_NATS_OUTBOX_ENABLED` | `true` | Record a publication the broker refused in the `nats_outbox` table and republish it when NATS returns. **This is what lets NATS be a non-blocking readiness check.** With it off there is nowhere to write a refused message down, so the publication that owns the bus hop fails instead of closing: the run's `run_publications` row retries, ends `dead` and takes the run's own projections with it. That is the one configuration in which a broker outage still costs a scan — loudly rather than silently, but it costs it. See [operations.md § NATS outbox](operations.md#nats-outbox) |
| `OCTO_NATS_OUTBOX_INTERVAL_SECONDS` | `30` | How often this replica drains the due end of the outbox. Floored at 1 |
| `OCTO_NATS_OUTBOX_BATCH_SIZE` | `10` | Entries republished per tick. Small on purpose, unlike the webhook dispatcher's 50: one ingest entry carries a run archive, so a batch is megabytes held in the process at once |
| `OCTO_NATS_OUTBOX_MAX_ATTEMPTS` | `20` | Republish attempts before an entry goes `dead` and waits for an operator (`nats_outbox.requeue_dead`). At the default backoff that is close to four hours of retrying |
| `OCTO_NATS_OUTBOX_RETRY_BASE_SECONDS` | `15` | First backoff after a failed republish; doubles per attempt |
| `OCTO_NATS_OUTBOX_RETRY_MAX_SECONDS` | `900` | Cap on that backoff |
| `OCTO_NATS_INGEST_DEDUPE_SECONDS` | `86400` | JetStream duplicate window on the `INGEST` stream, clamped to `OCTO_NATS_INGEST_MAX_AGE_SECONDS` unless that is `0` (unbounded retention), which does **not** switch dedupe off. Wide enough to cover the whole retry schedule above: a publish whose ack timed out after the server stored it is a genuine duplicate on replay, and JetStream's own 2-minute default is shorter than a single backoff |
| `OCTO_NATS_OUTBOX_BACKLOG_ALERT_SECONDS` | `300` | How long a publication may stay unrecovered before `/readyz` and `/api/health` report `ingest_backlog: error` and call the installation degraded. Longer than a broker restart, shorter than an outage nobody should have to find by hand |

The unrecovered backlog is the `ingest_backlog` check on `/readyz` and
`/api/health` and the `octo_nats_outbox_backlog` gauge; draining it is
[operations.md § NATS outbox](operations.md#nats-outbox).

Outbound webhooks (see
[architecture.md](architecture.md#outbound-webhooks)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_WEBHOOKS_ENABLED` | `true` | Register `/api/webhooks` and consume asset events. Off means no subscriptions, no deliveries, no endpoints |
| `OCTO_WEBHOOK_DISPATCH_ENABLED` | `true` | Run the delivery loop in *this* replica. Off keeps the API surface (subscriptions, DLQ, audit trail) while confining outbound HTTP to selected replicas |
| `OCTO_WEBHOOK_FANOUT_ENABLED` | `true` | Run the JetStream fan-out consumer in *this* replica (events → delivery rows). Independent of dispatch since #153; see [deployment modes](architecture.md#webhook-deployment-modes) |
| `OCTO_WEBHOOK_MAX_ATTEMPTS` | `6` | Attempts, including the first, before a delivery is dead-lettered |
| `OCTO_WEBHOOK_RETRY_BASE_SECONDS` | `30` | First backoff; doubles per attempt |
| `OCTO_WEBHOOK_RETRY_MAX_SECONDS` | `3600` | Backoff cap |
| `OCTO_WEBHOOK_TIMEOUT_SECONDS` | `10` | Per-request timeout. A receiver needing longer is doing work in the request instead of queueing it |
| `OCTO_WEBHOOK_DISPATCH_INTERVAL_SECONDS` | `5` | How often the due end of the queue is drained |
| `OCTO_WEBHOOK_DISPATCH_BATCH_SIZE` | `50` | Deliveries claimed per tick |
| `OCTO_WEBHOOK_DELIVERY_RETENTION_DAYS` | `30` | Age past which delivered/dead rows are pruned; `0` keeps the audit trail forever. Pending rows are never pruned |
| `OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS` | `false` | Allow webhook URLs resolving to loopback/private/link-local addresses. Needed for an on-cluster receiver; it also removes the SSRF guard, so scope it to installations where operators are trusted with internal reachability |
| `OCTO_WEBHOOK_MAX_SUBSCRIPTIONS_PER_TENANT` | `20` | Bound on how much fan-out one event can cause |

### Notification channels

Where a **finished run** is announced, per tenant
([#351](https://github.com/onixus/Shapoclyack/issues/351)). Managed through
`POST /api/notification-channels` — see
[api-and-rbac.md](api-and-rbac.md#notification-channels) — not through
environment variables, because the destination is a property of a tenant and
not of the installation.

Five kinds: `slack`, `msteams`, `mattermost` (a JSON POST to an incoming
webhook, whose URL is the credential and is encrypted at rest), `email` (the
tenant's recipients through the installation's `OCTO_REPORT_SMTP_*` relay) and
`defectdojo` (the bulk Generic Findings Import into *this tenant's* product).

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `OCTO_NOTIFICATION_CHANNELS_ENABLED` | API | `true` | Register `/api/notification-channels` and announce finished runs. Off means no channels and no sending; unlike webhooks the two cannot be split across replicas, because the send is started by the process that finished the job |
| `OCTO_NOTIFICATION_CHANNEL_MAX_PER_TENANT` | API | `10` | Bound on the destinations one tenant's runs can reach |
| `OCTO_NOTIFICATION_CHANNEL_TIMEOUT_SECONDS` | API | `30` | Per-send budget, for every kind including `email`. Longer than the webhook timeout because a DefectDojo import deduplicates inside the request. The send runs on a background thread, so a channel spending the whole budget delays no request |
| `OCTO_SINGLE_TENANT_ALERTS` | **scanner** | `false` | Declare this installation single-tenant, which is what re-enables the **installation-wide** alert credentials below |

`OCTO_SINGLE_TENANT_ALERTS` is the one row above that the API never reads: the
stages it gates are `scanner/pipeline/alerts.py` and
`scanner/pipeline/defectdojo.py`, which run in the *scanner* process. On the
API host that is the scan subprocess and it inherits the Deployment's
environment; in Kubernetes a scheduled scan is a separate CronJob pod, so the
variable has to be set **there** — it belongs in the `shapoclyack-alerts`
Secret the CronJob already mounts
(`k8s/shapoclyack/examples/api-secrets.example.yaml`), not on the API
Deployment. Set on the API alone it changes nothing at all, silently.

`OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS` also governs channel URLs: a Slack or
DefectDojo target resolving to a loopback, private or link-local address is
refused under the same SSRF boundary, at creation and again at send time.

#### Migrating off the installation-wide alert variables

Before #351 the scanner's alert stage read `OCTO_SLACK_WEBHOOK`,
`OCTO_TELEGRAM_BOT_TOKEN` / `OCTO_TELEGRAM_CHAT_ID` and `OCTO_SMTP_*`, and the
bulk export read `OCTO_DEFECTDOJO_URL` / `OCTO_DEFECTDOJO_API_KEY`. All of them
are installation-wide, and nothing at that point in the pipeline knew which
tenant the run belonged to — so on a multi-tenant installation every tenant's
scan announced itself in one Slack channel and every tenant's findings were
imported into one DefectDojo product.

They still work, and **only** for an installation that declares itself
single-tenant:

* set `OCTO_SINGLE_TENANT_ALERTS=true` and nothing changes — the config file's
  `alerts:` and `defectdojo:` sections behave exactly as before. This is the
  answer for the standalone scanner CLI, which has no API and no database;
* leave it unset (the default) and both stages skip with
  `skipped_reason: multi_tenant_use_notification_channels` in `alerts.json` /
  `defectdojo.json`, without opening a connection. Nothing is sent to the wrong
  tenant, which is the direction this had to fail in.

To move a multi-tenant installation across, per tenant:

1. `POST /api/notification-channels` with `kind: "slack"` and the incoming
   webhook URL from `OCTO_SLACK_WEBHOOK` as `secret` (a chat webhook URL *is* a
   credential, so it goes in the column that is encrypted, not in `endpoint`);
2. for mail, `kind: "email"` with `config.to` holding what was in
   `OCTO_SMTP_TO`. The relay stays installation-wide — it is infrastructure,
   like Postgres, and was never the part that crossed tenants — so keep
   `OCTO_REPORT_SMTP_HOST` / `OCTO_REPORT_SMTP_FROM` set;
3. for DefectDojo, `kind: "defectdojo"` with `endpoint` = the instance URL,
   `secret` = the API token and `config.product_name` = a product **per
   tenant**. `product_name` is required for exactly that reason;
4. clear the old Secret (`shapoclyack-alerts`, `shapoclyack-defectdojo` in
   `k8s/shapoclyack/examples/api-secrets.example.yaml`) and leave
   `OCTO_SINGLE_TENANT_ALERTS` unset — **but read the next paragraph first if
   any of your scans are CronJob scans**, because for those this step turns
   alerting off and channels do not replace it.

> **Channels only cover runs the API knows about.** The fan-out hangs off job
> completion (`jobs.complete_job` for a sensor upload, `jobs._run_job` for a
> local scan), so it fires for a scan started through `POST /api/jobs`, a
> schedule, or a sensor. A `k8s/shapoclyack/base/cronjob.yaml` scan and a
> bare `python -m scanner.main` run create no job row, reach neither function,
> and are therefore **never** announced through a notification channel. For
> those the installation-wide stages are still the only alerting there is:
> keep `shapoclyack-alerts` populated and set `OCTO_SINGLE_TENANT_ALERTS=true`
> on the CronJob — accepting that those alerts are installation-wide — or move
> the schedule into `POST /api/schedules`, where the scan gets a job row, a
> tenant and its tenant's channels. Giving CronJob scans per-tenant channels is
> [#351](https://github.com/onixus/Shapoclyack/issues/351)'s explicit
> non-goal, not an oversight.

Two things this does **not** do. There is no Telegram channel kind: Telegram
was never a per-tenant destination in any installation we know of, and a kind
with no user is a wire format to keep working forever — a tenant that wants it
uses a `webhook` subscription. And a channel send is **not** queued or
retried the way a webhook delivery is: a run summary is only interesting while
it is fresh, so a failure is recorded on the channel (`last_status`, visible in
`GET /api/notification-channels`) and in the job log instead of being replayed.
For the DefectDojo import that is a real limitation — a `503` from the tracker
loses that run's import, and the next scan's import is what recovers it.
Remediation-workflow events and SLA escalation
([#349](https://github.com/onixus/Shapoclyack/issues/349), see
[vulnerability-lifecycle.md](vulnerability-lifecycle.md#workflow-events-and-sla-escalation)).
The events are opt-in per subscription, so turning these on does not by itself
send anything anywhere:

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_WORKFLOW_EVENTS_ENABLED` | `true` | Emit the eight workflow kinds at all. Off means a subscription naming them simply never matches, and the SLA worker does not start |
| `OCTO_SLA_ESCALATION_ENABLED` | `true` | Run the worker that derives `sla_due_soon`, `sla_breached`, `exception_expiring` and `agent_offline`. Leader-locked, so it is safe to leave on in every replica. Set it to `false` **before** an upgrade if the installation would rather not have its whole existing breach backlog announced by the first tick |
| `OCTO_SLA_ESCALATION_INTERVAL_SECONDS` | `900` | Worker tick (floored at 30). An SLA is measured in days, so a tighter tick buys nothing; a longer one delays a notification rather than losing it, because the marker table decides what has already been said |
| `OCTO_SLA_ESCALATION_MAX_FINDINGS` | `500` | Findings one tenant's tick may announce, oldest deadline first. A tenant that imports a backlog of overdue findings must not turn one tick into that many webhook deliveries. A **window**, not a ceiling: the worker keeps a cursor per tenant and the next tick continues after the last deadline this one reached, so a backlog of 600 findings at the default is drained in two ticks (30 minutes) rather than stopping at 500. The same budget and the same cursor now bound the fleet-wide `agent_offline` sweep, which had neither: a site outage that silenced eight hundred sensors announced all eight hundred in one tick |
| `OCTO_WORKFLOW_MARKER_RETENTION_DAYS` | `365` | Age past which an "already announced" marker is deleted. Deleting one **re-arms its event**, so this is also the period after which a still-breached finding is raised a second time; `0` disables both the sweep and the re-announcement. A claim taken for a fan-out that then failed is released immediately rather than waiting for this sweep, so a database hiccup delays a notification by one tick |

The owner digest uses the report relay (`OCTO_REPORT_SMTP_*` below): with no
relay configured the digest is skipped with a logged reason and the webhook
events still go out.
Inbound ticket sync — the poller that reads Jira / ServiceNow / DefectDojo
back onto the findings ([#347](https://github.com/onixus/Shapoclyack/issues/347),
see [vulnerability-lifecycle.md](vulnerability-lifecycle.md#inbound-ticket-sync)).
It polls only tickets linked to a finding whose tenant has an enabled
subscription for that transport; the credential and the base URL are that
subscription's:

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_TICKET_SYNC_ENABLED` | `true` | Run the poller in *this* replica. Off keeps the manual `POST /api/vulnerabilities/{id}/ticket/sync` button and the outbound reflection; only the cadence goes away. Leader-locked, so only one replica of those that run it ever polls |
| `OCTO_TICKET_SYNC_POLL_INTERVAL_SECONDS` | `60` | How often the thread wakes to look for due findings. Not the poll cadence — floored at 5 |
| `OCTO_TICKET_SYNC_INTERVAL_SECONDS` | `900` | Default seconds between two reads of the *same* ticket. Overridden per subscription by `transport_config.sync_interval_seconds` (`0` = use this; otherwise ≥ 60). Floored at 60: the poll is one GET per linked finding |
| `OCTO_TICKET_SYNC_BATCH_SIZE` | `200` | Findings polled per subscription per tick, oldest cursor first. The rest stay due for the next tick; raise it if `octo_ticket_sync_lag_seconds` grows while trackers are healthy |
| `OCTO_TICKET_SYNC_RETRY_BASE_SECONDS` | `120` | First hold-off after a *retryable* failure (5xx, timeout); doubles per consecutive failure. The whole subscription is held off, not one ticket — a tracker that is down fails identically for every ticket on it |
| `OCTO_TICKET_SYNC_RETRY_MAX_SECONDS` | `3600` | Hold-off cap |
| `OCTO_TICKET_SYNC_REOPEN_WINDOW_DAYS` | `30` | How long after a `ticket_resolved` closure the tracker may still reopen the finding. Closed findings stay pollable for that path to exist and leave the queue afterwards, or every closure accumulates forever and a year of dead tickets fills the batch ahead of live work. `0` drops the reopen path |

The per-request timeout and the private-target rule are the webhook ones
(`OCTO_WEBHOOK_TIMEOUT_SECONDS`, `OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS`): it is
the same wire to the same tracker, and giving the poller its own copies would
be two places to change when a self-hosted Jira moves inside the cluster.

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
| `OCTO_REPORT_SMTP_VERIFY_TLS` | `true` | Verify the relay's certificate and hostname during STARTTLS. `smtplib`'s own default verifies neither, so `false` buys encryption against a passive listener and nothing against a relay that is not the one you meant. Prefer trusting the internal CA system-wide; a `prod` process warns while this is off |
| `OCTO_REPORT_SMTP_TIMEOUT_SECONDS` | `20` | Per-message budget |

Per-tenant usage quotas (ROADMAP Track E, MSSP operations; see
[api-and-rbac.md](api-and-rbac.md#usage-metering-and-quotas)). These are the
platform **defaults**, applied to any tenant that has no `tenant_quotas` row of
its own; a row overrides them in either direction, including back to unlimited.
The shipped default is **unlimited**, and that is a decision, not an oversight:
a quota is a commercial boundary, so it fails open on upgrade, unlike the
approved scan scope, which deliberately fails closed. An installation that
never sold a limit keeps scanning exactly as before.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_QUOTA_DEFAULT_MAX_ASSETS` | `0` | Assets a tenant without its own quota row may hold (`active` or `stale`). `0` means unlimited. Newly discovered assets past the limit are not registered; existing ones keep being updated and the scan still succeeds |
| `OCTO_QUOTA_DEFAULT_MAX_SCANS_PER_MONTH` | `0` | Scans a tenant without its own quota row may start per UTC calendar month. `0` means unlimited. Past the limit `POST /api/jobs` answers `429` with `Retry-After` set to the seconds left in the period |
| `OCTO_QUOTA_ENFORCEMENT_ENABLED` | `true` | Whether a reached limit actually refuses anything. Off, the meter still counts and `/api/usage` still answers — metering-only is the normal first state, because an MSSP wants to watch consumption against the number it sold for a billing period or two before it starts refusing its customer's scans |

A negative value is floored to `0`, i.e. unlimited: this is a billing setting,
and the safe direction for it to fail in is "do not refuse the customer".

Logging ([#330](https://github.com/onixus/Shapoclyack/issues/330)). Read from
the environment rather than from a settings object, because the configuration
has to be in place before `load_settings()` runs — a `prod` start that refuses
on built-in credentials is the one line an operator will read. The same two
variables are honoured by the API and by the sensor (`agent/worker.py`); see
[operations.md](operations.md#logs-and-observability) for the log shape and
what the redaction filter does and does not cover.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_LOG_FORMAT` | `text` | `text` or `json`. `json` emits one object per line (`ts`, `level`, `logger`, `msg`, `request_id`, plus `exc` on a traceback) for a shipper; `text` stays readable in a terminal. The same five fields on both processes — on the sensor `request_id` is always empty, since it serves no requests and correlates by `job_id`, but the field is there so one shipper schema covers both. Both formats timestamp in UTC. An unrecognised value warns on stderr and reads as `text`. The API hands the same formatter to uvicorn, so `uvicorn.access` is in the chosen format too |
| `OCTO_LOG_LEVEL` | `INFO` | Any level name (`DEBUG`, `INFO`, `WARNING`, `ERROR`). An unrecognised name warns and reads as `INFO` rather than silencing the process, and so does `NOTSET` — on the root logger it means "no level check at all". `DEBUG` does not reach `sqlalchemy.engine`/`sqlalchemy.pool` (held at `WARNING`, because the statement log prints bound parameters) or `paramiko`/`httpx`/`httpcore`/`nats` (held at `INFO`); see [operations.md](operations.md#secret-redaction-and-what-it-does-not-cover). On the sensor, `--verbose` still wins over this |

OpenTelemetry (ROADMAP P3). Empty endpoint means no TracerProvider — the
API does not buffer spans nobody will read. Traces are request timing, not
scan observations.

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_OTEL_EXPORTER_OTLP_ENDPOINT` | *(empty)* | OTLP HTTP traces URL (`http://collector:4318/v1/traces`). Empty disables tracing |
| `OCTO_OTEL_SERVICE_NAME` | `shapoclyack-api` | `service.name` resource attribute |
| `OCTO_OTEL_TRACES_SAMPLER_RATIO` | `1.0` | Share of **root** spans kept, `0.0`-`1.0` ([#330](https://github.com/onixus/Shapoclyack/issues/330)). Sampling is parent-based: a request arriving with a `traceparent` keeps the decision the ingress or the console already made, so a sampled trace never loses its API span. `1.0` keeps everything, which is right for a demo and expensive for an installation whose console polls run state all day. A value outside the range is clamped, and one that is not a number warns and reads as `1.0` — an observability knob should not be able to stop the API from starting |

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
| `OCTO_AUDIT_EVENT_RETENTION_DAYS` | `365` | Age past which `audit_events` (the administrative trail, #327) rows are pruned; `0` keeps them forever. The API never prunes them — the rows are append-only and only `python -m api.services.audit_retention`, run with its own credentials, can, see [operations.md](operations.md#audit-trail-immutability-and-retention-327-329) |

Audit trail to a SIEM ([#328](https://github.com/onixus/Shapoclyack/issues/328),
see [operations.md](operations.md#audit-events-to-siem-328)). The API side needs
no configuration of its own: with `OCTO_NATS_URL` set, each committed
`audit_events` row is published to `events.audit.{tenant}` after the commit, and
with it unset **nothing is published**. The variables below are read by the
forwarder worker (`python -m api.services.audit_syslog_forwarder`) only:

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_AUDIT_SYSLOG_URL` | *(empty)* | `tls://host:6514` or `tcp://host:514`. Required — the worker refuses to start without it rather than forwarding nothing quietly. `tcp://` connects and warns on every connect; **UDP is not implemented**, because it carries no delivery signal and so nothing could decide when an event may be acknowledged |
| `OCTO_AUDIT_SYSLOG_SOURCE` | `nats` | `nats` reads `events.audit.>` from JetStream (durable `octo-audit-syslog`); `db` walks `audit_events` by id and keeps its place in `audit_forward_cursors`. `db` exists for installations with no `OCTO_NATS_URL` and has a visibility window `nats` does not — see the table in operations.md |
| `OCTO_AUDIT_SYSLOG_CA` | *(empty)* | PEM bundle verifying the collector. Unset falls back to the system trust store, which is right for a publicly issued certificate. `OCTO_CA_BUNDLE` is not consulted here: the SIEM link is not the outbound-HTTPS trust decision |
| `OCTO_AUDIT_SYSLOG_CERT` / `OCTO_AUDIT_SYSLOG_KEY` | *(empty)* | Client certificate and key, for a collector that requires one |
| `OCTO_AUDIT_SYSLOG_TLS_HOSTNAME` | *(empty)* | Name to verify the collector's certificate against, when it differs from the host in the URL |
| `OCTO_AUDIT_SYSLOG_HOSTNAME` | *(hostname)* | Value of the RFC 5424 `HOSTNAME` field. Set it to the installation's name: the pod name changes on every restart and makes a SIEM's host list unusable |
| `OCTO_AUDIT_SYSLOG_FACILITY` | `13` | Syslog facility. 13 is `log audit`, which is what CEF ingest rules are usually written against |
| `OCTO_AUDIT_SYSLOG_TIMEOUT_SECONDS` | `10` | Connect and write timeout, per write. In `db` mode the whole batch is sent inside the transaction that moves the cursor, so a slow-but-alive receiver can hold that row lock for up to this × `OCTO_AUDIT_SYSLOG_DB_BATCH` — lower the batch, not just the timeout, if that matters |
| `OCTO_AUDIT_SYSLOG_DB_BATCH` | `200` | Rows per `db`-mode poll. Small for the same reason |
| `OCTO_AUDIT_SYSLOG_DB_POLL_SECONDS` | `10` | Idle wait between `db`-mode polls. A full batch goes straight round again |
| `OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS` | `15` | How far behind the present `db` mode reads. `occurred_at` is stamped when the change is recorded but the row appears only at COMMIT, so a shorter lag risks passing a row that had not yet been published; a transaction that outlives this window between the two can still be skipped |

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
| `OCTO_OIDC_STATE_TTL_SECONDS` | `600` | How long one authorization request stays valid — it only has to cover a human typing a password at the provider. It is also the whole bound on the `oidc_pending_states` table: the record is a row shared by every replica (#321), single-use, and swept once it expires. No session affinity is needed, and nothing evicts a *live* pending login the way the old 10,000-per-replica cap did |
| `OCTO_OIDC_HTTP_TIMEOUT_SECONDS` | `10` | Per-request timeout for discovery, JWKS and the token exchange |
| `OCTO_OIDC_POST_LOGIN_REDIRECT` | *(empty)* | Where the callback sends the browser once the session exists, with the token in the URL **fragment** (never a query string, which lands in access logs). Empty makes the callback answer with the same JSON body as password login, which is what an API-only install wants; a console install points this at its `/login` page |

Multi-factor authentication and local-login policy (see
[api-and-rbac.md](api-and-rbac.md#multi-factor-authentication),
[#315](https://github.com/onixus/Shapoclyack/issues/315)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_MFA_REQUIRED_ROLES` | *(empty)* | Comma-separated console roles that must carry a second factor, e.g. `admin`. Empty — the default — means enrolment is available to everyone and required of nobody, which is why an upgrade changes nothing. An account in a listed role that has not enrolled still signs in, but its session carries `mfa_pending` and reaches only the MFA setup routes, `/api/auth/me` and the two ways out. An unknown role is dropped with a warning rather than refusing startup: dropping one only relaxes the requirement, where raising would take the API down over a typo |
| `OCTO_MFA_STEPUP_MINUTES` | `15` | How recently the second factor must have been proved to mint or revoke a service token or a provisioning key, to replace a tenant's scan scope, or to create an account / set a password / change a role / reset somebody's MFA — the full list is in [api-and-rbac.md](api-and-rbac.md#step-up). Applies **only** to accounts that have MFA enabled. Values below `1` are clamped to `1`: zero would demand a code per click, which teaches people to keep an authenticator open beside the console |
| `OCTO_MFA_PHISHING_RESISTANT_ROLES` | *(empty)* | Comma-separated console roles whose sessions count as fully signed in only when the second factor was a **security key or passkey** (WebAuthn), not a TOTP or recovery code. Implies `OCTO_MFA_REQUIRED_ROLES` for those roles. A session of a listed role proved with a code is confined to the MFA routes — where it can register a key and verify with it — rather than refused; its step-ups must be a key as well. Same parsing as `OCTO_MFA_REQUIRED_ROLES`. In `prod`, refuses startup when no WebAuthn relying party can be derived ([api-and-rbac.md](api-and-rbac.md#requiring-a-phishing-resistant-factor)) |
| `OCTO_MFA_STEPUP_PHISHING_RESISTANT` | `false` | When `true`, every step-up (credentials, account administration, removing a key) must be proved with a security key, for every account that has MFA enabled — an account holding only an authenticator app cannot perform those operations until it registers a key. Same `prod` startup check as above |
| `OCTO_WEBAUTHN_RP_ID` | *(hostname of `OCTO_PUBLIC_BASE_URL`)* | The WebAuthn relying-party ID: the domain keys are scoped to, e.g. `shapoclyack.example.com`. It must equal, or be a registrable suffix of, the host the console is served from. Changing it later orphans every registered key — they are bound to the old ID by the authenticator itself |
| `OCTO_WEBAUTHN_ORIGINS` | *(origin of `OCTO_PUBLIC_BASE_URL`)* | Comma-separated exact origins (`scheme://host[:port]`) a ceremony may come from — the **console's** origin(s), which is not necessarily the API's when they are served separately. An assertion signed on any other origin is refused; this is the check that makes a key phishing-resistant. Never taken from the request. Lower-cased on read, as browsers serialise origins. In `prod` each must be `https` (`localhost` excepted) and have `OCTO_WEBAUTHN_RP_ID` as its host or a parent of it, and the RP ID must not be an IP address — checked whenever WebAuthn is configured or a policy uses it |
| `OCTO_WEBAUTHN_RP_NAME` | `Shapoclyack` | The name the browser shows in its security-key prompt |
| `OCTO_LOCAL_LOGIN` | `enabled` | What password login is for once SSO is configured: `enabled` (the pre-#315 behaviour), `break-glass` (only the accounts below), `disabled` (SSO only). **Ignored entirely when no OIDC provider is set** — an installation with neither is one nobody can reach. An unrecognised value keeps password login *enabled* with a warning, deliberately the opposite of the other unknown-value readers: closing this one locks every operator out of an installation whose SSO may be the broken part |
| `OCTO_BREAK_GLASS_USERS` | *(empty)* | Comma-separated usernames allowed to present a password under `break-glass`. Names, not roles: the point of a break-glass account is that it is specific and closely watched, not a property somebody acquires by promotion. `break-glass` with an empty list behaves as `disabled` and warns at startup in `prod` |

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
| `OCTO_JOB_LEASE_SECONDS` | `300` | How long a claimed/running job survives without its executor renewing. Keep it well above the sensor heartbeat interval (60s) — too low and live scans are requeued under a working sensor |
| `OCTO_JOB_INGEST_LEASE_SECONDS` | `900` | How long the lease is held open while a *result* is ingested. The scan is over, but the archive still has to be transferred and extracted and its artifacts written, and a lease lapsing in that window has the reaper hand the job to a second attempt while the first one's result is being processed. Longer than `OCTO_JOB_LEASE_SECONDS` because it covers a transfer over a branch office's uplink plus the ingest itself. A result from a replaced attempt is refused at the final write either way — this is what keeps that refusal rare rather than routine |
| `OCTO_JOB_MAX_ATTEMPTS` | `3` | Hand-outs a job gets before an expired lease fails it instead of requeueing it |
| `OCTO_JOB_CANCEL_GRACE_SECONDS` | `300` | How long a scan an operator stopped may sit in `cancelling` before the reaper finishes it as `cancelled` without the sensor's confirmation ([#360](https://github.com/onixus/Shapoclyack/issues/360)). A cooperating sensor answers on its next heartbeat, so this is the bound on a sensor too old to understand the request, or one that died with the signal in flight. **It is not the only clock on a stop.** A job whose *result* is being ingested is passed over while its ingest lease is open, so a stop pressed during an upload waits out `OCTO_JOB_INGEST_LEASE_SECONDS` (900s) rather than this — deliberately, since dropping a live upload at 300s would refuse it at the fence and take the partial archive with it. Pressing stop a second time past that lease drops a marker a dead replica left behind; see [troubleshooting.md](troubleshooting.md). **Floored at `OCTO_AGENT_STALE_SECONDS` + `OCTO_JOB_REAPER_INTERVAL_SECONDS` (180s by default), not at a constant**: the stop only reaches the sensor on a heartbeat and the reaper only looks once a tick, so a shorter value cannot be answered at all — every cancellation would be recorded as unconfirmed, alerting on each click, and the sensor's honest confirmation would arrive at a job already finished |
| `OCTO_BULK_ACTION_BUDGET_SECONDS` | `45` | How long `POST /api/{vulnerabilities,assets}/bulk` may spend applying ids before it stops and answers with a partial report ([#346](https://github.com/onixus/Shapoclyack/issues/346)). Each id is its own transaction and, for a finding with a tracker key, its own outbound call, so a batch against a slow Jira outruns the proxy in front of the API — and a `504` there leaves work half applied with no statement of which half. Past the budget the ids the batch never reached come back with outcome `deadline` and the caller sends them again. Keep it **below** the read timeout of that proxy (nginx defaults to 60s); `0` turns the budget off |
| `OCTO_JOB_REAPER_ENABLED` | `true` | Run the expiry sweep in this replica. Safe in all replicas; disabling it everywhere means abandoned jobs stay in flight forever |
| `OCTO_JOB_REAPER_INTERVAL_SECONDS` | `60` | Sweep interval |
| `OCTO_RUN_PUBLICATION_MAX_ATTEMPTS` | `5` | How many times an accepted run's publication — object store, run directory, `latest_run.json`, `ingest.results.{tenant}` — is retried before the `run_publications` row stays `dead` for an operator. It also sets the second bound, at twice this many *claims* without one of them reaching an outcome: an attempt is counted where the store refuses, so a publication that kills the replica running it (a tree past the pod's memory limit) records nothing at all and would otherwise be retried forever in silence. The upload is already accepted and the extracted run is on the accepting replica's disk, so this is not a bound on losing data: it is the point at which a store or broker that has been refusing for minutes becomes somebody's decision instead of a timer's. A `dead` row turns `/api/health` degraded (advisory — `/readyz` is unaffected), raises `octo_run_publication_backlog{status="dead"}` and puts a note on the job's `error` |
| `OCTO_RUN_PUBLICATION_RETRY_BASE_SECONDS` | `15` | First backoff after a failed publication; doubles per attempt |
| `OCTO_RUN_PUBLICATION_RETRY_MAX_SECONDS` | `900` | Ceiling for that backoff |
| `OCTO_RUN_PUBLICATION_WORKER_ENABLED` | `true` | Run the publication reconciler in this replica. Safe in all replicas: rows are claimed with `FOR UPDATE SKIP LOCKED` — by a tick and by the accepting request alike — and a running publication renews its hold as it works, so the two do not publish one row at once however long the work takes. Disabling it everywhere means a publication a request could not finish is never finished; disabling it *somewhere* means those replicas never adopt a peer's row, which is worth knowing when a row reaches the orphan deadline (see [operations.md](operations.md)) |
| `OCTO_RUN_PUBLICATION_INTERVAL_SECONDS` | `30` | Reconciler tick |
| `OCTO_RUN_PUBLICATION_ORPHAN_DEADLINE_SECONDS` | `3600` | How long a publication whose extracted tree no replica can reach may go **untouched** before it is declared `dead`. Untouched, not old: the clock runs from the last time some replica was demonstrably working on the row — a publication in flight renews it every few seconds, and a recorded failure writes it — so a replica that is alive and retrying a slow store keeps its own rows however long the upload has been owed. The paths in the row are on the disk of the replica that accepted the upload; a peer that cannot see them gives the row back rather than condemning a run that is merely on somebody else's volume, and with the artifact cache on an `emptyDir` (the HA overlay's default) *no* peer ever can — a row left by a pod the autoscaler removed would otherwise be handed around forever while the job says `succeeded` with nothing behind it. Floored at two adoption windows (`10 × OCTO_RUN_PUBLICATION_INTERVAL_SECONDS`, at least 300s each) so it cannot land before adoption has been tried. Raise it only where the cache is a shared RWX volume and a pod really can come back for its own row |

Recurring-scan dispatcher (see
[architecture.md](architecture.md#schedule-dispatcher-leadership)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_SCHEDULER_DISPATCH_ENABLED` | `true` | Start the dispatcher thread in this replica. Safe to leave on everywhere: only the replica holding the advisory lock dispatches. Disabling it in *every* replica stops recurring scans entirely |

Endpoint inventory — snapshots submitted by the Agent (Lariska, the endpoint
inventory agent; `agent_kind = endpoint`):

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
| `OCTO_ENDPOINT_INVENTORY_RATE_LIMIT_PER_HOUR` | `12` | Accepted submissions per Agent per hour |
| `OCTO_ENDPOINT_STALE_HOURS` | `48` | Age after which a device reports `status: "stale"` |
| `OCTO_ENDPOINT_RETENTION_ENABLED` | `true` | Run the in-process retention sweep |
| `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` | `90` | Age after which a snapshot's software rows are pruned |
| `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` | `365` | Age after which software change events are deleted |
| `OCTO_ENDPOINT_RETENTION_INTERVAL_SECONDS` | `21600` | Sweep interval |
| `OCTO_ENDPOINT_RETENTION_BATCH_SIZE` | `5000` | Rows deleted per statement |

Software→CVE findings in the vulnerability lifecycle (Track E, M3 — see
[software-cve-matching.md](software-cve-matching.md#lifecycle-tracked-findings)):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_SOFTWARE_MATCH_ENABLED` | `true` | Run the in-process worker that re-matches endpoints whose latest snapshot moved and folds the result into `vulnerabilities`. Leader-locked, so it is safe to leave on in every replica. Off means software findings only move when somebody calls the refresh route |
| `OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS` | `900` | Worker tick. A ceiling on how stale a tracked software finding can be, not a scan cadence — an accepted submission wakes the worker early. It is a real ceiling only while a tick can drain the queue; when it cannot, the log says so and the budget below is what to raise |
| `OCTO_SOFTWARE_MATCH_BATCH_SIZE` | `100` | Devices per batch — per `SELECT`, per matcher run and per fold transaction. A tick takes as many batches as its budget allows, so this is a memory and statement-size knob, not the amount of work a tick does |
| `OCTO_SOFTWARE_MATCH_TICK_BUDGET_SECONDS` | `60` | How long one tick may spend draining, shared across tenants. Whatever is left is still due and is taken by the next tick. Raise it on a large estate; a tick that repeatedly logs `out of tick budget` is the signal |
| `OCTO_SOFTWARE_FINDING_MIN_SEVERITY` | *(unset)* | Severity floor for creating a tracked finding: `critical`, `high`, `medium` or `low`. Unset means no floor. Applies **on top of** the built-in rule that only a match with a published fix becomes a finding at all — raise it when the SLA dashboard is drowning in low-severity backports. Raising it does **not** close the findings that fall below the new floor: they stay open and stop being re-tracked, because a change to this variable is not a remediation anybody performed |

Artifact storage ([#336](https://github.com/onixus/Shapoclyack/issues/336)):

Scan artifacts — run directories, screenshots, generated reports, the input
files a job hands its executor — go either on the filesystem this process can
see, or in object storage. (Materialised wordlists do not: they are a scratch
copy of a row the database already holds, read by a subprocess on the pod that
wrote them.) The filesystem is the
default and behaves exactly as every release before this one did. Object
storage is what lets the API run more than one replica: artifacts on a
ReadWriteOnce volume pin every pod that mounts it to one node
([high-availability.md](high-availability.md)).

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_ARTIFACT_BACKEND` | `local` | `local` (the filesystem under `OCTO_OUTPUT_DIR` / `OCTO_STATE_DIR`) or `s3`. Anything else **refuses startup** — an operator who asked for object storage and silently got a filesystem would find out when the second replica could not see the first one's runs |
| `OCTO_ARTIFACT_S3_BUCKET` | *(unset)* | Bucket for artifacts. **Required** when the backend is `s3`; refuses startup in `prod` without it |
| `OCTO_ARTIFACT_S3_PREFIX` | *(unset)* | Key prefix inside the bucket, so one bucket can hold several installations. Per-**tenant** prefixes are [#311](https://github.com/onixus/Shapoclyack/issues/311); this one is per installation |
| `OCTO_ARTIFACT_S3_ENDPOINT_URL` | *(unset)* | Empty means AWS. MinIO, Ceph RGW and every other gateway are named here — the same variable shape as the Postgres backup CronJob's `S3_ENDPOINT_URL` |
| `OCTO_ARTIFACT_S3_REGION` | *(unset)* | Passed to boto3 as `region_name` |
| `OCTO_ARTIFACT_S3_ACCESS_KEY_ID` / `OCTO_ARTIFACT_S3_SECRET_ACCESS_KEY` | *(unset)* | Static credentials. Leave both unset on a cluster with an instance role or IRSA — boto3's own credential chain is the preferred shape, and a Secret that does not exist cannot leak |
| `OCTO_ARTIFACT_S3_SESSION_TOKEN` | *(unset)* | For temporary credentials; only read when the two above are set |
| `OCTO_ARTIFACT_S3_ADDRESSING_STYLE` | `auto` | `path` for most self-hosted gateways, `virtual` for AWS, `auto` to leave the choice to boto3 |
| `OCTO_ARTIFACT_S3_VERIFY_TLS` | `true` | `false` skips certificate verification against the gateway. A deliberate downgrade for a lab MinIO with a self-signed certificate; prefer adding the CA |
| `OCTO_ARTIFACT_PRESIGN_ENABLED` | `false` | Answer a download with a redirect to a short-lived signed URL instead of streaming the bytes through the API. Faster, and keeps large artifacts off the API's event loop — but it does not work until you have done something else, which is why it is off. The console downloads through XHR, so the redirect is a cross-origin request the browser blocks unless the **bucket sends CORS headers** for the console's origin; and an in-cluster MinIO is usually not reachable from a browser at all. Turn it on once the bucket's CORS configuration allows `GET` from the console origin |
| `OCTO_ARTIFACT_PRESIGN_EXPIRES_SECONDS` | `900` | How long a signed URL lasts. It is a bearer token for one artifact, valid without a session, so this is clamped to 30 seconds .. 1 day |
| `OCTO_ARTIFACT_CACHE_DIR` | `$OCTO_STATE_DIR/cache/runs` | Node-local working copies of run directories, on a remote backend. A cache and nothing else: losing it costs a re-fetch, never an artifact, so an `emptyDir` is the right volume |
| `OCTO_ARTIFACT_CACHE_TTL_SECONDS` | `60` | How long a working copy is served without re-checking the store. Also how long a replica can disagree with it — a run published elsewhere appears in this pod's copy within the window. `0` re-checks every time |
| `OCTO_ARTIFACT_CACHE_MAX_MB` | `2048` | Budget for the working-copy cache; the oldest copies are evicted past it, never the one being fetched. `0` disables eviction, which on an `emptyDir` means the pod eventually fills its node |

Moving an existing installation into a bucket: `scripts/migrate-artifacts.py`
copies what is on the volume under the same keys new artifacts get. It deletes
nothing, skips what is already there, and is safe to re-run.

Web screenshots (ROADMAP P4.4 / Phase 9.3):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_SCREENSHOT_RETENTION_ENABLED` | `true` | Run the in-process PNG reaper. Safe in every replica; deletes are idempotent |
| `OCTO_SCREENSHOT_RETENTION_DAYS` | `14` | Age after which `runs/*/screenshots/*.png` is deleted, from the artifact store. `0` disables the reaper. `screenshots.json` is never deleted by this worker |
| `OCTO_SCREENSHOT_RETENTION_INTERVAL_SECONDS` | `3600` | Sweep interval (floored at 60) |

Scan run artifact retention (ROADMAP #187):

| Variable | Default | Purpose |
|---|---|---|
| `OCTO_RUN_RETENTION_ENABLED` | `true` | Run the in-process scan artifact reaper. Safe in every replica; directory removals are idempotent |
| `OCTO_RUN_RETENTION_DAYS` | `30` | Age after which a run is deleted — from the artifact store, so the same setting bounds a volume and a bucket. `0` disables the reaper. Do **not** add a bucket lifecycle rule as well: it would expire runs the console still lists |
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

## Serving the API over TLS

The API terminates TLS itself when `OCTO_API_TLS_CERT` and `OCTO_API_TLS_KEY`
both point at a PEM certificate and its key. An ingress in front of it is still
the right answer for a cluster that has one; this is for the installations that
do not — a lab stand, a single node, an appliance — and for the case where a
client refuses to talk to plaintext at all.

**Both or neither.** Setting one without the other refuses to start, and so
does a path that does not exist. A listener that was meant to be encrypted and
silently is not is worse than one that does not come up, because every client
that trusted it would have been right to refuse and would not know to.

```
OCTO_API_TLS_CERT=/etc/shapoclyack/tls/tls.crt
OCTO_API_TLS_KEY=/etc/shapoclyack/tls/tls.key
```

Kubernetes probes must move to `scheme: HTTPS` with it, or they speak plaintext
to a TLS listener and the pod never becomes ready. `kubelet` does not verify
the certificate for an `httpGet` probe, so a self-signed one is fine there.

### The kind stand

`scripts/dev-up.sh` calls `scripts/dev-tls-cert.sh`, which issues a
development CA and a server certificate and puts them in the cluster as the
`shapoclyack-api-tls` Secret. The stand then answers **https** on the same port
as before — 8080 — because changing the port would mean editing
`k8s/kind-config.yaml`, and that means recreating the cluster and discarding
the Postgres volume with the inventory in it.

The certificate covers `127.0.0.1`, `localhost`, the in-cluster service names
and **the machine's LAN address**. That last one is the point: a sensor or an
Agent on another machine connects by IP, and a certificate without it verifies perfectly
from the host that issued it and fails everywhere else — the shape of bug that
is found last. It is reissued when the address changes or the certificate is
within a week of expiry, and left alone otherwise, so a rebuild does not hand
every sensor and Agent a new trust anchor.

Hand `.dev-tls/ca.crt` to whatever connects:

```bash
curl --cacert .dev-tls/ca.crt https://127.0.0.1:8080/api/health
```

An Agent (Lariska) takes it as `tls_ca_file` (`/ca <path>` for
`install-lariska.cmd`). This is what a remotely offered Agent upgrade needs:
without TLS the Agent refuses it, because the build and the sha256 that vouches
for it travel on the same connection and whoever can rewrite one can rewrite
both.

`.dev-tls/` is git-ignored. It holds a private key and a CA whose only purpose
is to be trusted by lab agents; nothing in it belongs in a repository or on a
machine that matters.
