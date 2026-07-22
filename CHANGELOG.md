# Changelog

All notable changes to the Octo-man product (hosted in Shapoclyack) are documented in this file.

## Unreleased

### Changed

- **Node.js 22 → 24** across the project: `Dockerfile.allinone`/`Dockerfile.api`'s
  `web-build` stage base image, `.github/workflows/ci.yml`'s `actions/setup-node`
  step, and a new `engines.node: ">=24"` in `web-next/package.json` (Node 24
  is the current Active LTS; Node 22 moves to Maintenance).

### Added

- **Phase 10.1 asset-level diff events** — `scanner/pipeline/report_diff.py`
  already diffed hosts/ports/vulnerabilities between two runs but only as
  three separate added/removed lists, with no cert-expiry or asset-lifecycle
  awareness and no shape a generic event bus could consume. Added a
  normalized `events: [{"kind": ...}]` list to its output: `new_asset` (from
  the existing host-added set), `new_open_port` (host/port/protocol, parsed
  via the existing `parse_endpoint` helper), and `new_cve` (the existing
  added-vulnerability dicts, tagged with a `kind`) — plus a genuinely new
  `cert_expiring` event, fired the run a host:port's `tls_posture.json`
  *first* shows a `cert_expired`/`cert_expiring_soon` issue (not on every run
  it's still present). `diff.md` gained a matching `## Events` section.
  `api/services/ch_diff.py`'s tenant-wide ClickHouse diff path (Phase 3.4,
  previously unused/dead code) gets the same `new_cve`/`new_open_port` event
  shape. `decommissioned_host` is handled separately since it's Postgres
  `Asset.status` data the scanner package can't see: `PATCH /api/assets/{id}`
  now accepts `status: "decommissioned"` (the only status an operator may set
  manually — active/stale stay system-managed) and logs the transition once,
  not on a repeat PATCH. No NATS/alerting wiring yet — event *publishing* is
  Phase 10.2.
- **Phase 9.4 business-context criticality** — `api/services/risk_scoring.py`'s
  `asset_criticality` was purely a per-vulnerability heuristic (severity/CVSS
  band, bumped for a hardcoded high-value-port set) with no awareness of
  which asset actually matters to the business. The Phase 7 `Asset` table
  already had an `asset_criticality` column scaffolded for exactly this but
  nothing wrote to it. Added `PATCH /api/assets/{asset_id}` (operator role)
  so an operator can set `asset_criticality` (0–4), `owner_email`, and
  `business_unit` directly on an asset; `api/services/ch_transform.py`'s
  `vulnerabilities_to_rows` now looks up the stored criticality per host
  (one DB read per distinct host per ingest batch, not per vulnerability row)
  and passes it into `RiskScoring.score_vulnerability` as an override that
  wins outright over the heuristic. Falls back to the existing heuristic
  unchanged whenever an asset has no criticality set, or when Postgres/tenant
  context isn't available (e.g. unit tests, no-DB deployments) — non-breaking
  by construction.

## [0.34-0722] — 2026-07-22

### Added

- **Production enrichment data pipeline (GeoIP / EPSS / KEV / CVSS4)** — the
  `shapoclyack-0.33-0507` release shipped with only tiny seed stubs for these
  four datasets (5 hardcoded IPs for GeoIP, 2–3 CVEs for EPSS/KEV) and no way
  to get real data into a running deployment. Added `scripts/fetch-epss-db.sh`
  (FIRST.org, keyless, ~350k CVEs) and `scripts/fetch-kev-db.sh` (CISA KEV,
  keyless, ~1.6k CVEs), plus `scripts/fetch-enrichment.sh` orchestrating all
  four sources (GeoIP auto-selects MaxMind GeoLite2-City when
  `MAXMIND_LICENSE_KEY` is set, else keyless DB-IP City Lite) with per-source
  non-fatal failure handling. `k8s/octo-man/overlays/enrichment` adds a shared
  ReadWriteMany PVC refreshed by a daily CronJob and mounted read-only into
  API/scan pods (plus a cold-start initContainer); `docker-compose.enrichment.yml`
  mirrors this for compose. `api/services/risk_scoring.py`'s EPSS/KEV scorer —
  previously a process-global singleton loaded once at startup with no reload
  path — now hot-reloads when the overlay files' mtimes change on disk,
  gated by `OCTO_ENRICHMENT_RELOAD_SECONDS` (default 60s) so replicas pick up
  the CronJob's refresh without a restart or per-request stat() overhead.
  `scanner/main.py` gained `OCTO_GEOIP_DATABASE` / `OCTO_CVSS4_DATABASE` env
  overrides so the shared-volume path can win over the baked-in config default.
- **Phase 9.1 tech stack fingerprinting** — `scanner/pipeline/fingerprint.py`
  (new): runs after the ports/NSE stages against endpoints already found open
  in `open_ports.txt` filtered to configurable web ports (`http_ports` /
  `https_ports`, default 80/8080/8000/8008/8888 and 443/8443) — no new port
  scan happens here, and unlike a naive add-on this issues exactly one
  streamed, size-capped (`body_max_bytes`, default 64 KiB) GET per endpoint
  rather than a second independent HTTP pass duplicating NSE's own
  `-sV`/script checks (NSE doesn't currently emit structured, parseable
  header/body data this module could reuse). That single response is
  classified against a small, intentionally non-exhaustive signature set:
  CDN/WAF detection from headers (`cf-ray` → Cloudflare, `x-akamai-*` →
  Akamai, `x-sucuri-id`/`x-sucuri-cache` → Sucuri, `x-iinfo`/`incap_ses`
  cookies → Imperva/Incapsula, `x-amz-cf-id`/`via` → CloudFront,
  `x-served-by`/`x-fastly-request-id` → Fastly) and CMS/framework detection
  from header + lightweight body/meta-tag markers (WordPress, Drupal,
  Joomla, Next.js, generic PHP). New `fingerprint.*` config block
  (`FingerprintConfig` in `config_schema.py`), opt-in and disabled by
  default like `discovery.cloud`/`discovery.asn`, with `concurrency` and
  `max_targets` hard caps — past the cap the run is flagged `truncated`
  rather than silently fingerprinting every open port. Findings are written
  to `fingerprint.json` / `fingerprint_matches.txt` and, matching
  `cloud_discovery.py`'s non-escalation principle, are never merged into
  scan scope or asset identity.
- **Phase 9.2 TLS / certificate posture** — `scanner/pipeline/tls_posture.py`
  (new): rather than adding a second scan pass or a Python TLS-handshake
  dependency (`cryptography`/`pyopenssl`), this parses the free-text `output`
  nmap's own `ssl-cert` / `ssl-enum-ciphers` NSE scripts already write into
  `nmap/tcp/*.xml` via the `nse` stage — the same XML `report.py`'s
  `_parse_nmap_xml`/`_script_record` already walk generically. `ssl-cert`
  output yields subject/issuer/SAN/signature algorithm/public key
  size/validity window, driving `cert_expired` (critical) and
  `cert_expiring_soon` (medium, within `expiring_soon_days`, default 30)
  findings, plus a `self_signed` (medium) heuristic — subject/issuer
  commonName match, case-insensitive, always tagged `heuristic` since it is
  a signal and not chain verification. `ssl-enum-ciphers` output yields
  per-TLS-version cipher lists and nmap's own letter grade, driving
  `weak_protocol` (high; SSLv2/SSLv3/TLSv1.0/TLSv1.1), `weak_cipher_grade`
  (medium; nmap grade C/D/E/F), and `weak_cipher_name` (medium; RC4/DES/3DES/
  NULL/EXPORT/anon/MD5 substrings) findings. `ssl-enum-ciphers` was added by
  name to the `vuln` and `service_specific` NSE profiles' `scripts` in
  `scanner/config/default.yaml` (cert expiry/self-signed already work off
  `ssl-cert` alone via nmap's default/safe categories; `baseline` and
  `vuln-offline` are untouched). New `tls_posture.*` config block
  (`TlsPostureConfig` in `config_schema.py`), opt-in and disabled by default,
  capped by `max_targets` (default 2000) with the run flagged `truncated`
  past the cap. Since nmap's script output is free text rather than a
  stable, versioned schema, all parsing is fail-soft (unparseable
  fields/lines are skipped or `None`, never raise). Findings are written to
  `tls_posture.json` / `tls_posture_findings.txt` and, matching
  `fingerprint.py`'s non-escalation principle, are never merged into scan
  scope or asset identity. Hostname/SAN-CN mismatch checking is out of scope
  for this module.
- **Phase 8.4 typosquat / domain monitoring** — `scanner/pipeline/domain_monitor.py`
  (new): two independent, opt-in sub-checks. (1) Typosquat/look-alike domain
  detection generates candidates of the org's seed domains across six
  generator classes (character omission, adjacent transposition,
  keyboard-adjacent substitution, doubling/de-doubling, homoglyph
  substitution, TLD swap), interleaved round-robin across classes and capped
  at `max_candidates` (default 150) per seed, then resolves each candidate's
  A/AAAA records via the already-vendored `dnsx` binary (no new dependency) —
  passive DNS only, same risk class as `ct.brute_force`'s wordlist brute
  force. A candidate that resolves is reported as a `typosquat_registered`
  finding (someone else has registered it); these domains are never owned by
  the org and are never merged into scan scope. (2) A dangling-CNAME /
  subdomain-takeover heuristic resolves the CNAME chain for the org's own
  already-in-scope FQDNs and flags targets whose CNAME matches a curated,
  non-exhaustive list of commonly-abused service suffixes (`github.io`,
  `herokuapp.com`, `s3.amazonaws.com`, `azurewebsites.net`, `cloudfront.net`,
  etc.) AND have no A/AAAA record of their own — a conservative "looks
  abandoned" gate. This only flags the heuristic pattern match plus
  non-resolution; it never attempts to confirm an actual takeover (no
  requests to the third-party service, no claiming/registering anything),
  matching `cloud_discovery.py`'s findings-only, non-escalating posture. New
  `discovery.domain_monitor.*` config block (`DomainMonitorConfig` in
  `config_schema.py`: `enabled`, `domains`, `typosquat_enabled`,
  `dangling_cname_enabled`, `max_candidates`, `concurrency`,
  `timeout_seconds`, `retries`), disabled by default, runs as its own
  `domain_monitor` pipeline stage right after `resolve` so the dangling-CNAME
  check sees the final in-scope FQDN list. Findings are written to
  `domain_monitor.json` / `domain_monitor_findings.txt`.
- **Routine dependency/image maintenance bump.** Python pins: `PyYAML`
  6.0.2→6.0.3, `pydantic` 2.10.6→2.13.4, `nats-py` 2.9.0→2.15.0 (all in
  `requirements.txt`); `fastapi` 0.115.12→0.139.2, `uvicorn` 0.34.2→0.51.0,
  `PyJWT` 2.10.1→2.13.0, `cryptography` 44.0.2→49.0.0, `python-multipart`
  0.0.20→0.0.32, `clickhouse-connect` 0.8.17→1.5.0, `SQLAlchemy`
  2.0.36→2.0.51, `alembic` 1.14.0→1.18.5, `psycopg` 3.2.3→3.3.4 (all in
  `requirements-api.txt`); `pytest` 9.0.3→9.1.1, `ruff` 0.15.20→0.15.22 (in
  `requirements-dev.txt`). `fpdf2` and `httpx` were already at PyPI latest
  (2.8.7 / 0.28.1) and left as-is. `geoip2` (4.8.1) and `bcrypt` (4.2.1) were
  left pinned: their latest releases (5.3.0 and 5.0.0 respectively) cross a
  major version boundary, which is out of scope for a routine maintenance
  bump. Full suite re-verified at 224 passed / 28 skipped after the bump
  (unchanged from the pre-bump baseline), plus a clean `ruff check` and
  `compileall` pass. `clickhouse-connect` 1.x is a major bump from the
  previous 0.8.17 pin; it installed and the full test suite passed against
  it, so it was kept — no clickhouse-connect-specific behavior surfaced in
  tests, but this is worth a closer look at the next opportunity given it
  crosses a major version.
- **web-next npm dependencies** — ran `npm update`, which bumped several
  `@radix-ui/*` packages, `@tanstack/react-query`, and their transitive
  dependencies to the latest versions satisfying their existing `package.json`
  semver ranges (only `package-lock.json` changed; no `package.json` ranges
  needed adjusting). Left `next` (14.2.35), `react`/`react-dom` (18.x),
  `date-fns` (3.6.0), `eslint` (8.x), `tailwindcss` (3.x), and `typescript`
  (5.x) pinned as-is: their available updates (`next`/`react`/`react-dom` 16.x
  / 19.x, `date-fns` 4.x, `eslint` 10.x, `tailwindcss` 4.x, `typescript` 7.x)
  are all major-version jumps, out of scope for this routine bump. `npm run
  lint` and `npm run build` both pass clean after the update.
- **Docker image / tool pins left unchanged.** Attempted to verify newer
  `dnsx`/`naabu` releases (projectdiscovery) and a newer `python:3.12-slim`
  digest, but this environment's egress policy blocks `github.com` /
  `api.github.com` (403 from the pre-configured agent proxy) and the Docker
  Hub CDN blob host used by `docker manifest inspect` (also 403), and no
  Docker daemon is available to `docker pull`/`docker build` for an
  independent check. Per the "never fabricate a checksum/digest" rule, the
  `DNSX_VERSION`/`NAABU_VERSION` pins, their per-arch sha256 checksums, the
  `python:3.12-slim` base image digest, and the `NMAP_VULNERS_REF`/
  `VULSCAN_REF` NSE script commit pins are all left untouched in `Dockerfile`,
  `Dockerfile.api`, and `Dockerfile.allinone`.

## [0.33-0507] — 2026-07-21

### Added

- **Phase 8.3 cloud resource discovery** — `scanner/pipeline/cloud_discovery.py`
  (new): org tokens derived from scan domains × a built-in wordlist
  (`scanner/data/wordlists/bucket-names-small.txt`) → candidate bucket/container
  names, checked via unauthenticated HEAD/GET against S3, GCS, and Azure Blob's
  public REST endpoints (`discovery.cloud`, opt-in; `azure` excluded from the
  default `providers` list — its two-level namespace and GET-only list API make
  it the least reliable of the three). Hard-capped at `max_candidates` (default
  500) and `concurrency` (default 10), more conservative than
  `ct.brute_force`'s DNS-query defaults since this hits shared third-party
  cloud infrastructure. Findings are reported (`cloud_discovery.json` /
  `cloud_discovery_public.txt`) and never merged into scan scope — a
  discovered bucket is a finding, not a port-scan target. The original
  roadmap line's "public cloud ranges by org tag" half was dropped: AWS/GCP
  publish IP ranges by service+region, not by customer org, so there's no
  honest way to attribute a cloud IP to a specific organization.
- **Web UI v2 full cutover (Phase 6.6)** — legacy Vite dashboard (`web/`) removed
  from the repo; `web-next/` is now the only web UI. CI's `web` job was still
  building/caching `web/` and never built `web-next/` at all — fixed to
  `npm ci && npm run lint && npm run build` inside `web-next/`. The Assets page
  (`web-next/src/app/(dashboard)/assets/`) previously aggregated the *latest
  run's* hosts/ports/vulns client-side (leftover Phase 6 code) despite being
  named "Assets" — it now calls the real Phase 7 cross-run registry
  (`GET /api/assets`, `GET /api/assets/{id}`) with status filtering and an
  identifier/tags detail view. Removed now-dead `buildAssetRows` and friends
  from `lib/run-data.ts`, plus the unused `diff-badge.tsx` and `mock-data.ts`.
  `Dockerfile.api`/`Dockerfile.allinone` already built `web-next/` exclusively
  before this change — only CI and the repo tree were still lagging.
- **Phase 8.1–8.2 outside-in discovery** — `scanner/pipeline/asn_discovery.py`
  (new): seed domain → resolved IP → ASN → announced prefixes via RIPEstat's
  free keyless API (`discovery.asn`, opt-in), hard-capped at `max_total_ips`
  (default 4096) since a single ASN can span far more than one org's
  infrastructure — results are flagged `truncated` rather than silently
  scoping up. `scanner/pipeline/hostnames.py` gains an `otx` (AlienVault OTX
  passive DNS) provider alongside crt.sh/Cert Spotter, plus an opt-in
  concurrency/candidate-capped wordlist brute-force pass
  (`discovery.ct.brute_force`, built-in `scanner/data/wordlists/subdomains-small.txt`).
  Both stages are checkpoint/resume-aware and merge into scan scope only when
  explicitly enabled. Adds `httpx` as a scanner-side dependency (previously
  API-only) for RDAP/BGP calls.
- **`api/app.py` lazy app construction** — the module-level `app` singleton is
  now built on first attribute access (PEP 562 `__getattr__`) instead of at
  import time. Phase 7 made `create_app()` fail fast without a reachable
  Postgres; building `app` eagerly meant a bare `from api.app import
  create_app` (every API test file) required Postgres just to import the
  module. `uvicorn.run("api.app:app", ...)` / `python -m api` are unaffected —
  they still resolve `app` (and its fail-fast check) the same way.
- **Phase 7 asset inventory (Postgres PRIMARY_DB)** — first SQL database in the
  repo (SQLAlchemy + Alembic, `api/db/`). `tenants`/`provisioning_keys` moved
  off JSON files onto Postgres behind the same `api/services/tenants.py`
  function signatures (zero caller changes); `resolve_provisioning_key` is now
  O(1) via an indexed `key_lookup` prefix instead of scan-and-bcrypt-verify-all.
  New cross-run asset registry (`assets`/`asset_identifiers`/`asset_tags`) with
  stable identity via `scanner/pipeline/asset_identity.py` (tenant+IP or
  tenant+FQDN sha256 keys), `first_seen`/`last_seen`/`status` lifecycle
  (`OCTO_ASSET_STALE_DAYS`), and new `GET /api/assets` / `GET /api/assets/{id}`
  endpoints — hooked from both local-mode and agent-upload scan completion in
  `api/services/jobs.py`. **Postgres is a hard dependency, not opt-in** like
  NATS/ClickHouse — API startup fails fast if `OCTO_POSTGRES_URL` is empty.
  `k8s/octo-man/base/postgres/` + `docker-compose.postgres.yml` mirror the
  ClickHouse deployment pattern; an `initContainer` runs `alembic upgrade head`
  before API replicas start.
- **Phase 1 NATS retention + HA** — JetStream `JOBS`/`INGEST` streams now bound
  storage by default (`OCTO_NATS_JOBS_MAX_AGE_SECONDS`,
  `OCTO_NATS_INGEST_MAX_AGE_SECONDS`, `OCTO_NATS_INGEST_MAX_BYTES`; applied on
  redeploy via `update_stream`, not just first creation); `k8s/octo-man/base/nats/`
  ships a cluster-ready config (safe at `replicas=1`) — scale to 3 nodes with
  `examples/nats-ha-patch.yaml` + `OCTO_NATS_STREAM_REPLICAS=3` for JetStream R3
- **Phase 1 NATS harden** — `docker-compose.nats.yml` auto-wires `OCTO_NATS_URL` + NATS
  health wait; agent uses a long-lived JetStream pull session; live broker tests
  (`tests/test_nats_live.py`, CI starts `nats:2.10.24` with JetStream)
- **Phase 3 ClickHouse compose auto-wire** — `docker-compose.clickhouse.yml` sets
  `OCTO_CLICKHOUSE_URL` + health wait for the NATS→CH ingest worker
- **Phase 3 risk scoring (mvp-1)** — ClickHouse vuln rows fill `epss_score`,
  `asset_criticality`, `exploit_active`, `cisa_decision`, `contextual_score` via
  `api/services/risk_scoring.py` (optional EPSS/KEV JSON overlays; prefers CVSS4)
- **Phase 6 aio Web UI v2** — `web-next` static export (`output: "export"`) is built into
  `Dockerfile.allinone` / `Dockerfile.api` (`out/` → `/app/web/dist`); FastAPI serves
  `/_next` and directory `index.html` routes; run detail at `/runs/view?runId=`
- **Phase 6 run detail** — `web-next` `/runs/view?runId=` with hosts / ports / severity
  findings + diff counts; Runs table links into detail
- **Phase 6 live Dashboard / Assets** — KPIs and inventory from latest run API
  (`runs` / `hosts` / `ports` / `vulnerabilities`)
- **Phase 6.4 (Web UI v2 API wire)** — `web-next` JWT login + AuthGate; live
  React Query pages for Runs / Agents / Jobs / Tenants (create + provisioning key);
  Axios client helpers; `/api` rewrite proxy for local Next dev
- **Phase 5 (advanced discovery & notifications)** —
  - Cloudflare DNS zone import + unproxied A/AAAA misconfig findings
    (`discover.import_cloudflare_dns_targets`, `OCTO_CLOUDFLARE_API_TOKEN`)
  - Async CT subdomain discovery via crt.sh / Cert Spotter (`hostnames.discover_ct_subdomains`)
  - SMTP alerts via local Maddy/relay with optional DKIM TXT + PTR pre-send checks
    (`alerts.smtp`, `OCTO_SMTP_*`); example `maddy-compose.example.yaml`
- **Phase 4 (agent topology spread + VPA)** — `base/agents/` Deployment with
  zone + hostname `topologySpreadConstraints`; VPA Auto (`agent-vpa.yaml`);
  opt-in overlay `overlays/agents` (replicas 3, API `OCTO_JOB_EXECUTION_MODE=agent`);
  example YAML updated; agents stay out of default base apply
- **Phase 3 (ClickHouse ingest)** — NATS→CH worker (`ch_ingest_worker`), transforms
  archives into `shapoclyack_vulnerabilities` + `shapoclyack_open_ports`;
  `OCTO_CLICKHOUSE_URL` / `OCTO_CH_INGEST_ENABLED`; CH diff helpers (`ch_diff.py`);
  health reports NATS/CH/worker stats
- **API gateway ingest** — publish validated results to `ingest.results.{tenant_id}`
  (plus legacy `ingest.raw_results`); NATS bus starts on FastAPI lifespan
- **`POST /api/v1/auth/exchange`** — provisioning key → 2h agent JWT (`tenant_id` + `agent_id`);
  `api/core/security.py` (`API_SECRET_KEY` / `OCTO_JWT_SECRET`)
- **Deps:** `cryptography`, `clickhouse-connect` (ready for Phase 3 queries)
- **Compose:** optional `clickhouse` profile + local `init-local.sql`
- **Phase 2 (MSSP tenancy)** — JSON-backed tenants + provisioning keys; agents exchange
  keys for short-lived JWTs (`tenant_id` claims); cross-tenant claim/upload denied;
  NATS messages carry `tenant_id` headers; NetworkPolicy + ExternalSecrets examples
- **Phase 1 (NATS JetStream)** — opt-in via `OCTO_NATS_URL`:
  - k8s StatefulSet/Services `octo-man-nats` (+ client Service)
  - API publishes agent jobs to `jobs.scan` and raw archives to `ingest.raw_results`
    (JetStream `Nats-Msg-Id` idempotency); filesystem extract unchanged for UI
  - Agent pull consumer (durable `octo-agents`) when NATS URL set; HTTP claim remains default
  - Compose profile `nats`; example patches under `k8s/octo-man/examples/nats-*.yaml`

### Changed

- Promoted discovery completeness knobs from `discovery-bench-realistic` into
  prod configs (`scanner/config/default.yaml`, `k8s/octo-man/base/config/k8s.yaml`):
  `discovery.verify` on, `adaptive.wave2_rate: 2500`, `batching.ipv4_prefix: 24`,
  smaller `max_targets_per_batch`; default `balanced.discover_rate` 6000 → 4000
- Documented platform evolution roadmap ([ROADMAP.md](ROADMAP.md)): NATS JetStream,
  MSSP multi-tenancy, ClickHouse analytics, K8s autoscaling, Cloudflare/CT/Maddy,
  Shapoclyack Web UI v2 (`web-next/` — Next.js 14)
- Updated [octo_man.html](octo_man.html) roadmap infographic to match

## [0.33] — 2026-07-16

GitHub release / tag: [`shapoclyack-0.33`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.33).

### Added

- **CVSS v4 enrichment** (`enrichment.cvss4`): local CVE → CVSS 4.0 JSON map
  (`scanner/data/cvss4/`); refresh with `scripts/fetch-cvss4-db.py`
- **GeoIP enrichment** (`enrichment.geoip`): country/city per host via MaxMind GeoLite2
  `.mmdb` or JSON overlay; always export `alive_hosts.json` / `geoip.json`
- **Run results explore UI**: click **Alive hosts** / **Open ports** to list targets
  (with GeoIP) and port aggregation; filter findings by host or port
- API endpoints `GET /api/runs/{id}/hosts` and `GET /api/runs/{id}/ports`
- **Severity dashboard** in the Web UI (grouped, scrollable vulnerability lists)
- Test fixture `tests/data/geoip/GeoIP2-City-Test.mmdb` for the `.mmdb` reader path

### Changed

- **Container images are Shapoclyack-scoped** and no longer published under the legacy
  `ghcr.io/onixus/octo-man*` package names:
  - `ghcr.io/onixus/shapoclyack-aio`
  - `ghcr.io/onixus/shapoclyack-scanner`
  - `ghcr.io/onixus/shapoclyack-api`
- Compose service renamed to `shapoclyack`; Dockerfiles carry OCI source labels for this repo
- Vulnerability API backfills GeoIP from `geoip.json` / `alive_hosts.json` when missing on a finding

### Images

| Image | Tag |
|-------|-----|
| `ghcr.io/onixus/shapoclyack-aio` | `shapoclyack-0.33`, `latest` |
| `ghcr.io/onixus/shapoclyack-scanner` | `shapoclyack-0.33`, `latest` |
| `ghcr.io/onixus/shapoclyack-api` | `shapoclyack-0.33`, `latest` |

### Upgrade notes

- Pull `shapoclyack-*` images (do not use bare `ghcr.io/onixus/octo-man`)
- Update any local `image:` overrides to the new names
- For production GeoIP: `MAXMIND_LICENSE_KEY=… ./scripts/fetch-geoip-db.sh` and point
  `enrichment.geoip.database` at the `.mmdb`
- Existing scan runs without GeoIP fields need a new scan after enrichment is configured

## [0.3.2.1] — 2026-07-16

All-in-one release: Web UI can start scans by default.

### Added

- **All-in-one image** (`Dockerfile.allinone`): scanner tools + API + React UI + agent client
- **`docker-compose.yml`**: one-command local stack with Jobs UI scan start enabled
- Kustomize overlay `overlays/api-readonly` for the thin results-only API image

### Changed

- Default API Deployment uses **aio** image with `OCTO_ALLOW_SCAN_START=true`, writable PVC mounts, `NET_RAW`, and optional `scan-targets` inputs
- GHCR publish matrix builds scanner, api, and aio (tag matching supports `v0.3.2.1`)
- Phase 3 items (DefectDojo, PDF, remote agents, scan targets / UDP ports) are included in this release train

### Images (historical; superseded by `shapoclyack-*` in 0.33)

| Image (historical) | Tag |
|-------|-----|
| `ghcr.io/onixus/octo-man-aio` | `0.3.2.1`, `latest` |
| `ghcr.io/onixus/octo-man-api` | `0.3.2.1`, `latest` |
| `ghcr.io/onixus/octo-man-scanner` | `0.3.2.1`, `latest` |

### Upgrade notes

- Preferred local path: `docker compose up --build` → http://localhost:8080
- Preferred cluster path: `kubectl apply -k k8s/octo-man/overlays/dev` (aio + UI job start)
- For results-only API (no local scans): `kubectl apply -k k8s/octo-man/overlays/api-readonly`
- Change default API demo passwords / set `OCTO_JWT_SECRET` before any real use

## [0.3.0] — 2026-07-16

First Shapoclyack-hosted product release after Phase 1–2 and the Kubernetes cutover.

### Added

- **Phase 1 — quick wins**
  - Report diffs between runs (`diff.json` / `diff.md`, `--compare-run-id`, `--no-diff`)
  - Slack / Telegram alerts (`alerts.*`, `--notify`, env credentials)
  - In-process scheduler (`python -m scanner.scheduler`) for labs
- **Phase 2 — interface & API**
  - FastAPI control plane (`api/`) with JWT RBAC (`viewer` / `operator` / `admin`)
  - React dashboard (`web/`) served from the API image
  - Run catalog, vulnerabilities, diffs, artifacts, optional scan jobs
- **Kubernetes primary runtime**
  - kustomize under `k8s/octo-man` (Job, CronJob, API Deployment/Service, PVC)
  - `dev` / `prod` overlays; Secrets and Ingress examples
  - `./k8s/scripts/validate-kustomize.sh` + CI kustomize job

### Changed

- Retired `docker-compose.yml` as the deploy path (Dockerfiles remain for image builds)
- Scanner and API container UIDs pinned to `1000` for Kubernetes `securityContext`
- Restored GHCR publish workflow for both product images
- Extracted reusable composite action `.github/actions/synthetic-load-test` for CI / heavy load workflows

### Images (historical)

| Image | Tag |
|-------|-----|
| `ghcr.io/onixus/octo-man` | `0.3.0`, `0.3`, `0`, `latest` |
| `ghcr.io/onixus/octo-man-api` | `0.3.0`, `0.3`, `0`, `latest` |

### Upgrade notes

- Deploy with `kubectl apply -k k8s/octo-man/overlays/dev` (or `prod`)
- Change default API demo passwords / set `OCTO_JWT_SECRET` before any real use
- Prefer cluster `CronJob` over the in-process scheduler

## [0.2.1] — 2026-07-15

Inherited from pre-Shapoclyack Octo-man history (NSE `-Pn` fix, docs/infographic).
