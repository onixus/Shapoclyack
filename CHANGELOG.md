# Changelog

All notable changes to Shapoclyack are documented in this file.

## Unreleased

### Added

- **Finding taxonomy and risk-priority explanation** (scoring model `mvp-1` →
  **`mvp-2`**; closes the ROADMAP [P4](ROADMAP.md) "risk-priority explanation"
  item). Pulse labels every finding as observation or hypothesis, and
  Shapoclyack was throwing those labels away at the adapter boundary.
  - `octo.cve.v1` gained `finding_class`, `confidence`,
    `requires_confirmation`, `evidence`, `ruleset_version`, `epss`, and
    `in_kev`, all carried into `vulnerabilities.json`.
  - **CVE-less findings are no longer dropped.** `exposure` (reachable
    service, no CVE claimed) and `tls` findings used to be discarded by the
    parser; they now survive with a synthetic `script_id`
    (`pulse:<class>:<port>:<slug>`) so each stays a distinct row in the report
    dedupe and in ClickHouse instead of collapsing per host.
  - Scoring prefers the finding's own EPSS/KEV data over the local
    `OCTO_EPSS_DATABASE` / `OCTO_KEV_DATABASE` overlays, whose committed
    defaults are seed stubs. The overlays still cover nuclei/NSE findings.
  - Unconfirmed findings (`exposure`, `keyword_cve`, or anything the scanner
    marks `requires_confirmation`) are discounted by their confidence and
    capped below the `Act` decision, so an unverified keyword hit no longer
    outranks a confirmed, KEV-listed vulnerability.
  - Every finding now carries `contextual_score`, `cisa_decision`, and a
    one-line `risk_explanation`; `GET /runs/{id}/vulnerabilities` returns them
    (and orders by score), and the run's Findings tab renders the score,
    decision, explanation, and `unconfirmed` / `KEV` badges.

  **Expected change in numbers:** `potential_vulnerabilities` rises on Pulse
  runs, because exposures that were silently discarded are now reported. The
  new `summary.json` key `unconfirmed_findings` breaks out how much of the
  total is hypothesis rather than confirmed vulnerability. No ClickHouse
  schema change — the existing `cve_id` column already falls back to
  `script_id` for findings without a CVE.

- **Tenant-aware IAM — completed** (ROADMAP [P0](ROADMAP.md)) — runs are the
  last resource to gain tenant scoping, and the console gained a tenant
  switcher.
  - The API tags each completed run with its owning tenant by writing
    `tenant.json` into the run directory — from `_run_job` for local execution
    and from `complete_job` for agent uploads (the latter already wrote the
    file; both paths now share `runs_service.write_run_tenant`).
  - `GET /api/runs` and every run sub-resource (`hosts`, `ports`,
    `vulnerabilities`, `diff`, `artifacts/*`, `download/*`) moved from
    `require_role` to `require_tenant` and are filtered by that marker. A run
    in another tenant answers `404`, matching jobs/assets/schedules. A platform
    admin who names no tenant keeps the fleet-wide view.
  - `RunSummary`/`RunDetail` now carry `tenant_id`.
  - Web UI: a tenant switcher in the header (`TenantSwitcher`) drives an
    `activeTenant` in the auth store; an axios request interceptor attaches it
    as `tenant_id` to every call that does not already name one, and switching
    clears the React Query cache. The Endpoints page dropped its own
    page-local tenant selector in favour of the global one.

  **Compatibility:** a run without the marker reads as belonging to `default`,
  so pre-existing runs and runs produced by invoking `scanner.main` outside the
  API stay visible to the default tenant. There is no backfill — write
  `tenant.json` by hand for historical runs that belong to a customer tenant.

## [0.39-0805] — 2026-08-05

### Changed

- **Retired the legacy `octo-man` product name.** Nothing of that product
  remained apart from its name, so it is gone from code, manifests, docs, and
  runtime strings: loggers (`octo-man.*` → `shapoclyack.*`), the FastAPI title,
  NATS/agent client names, scanner User-Agents (`shapoclyack-octo-man/*` →
  `shapoclyack/*`), DefectDojo product/engagement/test defaults, the PDF report
  title, alert subjects, the Web UI sidebar, and `octo_man.html` →
  `shapoclyack.html`. Kubernetes moved from `k8s/octo-man/` to
  `k8s/shapoclyack/` with every `octo-man-*` object and
  `app.kubernetes.io/{name,part-of}` label renamed, and the Postgres database
  is now `shapoclyack`.
  **Operator action, existing clusters only:** resource and database renames
  create new objects, so run the one-time migration in
  [k8s/README.md](k8s/README.md#upgrading-a-cluster-deployed-before-the-octo-man--shapoclyack-rename)
  (`ALTER DATABASE octo_man RENAME TO shapoclyack;` plus an orphan-cascade
  delete of the old objects). Self-hosted installations need nothing: the
  sqlite default is now `shapoclyack.db` but falls back to an existing
  `octo_man.db`. **Deliberately unchanged** (not product naming, and renaming
  them would break running deployments): the `OCTO_*` environment variables,
  the `octo_*` Prometheus metric names, the `network-scan` namespace, the
  `octo` database user, and the already-Shapoclyack GHCR image names.
  DefectDojo exports land under the product name `Shapoclyack` from now on —
  set `defectdojo.product_name` back to `Octo-man` if you need findings to keep
  flowing into the existing product.

### Added

- **Tenant-aware IAM — foundation** (ROADMAP [P0](ROADMAP.md)) — new
  `user_tenants` table (migration `0007_user_tenants`) binds console usernames
  to tenants with a per-tenant role, managed by a platform admin via
  `GET/PUT/DELETE /api/tenants/{tenant_id}/members[/{username}]`. Every
  tenant-scoped route now derives its tenant from the authenticated user
  instead of trusting the `tenant_id` query parameter, which can only select
  among tenants the caller holds; anything else is `403`. Covers assets,
  jobs, agents, schedules, and endpoint inventory, including the request
  bodies of `POST /jobs` and `POST /schedules`. Cross-tenant lookups of a
  known id answer `404` rather than `403` so the id's existence stays
  private. `GET /api/auth/me` now returns `tenants`/`default_tenant`/
  `is_platform_admin`, and `GET /api/tenants` lists only the caller's tenants
  so an MSSP customer list cannot leak to one customer's operator.
  **Behaviour change**: a user with memberships is confined to them; a user
  with none keeps pre-P0 access to the `default` tenant, so existing
  single-tenant installations are unaffected. Runs and their artifacts are
  **not** scoped yet — run directories carry no tenant — and remain visible to
  any authenticated viewer.

- **Server-side pagination on every list endpoint** (ROADMAP
  [P3.2](ROADMAP.md)/[P3.3](ROADMAP.md)) — `GET /api/runs`, `/jobs`, `/agents`,
  `/assets`, and `/schedules` now take `offset`/`limit`/`q`/`sort`/`order` and
  answer with `{items, total, offset, limit, has_more}`. **Breaking**: these
  five routes previously returned a bare JSON array; clients must read
  `.items`. Filtering happens before `total` is counted, and an unknown `sort`
  falls back to the resource default rather than erroring. `jobs`/`agents`/
  `schedules` were fully unbounded before this. Asset listing pushes the
  identifier search into an EXISTS subquery, so `q` no longer post-filters an
  already-truncated page; run listing slices directories first and reads
  `run_meta.json`/`summary.json` for the requested page only.
- Web UI tables (assets, runs, jobs, agents, schedules, reports) drive paging,
  search, and sorting from the server instead of loading whole lists and
  filtering in the browser; search is debounced and any filter/sort change
  rewinds to the first page. The dashboard keeps aggregating and now shows the
  exact asset `total` alongside a note when its posture chart samples the cap.
- **Endpoint inventory retention, staleness, and operations (Agent_plan.md S9)**
  — an in-process sweep (`api/services/endpoint_retention.py`, started from the
  API lifespan like the schedule dispatcher) prunes `endpoint_software_items`
  for snapshots older than `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS`
  (90d, snapshot summary rows kept) and deletes `endpoint_software_changes`
  older than `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` (365d). Deletes
  are tenant-scoped, batched, and idempotent; a device's current snapshot is
  never pruned, since it backs the next submission's software diff.
- Server-side endpoint staleness (`OCTO_ENDPOINT_STALE_HOURS`, default 48):
  devices now carry a derived `status` (`active`/`stale`), read routes accept
  `device_status=` as a filter, and the Web UI uses the server value instead of
  recomputing the threshold client-side.
- Hard request-body cap on `POST /api/endpoint/inventory`
  (`OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES`, default 15 MiB) enforced from
  `Content-Length` before JSON parsing — oversized bodies get `413`, bodies
  without `Content-Length` get `411` and are never buffered.
- Endpoint-inventory Prometheus series (submission outcomes, ingest latency,
  entries per snapshot, change events, active/stale device gauge, retention
  deletions and sweep duration) plus an "Endpoint Inventory & Retention" panel
  on the System page and `endpoint_inventory` in `GET /api/system`.
- Migration `0006_endpoint_fk_cascade` — the endpoint FK chain now cascades from
  `tenants` (and nulls `asset_id` when an asset is deleted), so a future
  tenant-offboarding flow removes endpoint data without bespoke deletion code.
- **Cross-device software-changes feed** ([#98](https://github.com/onixus/Shapoclyack/issues/98)
  Phase 3) — `GET /api/endpoint/changes` returns recent installed/removed/
  updated software events across all endpoints for a tenant (joined with
  device hostname/asset), and the `/endpoints` page now shows a "Recent
  software changes" panel above the device table. Completes the one item
  left open from the Phase 3 endpoint-inventory plan (per-device history
  already existed on the asset view; this adds the global view).

### Changed

- **Nmap removed from default published images** ([#97](https://github.com/onixus/Shapoclyack/issues/97)
  Phase 1) — `docker-publish.yml` now builds the default `shapoclyack-scanner`/
  `-aio` GHCR images with `INSTALL_NMAP=0`; Pulse is already the default
  `service_probe.backend`, so this closes the actual NPSL redistribution risk
  in the distributed artifacts (previously only the config default was
  Pulse-first — the published images still bundled Nmap). A separate
  `-nmap` tag is published alongside for anyone who wants classic NSE.
- `docker-publish.yml` no longer hardcodes `PULSE_VERSION` as a build-arg —
  it now always follows the Dockerfiles' own `ARG PULSE_VERSION` default, so
  a Dockerfile version bump can't be silently overridden by a stale CI pin
  (this is what happened with the v0.2.7 bump below before this fix).

### Fixed

- **Pulse v0.2.7** — pin `PULSE_VERSION=v0.2.7` (fixes the `CVE-2024-6387`
  regreSSHion banner regex, which only matched OpenSSH 9.0-9.5 and silently
  missed the rest of the officially affected range, 8.5p1-9.7p1).
- **Endpoint software-change events had a blank name for removals** —
  `ingest_snapshot`'s diff only looked up display names from the *new*
  snapshot's software list, which doesn't contain removed items; both
  `GET /endpoint/devices/{id}/changes` and the new `/endpoint/changes` feed
  showed an empty name for every `removed` event. Now looked up from the
  previous snapshot instead. Found while building the changes feed above.

## [0.38-0729] — 2026-07-29

### Added

- **Pulse v0.2.6** — pin `PULSE_VERSION=v0.2.6` (fixes `pulse --cve` silently
  missing `version_cve` matches for services on non-standard ports; adds a
  Windows CLI build plus a native Windows GUI, `pulse-gui`, with the same
  glass-neon look as the macOS app).
- **Pulse v0.2.3** — pin `PULSE_VERSION=v0.2.3` (fingerprints/KEV feed/UDP + macOS GUI release assets).
- **Pulse v0.2.2** — pin `PULSE_VERSION=v0.2.2` (H2: HTTP probes, KEV/scope, weak TLS; `tls_posture` prefers `pulse/tls.json`).
- **Pulse service probe backend (opt-in)** — `service_probe.backend`:
  `nmap` (default) | `pulse` | `hybrid`. When `pulse`/`hybrid`, open ports
  from naabu are enriched via [Pulse](https://github.com/onixus/GenDec)
  (OS/banner/CVE → `services.json` / `os.json`). Override with
  `OCTO_SERVICE_BACKEND`. Scanner and all-in-one images multi-stage-build
  Pulse and install `/usr/local/bin/pulse` with raw-socket caps. System
  status lists `pulse --version`. Docs: `docs/pulse-backend.md`.
- **Pulse/Nmap shadow diff** — `service_probe.shadow` or `OCTO_PULSE_SHADOW=1`
  runs both backends and writes `diff_pulse_nmap.json` (endpoint Jaccard +
  OS family agreement). With `backend: nmap`, report still prefers nmap XML;
  Pulse CVEs can still attach when present.
- **TLS posture probe fallback (Phase 4)** — when nmap has no
  `ssl-cert`/`ssl-enum-ciphers` output, `tls_posture` can handshake open TLS
  ports via stdlib `ssl` (`probe_fallback`, default on). Writes
  `tls_probe.json` and fills `tls_posture.json` with `source: pulse-tls-probe`
  (cert expiry, self-signed heuristic, weak negotiated protocol/cipher).
- **Pulse default service probe (Phase 4.1)** — `service_probe.backend`
  defaults to `pulse` (OS/banner/CVE; no nmap NSE). Per-profile Pulse knobs
  under `profiles.<safe|balanced|fast>.pulse.*`. Full NSE via
  `backend: nmap|hybrid` and `nse_profiles.vuln_legacy`. `--skip-nse` remains
  ports-only L1 (skips Pulse and nmap).
- **CVE stack without nmap-vulners (Phase 4.2)** — default path is Pulse
  `--cve` + Nuclei (now **enabled by default**) + CVSS4 enrichment.
  Vulns tagged `source: pulse|nuclei|nmap-nse`; host:port:CVE deduped in
  reports. nmap-vulners only via `vuln_legacy` when backend is nmap/hybrid.
- **Optional nmap (Phase 5)** — `INSTALL_NMAP=0` build arg for lean
  Pulse-only images; `run_nse` skips cleanly if nmap is missing. System
  status marks nmap optional and surfaces `service_backend`. UI: “Ports
  only (skip service probe)” and “Legacy nmap NSE profiles”.
- **Pulse v0.2.1** — pin `PULSE_VERSION=v0.2.1` (findings taxonomy H1, TLS, fingerprint).
- **Pulse from GenDec releases** — Docker installs Pulse via
  `PULSE_VERSION` GitHub Release assets (no vendored Rust tree). CI uses
  optional `GENDEC_READ_TOKEN` for private GenDec. See GenDec
  `docs/release.md`.

## [0.37-0727] — 2026-07-27

### Fixed

- Shut down the dedicated NATS event loop cleanly so pending client tasks do not
  survive until pytest closes the loop.
- **NSE host batching could fail an entire group over one slow host** —
  `nse_hosts_per_scan` (nmap processes now scan one host each instead of
  batching up to 8 per invocation, `scanner/config/default.yaml` and
  `k8s/shapoclyack/base/config/k8s.yaml`). Bundling several hosts into one nmap
  invocation meant they shared the `nse_timeout_seconds` budget (hard-capped
  at 600s); a single host doing heavy `vulners`/`ssl-enum-ciphers` NSE work
  could blow that shared budget and fail every other host in the group, even
  though they would have finished fine scanned individually.
- Accepted `GHSA-r277-6w6q-xmqw` (kin-openapi fail-open auth bypass, pulled in
  transitively by the `nuclei` binary's OpenAPI spec parser) as a documented
  Trivy CI exception — no nuclei release has shipped the fix yet, and the
  vulnerable code path (`openapi3filter.ValidationHandler`) is unreachable in
  how nuclei actually uses the dependency.

### Changed

- Refactored the documentation into task-oriented guides under `docs/`, reduced
  the root English and Russian READMEs to stable project entry points, and
  aligned the Web UI, Kubernetes, roadmap, security, and endpoint-inventory
  documents with the current platform.
- Added a documented, privacy-safe interface screenshot inventory and
  reproducible capture procedure in `docs/ui.md`.

### Added

- **Endpoint inventory ingestion (Lariska agent integration, S1-S7)** — a new
  `POST /api/endpoint/inventory` contract (schema v1) lets the separate
  Lariska endpoint agent submit device identity/OS metadata and installed-
  software snapshots, authenticated via the existing agent-JWT/legacy-token
  `require_agent` dependency and kept fully independent of the network-scan
  agent protocol (`ingest.raw_results`, job claim/upload). New Postgres tables
  (`endpoint_devices`, `endpoint_identifiers`, `endpoint_inventory_snapshots`,
  `endpoint_software_items`, `endpoint_software_changes`, migration `0004`)
  back idempotent snapshot ingestion (natural-key digest, replay-safe),
  tenant-scoped asset reconciliation (exact-FQDN link, new endpoint-backed
  asset, or a reviewable `conflict` state — never auto-merged), and
  installed/removed/updated software-diff events (suppressed on first
  snapshot). Only agent-hashed platform identifiers are ever stored, never a
  raw MAC/serial. New read APIs (`GET /api/endpoint/devices[/…]`,
  `GET /api/assets/{id}/software`) and an Endpoint/Software section on the
  Web UI asset card. Gated by `OCTO_ENDPOINT_INVENTORY_ENABLED` (default on).
  NATS event publish (S8), retention/ops (S9), and the cross-repo e2e test
  (S10) are deferred to a follow-up.

- **Continuous org-level scan scheduling (Phase 8.5)** — a new per-tenant
  `scan_schedules` table (cron or fixed-interval cadence, target set + scan
  options) managed via `/api/schedules` (`GET`/`POST`/`PATCH` for operators,
  `DELETE` for admins). An in-process dispatcher thread, started from the API
  `lifespan` alongside the existing ClickHouse ingest worker, polls due
  schedules every 30s and starts jobs through the existing `jobs_service.start_scan`
  — skipping a tick if the schedule's previous job is still running. No new
  K8s CronJob/Deployment needed; the original single-tenant `scanner/scheduler.py`
  and static `k8s/shapoclyack/base/cronjob.yaml` are unchanged for simple
  self-hosted deployments.

## [0.36-0723] — 2026-07-23

### Fixed

- **OS detection (`nmap -O`) silently failing as the non-root container user**
  — `docker-compose.yml`'s `shapoclyack` service only granted `NET_RAW`
  (missing `NET_ADMIN`, which nmap's libcap-ng-based privilege drop needs
  alongside `NET_RAW` for `-O`), and `k8s/shapoclyack/base/api-deployment.yaml`'s
  `api` container plus `k8s/shapoclyack/base/agents/agent-deployment.yaml` set
  `allowPrivilegeEscalation: false`, which sets Linux's `no_new_privs` flag —
  this blocks the `setcap` file-capability grant on `nmap`/`naabu` outright,
  regardless of what's listed under `capabilities.add`. Brought all three in
  line with `job.yaml`/`cronjob.yaml`'s already-working
  `allowPrivilegeEscalation: true` + `capabilities.add: [NET_RAW, NET_ADMIN]`,
  and `Dockerfile`/`Dockerfile.allinone`'s `setcap` step now grants
  `cap_net_admin` in addition to `cap_net_raw` on both binaries. Every place
  this image actually runs scans (`docker-compose.yml`, `tests/e2e/run.sh`,
  the k8s manifests) already grants `NET_ADMIN` at the container level to
  match — `ci.yml`'s image smoke-check was the only place still invoking the
  image with zero `--cap-add`, which broke outright once the binaries carried
  a file capability outside that empty bounding set (a file capability beyond
  the runtime bounding set fails the whole `execve()` with `EPERM` rather than
  being silently dropped); fixed by adding the same `--cap-add` flags there.
- **Stale `shapoclyack-0.33` image tags across every k8s manifest** —
  `api-deployment.yaml`, `agent-deployment.yaml`, `cronjob.yaml`, `job.yaml`,
  `job-resume.yaml`, `enrichment/cronjob.yaml`, both overlay patches, and the
  agent example manifest all still pointed at the pre-fix `0.33` image, so
  `kubectl apply -k` deployments silently ran stale code even after pulling
  the latest release. Bumped all references to `shapoclyack-0.36-0723`.

### Added

- **Editable configurator** — the System page gains an admin-editable scanner
  config panel (`GET`/`PUT /api/config`): pipeline-stage toggles
  (`fingerprint`/`tls_posture`/`nuclei`/`reporting.pdf_summary`), nuclei
  severities/exclude-tags, and per-profile scan tuning (`discover_rate`,
  `port_rate`, `top_ports`, `nmap_timing`). Only a strict whitelist of paths is
  editable and the merged result is validated against the full `AppConfig`
  schema before it can be saved. Overrides persist in a new Postgres
  `config_overrides` table (migration `0002`) and are deep-merged onto the base
  config into a job-specific file at **local** scan start — so operators can
  tune scans without editing the (often read-only) config file. Agents keep
  their mounted config (documented limitation). Viewers see the effective
  values read-only; only `admin` can edit.
- **Services layer on the attack-surface graph** — the graph gains a fourth
  column, so it now maps **hostnames → IPs → ports → services**. The
  `/runs/{id}/ports` API aggregates distinct service names per port from
  `findings.json` (new `services` field on `PortAggregateItem`), and the graph
  draws port → service edges (capped like the other columns).
- **ASN/org enrichment + attack-surface clustering** — alive hosts are now
  annotated with their Autonomous System number and holder/org name via a new
  offline `scanner/pipeline/asn_enrich.py` (`enrichment.asn`, MaxMind
  GeoLite2-ASN / DB-IP ASN Lite `.mmdb` or a JSON overlay, fail-soft — mirrors
  the GeoIP path and is distinct from the opt-in scope-expanding
  `asn_discovery` stage). Docker builds bake a real ASN `.mmdb`
  (`scripts/fetch-asn-db.sh`, wired into `fetch-enrichment.sh`). The
  `/runs/{id}/hosts` API and the **Attack Surface** graph pick this up: IP
  nodes now **cluster/color by network (ASN/org)** when available, falling
  back to GeoIP country — closing the ASN/org clustering deferred from the
  initial attack-surface work.
- **Attack surface graph** — a new **Attack Surface** page renders a run's
  hostnames → IPs → ports as a three-column layered graph, with IP nodes
  colored by GeoIP country and ports flagged when they carry findings. Built
  as dependency-free SVG (no graph library, static-export safe) from the
  existing `/runs/{id}/hosts` and `/runs/{id}/ports` endpoints; node counts are
  capped (IPs ranked by finding count) so large fleets stay legible, and a run
  selector switches between runs. ASN/org clustering is deferred — that data
  needs the opt-in `asn_discovery` stage, so country is used for now.
- **Executive dashboard** — the home dashboard is now an exec-level exposure
  view: added a findings-by-severity donut, a "top critical & high findings"
  table (sorted by CVSS v4/v3) for the latest run, an **asset posture** panel
  (business-criticality distribution + active/stale/decommissioned counts from
  the asset inventory), and a "vulnerable hosts" KPI, alongside the existing
  exposure trend and top-ports charts. All derived from existing endpoints
  (runs, latest-run findings/ports, assets) — no new backend.
- **Asset detail card** — a full asset page (`/assets/view`) replaces the cramped
  dialog: it shows the cross-run asset (status, business criticality, owner,
  business unit, identifiers, tags) alongside its most recent per-run
  observation — vulnerabilities, open ports, and OS/GeoIP — correlated by the
  asset's primary IP against the latest run. Operators can edit
  `owner_email`/`business_unit`/`asset_criticality` and one-way **decommission**
  an asset inline (wiring the already-shipped `PATCH /api/assets/{id}`, which had
  no UI before); the edit panel is hidden for viewers. The Assets list now links
  rows to the card and shows a criticality column. `api.ts` gains
  `asset_criticality` on the asset types plus an `updateAsset()` call.
- **System status page (read-only installation configurator)** — a new
  `GET /api/system` endpoint (`api/services/system_status.py`, viewer role)
  and a **System** page in `web-next/` surface, at a glance: the app version;
  scanner tool versions (nmap/naabu/nuclei/dnsx, probed via subprocess,
  cached, fail-soft when a tool is absent); enrichment-database freshness
  (EPSS/KEV/GeoIP/CVSS4 — present/size/age at their effective env-or-config
  paths, with fresh/stale/missing badges); enabled pipeline stages and scan
  profiles parsed from the effective scan config; runtime flags
  (`allow_scan_start`, job execution mode, Postgres/ClickHouse/NATS/ingest
  enablement as booleans); and tenant/agent counts. Exposes no secrets — URLs,
  tokens, and the JWT secret are reduced to booleans and never serialized.
- **Reports in the Web UI** — run artifacts (including the business `summary.pdf`)
  are now surfaced in `web-next/`: a new **Reports** tab on the run detail page
  lists every artifact with inline preview for text (JSON/TXT/MD, pretty-printed
  for JSON) and one-click download, and a new top-level **Reports** page lists
  runs with a direct PDF download. Previously `RunDetail.artifacts` came back
  from the API but was never rendered, and the PDF was effectively
  unreachable. Backend: a new binary-safe `GET /runs/{id}/download/{path}`
  endpoint (`FileResponse` with an extension-derived content-type and an
  attachment disposition) — the existing `artifacts/{path}` endpoint
  UTF-8-decodes and truncates to 1 MB, which is fine for previewing text but
  corrupts binaries like the PDF. The shared path-traversal guard is factored
  into `runs_service.resolve_artifact()` and reused by both endpoints.
- **Nuclei template-based vulnerability/misconfig scanning** — a new opt-in
  stage (`scanner/pipeline/nuclei_scan.py`, `nuclei` config key) runs the
  `nuclei` engine against the same already-open web ports as `fingerprint`
  (no new port scan), covering HTTP-specific CVEs/misconfigs/exposed panels
  that `nmap-vulners`/`vulscan` (version-detection-driven) don't reach.
  Conservative by default: `severities: [critical, high, medium]` and
  `exclude_tags: [intrusive, fuzz, dos]` keep nuclei's more aggressive
  template categories (active SQLi/RCE-style payloads) off unless explicitly
  widened. CVE-tagged matches merge into `vulnerabilities.json`
  (`source: "nuclei"`, feeding CVSS4/EPSS/KEV enrichment, risk scoring, and
  report diffs via `report.py`'s new `extra_vulnerabilities` parameter);
  everything else (exposed panels, misconfig, tech detection) is
  findings-only in `nuclei.json`. Never fails the scan: a missing
  `templates_dir`, missing `nuclei` binary, or a failed/timed-out invocation
  all degrade to a clean `skipped_reason`.
  `Dockerfile`/`Dockerfile.allinone` build the `nuclei` binary from source in
  a dedicated `golang` stage (`go install` at a pinned version tag — verified
  by Go's own module checksum database rather than a hand-copied release
  sha256, since nuclei has no per-arch prebuilt archive to pin the
  dnsx/naabu way) and clone `nuclei-templates` pinned to a release tag, with
  a new `scripts/fetch-nuclei-templates.sh` best-effort refresh step
  matching the vulscan/enrichment fetch scripts' fail-soft philosophy.

## [0.35-0722] — 2026-07-22

### Changed

- **Node.js 22 → 24** across the project: `Dockerfile.allinone`/`Dockerfile.api`'s
  `web-build` stage base image, `.github/workflows/ci.yml`'s `actions/setup-node`
  step, and a new `engines.node: ">=24"` in `web-next/package.json` (Node 24
  is the current Active LTS; Node 22 moves to Maintenance).
- **Enrichment data baked into Docker builds** — `Dockerfile`/`Dockerfile.allinone`
  now run `scripts/fetch-enrichment.sh` (GeoIP via the keyless DB-IP provider,
  CVSS4, EPSS, KEV) as a best-effort build step, and `Dockerfile.api` runs the
  EPSS/KEV fetches it actually uses; a fresh image now ships with real
  enrichment data instead of only the committed seed stubs (a 5-IP GeoIP demo
  overlay, a handful of seed CVEs). Never fails the build — an
  offline/network-restricted build just keeps the seed data, same as before.
  `scanner/config/default.yaml`'s `enrichment.geoip.database` default now
  points at the baked-in `.mmdb` path instead of the JSON demo overlay (which
  remains in the repo for hand-editable lab/test use via an explicit config
  override).
- **vulscan offline CVE databases refreshed at build time** — new
  `scripts/fetch-vulscan-db.sh` (mirrors vulscan's own `update.sh`, fetching
  the same computec.ch-published CSVs with per-database non-fatal error
  handling). `Dockerfile`/`Dockerfile.allinone` clone `scipag/vulscan` pinned
  to a specific commit for reproducible builds, which also freezes its
  bundled CVE/exploit-db/openvas/etc. CSVs at that commit's snapshot; this
  script refreshes them in place as a best-effort build step (never fails
  the build) so the `vuln-offline` NSE profile matches against current data.

### Added

- **OS fingerprint surfaced in the API/UI** — nmap's `-O` OS detection already
  ran on every scan and `os_findings.json` was already written per run, but
  the best-match-by-accuracy result was only ever counted
  (`summary.json`'s `os_detected_hosts`), never attached to a host record.
  `scanner/pipeline/report.py` now stamps `os_name`/`os_accuracy` onto each
  `alive_hosts.json` entry (same pattern as the existing GeoIP `country`/`city`
  fields); `AliveHostItem` (`api/schemas.py`) and `GET /runs/{id}/hosts` expose
  it, and the Hosts tab in `web-next`'s run view shows it inline.

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
  non-fatal failure handling. `k8s/shapoclyack/overlays/enrichment` adds a shared
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
  `k8s/shapoclyack/base/postgres/` + `docker-compose.postgres.yml` mirror the
  ClickHouse deployment pattern; an `initContainer` runs `alembic upgrade head`
  before API replicas start.
- **Phase 1 NATS retention + HA** — JetStream `JOBS`/`INGEST` streams now bound
  storage by default (`OCTO_NATS_JOBS_MAX_AGE_SECONDS`,
  `OCTO_NATS_INGEST_MAX_AGE_SECONDS`, `OCTO_NATS_INGEST_MAX_BYTES`; applied on
  redeploy via `update_stream`, not just first creation); `k8s/shapoclyack/base/nats/`
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
  - k8s StatefulSet/Services `shapoclyack-nats` (+ client Service)
  - API publishes agent jobs to `jobs.scan` and raw archives to `ingest.raw_results`
    (JetStream `Nats-Msg-Id` idempotency); filesystem extract unchanged for UI
  - Agent pull consumer (durable `octo-agents`) when NATS URL set; HTTP claim remains default
  - Compose profile `nats`; example patches under `k8s/shapoclyack/examples/nats-*.yaml`

### Changed

- Promoted discovery completeness knobs from `discovery-bench-realistic` into
  prod configs (`scanner/config/default.yaml`, `k8s/shapoclyack/base/config/k8s.yaml`):
  `discovery.verify` on, `adaptive.wave2_rate: 2500`, `batching.ipv4_prefix: 24`,
  smaller `max_targets_per_batch`; default `balanced.discover_rate` 6000 → 4000
- Documented platform evolution roadmap ([ROADMAP.md](ROADMAP.md)): NATS JetStream,
  MSSP multi-tenancy, ClickHouse analytics, K8s autoscaling, Cloudflare/CT/Maddy,
  Shapoclyack Web UI v2 (`web-next/` — Next.js 14)
- Updated [shapoclyack.html](shapoclyack.html) roadmap infographic to match

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
  `ghcr.io/onixus/shapoclyack*` package names:
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

- Pull `shapoclyack-*` images (do not use bare `ghcr.io/onixus/shapoclyack`)
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
| `ghcr.io/onixus/shapoclyack-aio` | `0.3.2.1`, `latest` |
| `ghcr.io/onixus/shapoclyack-api` | `0.3.2.1`, `latest` |
| `ghcr.io/onixus/shapoclyack-scanner` | `0.3.2.1`, `latest` |

### Upgrade notes

- Preferred local path: `docker compose up --build` → http://localhost:8080
- Preferred cluster path: `kubectl apply -k k8s/shapoclyack/overlays/dev` (aio + UI job start)
- For results-only API (no local scans): `kubectl apply -k k8s/shapoclyack/overlays/api-readonly`
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
  - kustomize under `k8s/shapoclyack` (Job, CronJob, API Deployment/Service, PVC)
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
| `ghcr.io/onixus/shapoclyack` | `0.3.0`, `0.3`, `0`, `latest` |
| `ghcr.io/onixus/shapoclyack-api` | `0.3.0`, `0.3`, `0`, `latest` |

### Upgrade notes

- Deploy with `kubectl apply -k k8s/shapoclyack/overlays/dev` (or `prod`)
- Change default API demo passwords / set `OCTO_JWT_SECRET` before any real use
- Prefer cluster `CronJob` over the in-process scheduler

## [0.2.1] — 2026-07-15

Inherited from the pre-rename history (NSE `-Pn` fix, docs/infographic).
