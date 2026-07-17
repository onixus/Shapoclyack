# Changelog

All notable changes to the Octo-man product (hosted in Shapoclyack) are documented in this file.

## Unreleased

### Added

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
