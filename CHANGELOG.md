# Changelog

All notable changes to the Octo-man product (hosted in Shapoclyack) are documented in this file.

## Unreleased

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
