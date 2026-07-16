# Changelog

All notable changes to the Octo-man product (hosted in Shapoclyack) are documented in this file.

## Unreleased

### Changed

- **Container images are Shapoclyack-scoped** and no longer published under the legacy
  `ghcr.io/onixus/octo-man*` package names:
  - `ghcr.io/onixus/shapoclyack-aio`
  - `ghcr.io/onixus/shapoclyack-scanner`
  - `ghcr.io/onixus/shapoclyack-api`
- Compose service renamed to `shapoclyack`; Dockerfiles carry OCI source labels for this repo

### Upgrade notes

- Retag / pull `shapoclyack-*` images (do not use bare `ghcr.io/onixus/octo-man`)
- Update any local `image:` overrides to the new names

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

### Images (at release; superseded by `shapoclyack-*` names — see Unreleased)

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
