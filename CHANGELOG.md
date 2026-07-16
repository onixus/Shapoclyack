# Changelog

All notable changes to Octo-man are documented in this file.

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

### Unreleased (Phase 3)

- DefectDojo export: Generic Findings Import via `/api/v2/reimport-scan/` (`defectdojo.*`, `--export-defectdojo`, env `OCTO_DEFECTDOJO_*`)

### Images

| Image | Tag |
|-------|-----|
| `ghcr.io/onixus/octo-man` | `0.3.0`, `0.3`, `0`, `latest` |
| `ghcr.io/onixus/octo-man-api` | `0.3.0`, `0.3`, `0`, `latest` |

### Upgrade notes

- Deploy with `kubectl apply -k k8s/octo-man/overlays/dev` (or `prod`)
- Change default API demo passwords / set `OCTO_JWT_SECRET` before any real use
- Prefer cluster `CronJob` over the in-process scheduler

## [0.2.1] — 2026-07-15

Inherited from upstream Octo-man (NSE `-Pn` fix, docs/infographic). See prior Octo-man releases for 0.2.x history.
