# Octo-man

[![CI](https://github.com/onixus/Shapoclyack/actions/workflows/ci.yml/badge.svg)](https://github.com/onixus/Shapoclyack/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/onixus/Shapoclyack)](https://github.com/onixus/Shapoclyack/releases/latest)

Containerized network reconnaissance pipeline with a Kubernetes control plane, HTTP API, and dashboard.

**Product:** Octo-man · **Repository / container registry:** Shapoclyack  
(`ghcr.io/onixus/shapoclyack-{aio,scanner,api}` — not the legacy `octo-man` GHCR packages).

English is the primary documentation language.  
Russian ops notes: [README.ru.md](README.ru.md).

| | |
|---|---|
| **Pipeline** | `resolve → discovery → hostnames → ports → NSE (service/OS + CVE)` |
| **Inputs** | CIDR / IP / FQDN |
| **Outputs** | JSON / JSONL / CSV + Markdown / HTML (+ diffs, alerts) |
| **Runtime** | All-in-one (`docker compose`) or Kubernetes + kustomize ([k8s/README.md](k8s/README.md)) |
| **Release** | **[shapoclyack-0.33](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.33)** — `ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.33` (+ `shapoclyack-scanner` / `shapoclyack-api`) |

### Docs map

- [CHANGELOG.md](CHANGELOG.md) — release history
- [ROADMAP.md](ROADMAP.md) — MSSP / Enterprise platform evolution (NATS, tenancy, ClickHouse, Web UI v2, …)
- [k8s/README.md](k8s/README.md) — deploy Job / CronJob / API
- [.github/SECURITY.md](.github/SECURITY.md) — vulnerability reporting
- [octo_man.html](octo_man.html) — product roadmap infographic

## What It Implements

- Input contract with validation and normalization.
- Speed profiles: `safe`, `balanced`, `fast`.
- DNS resolve for FQDN via `dnsx`.
- Host discovery and fast port scan via `naabu` (TCP, UDP, or both).
- **Probe ladder**: ordered ICMP (`fping`) → TCP SYN probe → naabu host discovery (`discovery.probe_order`).
- **Adaptive discovery**: wave-1 batched sweep plus optional wave-2 gap fill for missed hosts.
- **Discovery presets** (`discovery.profile: auto|fast|balanced|thorough|custom`) and **delta discovery** (`--delta`) for incremental scans vs a previous run.
- **Hostname enrichment** (forward DNS map + reverse PTR via `dnsx`) between discovery and port scan.
- **Disjoint-batch parallelism**: non-overlapping CIDR batches run discover in parallel; overlapping batches stay sequential with `skip_known_alive`.
- **Deferred NSE** (`runtime.skip_nse` / `--skip-nse`): L1 run (discover + ports + reports), then `--resume` for enrichment.
- Enrichment with Nmap `-sV`, OS detection (`-O`) and NSE profiles (incl. `vuln`).
- Parallel NSE/OS stage (configurable `nse_concurrency`) for faster large scans.
- Parallel discovery/port batches (`discover_concurrency`, `ports_concurrency`) for faster naabu stages.
- Retry + timeout handling per external command (with a separate per-host `nse_timeout_seconds`).
- Range batching + fine-grained checkpoint/resume (per discovery/port batch and per NSE host).
- Report exports with summary, parsed Nmap service data, OS matches and vulnerability findings.
- **CVSS v4 enrichment** (`enrichment.cvss4`): local CVE → CVSS 4.0 JSON map (`scanner/data/cvss4/`); refresh via `scripts/fetch-cvss4-db.py`.
- **GeoIP enrichment** (`enrichment.geoip`): country/city per host via MaxMind GeoLite2 `.mmdb` or JSON overlay; Web UI shows location on Alive hosts / findings. Fetch MMDB with `scripts/fetch-geoip-db.sh` (do not redistribute MaxMind DB files in the image).
- **Report diffs** (`reporting.diff` / `--compare-run-id`): hosts, ports, and CVE delta vs the previous run → `diff.json` / `diff.md`.
- **Slack / Telegram alerts** (`alerts` / `--notify`): optional post-scan notifications (credentials via env preferred).
- **DefectDojo export** (`defectdojo` / `--export-defectdojo`): Generic Findings Import via API v2 reimport (Phase 3).
- **Business PDF reports** (`reporting.pdf_summary`): executive `summary.pdf` with severity KPIs and priority findings (Phase 3).
- **Lab scheduler** (`python -m scanner.scheduler`): interval/cron helper; prefer Kubernetes CronJob in production.
- **API + dashboard**: FastAPI + React UI, JWT RBAC (`viewer` / `operator` / `admin`); severity dashboard; click Alive hosts / Open ports to explore and filter findings.
- **All-in-one** (`shapoclyack-aio` / `docker compose`): Web UI starts local scans by default.
- **Kubernetes**: `Job` / `CronJob` / aio API Deployment under `k8s/octo-man` (includes optional NATS JetStream StatefulSet; enable with `OCTO_NATS_URL`).
- **Remote agents**: HTTP claim/upload by default; set `OCTO_NATS_URL` for a long-lived
  JetStream pull on `jobs.scan` + ingest publish (`ingest.results.{tenant}` /
  legacy `ingest.raw_results`). Prefer `OCTO_AGENT_PROVISIONING_KEY` (Phase 2 JWT)
  over legacy `OCTO_AGENT_TOKEN`. Compose helper: `docker-compose.nats.yml`.
- **MSSP tenancy (Phase 2)**: `POST /api/tenants` + provisioning keys; agents call `POST /api/auth/agent/token` for a short-lived JWT with `tenant_id`.
- **Asset inventory (Phase 7)**: Postgres-backed cross-run asset registry (`GET /api/assets`, `GET /api/assets/{id}`) with stable identity, `first_seen`/`last_seen`/`status` lifecycle. `OCTO_POSTGRES_URL` is required — see [k8s/README.md](k8s/README.md#postgres-primary-db--phase-7).

## Project Layout

- `Dockerfile` / `Dockerfile.api` — image builds (scanner + API/UI)
- `k8s/` — **primary runtime**: kustomize base + `dev`/`prod` overlays ([k8s/README.md](k8s/README.md))
- `scanner/config/default.yaml` (+ optional `discovery-bench*.yaml` for discovery tuning)
- `scanner/inputs/{ranges.txt,domains.txt,ports.txt,ports_udp.txt}`
- `scanner/main.py`
- `scanner/scheduler.py` — optional in-process scheduler (K8s prefers CronJob)
- `scanner/pipeline/*`
- `api/` — FastAPI app (`python -m api`)
- `api/db/` — Postgres PRIMARY_DB: SQLAlchemy models + Alembic migrations (tenants, provisioning keys, asset inventory — required, see [k8s/README.md](k8s/README.md))
- `web-next/` — Web UI v2 (Next.js static export; served by aio/API images)
- `web/` — legacy React/Vite dashboard (kept for reference)
- `tests/{e2e,load}/` — CI integration tests
- `scripts/{smoke.sh,load-test.sh,schedule.sh}` — local helpers
- `bench/{up,down,run-discovery,run-realistic}.sh` — local discovery benchmark lab
- `scanner/output/*` (generated; per-run under `scanner/output/runs/<run_id>/` when enabled)
- `scanner/state/checkpoint.json` (generated; per-run under `scanner/state/runs/<run_id>/` by default)

## Input Contract

### `scanner/inputs/ranges.txt`

One target per line:
- CIDR (`10.0.0.0/16`)
- single IP (`10.0.1.10`, `2001:db8::1`)

### `scanner/inputs/domains.txt`

One FQDN per line:
- `api.example.com`
- `db01.corp.local`

### `scanner/inputs/ports.txt` (optional)

Custom **TCP** port selectors (one per line).  
If empty, `top-ports` from the selected profile are used.

### `scanner/inputs/ports_udp.txt` (optional)

Custom **UDP** ports for `ports.protocol: udp` or `tcp_udp`.  
If empty, a built-in top-UDP list (`ports.top_udp_ports`, default 100) is used.

Examples:
- `22`
- `80,443,8443`
- `1-1024`

Invalid lines are written to `scanner/output/normalized/contract_validation.json`.

## Usage

Primary runtime is **Kubernetes**. Full steps: [k8s/README.md](k8s/README.md).

### 1) Build images

```bash
docker build -t ghcr.io/onixus/shapoclyack-scanner:local -f Dockerfile .
docker build -t ghcr.io/onixus/shapoclyack-api:local -f Dockerfile.api .
```

### 2) Prepare targets + deploy (Kubernetes)

```bash
kubectl create secret generic scan-targets -n network-scan \
  --from-file=ranges.txt=scanner/inputs/ranges.txt \
  --from-file=domains.txt=scanner/inputs/domains.txt \
  --from-file=ports.txt=scanner/inputs/ports.txt \
  --from-file=ports_udp.txt=scanner/inputs/ports_udp.txt \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -k k8s/octo-man/overlays/dev
kubectl -n network-scan logs -f job/network-scan
```

### 3) Local one-shot without a cluster (optional)

```bash
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/scanner/inputs:/app/scanner/inputs" \
  -v "$PWD/scanner/config:/app/scanner/config" \
  -v "$PWD/scanner/output:/app/scanner/output" \
  -v "$PWD/scanner/state:/app/scanner/state" \
  ghcr.io/onixus/shapoclyack-scanner:local \
  --config scanner/config/default.yaml --mode balanced
```

### 4) Resume after interruption

Kubernetes:

```bash
kubectl apply -f k8s/octo-man/base/job-resume.yaml
```

Local docker run: add `--resume` (and optional `--run-id …`). With per-run output enabled
(default), resume continues the latest run in `scanner/state/latest_run.json`.

### 5) L1 scan, then enrich with NSE later

Use `--skip-nse` on the first Job/run, then `--resume` (or `job-resume.yaml`) for Nmap/NSE.
Or set `runtime.skip_nse: true` in the config.

### 6) Incremental (delta) discovery

Re-probe only hosts new to scope since the previous run, plus a random refresh sample of
known-alive hosts. Requires a prior full baseline scan with `per_run_output: true`:

```bash
# CronJob already passes --delta; for a one-shot Job, patch args or run locally:
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/scanner:/app/scanner" ghcr.io/onixus/shapoclyack-scanner:local \
  --config scanner/config/default.yaml --mode balanced --delta
```

Or enable `discovery.delta.enabled: true` in the config. Optional `discovery.seed_alive_file`
pre-seeds alive hosts from CMDB/DHCP before the first delta run. Do **not** use delta on the
first scan, after changing input ranges, or when you need a full baseline.

### 7) Report diffs (Phase 1)

After reports are written, the pipeline compares the current run to the previous one
(from `scanner/state/latest_run.json`, or an explicit path / id). Disable with `--no-diff`
or `reporting.diff.enabled: false`. Artifacts: `diff.json` / `diff.md`.

### 8) Slack / Telegram alerts (Phase 1)

Provide credentials via Secret `octo-man-alerts` (see `k8s/octo-man/examples/api-secrets.example.yaml`)
or env `OCTO_SLACK_WEBHOOK` / `OCTO_TELEGRAM_*`, and pass `--notify` on the Job.
Or set `alerts.enabled: true` in YAML. Delivery is fail-soft (`alerts.json`).

### 9) DefectDojo export (Phase 3)

Push ranked `vulnerabilities.json` into DefectDojo as **Generic Findings Import** through
`/api/v2/reimport-scan/` (auto-creates Product / Engagement when allowed).

```bash
export OCTO_DEFECTDOJO_URL="https://defectdojo.example.com"
export OCTO_DEFECTDOJO_API_KEY="your-api-token"
python -m scanner.main --config scanner/config/default.yaml --mode balanced --export-defectdojo
```

Or set `defectdojo.enabled: true` in YAML. Always writes `defectdojo_findings.json` (payload) and
`defectdojo.json` (status). Delivery is fail-soft — scan exit code stays success if DD is down.

Key settings: `product_name`, `engagement_name` (stable name recommended for reimport),
`min_severity`, `close_old_findings`, `verify_ssl`.

API jobs accept `"export_defectdojo": true` on `POST /api/jobs`.

### 10) Business PDF report (Phase 3)

When `reporting.pdf_summary: true` (default), the pipeline writes an executive PDF after reports
and (if present) the run diff:

- file: `summary.pdf`
- contents: KPIs, severity breakdown, top services, priority findings table, optional delta vs previous run
- branding: `reporting.pdf_title`, `reporting.pdf_org_name`
- truncate findings list with `reporting.pdf_max_vulnerabilities` (default 40)

Disable with `reporting.pdf_summary: false`. PDF generation is fail-soft.

### 11) Scheduling (Phase 1)

In Kubernetes use `CronJob/network-scan-scheduled` (preferred). The in-process helper remains
for labs: `python -m scanner.scheduler --dry-run` / `--once`.

## Configuration validation

The YAML config is validated at startup with **Pydantic** (`scanner/pipeline/config_schema.py`).
Unknown keys, invalid profile references, out-of-range values, and missing required profiles
(`safe`/`balanced`/`fast`) fail fast with a readable error (exit code `2`).

## Per-run output directories

When `runtime.per_run_output: true` (default), each scan writes to isolated directories:

- `scanner/output/runs/<run_id>/` — artifacts and `run_meta.json`
- `scanner/state/runs/<run_id>/` — checkpoint for that run
- `scanner/state/latest_run.json` — pointer to the most recent run id

`run_id` defaults to a UTC timestamp (`20260626T104530Z`) or can be set via `--run-id`.
Set `per_run_output: false` to keep the legacy flat layout (`scanner/output/`).

## Phase 2: API, dashboard, and RBAC

HTTP control plane for reviewing runs and (optionally) launching scans.

### Start the API + UI

### All-in-one (default)

```bash
docker compose up --build
# open http://localhost:8080  — operator / operator-change-me

# Optional NATS JetStream (auto-wires OCTO_NATS_URL=nats://nats:4222):
docker compose -f docker-compose.yml -f docker-compose.nats.yml --profile nats up --build
# expect GET /api/health → "nats": true

# NATS + ClickHouse ingest (also sets OCTO_CLICKHOUSE_URL=http://clickhouse:8123):
docker compose -f docker-compose.yml -f docker-compose.nats.yml -f docker-compose.clickhouse.yml \
  --profile nats --profile clickhouse up --build
# expect GET /api/health → "nats": true, "clickhouse": true, "ch_ingest": {...}
```

Image: `ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.33` (scanner tools + API + UI).  
`OCTO_ALLOW_SCAN_START=true` and `OCTO_JOB_EXECUTION_MODE=local` are baked in.

Kubernetes (aio Deployment, UI can start scans):

```bash
kubectl apply -k k8s/octo-man/overlays/dev
kubectl -n network-scan port-forward svc/octo-man-api 8080:8080
```

Local API-only development (no scanner binaries in PATH unless installed):

```bash
pip install -r requirements-api.txt
cd web-next && npm install && npm run build && cd ..
OCTO_JWT_SECRET=dev-secret python -m api
```

### Default users (change immediately)

| User | Password | Role |
|------|----------|------|
| `admin` | `admin-change-me` | admin |
| `operator` | `operator-change-me` | operator |
| `viewer` | `viewer-change-me` | viewer |

Override with `OCTO_API_USERS` (JSON list of `{username,password,role}`) and set a strong
`OCTO_JWT_SECRET`.

### Roles

| Role | Capabilities |
|------|----------------|
| `viewer` | List/read runs, summaries, diffs, vulnerabilities, artifacts |
| `operator` | Viewer + start/list scan jobs and view remote agents |
| `admin` | Same as operator in this release (reserved for future admin APIs) |

### Key endpoints

- `POST /api/auth/login` → JWT
- `GET /api/auth/me`
- `GET /api/runs`, `GET /api/runs/{run_id}`, `GET /api/runs/{run_id}/vulnerabilities`
- `GET /api/runs/{run_id}/diff`, `GET /api/runs/{run_id}/artifacts/{path}`
- `GET|POST /api/jobs` (operator+) — optional body fields `ranges` / `domains` / `ports` /
  `ports_udp` (newline-separated). When set, the API writes per-job inputs under
  `state/job_inputs/<job_id>/` and passes `--ranges` / `--domains` / `--ports-file` /
  `--ports-udp-file`. The Jobs page exposes the same fields.
- `GET /api/agents` (operator+) — registered remote agents
- Agent API (shared bearer `OCTO_AGENT_TOKEN`): `POST /api/agent/register`,
  `POST /api/agent/heartbeat`, `POST /api/agent/jobs/claim`,
  `POST /api/agent/jobs/{id}/results`

**Default (aio / compose / k8s base):** Web UI job start is **on** (`OCTO_ALLOW_SCAN_START=true`).  
The thin `shapoclyack-api` image still has no naabu/nmap — use it only via
`k8s/octo-man/overlays/api-readonly` (`OCTO_ALLOW_SCAN_START=false`) when the UI should be
results-only and scans run as `Job` / `CronJob` / remote agents.

### Remote agents (Phase 3)

Set `OCTO_JOB_EXECUTION_MODE=agent` so `POST /api/jobs` only enqueues work. Remote workers run
the scanner and upload a run tarball back to the API.

```bash
# API
export OCTO_JOB_EXECUTION_MODE=agent
export OCTO_ALLOW_SCAN_START=true
export OCTO_AGENT_TOKEN=replace-me
export OCTO_JWT_SECRET=dev-secret
python -m api

# Worker (scanner image / host with naabu+nmap)
export OCTO_API_URL=http://127.0.0.1:8080
export OCTO_AGENT_TOKEN=replace-me
python -m agent --config scanner/config/default.yaml
```

Operators can watch agents on the **Agents** page. Jobs show `execution=agent` and the assigned
agent id. See `k8s/octo-man/examples/agent-mode-api-patch.yaml` and
`agent-deployment.example.yaml`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Unexpected internal error |
| `2` | Configuration validation error |
| `3` | No valid input targets after contract validation |
| `4` | External tool stage failed after retries |
| `130` | Interrupted (Ctrl+C) |

## Logging

Pipeline logs use a **rotating file** at `logs_dir/pipeline.log` (defaults:
`log_max_bytes: 10485760`, `log_backup_count: 5`). Tune under `runtime:` in the config.

## Resource limits (Kubernetes)

Base Job/CronJob requests/limits are `4–8 CPU` / `4–8Gi` memory. The `dev` overlay lowers these
and uses `--mode safe`. Tune patches under `k8s/octo-man/overlays/*/`.

## Validation Helpers

- `scripts/smoke.sh` — compile sources and run the pipeline against current inputs
- `scripts/load-test.sh <cidr>` — write a temporary CIDR and run `fast` in a local container
- `./k8s/scripts/validate-kustomize.sh` — render/validate `dev` and `prod` overlays
- `scripts/schedule.sh` — thin wrapper around `python -m scanner.scheduler` (labs only)

## Tests

Unit tests cover pipeline helpers (contract, batching, discovery, NSE, reports, diffs,
alerts, scheduler, config schema, run paths) and the Phase 2 API (auth, RBAC, runs).

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check scanner api tests
```

## Continuous Integration

`.github/workflows/ci.yml` runs on every push to `main` and on pull requests:

- **lint**: `ruff check scanner api tests`
- **test**: `compileall` + `pytest` on Python 3.11 and 3.12
- **web**: `npm ci` + static export of Web UI v2 (`web-next/`)
- **kustomize**: `./k8s/scripts/validate-kustomize.sh`
- **image**: build scanner image, toolchain smoke, e2e scan, light load test via
  `.github/actions/synthetic-load-test` (16 hosts), Trivy gate, SBOM artifact

Heavy load runs live in `.github/workflows/load-test.yml` (manual / weekly / `workflow_call`).

Release tags (`v*`) and published GitHub releases trigger `.github/workflows/docker-publish.yml`
for the GHCR images (`shapoclyack-aio` / `scanner` / `api`).

### End-to-end test

`tests/e2e/run.sh` builds nothing itself — given the built image it spins up a target
container (`nginx:alpine`) on a private docker network, runs the scanner against it with a
minimal offline config (`tests/e2e/config.yaml`), and asserts (via
`tests/e2e/check_results.py`) that the host is found alive, port `80` is open, an Nmap
service is detected, and the report artifacts exist. Run locally:

```bash
docker build -t network-scan-cli:ci .
tests/e2e/run.sh network-scan-cli:ci
```

### Synthetic load test

`tests/load/run.sh` exercises the pipeline under multi-target load on a private docker network
(no internet, no real CIDR). It spins up `N` target containers (`nginx:alpine` by default),
runs discovery → ports → parallel NSE across batches, validates that ≥95% of targets are found,
and records duration / peak RSS metrics.

Reusable composite action: `.github/actions/synthetic-load-test` (build optional, metrics artifact,
job summary). Used by:

| Trigger | Hosts | Config | Resume |
|---------|------:|--------|--------|
| CI image job (every PR) | 16 | `tests/load/config.yaml` | no |
| `Load test` workflow (`workflow_dispatch`) | 32 (default) | `tests/load/config-heavy.yaml` | yes (default) |
| `Load test` workflow (weekly cron) | 32 | heavy | no |
| `workflow_call` into `load-test.yml` | caller-defined | caller-defined | caller-defined |

Environment overrides for `tests/load/run.sh`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CHECKPOINT_TIMEOUT_SEC` | `120` | Max wait for resume checkpoint (heavy workflow sets this) |
| `SCAN_TIMEOUT_SEC` | `2400` | Hard timeout on scanner container (heavy: `1800`) |
| `KEEP_WORK=1` | off | Keep temp workdir on exit (debug) |

Run locally:

```bash
docker build -t network-scan-cli:ci .
tests/load/run.sh network-scan-cli:ci --hosts 16
tests/load/run.sh network-scan-cli:ci --hosts 32 --config tests/load/config-heavy.yaml \
  --run-id local-heavy --resume-test
```

Manual / scheduled heavy run: **Actions → Load test → Run workflow**.

For a **real-network** load run against your own CIDR (outside CI), use `scripts/load-test.sh <cidr>`.

### Local discovery benchmark (docker lab)

Tuned discovery configs for throughput experiments:

- `scanner/config/discovery-bench.yaml` — fast discovery profile, minimal NSE
- `scanner/config/discovery-bench-realistic.yaml` — adaptive wave-2 + verify, closer to production

Sample inputs: `scanner/inputs/bench/`. The `bench/` harness emulates a private network with
nginx targets and writes JSON metrics (`hostname`, `cpu_count`, `mem_total_mb`, `scan_mode`,
`alive_containers`, `discover_sec`, etc.).

```bash
# 1) Bring up lab network + alive targets (default: 32 nginx on 10.99.0.0/22)
bench/up.sh [alive_hosts] [target_count] [cidr|list]

# 2) Run discovery benchmark (builds image if missing)
bench/run-discovery.sh [alive_hosts] [target_count] [cidr|list]

# 3) Realistic preset: 400 alive hosts, balanced mode, docker resource limits
bench/run-realistic.sh [alive_hosts]

# 4) Tear down network and containers
bench/down.sh
```

Defaults and overrides live in `bench/env.defaults` (`BENCH_NET_NAME`, `BENCH_SUBNET`,
`BENCH_CONFIG`, `BENCH_MODE`, …). Set `BENCH_DOCKER_LIMITS=1` to apply `--memory 8g` and
`--cpus` caps (enabled by default in `run-realistic.sh`). Metrics land in
`scanner/output/bench/<run_id>-metrics.json`.

### Image scanning & SBOM

- **Trivy** scans the built image: a non-blocking report (CRITICAL/HIGH/MEDIUM) plus a gate
  that fails only on **fixable CRITICAL** vulnerabilities. Documented, accepted exceptions
  (e.g. a CVE in an upstream tool binary with no fixed release yet) are listed in
  `.trivyignore` — the report still shows them, only the gate skips them.
- A **CycloneDX/SPDX SBOM** is generated (Syft) and uploaded as the `sbom` CI artifact.
- The publish workflow additionally attaches **SBOM + SLSA provenance attestations** to the
  image pushed to GHCR (`sbom: true`, `provenance: mode=max`).

## Container Image (GHCR)

`.github/workflows/docker-publish.yml` builds multi-arch images (`linux/amd64`, `linux/arm64`)
and pushes them to GitHub Container Registry. It runs when a `v*` tag is pushed, when a GitHub
release is published, or manually via **workflow_dispatch**.

Published product images:

| Image | Dockerfile |
|-------|------------|
| `ghcr.io/onixus/shapoclyack-aio` | `Dockerfile.allinone` (scanner + API + UI, **default**) |
| `ghcr.io/onixus/shapoclyack-scanner` | `Dockerfile` (scanner-only) |
| `ghcr.io/onixus/shapoclyack-api` | `Dockerfile.api` (thin API + Web UI v2) |

Tagging: tag name as image tag (e.g. `shapoclyack-0.33`), semver patterns when the tag is
`v*`-shaped, commit `sha-<...>`, and `latest` on tag/release publishes.
`workflow_dispatch` can publish an extra ad-hoc tag.

Pull and run all-in-one:

```bash
docker pull ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.33
docker compose up
```

Scanner-only:

```bash
docker pull ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.33
docker run --rm \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/scanner/inputs:/app/scanner/inputs" \
  -v "$PWD/scanner/output:/app/scanner/output" \
  -v "$PWD/scanner/config:/app/scanner/config" \
  -v "$PWD/scanner/state:/app/scanner/state" \
  ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.33 --config scanner/config/default.yaml --mode balanced
```

To cut a release build, push a version tag and/or publish a GitHub Release (triggers GHCR publish):

```bash
git tag shapoclyack-0.33 && git push origin shapoclyack-0.33
# or: gh release create shapoclyack-0.33 --generate-notes
```

> The GHCR package may be **private** by default; make it public (or authenticate
> with a token) to pull it from other hosts.

## Reproducible & Pinned Builds

The image is pinned end-to-end so a rebuild is byte-reproducible and protected from
upstream/MITM tampering:

- **Base image** pinned by multi-arch **index digest** (`python:3.12-slim@sha256:...`).
- **dnsx / naabu** pinned by version **and** per-arch **sha256** (`*_SHA256_AMD64/ARM64`
  build args); the downloaded archive is verified with `sha256sum -c` during build.
- **nmap-vulners / vulscan** pinned to specific **commit SHAs** (`NMAP_VULNERS_REF`,
  `VULSCAN_REF`).

Upgrading a pin:

```bash
# base image digest
docker manifest inspect python:3.12-slim | grep -m1 digest
# tool sha256 (from the release checksums file)
curl -fsSL https://github.com/projectdiscovery/dnsx/releases/download/vX.Y.Z/dnsx_X.Y.Z_checksums.txt
# NSE script commit
git ls-remote https://github.com/vulnersCom/nmap-vulners.git HEAD
```

Then update the corresponding `FROM ... @sha256` / `ARG` defaults in the `Dockerfile`
(or override them via `--build-arg`). Because the digest is frozen, re-pin periodically to
pick up base-image security updates (see image scanning in the production hardening backlog).

## Profiles

- `safe`: lower packet rate, `top-100`, conservative timing, `baseline` NSE (no `vuln`), `nse_concurrency: 2`, `nse_max_rate: 500`.
- `balanced`: default profile, `top-1000`, `vuln` NSE + OS detection, `nse_concurrency: 4`, `nse_max_rate: 2000`.
- `fast`: higher discovery/scan rate, `top-1000`, `vuln` NSE + OS detection, `nse_concurrency: 8`, `nse_max_rate: 5000`.

### Vulnerability checking

The NSE stage performs CVE/vulnerability checks driven by `nse_profiles`:

- `vuln`: Nmap `vuln` category **plus** `vulners` — maps detected service versions (`-sV`) to CVEs via the vulners.com API. Wired to `balanced`/`fast`. **Requires outbound internet** for the vulners lookups.
- `vuln-offline`: Nmap `vuln` category **plus** `vulscan` — offline CVE matching against bundled local databases (no internet). Select with `--mode` after setting it as a profile's `nse_profile`, or edit the profile.
- `service_specific`: targeted scripts (`http-*`, `ssl-cert`, `smb-*`, `ssh-*`, `dns-*`) without OS detection — useful for focused service checks.
- `baseline`: non-intrusive `default,safe` only (used by `safe`).

The `nmap-vulners` and `vulscan` scripts are installed into the image at build time
(see `Dockerfile`; pin via `NMAP_VULNERS_REF` / `VULSCAN_REF` build args).

Findings are parsed into structured results: each `CVE` gets a `cvss` score and a derived
`severity` (`critical >= 9.0`, `high >= 7.0`, `medium >= 4.0`, `low > 0`, else `unknown`).
Scripts reporting `State: VULNERABLE` without a CVE are also captured (severity `unknown`).

Tune profile parameters in `scanner/config/default.yaml`.

### Discovery tuning

Under `discovery:` in the config:

```yaml
discovery:
  profile: auto              # auto | fast | balanced | thorough | custom
  skip_discovery: false       # true = treat input IPs as alive (synthetic/load tests)
  skip_known_alive: true      # skip IPs already found in earlier discover batches
  disjoint_batches: true      # parallel discover when batches do not overlap
  adaptive:
    enabled: true             # wave-2 gap fill after wave-1
    min_gap: 1                # minimum gap hosts before wave-2 runs
    wave2_rate: 800           # optional; default ≈ discover_rate / 4
    max_gap_hosts: 65536
  exclude_alive: []           # CIDRs/IPs never marked alive
  exclude_last_octets: []     # e.g. [0, 255]
  verify:
    enabled: false            # re-probe alive hosts with no open ports
    rate: 750                 # optional verify rate
  icmp:
    enabled: false            # fping pre-filter before naabu (large CIDRs)
  tcp_probe:
    enabled: false            # SYN probe on common ports (firewall-heavy nets)
    ports: [80, 443, 22]
  probe_order: [icmp, tcp, naabu]
```

For **firewall-heavy** networks, enable `tcp_probe` (and optionally `icmp`) so hosts blocking ICMP still surface via TCP/80 or /443 before the full `naabu -sn` sweep. Per-method hit counts are written to `discovery_stats.json`.

**Discovery presets** (`discovery.profile: auto` maps from `runtime.mode` — `safe`→thorough, `balanced`→balanced, `fast`→fast):

| Preset | Wave2 | Verify | ICMP | PTR | discover_rate |
|--------|-------|--------|------|-----|---------------|
| fast | skip if coverage ≥95% | off | off | off | ×1.5 |
| balanced | gap ≥ min_gap | off | off | forward only | ×1 |
| thorough | gap ≥ min_gap | on | on | forward+reverse | ×0.75 |

Set `discovery.profile: custom` to keep YAML values without preset overrides.

**Delta discovery** (`discovery.delta.enabled` or `--delta`): probes only hosts new to scope since the previous run's `alive_ips.txt`, plus a random refresh sample of known-alive hosts. Do not use on the first scan, after changing input ranges, or when you need a full baseline.

```yaml
discovery:
  seed_alive_file: scanner/inputs/seed_alive.txt
  delta:
    enabled: false
    previous_run_dir: ""      # default: latest per-run output
    refresh_rate: 0.1         # fraction of known-alive to re-probe
```

Wave-1 splits targets via `batching:` (same rules as ports). When batches are **disjoint**
(e.g. `/22` → four `/24`s), discovery runs with `discover_concurrency` in parallel. Overlapping
batches force sequential discover with `skip_known_alive` to avoid duplicate probes. Adaptive
wave-2 rescans hosts in the scope that wave-1 missed. Delta refresh uses checkpoint stage
`discover-refresh`. Checkpoints: `discover`, `discover-wave2`, `discover-refresh`, and
`discover-hostnames` batch/stage ids.

### Scan protocol (TCP / UDP / TCP+UDP)

Under `ports:` in the config:

```yaml
ports:
  protocol: tcp        # tcp | udp | tcp_udp
  top_udp_ports: 100   # when no custom UDP list
  udp_probes: true     # naabu -uP (protocol payloads for UDP)
  custom_ports_file: scanner/inputs/ports.txt
  custom_udp_ports_file: scanner/inputs/ports_udp.txt
```

- **`tcp`** (default): naabu `-top-ports` / custom TCP list → nmap `-sV` (+ optional `-O`).
- **`udp`**: naabu `-p u:53,u:123,...` with optional `-uP` → nmap `-sU -sV` (OS detection disabled for UDP).
- **`tcp_udp`**: both passes; results in `open_ports.txt` as `host:port/tcp` and `host:port/udp`.

NSE checkpoint keys use `host/tcp` and `host/udp`. Nmap XML lives under `nmap/tcp/` and `nmap/udp/`.

### NSE / OS detection

- `nse_profiles.<name>.scripts`: Nmap `--script` selector (e.g. `default,safe,vuln`).
- `nse_profiles.<name>.os_detection`: enables `nmap -O --osscan-guess`.
- `runtime.nse_concurrency` / `profiles.<name>.nse_concurrency`: number of nmap processes run in parallel.
- `runtime.nse_hosts_per_scan`: hosts scanned per nmap process (default `8`). Reduces nmap
  startup overhead by grouping multiple targets in one invocation; checkpoint remains per host.
- `runtime.discover_concurrency` / `runtime.ports_concurrency`: number of naabu
  discovery/port batches run in parallel (default `4`). Set to `1` for strictly serial
  behavior. Effective pps ≈ `rate × concurrency`.
- `runtime.nse_max_rate` / `profiles.<name>.nse_max_rate`: global packets/sec budget for the NSE/OS stage. It is split across the parallel nmap processes (each gets `nse_max_rate / nse_concurrency` via `nmap --max-rate`). `0` means unlimited (rely on the timing template). This keeps aggregate scan noise bounded regardless of concurrency.
- `runtime.nse_timeout_seconds`: per-host nmap timeout (independent of the global command timeout; max **600** s / 10 min).
- `runtime.skip_nse`: skip the NSE stage (L1 scan). Combine with `--resume` for a two-phase workflow.

OS detection and SYN/ICMP probing require raw sockets. The container is granted
`NET_RAW`/`NET_ADMIN` in the Kubernetes Job/CronJob securityContext (or `--cap-add` for local `docker run`).

## Batching & Resume

Large inputs are split into independent, resumable batches so a single huge
`naabu`/`nmap` run can't hit the global timeout, a failed batch doesn't abort the
whole scan, and `--resume` only redoes what's left.

- IPv4 networks larger than `batching.ipv4_prefix` are split into `/ipv4_prefix`
  batches (e.g. a `/16` becomes 16 × `/20`). Single IPs, IPv6 and smaller nets are
  grouped into chunks of `batching.max_targets_per_batch`.
- Discovery and port-scan run **per batch** (optionally **in parallel** via
  `runtime.discover_concurrency` / `runtime.ports_concurrency`); alive hosts and
  open ports are aggregated incrementally into `alive_ips.txt` / `open_ports.txt`.
  Each parallel naabu process uses the profile `discover_rate` / `port_rate`, so
  effective network load scales with concurrency.
- The NSE/OS stage is checkpointed **per host** — `--resume` skips hosts whose
  scan already completed.
- Progress is tracked in `scanner/state/runs/<run_id>/checkpoint.json` (or flat
  `scanner/state/checkpoint.json` when `per_run_output: false`) with stage flags and
  per-item sets (`discover` / `discover-wave2` / `discover-refresh` / `discover-hostnames`
  / `ports` batch ids, `nse` hosts). Writes are atomic per item and thread-safe.

Tune or disable batching under `batching:` in `scanner/config/default.yaml`
(`enabled`, `ipv4_prefix`, `max_targets_per_batch`). Smaller `ipv4_prefix` means
finer resume granularity at the cost of more tool invocations.

## Output Artifacts

Paths below assume `runtime.per_run_output: true` (default); artifacts live under
`scanner/output/runs/<run_id>/` unless noted.

- `run_meta.json` — run id, profile, config path, timestamps
- `normalized/ip_targets.txt`, `normalized/fqdn_targets.txt`
- `normalized/contract_validation.json` (counts + rejected inputs)
- `dns_resolution.json` / `dnsx_records.jsonl` (DNS resolve data)
- `resolved_ips.txt`, `all_targets.txt`
- `alive_ips.txt` (aggregated; per-batch files under `discover/`)
- `discovery_stats.json` (probe-ladder hit counts: icmp / tcp / naabu)
- `discovery_delta.json` (delta plan when `--delta` or `discovery.delta.enabled`)
- `hostnames.json` (forward + reverse names per alive IP)
- `open_ports.txt` (aggregated; per-batch files under `ports/`)
- `nse_targets.txt`
- `nmap/*` (`.nmap`, `.gnmap`, `.xml`; `nmap/tcp/` and `nmap/udp/` when applicable)
- `findings.{json,jsonl,csv}`
- `alive_hosts.json` (alive list with primary hostname, when hostnames enabled)
- `os_findings.json` (parsed Nmap OS matches)
- `script_findings.json` (all NSE script output)
- `vulnerabilities.json` (structured CVE findings with `cvss`/`severity`, severity-ranked)
- `vulnerabilities.csv` (same findings, flat CSV)
- `summary.{json,md,html}` (includes severity breakdown and hostname counts)
- `diff.json` / `diff.md` (report diff vs previous run when `reporting.diff.enabled`)
- `alerts.json` (notification attempt result when `alerts.enabled` / `--notify`)
- `defectdojo_findings.json` / `defectdojo.json` (DefectDojo payload + status when enabled)
- `summary.pdf` (business PDF when `reporting.pdf_summary`)
- `logs/pipeline.log`

## Notes

- Use only in environments where you are authorized to scan.
- Prefer running from a Linux host/network where raw scanning is allowed.
- High-rate profiles can trigger IDS/IPS and impact network stability.
- If `docker build` fails with Docker socket errors, start Docker daemon/Desktop first.
- Prefer `kubectl apply -k k8s/octo-man/overlays/dev` for day-to-day runs; see [k8s/README.md](k8s/README.md).

## Licenses

This project's own source code (`scanner/`, `api/`, `web/`, `k8s/`, `scripts/`, configs and docs)
has **no license declared yet**. Until a license is added, default copyright applies and
others have no redistribution rights — add a license (e.g. `MIT` or `Apache-2.0`) at the
repository root before publishing.

The container image **bundles third-party tools**, each under its own license. The Python
code only invokes them as separate executables / NSE scripts ("mere aggregation"), so it is
not a derivative work of them. However, **redistributing the built Docker image** must comply
with every license below.

### Runtime tools (bundled in the image)

| Component | Pinned version | License | Notes |
|---|---|---|---|
| Nmap | Debian package | Nmap Public Source License (NPSL) v0.95 | GPLv2-derived custom license with restrictions on certain commercial/OEM redistribution — see <https://nmap.org/npsl/> |
| naabu | `2.6.1` | MIT | ProjectDiscovery |
| dnsx | `1.2.3` | MIT | ProjectDiscovery |
| nmap-vulners | `NMAP_VULNERS_REF` | GPL-3.0 | NSE CVE-lookup script |
| vulscan | `VULSCAN_REF` | GPL-3.0 | NSE script + local CVE databases |

### Base image & OS packages (`python:3.12-slim`, Debian)

| Component | License |
|---|---|
| Python (CPython) | PSF License Agreement |
| ca-certificates (Mozilla CA bundle) | MPL-2.0 |
| curl | curl license (MIT/X11-style) |
| git | GPL-2.0 |
| jq | MIT |
| unzip (build-time only, removed from final image) | Info-ZIP License |

### Python dependencies

| Package | License | Scope |
|---|---|---|
| PyYAML | MIT | runtime (scanner) |
| pydantic | MIT | runtime (scanner + API) |
| FastAPI / Uvicorn / PyJWT / passlib / httpx | MIT / BSD | runtime (API) |
| pytest | MIT | dev/test |
| ruff | MIT | dev/lint |

### Compliance notes

- The image ships **GPL-3.0** components (`nmap-vulners`, `vulscan`) and **NPSL**-licensed Nmap.
  When distributing the image, provide the corresponding source or a written offer as required
  by the GPL, and observe NPSL terms (notably commercial/OEM redistribution restrictions; the
  Nmap Project offers a separate OEM license for such cases).
- The scanner orchestrates these tools via subprocess / NSE and does not statically link them,
  so your own code may use a different license.
- This summary is informational and **not legal advice**; verify the full license texts shipped
  with each component before redistribution.
