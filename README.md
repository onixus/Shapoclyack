# Network Scan CLI (Containerized)

[![CI](https://github.com/onixus/Octo-man/actions/workflows/ci.yml/badge.svg)](https://github.com/onixus/Octo-man/actions/workflows/ci.yml)

English is the primary documentation language.  
For a Russian version with extra operational recommendations, see [README.ru.md](README.ru.md).

Reproducible CLI pipeline for scanning large networks:
- input: `CIDR + IP + FQDN`
- stages: `resolve -> discovery -> hostname enrichment -> fast ports -> Nmap NSE (service/OS detection + vuln/CVE)`
- output: `JSON/JSONL/CSV` + `Markdown/HTML` summary

Latest release: **[v0.2.0](https://github.com/onixus/Octo-man/releases/tag/v0.2.0)** — container image `ghcr.io/onixus/octo-man:0.2.0`.

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
- **Report diffs** (`reporting.diff` / `--compare-run-id`): hosts, ports, and CVE delta vs the previous run → `diff.json` / `diff.md`.
- **Slack / Telegram alerts** (`alerts` / `--notify`): optional post-scan notifications (credentials via env preferred).
- **Task scheduler** (`python -m scanner.scheduler`): cron or interval runner for recurring scans.
- **Phase 2 API + dashboard**: FastAPI backend, React UI, JWT RBAC (`viewer` / `operator` / `admin`).

## Project Layout

- `Dockerfile` / `Dockerfile.api`
- `docker-compose.yml` (`scanner` + `api` services; optional `scheduler` profile)
- `scanner/config/default.yaml` (+ optional `discovery-bench*.yaml` for discovery tuning)
- `scanner/inputs/{ranges.txt,domains.txt,ports.txt,ports_udp.txt}`
- `scanner/main.py`
- `scanner/scheduler.py`
- `scanner/pipeline/*`
- `api/` — FastAPI app (`python -m api`)
- `web/` — React dashboard (Vite); production build served by the API
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

### 1) Build

```bash
docker compose build
```

### 2) Prepare targets

Edit:
- `scanner/inputs/ranges.txt`
- `scanner/inputs/domains.txt`
- optional `scanner/inputs/ports.txt`

### 3) Run a scan

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced
```

> `docker-compose.yml` defaults to `--mode fast` when you run `docker compose up scanner`
> without overriding `command`. Examples below use `balanced` explicitly.

### 4) Resume after interruption

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --resume
```

With per-run output enabled (default), resume continues the latest run recorded in
`scanner/state/latest_run.json`, or pass an explicit id:

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced \
  --resume --run-id 20260626T104530Z
```

### 5) L1 scan, then enrich with NSE later

Run discovery + port scan + reports only (skip NSE), then resume for Nmap/NSE:

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --skip-nse
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --resume
```

Or set `runtime.skip_nse: true` in the config. Useful for large networks: get alive hosts and open ports quickly, enrich in a second pass.

### 6) Incremental (delta) discovery

Re-probe only hosts new to scope since the previous run, plus a random refresh sample of
known-alive hosts. Requires a prior full baseline scan with `per_run_output: true`:

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced --delta
```

Or enable `discovery.delta.enabled: true` in the config. Optional `discovery.seed_alive_file`
pre-seeds alive hosts from CMDB/DHCP before the first delta run. Do **not** use delta on the
first scan, after changing input ranges, or when you need a full baseline.

### 7) Report diffs (Phase 1)

After reports are written, the pipeline compares the current run to the previous one
(from `scanner/state/latest_run.json`, or an explicit path / id):

```bash
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced
# next run automatically writes diff.json / diff.md vs the prior run
docker compose run --rm scanner --config scanner/config/default.yaml --mode balanced \
  --compare-run-id 20260626T104530Z
```

Disable with `--no-diff` or `reporting.diff.enabled: false`. Diff covers alive hosts,
open `host:port` pairs, and structured vulnerabilities.

### 8) Slack / Telegram alerts (Phase 1)

```bash
export OCTO_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export OCTO_TELEGRAM_BOT_TOKEN="123:abc"
export OCTO_TELEGRAM_CHAT_ID="-100123"
docker compose run --rm -e OCTO_SLACK_WEBHOOK -e OCTO_TELEGRAM_BOT_TOKEN -e OCTO_TELEGRAM_CHAT_ID \
  scanner --config scanner/config/default.yaml --mode balanced --notify
```

Or set `alerts.enabled: true` and enable `alerts.slack` / `alerts.telegram` in YAML.
Use `alerts.on_diff_only: true` to notify only when the report diff has changes.
Alert delivery is fail-soft (logged to `alerts.json`; scan exit code stays success).

### 9) Task scheduler (Phase 1)

```bash
# dry-run: print next fire time + command
python -m scanner.scheduler --config scanner/config/default.yaml --dry-run

# single immediate scan (ignores wait)
python -m scanner.scheduler --config scanner/config/default.yaml --once

# compose profile (set scheduler.enabled / cron in YAML, or OCTO_SCHEDULER_ENABLED=true)
docker compose --profile scheduler up scheduler
```

`scheduler.cron` is a 5-field UTC expression; `scheduler.interval_seconds` overrides cron when > 0.
For production hosts, a system crontab calling `docker compose run --rm scanner …` is also fine.

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

```bash
docker compose up --build api
# open http://localhost:8080
```

Local development:

```bash
pip install -r requirements-api.txt
cd web && npm install && npm run build && cd ..
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
| `operator` | Viewer + start/list scan jobs |
| `admin` | Same as operator in this release (reserved for future admin APIs) |

### Key endpoints

- `POST /api/auth/login` → JWT
- `GET /api/auth/me`
- `GET /api/runs`, `GET /api/runs/{run_id}`, `GET /api/runs/{run_id}/vulnerabilities`
- `GET /api/runs/{run_id}/diff`, `GET /api/runs/{run_id}/artifacts/{path}`
- `GET|POST /api/jobs` (operator+)

Scan start from the API image is **off by default** (`OCTO_ALLOW_SCAN_START=false`) because the
API image does not bundle naabu/nmap. Enable it when running the API with the scanner toolchain
available, or start scans via `docker compose run scanner …` and use the UI to inspect results.

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

## Resource limits (Docker Compose)

`docker-compose.yml` sets container limits to reduce the risk of host exhaustion during large
scans: `mem_limit: 8g`, `cpus: "8.0"`, and raised `nproc`/`nofile` ulimits (sized for
`--mode fast`: 8 parallel nmap + 4 parallel naabu batches). Lower for `safe`/`balanced`
on smaller hosts.

## Validation Helpers

- `scripts/smoke.sh`:
  - compiles Python sources;
  - runs pipeline with current input files.
- `scripts/load-test.sh <cidr>`:
  - writes a temporary CIDR target;
  - runs `fast` profile in container.

## Tests

Unit tests cover the pure helpers and parsers: input validation, port grouping,
custom port parsing, IPv6 `host:port` handling, TCP/UDP protocol modes, adaptive
discovery and coverage tracking, NSE rate-budget split, the nmap command builder,
report extraction (services, OS matches, CVE/CVSS + severity ranking), config schema
validation, per-run directory resolution, and load-test result checks.

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check scanner tests
```

## Continuous Integration

`.github/workflows/ci.yml` runs on every push to `master` and on pull requests:

- **lint**: `ruff check`.
- **test**: `compileall` + `pytest` on Python 3.11 and 3.12.
- **image**: builds the image, smoke-checks the toolchain, runs an **end-to-end scan**
  against a throwaway target container, a **light synthetic load test** (16 docker targets),
  scans the image with **Trivy**, and generates a **SBOM** artifact.

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

**CI (every PR):** 16 targets, config `tests/load/config.yaml`.

**Heavy (manual / weekly):** workflow `.github/workflows/load-test.yml` — default **32** targets,
`tests/load/config-heavy.yaml`, per-run dirs, optional mid-scan interrupt + `--resume` on manual
dispatch (scheduled weekly run skips resume).

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

`.github/workflows/docker-publish.yml` builds a multi-arch image (`linux/amd64`, `linux/arm64`)
and pushes it to GitHub Container Registry. It runs when a `v*` tag is pushed, when a GitHub
release is published, or manually via **workflow_dispatch**.

Published as `ghcr.io/onixus/octo-man` (image name is the lowercased `owner/repo`). Tagging:

- a version tag `vX.Y.Z` produces image tags `X.Y.Z`, `X.Y`, `X`, the commit `sha-<...>` and `latest`;
- non-semver tags (e.g. `v0.0.1a`) are published verbatim as the image tag (plus `latest`);
- `workflow_dispatch` can publish an extra ad-hoc tag via the `tag` input.

Pull and run:

```bash
docker pull ghcr.io/onixus/octo-man:latest
docker run --rm \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/scanner/inputs:/app/scanner/inputs" \
  -v "$PWD/scanner/output:/app/scanner/output" \
  -v "$PWD/scanner/config:/app/scanner/config" \
  -v "$PWD/scanner/state:/app/scanner/state" \
  ghcr.io/onixus/octo-man:latest --config scanner/config/default.yaml --mode balanced
```

To cut a release build, push a semver tag (triggers GHCR publish):

```bash
git tag v0.2.0 && git push origin v0.2.0
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
`NET_RAW`/`NET_ADMIN` via `docker-compose.yml`; outside compose run with equivalent capabilities.

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
- `logs/pipeline.log`

## Notes

- Use only in environments where you are authorized to scan.
- Prefer running from a Linux host/network where raw scanning is allowed.
- High-rate profiles can trigger IDS/IPS and impact network stability.
- If `docker compose build` fails with Docker socket errors, start Docker daemon/Desktop first.

## Licenses

This project's own source code (the `scanner/` package, `scripts/`, configs and docs)
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
| PyYAML | MIT | runtime |
| pydantic | MIT | runtime |
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
