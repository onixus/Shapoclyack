# Shapoclyack

Shapoclyack is a self-hosted external attack-surface discovery and vulnerability
management platform. It combines a staged network scanner, a FastAPI control
plane, distributed workers, persistent asset inventory, analytics, and a
Next.js operations console.

[Русская версия](README.ru.md) · [Documentation](docs/README.md) ·
[Kubernetes](k8s/README.md) · [Changelog](CHANGELOG.md) ·
[Roadmap](ROADMAP.md) · [Security policy](.github/SECURITY.md)

> Use Shapoclyack only against systems you own or are explicitly authorized to
> test.

## What you get

| Area | Capability |
|---|---|
| Discovery | CIDR, IP, and FQDN inputs; DNS, CT, ASN, cloud-resource, and domain monitoring stages |
| Scanning | TCP/UDP discovery, service and OS detection, NSE and Nuclei checks |
| Enrichment | CVSS v4, EPSS, CISA KEV, GeoIP, ASN, TLS posture, and fingerprints |
| Inventory | Cross-run assets, identifiers, ownership, criticality, lifecycle, endpoint software |
| Operations | Jobs, schedules, diffs, alerts, reports, remote agents, and resume |
| Platform | JWT RBAC, multi-tenancy, PostgreSQL, ClickHouse, and NATS JetStream |
| Deployment | All-in-one Docker Compose or Kubernetes with Kustomize |

The scanner pipeline is:

```text
targets → resolve → discovery → hostnames → ports → NSE/Nuclei → enrich → report
```

## Quick start

Requirements: Docker with the Compose plugin and at least 4 GB of free memory.

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack

docker compose up --build
```

Open <http://localhost:8080> and sign in as:

```text
operator / operator-change-me
```

Change the development JWT secret and demo passwords before exposing the
service outside a trusted lab. PostgreSQL is required for persistent tenant and
asset inventory:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.postgres.yml \
  --profile postgres \
  up --build
```

Add NATS and ClickHouse when distributed execution and analytics are required:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.postgres.yml \
  -f docker-compose.nats.yml \
  -f docker-compose.clickhouse.yml \
  --profile postgres \
  --profile nats \
  --profile clickhouse \
  up --build
```

See [Getting started](docs/getting-started.md) for targets, profiles, validation,
and first-scan verification.

## Interface

The Web UI provides these primary surfaces:

- exposure dashboard and historical trend;
- persistent asset inventory and asset detail;
- attack-surface graph;
- scan jobs, runs, findings, and reports;
- tenants and remote agent fleet;
- system status and editable safe configuration overrides.

Current interface screenshots and the capture procedure live in
[docs/ui.md](docs/ui.md).

## Deployment choices

| Mode | Best for | Required services |
|---|---|---|
| Scanner CLI | CI, one-shot assessment, troubleshooting | Scanner image only |
| All-in-one | Lab, evaluation, small installation | AIO container; PostgreSQL recommended |
| Distributed Compose | Persistent or multi-worker installation | AIO/API, PostgreSQL, NATS; ClickHouse optional |
| Kubernetes | Production, HA, isolated agents | Kustomize base plus selected overlays |

Detailed guides:

- [Docker and first scan](docs/getting-started.md)
- [Kubernetes](k8s/README.md)
- [Architecture](docs/architecture.md)
- [Configuration and profiles](docs/configuration.md)
- [Operations and data lifecycle](docs/operations.md)

## Repository layout

| Path | Purpose |
|---|---|
| `scanner/` | Discovery, scan, enrichment, diff, and reporting pipeline |
| `api/` | FastAPI control plane, auth, data access, scheduling, and ingest |
| `agent/` | Remote worker that claims and completes scan jobs |
| `web-next/` | Next.js 14 static-export operations console |
| `recon/` | Go-based discovery worker foundation |
| `k8s/octo-man/` | Kubernetes base, overlays, and examples |
| `bench/` | Local discovery benchmark harness |
| `tests/` | Unit, integration, load, and end-to-end tests |

## Inputs and outputs

Default input files:

```text
scanner/inputs/ranges.txt      # CIDR or individual IP, one per line
scanner/inputs/domains.txt     # FQDN, one per line
scanner/inputs/ports.txt       # optional TCP ports
scanner/inputs/ports_udp.txt   # optional UDP ports
```

Each run is isolated under `scanner/output/<run_id>/`. Depending on enabled
stages, artifacts include machine-readable JSON/JSONL/CSV, Markdown/HTML/PDF
reports, scan logs, Nmap XML, diffs, enrichment results, and checkpoints.

See [Operations](docs/operations.md) for artifact handling, exit codes, resume,
retention, and observability.

## API and access

The API is rooted at `/api`; interactive OpenAPI documentation is available at
`/docs` when enabled by the deployment.

| Role | Access |
|---|---|
| `viewer` | Read runs, findings, assets, reports, and system status |
| `operator` | Viewer access plus scan jobs and allowed asset updates |
| `admin` | Operator access plus tenants, provisioning, and configuration |

See [API and RBAC](docs/api-and-rbac.md) for authentication, principal types,
tenant boundaries, and endpoint groups.

## Development

```bash
python -m pytest
ruff check .

cd web-next
npm ci
npm run typecheck
npm run test
npm run build
```

The supported Web UI development runtime is Node.js 24 or newer. See
[Development](docs/development.md) for local API/UI setup and validation.

## Releases

The current documented release is
[`shapoclyack-0.36-0723`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.36-0723).
Published images:

| Image | Role |
|---|---|
| `ghcr.io/onixus/shapoclyack-aio` | API, Web UI, and scanner |
| `ghcr.io/onixus/shapoclyack-api` | API and Web UI |
| `ghcr.io/onixus/shapoclyack-scanner` | Scanner and agent runtime |

Pin a release tag in production. Do not depend on `latest`.

## Support and security

- Operational problems: [Troubleshooting](docs/troubleshooting.md)
- Vulnerability reporting and supported versions:
  [Security policy](.github/SECURITY.md)
- Planned work: [Roadmap](ROADMAP.md)
- Release history: [Changelog](CHANGELOG.md)

## License notes

Shapoclyack integrates third-party scanners and data sources under their own
licenses. Review image contents and redistribution terms—especially the Nmap
Public Source License—before commercial redistribution. See
[Third-party components](docs/third-party.md).
