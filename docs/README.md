# Shapoclyack documentation

This directory is the stable entry point for Shapoclyack documentation. Use it before hunting through release notes, PR descriptions, or source files like a digital archaeologist.

Commands assume the repository root unless a guide explicitly says otherwise.

## Terminology

Three words are used precisely throughout these guides:

- **Sensor** — a remote scanning node. It runs `agent/worker.py`, claims scan jobs from the API (over NATS JetStream or by HTTPS polling), executes the scanner (nmap/httpx/nuclei/…) and uploads the results. Registered in the `agents` table with `agent_kind = "scanner"`.
- **Agent** — the Lariska in-guest endpoint inventory agent installed on a managed host. It submits inventory snapshots to `POST /api/endpoint/inventory` and never claims scan jobs. Registered in the same `agents` table with `agent_kind = "endpoint"`.
- **Endpoint** — a managed host that has the Agent installed.

The bare word "agent" always means the Lariska endpoint Agent; anything that claims jobs and runs scans is a sensor. Code identifiers were not renamed: the Python package `agent/`, the `agents` table and `/api/agents/*` routes, the `OCTO_AGENT_*` variables, the k8s `agents` overlay and the console page at `/agents` (titled "Sensor Fleet") all keep their names and are described as "the sensor (API resource `agents`)" in prose.

## Start here

| Goal | Authoritative guide |
|---|---|
| Evaluate the platform and run a first scan | [Getting started](getting-started.md) |
| Demonstrate scan → remediation → mechanical re-verification | [Closed-loop remediation demo](demo-remediation-loop.md) |
| Read the Enterprise Wiki & role scenarios | [Enterprise Wiki (База знаний)](wiki/README.md) 🇷🇺 |
| Understand components, trust boundaries, and data flow | [Architecture](architecture.md) |
| Configure scanning, enrichment, and runtime settings | [Configuration](configuration.md) |
| Deploy or upgrade Kubernetes workloads | [Kubernetes deployment](../k8s/README.md) |
| Operate, monitor, back up, and recover the platform | [Operations](operations.md) |
| Run a profile that survives a node loss | [High availability](high-availability.md) |
| Recover from losing a datastore or the whole cluster | [Disaster recovery](disaster-recovery.md) |
| Use the Web UI | [Web interface](ui.md) |
| Diagnose failures | [Troubleshooting](troubleshooting.md) |
| Integrate with the API and understand tenant/RBAC rules | [API and RBAC](api-and-rbac.md) |
| Hand the firewall team what sensors and the API open | [Network requirements](network-requirements.md) |
| Develop or review changes | [Development](development.md) |
| Plan product certification under FSTEC requirements | [FSTEC certification roadmap](fstec-certification.ru.md) 🇷🇺 |

## Product and UX direction

Shapoclyack is evolving from a scanner-oriented console into a vulnerability and exposure management platform. The implementation plan for that transition lives in [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md) and is tracked by GitHub issues linked from that document.

The roadmap is **planned product behavior**, not documentation of already-delivered UI. For current routes and capabilities, use [Web interface](ui.md).

## Enterprise Wiki and role guides 🇷🇺

Enterprise knowledge base with role-based usage scenarios, security processes, and implementation roadmap (in Russian):

| Guide | Scope |
|---|---|
| [Wiki Portal](wiki/README.md) | Central portal: concept, data model, NIST SP 800-30, mechanical verification, index |
| [Security Engineer Scenarios](wiki/scenarios-security-engineer.md) | Day-to-day operations: scanning, triage, remediation kanban, mechanical re-verification, patch gaps, noise reduction |
| [Architect Scenarios](wiki/scenarios-architect.md) | Architecture: EASM, CMDB/AD integration, sensors in DMZ/VPC, CI/CD DevSecOps, compliance controls |
| [CISO Scenarios](wiki/scenarios-ciso.md) | Executive view: Risk Overview (NIST SP 800-30), CISA KEV threats, SLA & adoption metrics, board reporting |
| [Security Processes](wiki/security-processes.md) | Formal VM lifecycle, EASM, emergency 0-day response, IT/DevOps SLA collaboration |
| [Implementation Plan](wiki/implementation-plan.md) | 12-week enterprise rollout roadmap, milestones M1–M4, RACI matrix, deployment models, KPIs |

## Operator documentation

| Guide | Scope |
|---|---|
| [Getting started](getting-started.md) | Local deployment, target preparation, first scan, validation |
| [Closed-loop remediation demo](demo-remediation-loop.md) | Promotion/evaluation path from tracked finding to targeted re-scan and verified closure |
| [Configuration](configuration.md) | Profiles, stages, protocols, rates, enrichment, safe overrides |
| [Web interface](ui.md) | Current UI routes, tenant context, workflows, screenshot maintenance |
| [Operations](operations.md) | Scheduling, artifacts, retention, resume, alerts, metrics, backups |
| [Data retention](data-retention.md) | What is kept and for how long, per-tenant windows, legal hold, console users' data export and erasure — the DPA annex |
| [Tenant lifecycle](tenant-lifecycle.md) | Suspending and resuming a tenant, two-step deletion, the store-by-store purge, its journal and tombstones, re-applying deletions after a restore |
| [High availability](high-availability.md) | The `prod-ha` overlay: multi-replica API, NATS cluster, external PostgreSQL — its prerequisites and its limits |
| [Sizing](sizing.md) | CPU, memory and volumes for N assets / M sensors / K scans a day: the model, measured coefficients, and re-measuring them on your stand |
| [Disaster recovery](disaster-recovery.md) | Backup and restore of PostgreSQL, ClickHouse, artifacts and JetStream; restore order, reconciling restore points, RPO/RTO, the drill |
| [Network requirements](network-requirements.md) | Ports and directions for sensors, the cluster and the API; proxies, CA bundles, NATS on 443, upload shaping |
| [Air-gapped installation](air-gap.md) | Images by digest from an internal registry, pull secrets, feed mirrors, the offline enrichment bundle, and what stays unavailable offline |
| [Service level objectives](slo.md) | SLIs, targets, error budgets, measurement gaps |
| [Observability](observability.md) | Metrics catalogue and label bounds, Grafana dashboards, opt-in ServiceMonitor/PrometheusRule components, pool and sensor alerts |
| [Risk scoring](risk-scoring.md) | NIST SP 800-30 model, exploit maturity (PoC vs theoretical), asset criticality |
| [Vulnerability lifecycle](vulnerability-lifecycle.md) | Tracked findings, states, SLA, exceptions, audit trail |
| [Software → CVE matching](software-cve-matching.md) | Endpoint inventory matched against vendor advisories; statuses, offline datasets, and what it does not cover |
| [Reports and compliance](reports-and-compliance.md) | Branded report factory (templates, schedules, delivery) and PCI DSS / CIS / ISO 27001 / ФСТЭК / ГОСТ Р 57580.1 control mapping, with what it deliberately does not claim |
| [Asset business context](asset-context.md) | Owner, service, environment, classification, exposure; CMDB/AD-ready audit trail |
| [Asset identity](asset-identity.md) | When an IP observation and an FQDN observation are treated as one asset, and when they deliberately are not |
| [Troubleshooting](troubleshooting.md) | Startup, authentication, scanner, broker, database, UI diagnostics |
| [Pulse backend](pulse-backend.md) | Pulse service-probe backend and Nmap compatibility choices |

## Platform and integration documentation

| Guide | Scope |
|---|---|
| [Architecture](architecture.md) | Components, control-plane behavior, trust boundaries, storage, messaging |
| [API and RBAC](api-and-rbac.md) | Authentication, roles, tenant isolation, principals, endpoint groups |
| [Third-party components](third-party.md) | Runtime dependencies, data sources, licenses, redistribution notes |
| [Security policy](../.github/SECURITY.md) | Supported versions, disclosure, release controls, operator baseline |
| [Release contract](release-contract.md) | What a release ships, the Pulse support and update policy, and how a customer verifies the images |

## Engineering and planning documentation

| Guide | Scope |
|---|---|
| [Development](development.md) | Toolchains, local setup, tests, builds, review checklist |
| [Architecture decision records](adr/README.md) | Cross-component decisions and their status — currently the proposed Pulse distribution model |
| [FSTEC certification roadmap](fstec-certification.ru.md) 🇷🇺 | Certified boundary, УД4 planning baseline, evidence set, supply-chain and test traceability |
| [Architecture review — 2026-09-18](architecture-review-2026-09-18.ru.md) 🇷🇺 | Source-based assessment, ingestion risks, priorities, and local validation limits |
| [Scale profile](scale-profile.md) | Measured behavior at 1k/10k/50k assets and resulting fixes |
| [Scan performance](scan-performance.md) | Faster scans without more hardware: stage timings, intents, delta |
| [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md) | Planned VM/Exposure Management UI and backend dependencies |
| [Endpoint inventory design record](../Agent_plan.md) | Lariska integration history and design decisions; not the general product roadmap |
| [Roadmap](../ROADMAP.md) | Product delivery phases and remaining work |
| [ProjectDiscovery integration concept](projectdiscovery-integration-concept.md) 🇷🇺 | Architecture concept and scenarios for expanding ProjectDiscovery tools |
| [Организационный профиль (org_profile)](org-profile-module.ru.md) 🇷🇺 | Design record for the organization-profile module: ownership, related domains, DNS hygiene, mail posture, credential leaks, controls |
| [Changelog](../CHANGELOG.md) | Released and unreleased behavior changes |

Guides marked 🇷🇺 are written in Russian; everything else is English. The two
READMEs are the only pair kept in both languages.

## Source-of-truth rules

Avoid repeating the same operational truth in several documents. When documents overlap, use this order:

| Subject | Source of truth |
|---|---|
| Current user-facing product summary | `README.md` / `README.ru.md` |
| Current UI routes and behavior | `docs/ui.md` |
| API contract and authorization | OpenAPI + `docs/api-and-rbac.md` |
| Architecture and trust boundaries | `docs/architecture.md` |
| Configuration keys and profiles | `docs/configuration.md` and the configuration schema/defaults |
| Kubernetes topology and manifests | `k8s/README.md` + rendered manifests |
| Runtime operations and recovery | `docs/operations.md` |
| Planned work | `ROADMAP.md` and linked GitHub issues |
| Release-specific behavior | `CHANGELOG.md` and GitHub Releases |
| Security support/disclosure | `.github/SECURITY.md` |
| Release artifacts, Pulse policy, customer verification | `docs/release-contract.md` |

If prose disagrees with executable code, generated OpenAPI, or rendered manifests, treat that as a documentation defect and fix the prose rather than inventing a second truth.

## Documentation ownership

Documentation is part of the feature definition. A behavior change is incomplete when its authoritative guide is stale.

| Change type | Required documentation |
|---|---|
| User-visible UI behavior | `docs/ui.md`; root README only when the top-level product description changes |
| API, role, tenant, or principal behavior | `docs/api-and-rbac.md` |
| Deployment or environment variables | `docs/configuration.md` and/or `k8s/README.md` |
| Runtime lifecycle, storage, retention, recovery | `docs/operations.md` |
| Architecture or trust boundaries | `docs/architecture.md`; security policy when relevant |
| Developer workflow or validation | `docs/development.md` |
| Planned product behavior | `ROADMAP.md` or a focused design/roadmap document plus issues |
| Released behavior | `CHANGELOG.md`; update `ROADMAP.md` when a planned item lands |

## Documentation conventions

- Use reserved documentation networks and `.test` domains in examples.
- Write shell commands so they can be copied from the repository root.
- Show only relevant configuration keys and state where they belong.
- Label behavior that exists only on `main` and has not shipped in the latest release.
- Never include real credentials, targets, customer names, tokens, or internal infrastructure details.
- Prefer relative Markdown links for repository content.
- Keep headings task-oriented.
- Link to the authoritative procedure instead of copying it into another guide.
- Verify commands, routes, image tags, environment variables, and paths against current code or manifests before merging.

## Version scope

These guides describe `main` after release `shapoclyack-0.46-0922`. Release tags are immutable deployment references; `main` may contain additional behavior listed under `Unreleased` in [CHANGELOG.md](../CHANGELOG.md).
