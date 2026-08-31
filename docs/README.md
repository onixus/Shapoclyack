# Shapoclyack documentation

This directory is the stable entry point for Shapoclyack documentation. Use it before hunting through release notes, PR descriptions, or source files like a digital archaeologist.

Commands assume the repository root unless a guide explicitly says otherwise.

## Start here

| Goal | Authoritative guide |
|---|---|
| Evaluate the platform and run a first scan | [Getting started](getting-started.md) |
| Understand components, trust boundaries, and data flow | [Architecture](architecture.md) |
| Configure scanning, enrichment, and runtime settings | [Configuration](configuration.md) |
| Deploy or upgrade Kubernetes workloads | [Kubernetes deployment](../k8s/README.md) |
| Operate, monitor, back up, and recover the platform | [Operations](operations.md) |
| Use the Web UI | [Web interface](ui.md) |
| Diagnose failures | [Troubleshooting](troubleshooting.md) |
| Integrate with the API and understand tenant/RBAC rules | [API and RBAC](api-and-rbac.md) |
| Develop or review changes | [Development](development.md) |

## Product and UX direction

Shapoclyack is evolving from a scanner-oriented console into a vulnerability and exposure management platform. The implementation plan for that transition lives in [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md) and is tracked by GitHub issues linked from that document.

The roadmap is **planned product behavior**, not documentation of already-delivered UI. For current routes and capabilities, use [Web interface](ui.md).

## Operator documentation

| Guide | Scope |
|---|---|
| [Getting started](getting-started.md) | Local deployment, target preparation, first scan, validation |
| [Configuration](configuration.md) | Profiles, stages, protocols, rates, enrichment, safe overrides |
| [Web interface](ui.md) | Current UI routes, tenant context, workflows, screenshot maintenance |
| [Operations](operations.md) | Scheduling, artifacts, retention, resume, alerts, metrics, backups |
| [Service level objectives](slo.md) | SLIs, targets, error budgets, measurement gaps |
| [Risk scoring](risk-scoring.md) | NIST SP 800-30 model, exploit maturity (PoC vs theoretical), asset criticality |
| [Vulnerability lifecycle](vulnerability-lifecycle.md) | Tracked findings, states, SLA, exceptions, audit trail |
| [Software → CVE matching](software-cve-matching.md) | Endpoint inventory matched against vendor advisories; statuses, offline datasets, and what it does not cover |
| [Asset business context](asset-context.md) | Owner, service, environment, classification, exposure; CMDB/AD-ready audit trail |
| [Troubleshooting](troubleshooting.md) | Startup, authentication, scanner, broker, database, UI diagnostics |
| [Pulse backend](pulse-backend.md) | Pulse service-probe backend and Nmap compatibility choices |

## Platform and integration documentation

| Guide | Scope |
|---|---|
| [Architecture](architecture.md) | Components, control-plane behavior, trust boundaries, storage, messaging |
| [API and RBAC](api-and-rbac.md) | Authentication, roles, tenant isolation, principals, endpoint groups |
| [Third-party components](third-party.md) | Runtime dependencies, data sources, licenses, redistribution notes |
| [Security policy](../.github/SECURITY.md) | Supported versions, disclosure, release controls, operator baseline |

## Engineering and planning documentation

| Guide | Scope |
|---|---|
| [Development](development.md) | Toolchains, local setup, tests, builds, review checklist |
| [Scale profile](scale-profile.md) | Measured behavior at 1k/10k/50k assets and resulting fixes |
| [Scan performance](scan-performance.md) | Faster scans without more hardware: stage timings, intents, delta |
| [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md) | Planned VM/Exposure Management UI and backend dependencies |
| [Endpoint inventory design record](../Agent_plan.md) | Lariska integration history and design decisions; not the general product roadmap |
| [Roadmap](../ROADMAP.md) | Product delivery phases and remaining work |
| [ProjectDiscovery integration concept](projectdiscovery-integration-concept.md) | Architecture concept and scenarios for expanding ProjectDiscovery tools |
| [Changelog](../CHANGELOG.md) | Released and unreleased behavior changes |

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

These guides describe `main` after release `shapoclyack-0.43-0828`. Release tags are immutable deployment references; `main` may contain additional behavior listed under `Unreleased` in [CHANGELOG.md](../CHANGELOG.md).
