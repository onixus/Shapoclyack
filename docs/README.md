# Shapoclyack documentation

This directory is the stable entry point for operator, administrator,
integrator, and developer documentation. Commands assume the repository root
unless a guide explicitly says otherwise.

## Start here

| Goal | Guide |
|---|---|
| Evaluate the platform locally | [Getting started](getting-started.md) |
| Understand the system design | [Architecture](architecture.md) |
| Configure scan profiles and integrations | [Configuration](configuration.md) |
| Deploy on Kubernetes | [Kubernetes deployment](../k8s/README.md) |
| Operate and monitor the platform | [Operations](operations.md) |
| Diagnose a failure | [Troubleshooting](troubleshooting.md) |
| Develop or contribute changes | [Development](development.md) |

## Operator documentation

| Guide | Scope |
|---|---|
| [Getting started](getting-started.md) | Local deployment, target preparation, first scan, and validation |
| [Configuration](configuration.md) | Profiles, stages, protocols, rates, enrichment, and safe overrides |
| [Web interface](ui.md) | Dashboard surfaces, workflows, and screenshot maintenance |
| [Operations](operations.md) | Scheduling, artifacts, retention, resume, alerts, metrics, and backup considerations |
| [Service level objectives](slo.md) | SLIs, targets, error-budget policy, and known measurement gaps |
| [Troubleshooting](troubleshooting.md) | Startup, authentication, scanner, broker, database, and UI diagnostics |
| [Pulse backend](pulse-backend.md) | Pulse service-probe backend and Nmap compatibility choices |

## Platform and integration documentation

| Guide | Scope |
|---|---|
| [Architecture](architecture.md) | Components, trust boundaries, storage, messaging, and data flow |
| [API and RBAC](api-and-rbac.md) | Authentication, roles, tenant isolation, principals, and endpoint groups |
| [Third-party components](third-party.md) | Runtime dependencies, data sources, licenses, and redistribution notes |
| [Security policy](../.github/SECURITY.md) | Supported versions, disclosure process, release controls, and operator guidance |

## Engineering documentation

| Guide | Scope |
|---|---|
| [Development](development.md) | Toolchains, local setup, tests, builds, documentation rules, and review checklist |
| [Scale profile](scale-profile.md) | Measured query cost at 1k/10k/50k assets, the fixes it produced, and the `PARTITION BY` evaluation |
| [Endpoint inventory plan](../Agent_plan.md) | Lariska integration design, delivered decisions, and remaining backlog |
| [Roadmap](../ROADMAP.md) | Product phases and planned work |
| [Changelog](../CHANGELOG.md) | Released and unreleased behavior changes |

## Documentation ownership

Documentation changes are part of the feature definition, not post-release
cleanup. A change is incomplete when it modifies behavior without updating the
corresponding guide.

Use this ownership map:

| Change type | Required documentation |
|---|---|
| User-visible behavior | Root README or `docs/ui.md`, plus the relevant operator guide |
| API, role, or tenant behavior | `docs/api-and-rbac.md` |
| Deployment or environment variables | `docs/configuration.md` and/or `k8s/README.md` |
| Runtime lifecycle, storage, retention, or recovery | `docs/operations.md` |
| Architecture or trust boundaries | `docs/architecture.md` and security policy when relevant |
| Developer workflow or validation | `docs/development.md` |
| Released behavior | `CHANGELOG.md`; update `ROADMAP.md` when a planned item is delivered |

## Documentation conventions

- Use reserved documentation networks and `.test` domains in examples.
- Write shell commands so they can be copied from the repository root.
- Show only relevant configuration keys and state where they belong.
- Label behavior that exists only on `main` and is not yet in a release.
- Never include real credentials, targets, customer names, tokens, or internal
  infrastructure details in examples or screenshots.
- Prefer relative Markdown links for repository content.
- Keep headings task-oriented and avoid duplicating the same procedure across
  several files; link to the authoritative guide instead.
- Verify commands, paths, image tags, and environment variable names against the
  current code or manifests before merging.

## Version scope

These guides describe `main` after release `shapoclyack-0.40-0806`. Release tags
are immutable deployment references; `main` may include additional behavior
listed under `Unreleased` in [CHANGELOG.md](../CHANGELOG.md).
