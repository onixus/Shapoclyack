# Documentation

This index is the stable entry point for Shapoclyack documentation. Commands
assume the repository root unless a guide says otherwise.

## Operators

| Guide | Use it for |
|---|---|
| [Getting started](getting-started.md) | Start the stack, prepare targets, run and verify a scan |
| [Configuration](configuration.md) | Select profiles, stages, protocols, rates, and enrichment |
| [Web interface](ui.md) | Understand UI surfaces and refresh interface screenshots |
| [Operations](operations.md) | Artifacts, retention, resume, scheduling, alerts, and observability |
| [Troubleshooting](troubleshooting.md) | Diagnose startup, auth, scanner, broker, database, and UI issues |
| [Kubernetes](../k8s/README.md) | Deploy the base and optional overlays |

## Integrators and developers

| Guide | Use it for |
|---|---|
| [Architecture](architecture.md) | Components, trust boundaries, and data flow |
| [API and RBAC](api-and-rbac.md) | Authentication, roles, tenant scope, and endpoint groups |
| [Development](development.md) | Local development, tests, builds, and contribution checks |
| [Endpoint inventory backlog](../Agent_plan.md) | Lariska integration design and completed decisions |
| [Roadmap](../ROADMAP.md) | Delivered and planned platform phases |
| [Changelog](../CHANGELOG.md) | Release and unreleased changes |
| [Third-party components](third-party.md) | Runtime dependencies and license considerations |
| [Security policy](../.github/SECURITY.md) | Supported releases and vulnerability disclosure |

## Documentation conventions

- Examples use reserved documentation networks and `.test` domains.
- Shell blocks are intended to be copied from the repository root.
- Configuration snippets show only relevant keys; merge them into
  `scanner/config/default.yaml` or an environment-specific file.
- `Unreleased` features may exist on `main` but not in the latest image tag.
  Confirm against [CHANGELOG.md](../CHANGELOG.md).
- Secrets in examples are placeholders. Never reuse demo credentials or sample
  keys in an exposed environment.

## Version scope

These guides describe `main` after release `shapoclyack-0.36-0723`. The release
tag is the reference for immutable deployment behavior; `main` can include
additional entries documented under `Unreleased`.
