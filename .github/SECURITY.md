# Security policy

## Supported versions

Security fixes are applied to the latest published release and to `main` while a
fix is being prepared. Older release lines are not maintained indefinitely.

| Version | Support status |
|---|---|
| `0.40-0806` / current `0.40` line | Supported |
| `0.39` | Security fixes only; upgrade recommended |
| `0.38` and older | Unsupported |

Use immutable release tags in production. Do not depend on `latest`.

```bash
docker pull ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.40-0806
docker pull ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.40-0806
docker pull ghcr.io/onixus/shapoclyack-api:shapoclyack-0.40-0806
```

The current release is listed on the repository
[Releases](https://github.com/onixus/Shapoclyack/releases) page. When this file
and the release page disagree, the release page is authoritative until the
policy is corrected.

## Reporting a vulnerability

Do not open public issues for suspected security vulnerabilities.

Use one of these channels:

1. [GitHub private vulnerability reporting](https://github.com/onixus/Shapoclyack/security/advisories/new), preferred;
2. a private draft security advisory in this repository;
3. direct contact with the repository owner through GitHub when private
   reporting is unavailable.

Include enough information to reproduce and assess the issue:

- affected component and version or image tag;
- impact and realistic attack preconditions;
- reproduction steps or a minimal proof of concept;
- tenant, role, deployment, and network assumptions;
- logs or traces with credentials and customer data removed;
- suggested remediation, when available.

The maintainers aim to acknowledge a report within five business days and to
provide a remediation plan or status update within 30 days for confirmed
issues. Actual timelines depend on severity, exploitability, and release risk.

## Scope

### In scope

- Python code under `scanner/`, `api/`, and `agent/`;
- the Next.js console under `web-next/`;
- the Go discovery worker under `recon/`;
- shell helpers shipped under `scripts/` and `bench/`;
- Dockerfiles, Kubernetes manifests, and GitHub Actions workflows;
- authentication, authorization, tenant isolation, provisioning, and remote
  agent trust boundaries;
- unsafe defaults that expose the scanner host, operator credentials, tenant
  data, scan artifacts, or control-plane services;
- packaging or release weaknesses in official GHCR images.

### Out of scope

- vulnerabilities and exposures discovered on operator-provided targets;
- scanning systems without explicit authorization;
- denial of service caused solely by intentionally aggressive scan settings
  against third-party targets;
- upstream vulnerabilities when Shapoclyack does not introduce an unsafe
  integration and a fixed supported upstream release is not yet available;
- findings that require already-compromised cluster-admin or host-root access
  without crossing an additional documented trust boundary.

Accepted image exceptions are documented in [`.trivyignore`](../.trivyignore)
and must be reviewed when affected packages or base images change.

## Safe harbor

Good-faith research is welcome when it:

- stays within the scope above;
- avoids privacy violations, destructive actions, and unnecessary disruption;
- uses the minimum data and traffic needed to demonstrate the issue;
- gives maintainers reasonable time to remediate before public disclosure.

The maintainers will not treat such research as a project policy violation.
This statement does not grant authorization to test infrastructure owned by
third parties.

## Release security controls

Official release workflows include these controls:

- Ruff, compilation, unit, integration, and supported Python-version tests;
- Web UI formatting, linting, type checking, tests, and static-export build;
- Kubernetes manifest validation;
- image build, smoke, end-to-end, and synthetic load checks;
- Trivy reporting and a gate for fixable critical vulnerabilities;
- SPDX SBOM generation and release provenance where configured;
- pinned base image digests, tool checksums, and selected upstream revisions;
- non-root runtime users and workload-specific Linux capabilities.

Passing CI is necessary but not sufficient. Security-sensitive changes must
also document tenant impact, trust boundaries, compatibility, and any required
operator migration.

## Operator security baseline

The architecture and trust-boundary overview is in
[Architecture](../docs/architecture.md). Configuration and deployment details
are in [Configuration](../docs/configuration.md) and
[Kubernetes](../k8s/README.md).

At minimum:

- replace demo JWT secrets, passwords, and provisioning keys before exposing the
  service outside a trusted development environment;
- store credentials in Kubernetes Secrets or an external secret manager;
- restrict API, NATS, PostgreSQL, and ClickHouse network exposure;
- grant `NET_RAW` or `NET_ADMIN` only to scanner workloads that require them;
- never mount the Docker socket into scanner, agent, API, or Web workloads;
- treat scan artifacts, endpoint inventory, banners, findings, and logs as
  sensitive operational data;
- enforce tenant membership and role checks server-side rather than trusting
  client-supplied tenant identifiers;
- use TLS and authenticated transport for remote agents and external service
  integrations;
- pin official image tags and review release notes before upgrading;
- back up persistent data and test restoration before relying on retention or
  migration procedures.

## Security updates

Subscribe to repository Releases and GitHub Security Advisories. Dependency or
base-image fixes are published as new release tags; existing tags are not
silently replaced as a substitute for a documented release.
