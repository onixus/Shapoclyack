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
| Harden the Kubernetes deployment: Pod Security levels, the scanner-executor exception, Kyverno/Gatekeeper | [Kubernetes hardening](k8s-hardening.md) |
| Use the Web UI | [Web interface](ui.md) |
| Diagnose failures | [Troubleshooting](troubleshooting.md) |
| Integrate with the API and understand tenant/RBAC rules | [API and RBAC](api-and-rbac.md) |
| Hand the firewall team what sensors and the API open | [Network requirements](network-requirements.md) |
| Develop or review changes | [Development](development.md) |
| Maintain README, wiki, roadmap and installer guidance | [Documentation maintenance](documentation-maintenance.md) |
| Plan product certification under FSTEC requirements | [FSTEC certification roadmap](fstec-certification.ru.md) 🇷🇺 |
| Install on a single Linux server from prebuilt images | [Server installation](server-install.ru.md) 🇷🇺 |

## Identity, fleet trust and the scan queue

Where the procedures for the enterprise features live. Each row links the
operator procedure first, then the API contract and the variables; all of it is
on `main` after `shapoclyack-0.46-0922` and included in the prepared
`0.47-1009-rc1` candidate (see the changelog).

| Task | Procedure | API and configuration |
|---|---|---|
| Require MFA by role or by a permission held in any tenant, and upgrade an existing MFA policy | [Operations § Upgrading with an MFA policy](operations.md#upgrading-with-an-mfa-policy-tenant-admins-are-now-covered-504) | [Multi-factor authentication](api-and-rbac.md#multi-factor-authentication), [coverage by authority in a tenant](api-and-rbac.md#coverage-by-authority-in-a-tenant-504) |
| Define roles of a tenant's own | [Operations § Tenant-defined roles](operations.md#tenant-defined-roles) | [Tenant-defined roles](api-and-rbac.md#tenant-defined-roles) |
| Make the IdP authoritative and connect SCIM 2.0 | [Operations § Making the IdP authoritative, and SCIM](operations.md#making-the-idp-authoritative-and-scim) | [IdP-authoritative resync](api-and-rbac.md#idp-authoritative-resync), [SCIM 2.0 provisioning](api-and-rbac.md#scim-20-provisioning) |
| Prioritise scans and cap a tenant's concurrent and queued scans | [Operations § Scan queue](operations.md#scan-queue-priority-and-per-tenant-ceilings) | [Queue priority, concurrency and admission](api-and-rbac.md#queue-priority-concurrency-and-admission) |
| Put sensors on client certificates (mTLS) | [Operations § Sensor client certificates](operations.md#sensor-client-certificates) | [Configuration § Sensor and Agent client certificates](configuration.md#sensor-and-agent-client-certificates-mtls) |
| Update native sensors from the signed bundle | [Operations § Sensor bundle updates](operations.md#sensor-bundle-updates) | [Supply chain § The sensor bundle](supply-chain.md#the-sensor-bundle), `OCTO_AGENT_BUNDLE_DIR` / `OCTO_AGENT_AUTO_UPDATE` in [Configuration](configuration.md#environment-variables) |
| Negotiate inventory v2 and migrate Lariska to signed native packages | [Inventory v2 and signed updates](endpoint-inventory-v2.md) | Installation/source completeness, release envelope and installer selection; migrate the server first |
| Publish and audit Lariska Agent builds (platform admin) | [Operations § Endpoint Agent (Lariska) builds](operations.md#endpoint-agent-lariska-builds) | [Sensor fleet, deployment and upgrade](api-and-rbac.md#sensor-fleet-deployment-and-upgrade) |
| Import business context from a CMDB/AD export | [Asset business context](asset-context.md) | `POST /api/assets/import` |
| Understand request rate limits and the body cap | [Operations § When callers start getting 429](operations.md#when-callers-start-getting-429) | [Request rate limiting and body size](api-and-rbac.md#request-rate-limiting-and-body-size) |

What these do **not** cover yet is recorded in
[ROADMAP.md § Enterprise-readiness review](../ROADMAP.md#enterprise-readiness-review-epic-370) —
among others, Lariska cannot present a client certificate, sensor updates are
operator-run unless you enable a timer, and there is no SAML or LDAP.

## Product and UX direction

Shapoclyack is evolving from a scanner-oriented console into a vulnerability and exposure management platform. The implementation plan for that transition lives in [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md) and is tracked by GitHub issues linked from that document.

The roadmap is **planned product behavior**, not documentation of already-delivered UI. For current routes and capabilities, use [Web interface](ui.md).

## Enterprise Wiki and role guides 🇷🇺

Enterprise knowledge base with role-based usage scenarios, security processes, and implementation roadmap (in Russian):

| Guide | Scope |
|---|---|
| [Wiki Portal](wiki/README.md) | Central portal: role guide index, architecture contracts and links to delivery status |
| [Security Engineer Scenarios](wiki/scenarios-security-engineer.md) | Day-to-day operations: scanning, triage, remediation kanban, mechanical re-verification, patch gaps, noise reduction |
| [Architect Scenarios](wiki/scenarios-architect.md) | Architecture: EASM, CMDB/AD export import, sensors in DMZ/VPC, CI/CD DevSecOps, compliance controls |
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
| [Advisory coverage](advisory-coverage.md) | When a package reads `unknown` (no advisory data for the host's release) rather than assessed, and what a loaded dataset does not guarantee |
| [RPM advisories](rpm-advisories.md) | RHEL, SLES and Amazon Linux binary-RPM providers: supported inputs, explicit channel bindings, dataset overrides (#358, feed acceptance still open) |
| [Retro CVE matching](retro-cve-matching.md) | Matching stored service fingerprints against CVEs published after the scan |
| [Web fingerprinting](web-fingerprinting.md) | The one-GET technology catalogue: categories, versions, CPE keys, exposed consoles and remote-access gateways, and what earns the CDN/WAF risk discount |
| [Reports and compliance](reports-and-compliance.md) | Branded report factory (templates, schedules, delivery) and PCI DSS / CIS / ISO 27001 / ФСТЭК / ГОСТ Р 57580.1 control mapping, with what it deliberately does not claim |
| [Custom compliance catalogues](custom-compliance.md) | A customer's own control catalogue mapped onto the platform's evidence signals (W11 / #356), БДУ provenance and signed evidence packages |
| [Asset business context](asset-context.md) | Owner, service, environment, classification, exposure; CMDB/AD file import (`POST /api/assets/import`) and audit trail |
| [Asset identity](asset-identity.md) | When an IP observation and an FQDN observation are treated as one asset, and when they deliberately are not |
| [Troubleshooting](troubleshooting.md) | Startup, authentication, scanner, broker, database, UI diagnostics |
| [Pulse backend](pulse-backend.md) | Pulse service-probe backend and Nmap compatibility choices |
| [Exact Naabu → Pulse endpoints](pulse-endpoints.md) | The exact-endpoint planner and resume between port discovery and Pulse (#448) |
| [Server installation](server-install.ru.md) 🇷🇺 | `scripts/install-server.py`: prebuilt all-in-one image and PostgreSQL via Docker Compose, no build on the server |

## Platform and integration documentation

| Guide | Scope |
|---|---|
| [Architecture](architecture.md) | Components, control-plane behavior, trust boundaries, storage, messaging |
| [API and RBAC](api-and-rbac.md) | Authentication, roles, tenant isolation, principals, endpoint groups |
| [Tenant isolation in the database](tenant-isolation.md) | Row-level security as the second line behind every tenant predicate, `OCTO_TENANT_RLS`, grants, diagnostics |
| [Third-party components](third-party.md) | Runtime dependencies, data sources, licenses, redistribution notes |
| [Supply chain](supply-chain.md) | Signed release images and provenance, verifying them, admission policies, hash-locked Python dependencies, digest-pinned images, Renovate |
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
| [Sizing calibration](sizing-calibration.md) | Checking stand calibration artifacts for the sizing model (#337) — preparation, not the calibration itself |
| [Finding evidence: shadow contract](finding-evidence.md) | Stage 1 of #449: an offline evidence projection beside the production first-wins path, not a replacement for it |
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

This documentation index was reconciled with source baseline `main @ 577bd547` plus the CRL change (#534)
on **2026-10-09**. The documented published baseline is
`shapoclyack-0.46-0922` (2026-09-22). Downloading that release does not install
every feature described on `main`. Use the tagged documentation and
[CHANGELOG.md](../CHANGELOG.md) for its release contract.

The `0.47-1009-rc1` candidate is prepared from `main` at `274310a1` plus the
release-preparation change on **2026-10-09**. See
[candidate notes and validation checklist](releases/0.47-1009-rc1.md).
The stable-release references remain `0.46-0922` until a stable successor is
published.

Recent additions included in the candidate:

| Area | Current guide |
|---|---|
| Tenant MFA coverage, IdP-authoritative OIDC and SCIM, scan queue admission, sensor mTLS and signed sensor bundles | [Identity, fleet trust and the scan queue](#identity-fleet-trust-and-the-scan-queue) |
| Verification detector coverage, observing vantage and unreachable closure | [Vulnerability lifecycle](vulnerability-lifecycle.md) |
| TLS certificate strength, chain trust and explicit probe coverage | [Pulse backend](pulse-backend.md#what-the-probe-checks-and-what-it-can-establish) |
| Structured web technology catalogue and exposed consoles | [Web fingerprinting](web-fingerprinting.md) |
| Confirmed subdomain takeover candidates and bounded HTTP confirmation | [Configuration](configuration.md#subdomain-takeover-detection) |
| Expanded service product matching and distribution backports | [Retro CVE matching](retro-cve-matching.md) |

Open branches and PRs are not part of this contract. Endpoint inventory accepts
**schema v1 and v2** for a mixed fleet; registration/heartbeat advertise v2.
Installation identity, source completeness and signed native **Lariska** updates
are on `main` ([inventory and update contract](endpoint-inventory-v2.md),
migrations `0080`/`0081`). Unsigned executable uploads, offers and downloads
are prohibited, including releases stored by older API versions (#513).
Caller-owned bulk idempotency is contracted by migration `0082` (#517), and
maintenance windows are rechecked when queued work starts (#516).
Signed native **sensor** bundles use a separate update path. Lariska client
certificates remain tracked by #514. Issuer-scoped TLS-terminator CRLs (#515)
are included; deployments must configure publication, refresh and session
handling as described in [Operations](operations.md#tls-revocation-with-a-signed-crl-515). See [the remaining roadmap](../ROADMAP.md).

A source-tree review establishes documented behavior, not a successful
deployment or CI run. Check the exact revision and completed validation for
the build you install.
