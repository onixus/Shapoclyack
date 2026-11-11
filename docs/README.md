# Shapoclyack documentation

This directory is the stable entry point for Shapoclyack documentation. Use it before hunting through release notes, PR descriptions, or source files like a detective.

Commands assume the repository root unless a guide explicitly says otherwise.

Optional AI operator: [architecture and acceptance](local-operator.md),
[local/xAI/OpenRouter/OmniRouter/OpenAI-compatible providers](local-operator-providers.md),
[local inference on a Windows 12 GB GPU](local-operator-windows.md), and
[authenticated read-only MCP](mcp.md). The [durable session/queue/worker pilot](local-operator-service.md) adds one
read-only summary flow. The operator console and runtime/GPU acceptance remain pending.

## Terminology

Three words are used precisely throughout these guides:

* **Sensor** — a remote scanning node. It runs `agent/worker.py`, claims scan jobs from the API (over NATS JetStream or by HTTPS polling), executes the scanner (pulse/httpx/nuclei/...) and uploads the results. Registered in the `agents` table with `agent_kind = "scanner"`.

* **Agent** — the Lariska in-guest endpoint inventory agent installed on a managed host. It submits inventory snapshots to `POST /api/endpoint/inventory` and never claims scan jobs. Registered in the same `agents` table with `agent_kind = "endpoint"`.

* **Endpoint** — a managed host that has the Agent installed.

The bare word "agent" always means the Lariska endpoint Agent; anything that claims jobs and runs scans is a sensor. Code identifiers were not renamed: the Python package `agent/`, the `agents` table and `/api/agents/*` routes, the `OCTO_AGENT_*` variables, the k8s `agents` overlay and the console page at `/agents` (titled "Sensor Fleet") all keep their names and are described as "the sensor (API resource `agents`)" in prose.

## Start here

| Goal | Authoritative guide | 
| ----- | ----- | 
| Evaluate the platform and run a first scan | [Getting started](getting-started.md) | 
| Demonstrate scan -> remediation -> mechanical re-verification | [Closed-loop remediation demo](demo-remediation-loop.md) | 
| Read the Enterprise Wiki & role scenarios | [Enterprise Wiki (База знаний)](wiki/README.md) 🇷🇺 | 
| Understand components, trust boundaries, and data flow | [Architecture](architecture.md) | 
| Configure scanning, enrichment, decoupled Rhai plugins, and runtime settings | [Configuration](configuration.md) | 
| Classify assets with explainable rules and protected context | [Dynamic asset groups](dynamic-asset-groups.md) | 
| Decide which shared problem to fix first and track a fleet-wide fix finding by finding | [Problems and remediation campaigns](remediation-campaigns.md) | 
| Deploy or upgrade Kubernetes workloads | [Kubernetes / Kustomize](../k8s/README.md), [Helm chart](helm.md) | 
| Deploy with Helm instead of kustomize: values, existing Secrets, External Secrets, OCI publishing | [Helm chart](helm.md) | 
| Understand host inventory and credentialed-scanning coverage | [Coverage boundaries](operations.md#credentialed-scanning-scope-and-coverage-368) | 
| Operate, monitor, back up, and recover the platform | [Operations](operations.md) | 
| Run a profile that survives a node loss | [High availability](high-availability.md) | 
| Recover from losing a datastore or the whole cluster | [Disaster recovery](disaster-recovery.md) | 
| Harden the Kubernetes deployment: Pod Security levels, the scanner-executor exception, Kyverno/Gatekeeper | [Kubernetes hardening](k8s-hardening.md) | 
| Use the Web UI (APEX console, 1440px board, unified navigation tabs, dark/light themes) | [Web interface](ui.md), [Console design system](console-design-system.md) | 
| Diagnose failures | [Troubleshooting](troubleshooting.md) | 
| Integrate with the API and understand tenant/RBAC/SAML SLO rules | [API and RBAC](api-and-rbac.md), [API v1, exports and Python client](api-versioning.md) | 
| Hand the firewall team what sensors and the API open | [Network requirements](network-requirements.md) | 
| Develop or review changes | [Development](development.md) | 
| Maintain README, wiki, roadmap and installer guidance | [Documentation maintenance](documentation-maintenance.md) | 
| Plan product certification under FSTEC / 187-FZ requirements and BDU threat mapping | [FSTEC certification roadmap](fstec-certification.ru.md) 🇷🇺, [Reports and compliance](reports-and-compliance.md) | 

## Topic map

```
docs/
├── getting-started.md
├── demo-remediation-loop.md
├── wiki/ (База знаний / Enterprise Wiki) 🇷🇺
├── architecture.md
├── configuration.md
├── dynamic-asset-groups.md
├── remediation-campaigns.md
├── helm.md
├── operations.md
├── high-availability.md
├── disaster-recovery.md
├── k8s-hardening.md
├── ui.md
├── console-design-system.md
├── troubleshooting.md
├── api-and-rbac.md
├── api-versioning.md
├── network-requirements.md
├── development.md
├── documentation-maintenance.md
├── fstec-certification.ru.md 🇷🇺
├── local-operator.md
├── local-operator-providers.md
├── local-operator-windows.md
├── local-operator-service.md
├── mcp.md
├── vulnerability-lifecycle.md
├── pulse-backend.md
├── web-fingerprinting.md
├── endpoint-inventory-v2.md
├── nmap-migration.md
├── shared-scan-execution.md
├── finding-evidence.md
├── retro-cve-matching.md
├── releases/
│   ├── 0.47-1009-rc1.md
│   ├── 0.48-1021.md
│   └── 0.49-1111-rc1.md
└── adr/

```

## Detailed guide matrix

| Guide | Primary audience | Core topics | 
| ----- | ----- | ----- | 
| [Getting started](getting-started.md) | Operators, Evaluators | Quick installation, verification scan, initial UI login | 
| [Closed-loop remediation demo](demo-remediation-loop.md) | Evaluators, Security Engineers | End-to-end verification of detection, remediation, and re-scan | 
| [Enterprise Wiki (База знаний)](wiki/README.md) 🇷🇺 | Security Leads, Analysts | Role-based scenarios, architecture deep-dive, compliance maps | 
| [Architecture](architecture.md) | Architects, Security Leads | High-level component interactions, trust zones, security model | 
| [Configuration](configuration.md) | Administrators | Environment variables, scan limits, Pulse Rhai plugin sources, engine knobs, feature flags | 
| [Dynamic asset groups](dynamic-asset-groups.md) | Security Analysts, Fleet Owners | Tagging rules, expression language, protected scope definitions | 
| [Problems and remediation campaigns](remediation-campaigns.md) | Security Leads, Remediation Teams | Deduplication rules, `/api/problems` and `/api/remediation-campaigns` workflows, verification triggers | 
| [Helm chart](helm.md) | DevOps / K8s Admins | Helm deployment values, ingress setup, external database secrets | 
| [Operations](operations.md) | Systems Administrators | Fleet management, L2 neighbour limits (`scripts/neigh-table-limits.sh`), logging, monitoring metrics, backup schedules | 
| [High availability](high-availability.md) | Infrastructure Engineers | Multi-node deployments, API statelessness, database clustering | 
| [Disaster recovery](disaster-recovery.md) | SRE, Administrators | Backup restoration, database point-in-time recovery, cluster rebuild | 
| [Kubernetes hardening](k8s-hardening.md) | Security Engineers | Pod Security Standards, network policies, runtime enforcement | 
| [Web interface](ui.md) | All Users | APEX console navigation tabs, 1440px multi-stage board, dark/light themes, report exporting | 
| [Console design system](console-design-system.md) | UI Developers | Component library, color tokens, dark/light theme tokens, 1440px layout guidelines | 
| [Troubleshooting](troubleshooting.md) | Operators, Developers | Log analysis, common failure patterns, diagnostic commands | 
| [API and RBAC](api-and-rbac.md) | Integrators, Developers | OpenAPI endpoints, role matrix, SAML SLO session binding, token management | 
| [API v1, exports and Python client](api-versioning.md) | Developers, Script Writers | Versioning guarantees, SDK usage, structured export formats | 
| [Network requirements](network-requirements.md) | Network Engineers | Required inbound/outbound ports, proxy configuration | 
| [Development](development.md) | Contributors | Building, testing, local environment setup, pull request guidelines | 
| [Documentation maintenance](documentation-maintenance.md) | Technical Writers, Maintainers | Style guide, link validation, docs lifecycle | 
| [FSTEC certification roadmap](fstec-certification.ru.md) 🇷🇺 | Compliance Officers | 187-FZ regulatory mapping, BDU threat sync (`scripts/fetch-bdu-threats.py`), audit readiness | 
| [Local AI operator](local-operator.md) | Security Analysts | Local LLM setup, agentic workflows, execution safety bounds | 
| [AI operator providers](local-operator-providers.md) | Systems Engineers | Model provider adapters (`local`, `xai`, `openrouter`, `omnirouter`, `openai_compatible`) with public endpoint verification | 
| [Windows AI inference](local-operator-windows.md) | Workstation Admins | Running local operator models on Windows consumer GPUs | 
| [AI operator service](local-operator-service.md) | DevOps, Developers | Background worker queue for asynchronous LLM tasks | 
| [Model Context Protocol (MCP)](mcp.md) | AI Engineers | Read-only MCP server configuration for external tools | 
| [Vulnerability lifecycle](vulnerability-lifecycle.md) | Security Analysts | State transitions, re-testing rules, auto-closure logic | 
| [Pulse scanner backend](pulse-backend.md) | Security Engineers | Pulse `v1.5.0` native network discovery engine, 60+ Rhai protocol probes (phases 1–9), report schema v3, RDP X.224 observations | 
| [Web fingerprinting](web-fingerprinting.md) | Security Analysts | HTTP header parsing, HTML pattern matching, technology stack detection | 
| [Endpoint inventory v2](endpoint-inventory-v2.md) | Systems Admins | Lariska agent protocol v2, host telemetry collection | 
| [Nmap migration guide](nmap-migration.md) | Systems Admins | Migrating legacy configurations to Pulse native scanner (Nmap binaries/configs rejected) | 
| [Shared scan execution](shared-scan-execution.md) | SRE, Security Engineers | Multi-tenant worker sharing, resource limits, job isolation | 
| [Finding evidence format](finding-evidence.md) | Integrators | JSON evidence schema, payload verification, proof structure | 
| [Retro CVE matching](retro-cve-matching.md) | Analysts | Historical vulnerability matching on updated intelligence feeds | 

## Documentation ownership

Documentation is part of the feature definition. A behavior change is incomplete when its authoritative guide is stale.

| Change type | Required documentation | 
| ----- | ----- | 
| User-visible UI behavior | `docs/ui.md`; root README only when the top-level product description changes | 
| API, role, tenant, or principal behavior | `docs/api-and-rbac.md` | 
| Deployment or environment variables | `docs/configuration.md` and/or `k8s/README.md` | 
| Runtime lifecycle, storage, retention, recovery | `docs/operations.md` | 
| Architecture or trust boundaries | `docs/architecture.md`; security policy when relevant | 
| Developer workflow or validation | `docs/development.md` | 
| Console look, components or UI strings | `docs/console-design-system.md` | 
| Planned product behavior | `ROADMAP.md` or a focused design/roadmap document plus issues | 
| Released behavior | `CHANGELOG.md`; update `ROADMAP.md` when a planned item lands | 

## Documentation conventions

* Use reserved documentation networks and `.test` domains in examples.

* Write shell commands so they can be copied from the repository root.

* Show only relevant configuration keys and state where they belong.

* Label behavior that exists only on `main` and has not shipped in the latest release.

* Never include real credentials, targets, customer names, tokens, or internal infrastructure details.

* Prefer relative Markdown links for repository content.

* Keep headings task-oriented.

* Link to the authoritative procedure instead of copying it into another guide.

* Verify commands, routes, image tags, environment variables, and paths against current code or manifests before merging.

## Version scope

This documentation index was reconciled with `main @ f01c2b6a` (after #644)
on **2026-11-11**. The candidate pre-release cut from it,
[shapoclyack-0.49-1111-rc1](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.49-1111-rc1),
is the latest published pre-release; see its
[release notes](releases/0.49-1111-rc1.md). It succeeds the latest stable
release [`shapoclyack-0.48-1021`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.48-1021)
(2026-10-21, [notes](releases/0.48-1021.md)) and previous stable release
`shapoclyack-0.46-0922` (2026-09-22). Use the tagged documentation and
[CHANGELOG.md](../CHANGELOG.md) for a release's contract.

### Additions in `shapoclyack-0.49-1111-rc1` (2026-11-11)

| Area | Guide and delivered scope | 
| ----- | ----- | 
| Release baseline & migrations | [Release notes](releases/0.49-1111-rc1.md): API/sensor package `0.49-1111-rc1`, signed Pulse `v1.5.0` (`scripts/pulse-pinned.sha256`), DB head `0106_saml_session_binding` (migrations `0097`–`0106`) | 
| Security & SAML SLO integrity | [API and RBAC](api-and-rbac.md), [CHANGELOG](../CHANGELOG.md): `nuclei` patched with `go-jose/v4` `v4.1.6` closing CVE-2026-116587; SAML Single Logout (SLO) subject binding and pending request validation (`0105`, `0106`) | 
| Pulse `v1.5.0`, Rhai phases 1–9 & schema v3 | [Pulse backend](pulse-backend.md), [Configuration](configuration.md), [Nmap migration](nmap-migration.md): 60+ unauthenticated read-only probes across infrastructure, web, ICS/SCADA (Modbus, EtherNet/IP, S7) and protocols; Rhai plugins decoupled from containers via `scripts/fetch-pulse-plugins.sh` into `service_probe.pulse.plugins_dir`; Pulse report schema v3 support and preserved `pulse/raw.json` coverage/TLS posture fields | 
| FSTEC / 187-FZ compliance & BDU threats | [FSTEC certification](fstec-certification.ru.md), [Reports and compliance](reports-and-compliance.md): BDU threat mappings (`api/services/bdu_threats.py`, `scripts/fetch-bdu-threats.py`) and 187-FZ compliance reporting | 
| AI Operator & Remediation Campaigns | [AI operator providers](local-operator-providers.md), [Remediation campaigns](remediation-campaigns.md), [Web interface](ui.md): `xai` and `openai_compatible` providers with public endpoint verification; `/api/problems` and `/api/remediation-campaigns`; APEX console unified navigation tabs, 1440px board, and dark/light themes | 
| L2 discovery & RDP perimeter observations | [Operations](operations.md), [Architecture](architecture.md): L2 neighbour table limits (`scripts/neigh-table-limits.sh`), native RDP X.224 perimeter observations (`octo.perimeter_observation.v1`), and multi-arch Jenkins build enhancements | 

### Prior stable release `shapoclyack-0.48-1021` (2026-10-21) and `0.47-1009-rc1`

The `0.47-1009-rc1` candidate (2026-10-09, [notes](releases/0.47-1009-rc1.md))
was superseded by `0.48-1021` (`main @ b86aea6`, after #577, [notes](releases/0.48-1021.md)). Additions delivered across `0.47-1009-rc1` and `0.48-1021`:

| Area | Current guide | 
| ----- | ----- | 
| Tenant MFA coverage, IdP-authoritative OIDC and SCIM, scan queue admission, sensor mTLS and signed sensor bundles | [Identity, fleet trust and the scan queue](api-and-rbac.md#identity-fleet-trust-and-the-scan-queue) | 
| Verification detector coverage, observing vantage and unreachable closure | [Vulnerability lifecycle](vulnerability-lifecycle.md) | 
| TLS certificate strength, chain trust and explicit probe coverage | [Pulse backend](pulse-backend.md#what-the-probe-checks-and-what-it-can-establish) | 
| Structured web technology catalogue and exposed consoles | [Web fingerprinting](web-fingerprinting.md) | 
| Confirmed subdomain takeover candidates and bounded HTTP confirmation | [Configuration](configuration.md#subdomain-takeover-detection) | 
| Expanded service product matching and distribution backports | [Retro CVE matching](retro-cve-matching.md) | 
| Scanner contracts (#561, #563–#565) | [Nmap migration](nmap-migration.md), [shared execution](shared-scan-execution.md), [evidence](finding-evidence.md), [retro CVE matching](retro-cve-matching.md) | 
| Service credentials and CMDB (#566, included through #570) | [Token rotation and CIDRs](api-and-rbac.md#service-tokens), [ServiceNow synchronization](asset-context.md#asset-discovery-scope-and-cmdb-sync-566) | 
| Sensor integrity (#570) | [Schema and signature rollout](operations.md#sensor-result-integrity-schemas-and-signatures); schema mode defaults to `warn`, signatures enforced | 
| Deployment (#573) | [Helm chart](helm.md), including parity with the Kustomize base; OCI publication is not set up | 
| Ticket integration (#571) | [API contract](api-and-rbac.md): configurable mapping and GitHub/GitLab transports; Azure DevOps remains open | 
| Reports (#572) | [Reports](reports-and-compliance.md): CSV/XLSX, signed manifests when a signing key is configured, allowlisted S3 delivery; SFTP remains open | 
| API and console (#568–#569) | [API v1 / exports / SDK](api-versioning.md), [personal saved views](ui.md#saved-views) and keyboard accessibility; these are not separate docs | 
| Scanner acceptance and runtime repairs (#577) | [Acceptance map](issues-448-452-acceptance.md), [ADR-0003](adr/0003-port-discovery-backend.md) retaining Naabu / Pulse | 

Open branches and PRs are not part of this contract. Endpoint inventory accepts
**schema v1 and v2** for a mixed fleet; registration/heartbeat advertise v2.
Installation identity, source completeness and signed native **Lariska** updates
are on `main` ([inventory and update contract](endpoint-inventory-v2.md),
migrations `0080`/`0081`). Unsigned executable uploads, offers and downloads
are prohibited, including releases stored by older API versions (#513).
Caller-owned bulk idempotency is contracted by migration `0082` (#517), and
maintenance windows are rechecked when queued work starts (#516).
Signed native **sensor** bundles use a separate update path. Lariska builds
with client-certificate support use the enrollment/recovery contract described
in [Operations](operations.md#sensor-client-certificates); installing such builds
and accepting their fleet rollout remains necessary before `required`.
Issuer-scoped TLS-terminator CRLs (#515)
are included; deployments must configure publication, refresh and session
handling as described in [Operations](operations.md#tls-revocation-with-a-signed-crl-515). See [the remaining roadmap](../ROADMAP.md).

A source-tree review establishes documented behavior, not a successful
deployment or CI run. Check the exact revision and completed validation for
the build you install.
