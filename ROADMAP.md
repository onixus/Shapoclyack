# Octo-man Roadmap

**Product:** Octo-man  
**Repository:** [`onixus/shapoclyack`](https://github.com/onixus/Shapoclyack)  
**Domain target:** MSSP and Enterprise Vulnerability Management (up to **50,000 assets**)

Visual overview: [octo_man.html](octo_man.html) · Release history: [CHANGELOG.md](CHANGELOG.md)

---

## Current baseline (done)

Shipped through **[shapoclyack-0.33](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.33)**:

| Area | Status |
|------|--------|
| Scanner pipeline (`resolve → discovery → hostnames → ports → NSE`) | Done |
| CVSS v4 + GeoIP enrichment | Done |
| FastAPI API + React dashboard + JWT RBAC | Done |
| Remote agents, DefectDojo, PDF reports | Done |
| Kubernetes (`k8s/octo-man/`) + all-in-one compose | Done |
| GHCR images `shapoclyack-{aio,scanner,api}` | Done |

The phases below are the **next platform evolution** toward multi-tenant MSSP scale.

---

## Repository structure

Reference this layout verbatim (`onixus/shapoclyack`):

| Path | Role |
|------|------|
| `api/` | FastAPI/Python backend |
| `agent/` | Remote scanning workers |
| `scanner/` | Core pipeline (Nmap, CVSS4, GeoIP) |
| `web-next/` | Next.js 14 App Router dashboard (**Web UI v2**, served from aio) — the only web UI; legacy Vite `web/` was removed after the cutover |
| `k8s/octo-man/` | Kubernetes deployment manifests |

---

## Target tech stack

| Layer | Choice | Role |
|-------|--------|------|
| **PRIMARY_DB** | PostgreSQL | OLTP, state, RBAC, tenant isolation |
| **ANALYTICS_DB** | ClickHouse | OLAP, raw results, time-series, diff-reports |
| **MESSAGE_BROKER** | NATS JetStream | Pub/Sub, guaranteed delivery |
| **GATEWAY/PROXY** | Caddy | TLS termination, routing |
| **ALERTS** | Maddy | SMTP routing |
| **WEB UI v2** | Next.js 14 (App Router), TypeScript, Tailwind, Shadcn UI, Tremor, TanStack Table, Lucide, React Query | MSSP / Enterprise dashboard (`web-next/`) |

---

## Execution phases

### Phase 1 — NATS JetStream & API Gateway Integration

**Goal:** Decouple agents from DB polling and ensure resilient data ingestion.

**Status:** **Done** — JetStream manifests (cluster-ready, safe at `replicas=1`) + compose auto-wire + long-lived agent pull + live broker tests + bounded retention (`OCTO_NATS_*_MAX_AGE_SECONDS`/`MAX_BYTES`) + opt-in HA (`OCTO_NATS_STREAM_REPLICAS`, `examples/nats-ha-patch.yaml`).

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 1.1 | Deploy NATS JetStream | `k8s/octo-man/base/` | StatefulSet + headless/client Services; compose profile `nats` | **Done** |
| 1.2 | Refactor API ingest | `api/services/results_ingest.py`, `nats_bus.py` | Validate archive → publish `ingest.raw_results` (JetStream `Nats-Msg-Id` dedupe); still extract to FS for UI | **Done** |
| 1.3 | Update agent worker | `agent/worker.py` | When `OCTO_NATS_URL` set: JetStream pull on `jobs.scan` (durable `octo-agents`); else HTTP claim poll | **Done** |

### Phase 2 — MSSP Multi-tenancy & Authentication

**Goal:** Secure agent communication and enforce strict tenant isolation.

**Status:** **Done** — tenants/provisioning keys are Postgres-backed (migrated off JSON in Phase 7.4) + agent JWT; legacy `OCTO_AGENT_TOKEN` still maps to `tenant_id=default`.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 2.1 | Provisioning | `api/services/tenants.py`, `api/routes/auth.py` | Create tenants + provisioning keys (hashed); plaintext returned once | **Done** |
| 2.2 | JWT exchange | `POST /api/auth/agent/token`, `api/services/auth.py`, `agent/worker.py` | Exchange key → short-lived agent JWT (`typ=agent`, `tenant_id`) | **Done** |
| 2.3 | Gateway JWT validation | `require_agent`, jobs/ingest NATS publish | Enforce agent JWT + tenant match before claim/complete/NATS; `tenant_id` header on messages | **Done** |
| 2.4 | Kubernetes hardening | `k8s/octo-man/examples/networkpolicy-*.yaml`, `externalsecret.example.yaml` | Agent egress NetworkPolicy; ExternalSecrets example for keys via env | **Done** |

### Phase 3 — ClickHouse Analytics Engine

**Goal:** Handle 50k+ assets and generate analytical diff-reports.

**Status:** **Done** — CH tables + NATS→ClickHouse ingest worker; compose auto-wire;
risk scoring model ``mvp-1`` (CVSS4/EPSS/KEV overlays → contextual_score / cisa_decision);
FS diffs remain default (CH diff helpers available via `ch_diff.py`).

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 3.1 | ClickHouse deployment | `k8s/octo-man/base/clickhouse/` | StatefulSet + 50Gi PVC + init SQL | **Done** |
| 3.2 | NATS → ClickHouse consumer | `api/services/ch_ingest_worker.py` | Durable pull on `ingest.>`, bulk insert vulns + ports | **Done** |
| 3.3 | Schema setup | init.sql | `shapoclyack_vulnerabilities` + `shapoclyack_open_ports` (`ReplacingMergeTree`) | **Done** |
| 3.4 | Diff-report logic | `api/services/ch_diff.py` | CH query helpers for CVE/port deltas (scanner FS diff unchanged) | **Done** |


### Phase 4 — Kubernetes Hardening & Auto-scaling

**Goal:** Prevent outages during heavy / unpredictable VM scans.

**Status:** **Done** (merged).

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 4.1 | Agent distribution | `k8s/octo-man/base/agents/agent-deployment.yaml` | `topologySpreadConstraints` on zone + hostname | **Done** |
| 4.2 | Vertical Pod Autoscaling | `k8s/octo-man/base/agents/agent-vpa.yaml` | VPA Auto (CPU/RAM min-max) for agent pods | **Done** |
| 4.3 | Opt-in overlay | `k8s/octo-man/overlays/agents` | replicas=3 + API agent-mode; not in default base | **Done** |

### Phase 5 — Advanced Discovery & Notifications

**Goal:** Autonomous external monitoring.

**Status:** **Done**.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 5.1 | Cloudflare integration | `scanner/pipeline/discover.py` | Zone DNS import + unproxied A/AAAA misconfig findings | **Done** |
| 5.2 | CT logs scanning | `scanner/pipeline/hostnames.py` | Async crt.sh / Cert Spotter subdomain discovery | **Done** |
| 5.3 | SMTP alerts via Maddy | `scanner/pipeline/alerts.py` | Outbound SMTP + optional DKIM/PTR pre-send checks | **Done** |

### Phase 6 — Shapoclyack Web UI v2 (`web-next/`)

**Goal:** Replace the Vite React dashboard with an MSSP / Enterprise Vulnerability Management UI that scales to 50k+ assets (tenants, agents, jobs, runs, asset inventory).

**Status:** **Done** — full cutover complete: aio/API images serve web-next static export, CI builds/lints `web-next/`, and legacy `web/` has been removed from the repo.

**Stack:** Next.js 14 (App Router), TypeScript, Tailwind CSS, Shadcn UI (Slate), Tremor (charts), TanStack Table, Lucide React, React Query, Zustand, Axios, date-fns.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 6.1 | Initialization | `web-next/` | Next.js 14 + React Query / Table / Zustand / Axios / Tremor / Shadcn | **Done** |
| 6.2 | Application shell | `Sidebar`, `(dashboard)/layout`, `/login` | Sidebar + header + AuthGate JWT session | **Done** |
| 6.3 | Core pages | `(dashboard)/…` | Dashboard/Assets from latest run; Tenants/Agents/Jobs/Runs + `/runs/view` | **Done** |
| 6.4 | API integration | `lib/api.ts`, `lib/auth-store.ts` | Axios JWT + React Query; run hosts/ports/vulns clients | **Done** |
| 6.5 | Aio static serve | `Dockerfile.allinone`, `api/app.py` | `output: "export"` → `/app/web/dist`; FastAPI mounts `/_next` | **Done** |
| 6.6 | Full cutover | `.github/workflows/ci.yml`, `web/` (removed) | CI now builds/lints `web-next/` (was still building legacy `web/`); Assets page rewired from latest-run aggregation to the real Phase 7 `GET /api/assets` registry; `web/` deleted | **Done** |

#### Bootstrap notes (Phase 6.1 → 6.2 first)

```bash
npx create-next-app@latest web-next --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
cd web-next
npm install @tanstack/react-query @tanstack/react-table zustand axios date-fns @tremor/react
npx shadcn-ui@latest init   # Style: Default, Base color: Slate
npx shadcn-ui@latest add button card input table dialog dropdown-menu tabs badge
```

Then implement `Sidebar.tsx` and `(dashboard)/layout.tsx` before the remaining pages.

**Migration note:** All-in-one and API images serve `web-next` static export (`out/` → `OCTO_WEB_DIST`). Legacy Vite `web/` has been removed from the repo (6.6) — `web-next/` is the only web UI.

---

## EASM evolution (Phases 7–11)

**Goal:** evolve Octo-man from a run-centric VM scanner into a full External Attack Surface Management platform — continuous outside-in discovery, a persistent asset inventory with identity/lifecycle, exposure fingerprinting, and change-based alerting, on top of the MSSP foundation from Phases 1–6.

**Status:** Phase 7 **done** (MVP); Phase 8 partially done (8.1–8.4); Phase 9 partially done (9.1–9.2) — remainder **Planned**.

### Phase 7 — Asset Inventory & Identity Graph

**Goal:** replace per-run snapshots (`RunSummary`, `AliveHostItem`, `PortAggregateItem`) with a persistent asset registry — the core missing piece for EASM.

**Status:** **Done** (MVP). Postgres is a hard dependency once this ships (unlike NATS/ClickHouse) since the tenant store lives there — see `k8s/README.md` Postgres section. No IP↔FQDN↔cert-hash cross-identifier correlation yet (one asset per host record per run); no ownership-graph UI; `decommissioned` status is operator-only, never automatic. Deferred to Phase 9/11.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 7.1 | Postgres as PRIMARY_DB | `api/db/` (new), `api/services/` | SQLAlchemy/Alembic; `tenants`, `provisioning_keys`, `assets`, `asset_identifiers` (IP/domain/cert-hash), `asset_tags` tables | **Done** |
| 7.2 | Asset dedup / fingerprint | `scanner/pipeline/asset_identity.py` (new) | Stable `asset_id` keyed by tenant+IP or tenant+FQDN sha256 hash, to avoid duplicates across runs | **Done** |
| 7.3 | Lifecycle tracking | `api/services/assets.py`, hooked from `api/services/jobs.py` (`_run_job` + `complete_job`, covering both local-mode and agent-upload execution paths) | `first_seen` / `last_seen` / `status` (active/stale/decommissioned) per asset; staleness is a `last_seen` age threshold (`OCTO_ASSET_STALE_DAYS`, default 14d) | **Done** |
| 7.4 | Migrate tenants/keys off JSON | `api/services/tenants.py` | Postgres-backed behind the same public function signatures; `resolve_provisioning_key` now O(1) via an indexed `key_lookup` prefix instead of scan-and-bcrypt-verify-all | **Done** |

### Phase 8 — Outside-In Continuous Discovery

**Goal:** surface assets the customer never declared — the defining trait of EASM vs. seed-list scanning.

**Status:** **8.1–8.4 done** (MVP); **8.5 deferred** to a follow-up phase (continuous org-level scheduling — independent new surface, not an extension of 8.1–8.4's code). 8.3's original "public cloud ranges by org tag" half was dropped as not honestly implementable — AWS/GCP publish IP ranges tagged by service+region, not by customer organization; there is no public API that attributes a cloud IP to a specific org.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 8.1 | ASN / WHOIS / BGP org mapping | `scanner/pipeline/asn_discovery.py` (new) | Seed domain → resolved IP → ASN → announced prefixes via RIPEstat's free keyless API; hard-capped at `max_total_ips` (default 4096) since one ASN can span far more than one org's infra | **Done** |
| 8.2 | Expanded subdomain enum | `scanner/pipeline/hostnames.py` | Adds an `otx` (AlienVault OTX passive DNS) provider alongside crt.sh/Cert Spotter, plus an opt-in wordlist brute-force pass (`discovery.ct.brute_force`, built-in `scanner/data/wordlists/subdomains-small.txt`, concurrency/candidate-capped) | **Done** |
| 8.3 | Cloud resource discovery | `scanner/pipeline/cloud_discovery.py` (new) | S3/GCS/Azure Blob bucket + container enumeration via unauthenticated HEAD/GET against public provider endpoints; org tokens × wordlist candidates, hard-capped at `max_candidates` (default 500) and `concurrency` (default 10) since checks hit shared third-party cloud infrastructure, not the target's own hosts; findings reported, never merged into scan scope | **Done** |
| 8.4 | Typosquat / domain monitoring | `scanner/pipeline/domain_monitor.py` (new) | Look-alike domain candidates (omission/transposition/keyboard-adjacent/doubling/homoglyph/TLD-swap generators) resolved via passive dnsx A/AAAA lookups only — same risk class as `ct.brute_force`, never merged into scan scope; plus a dangling-CNAME/subdomain-takeover heuristic over the org's own in-scope FQDNs (CNAME target matches a known vulnerable-service suffix AND has no A/AAAA record) that flags the pattern + non-resolution only and never confirms an actual takeover | **Done** |
| 8.5 | Continuous org-level scheduling | `scanner/scheduler.py`, K8s CronJob | Move from one-shot scans to a recurring discovery loop with delta output | **Planned** |

### Phase 9 — Exposure Fingerprinting

**Goal:** enrich each asset with context beyond ports/CVEs, needed for real prioritization.

**Status:** 9.1–9.2 done; 9.3–9.4 Planned.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 9.1 | Tech stack fingerprinting | `scanner/pipeline/fingerprint.py` (new) | One HTTP GET per already-open web port (reuses `open_ports.txt`, no new port scan) → small built-in CDN/WAF header signature set (Cloudflare, Akamai, Sucuri, Imperva/Incapsula, CloudFront, Fastly) + CMS/framework header/body markers (WordPress, Drupal, Joomla, Next.js, generic PHP); opt-in (`fingerprint.enabled`), capped by `max_targets`/`concurrency`/`body_max_bytes` (streamed read); findings reported to `fingerprint.json`/`fingerprint_matches.txt`, never merged into scan scope | **Done** |
| 9.2 | TLS / certificate posture | `scanner/pipeline/tls_posture.py` (new) | Parses the free-text `output` of nmap's own `ssl-cert`/`ssl-enum-ciphers` NSE scripts (already written to `nmap/tcp/*.xml` by the `nse` stage) — no new scan, no TLS-handshake dependency. Findings: `cert_expired`/`cert_expiring_soon` (validity window vs. `expiring_soon_days`), `self_signed` (subject/issuer commonName heuristic, tagged `heuristic`, not certain), `weak_protocol`/`weak_cipher_grade`/`weak_cipher_name` (from `ssl-enum-ciphers`, now added to the `vuln`/`service_specific` NSE profiles). Opt-in (`tls_posture.enabled`), capped by `max_targets`; findings reported to `tls_posture.json`/`tls_posture_findings.txt`, never merged into scan scope. Since nmap's script output is free text rather than a stable schema, parsing is fail-soft (unparseable fields/lines are skipped, never raise). Hostname/SAN-CN mismatch checking is deferred/out of scope. | **Done** |
| 9.3 | Web asset screenshots | new worker (optional) | Visual inventory for UI review | **Planned** |
| 9.4 | Business-context criticality | `api/services/risk_scoring.py` | Replace port-based criticality heuristic with `asset_criticality` sourced from inventory owner/business-unit tags (Phase 7) | **Planned** |

### Phase 10 — Change Detection & Alerting at Asset Level

**Goal:** EASM value comes from tracking change, not one-off reports.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 10.1 | Asset-level diff events | `scanner/pipeline/report_diff.py`, `api/services/ch_diff.py` | Emit new-asset / new-open-port / cert-expiring / new-CVE / decommissioned-host events | **Planned** |
| 10.2 | Event bus for alerts | `scanner/pipeline/alerts.py` + NATS | Publish to `events.asset.*` instead of only post-scan summaries | **Planned** |
| 10.3 | Workflow integrations | `api/services/integrations/` (new) | Webhooks, Jira/ServiceNow ticket creation on new critical exposure; extend existing DefectDojo export | **Planned** |

### Phase 11 — Web UI v2: Attack Surface View

**Goal:** visualize the attack surface, not just per-run tables.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 11.1 | Asset inventory page | `web-next/src/app/(dashboard)/assets` | Cross-run asset list/filter with first/last seen, criticality, owner | **Planned** |
| 11.2 | Attack surface graph | new component in `web-next/` | Domains → subdomains → IPs → ports → services, clustered by ASN/org | **Planned** |
| 11.3 | Exposure trend & exec dashboard | Tremor charts in `web-next/` | Exposure score over time, top critical findings | **Planned** |

---

## Suggested delivery order

```text
Phase 1 (NATS + ingest gateway)
    → Phase 2 (tenancy + agent JWT)
        → Phase 6 (Web UI v2 shell + tenants/assets)   # can start shell in parallel after 2.1 APIs exist
        → Phase 3 (ClickHouse + analytical diffs)
            → Phase 4 (spread / VPA)
                → Phase 5 (Cloudflare / CT / Maddy SMTP)
                    → Phase 7 (Postgres asset inventory)   # foundation for EASM; depends on tenant isolation from Phase 2
                        → Phase 8 (outside-in discovery)   # can run in parallel with Phase 7
                        → Phase 9 (exposure fingerprinting)   # can run in parallel with Phase 7/8, enriches same asset records
                            → Phase 10 (change detection / alerting)   # depends on 7 + 8 + 9
                                → Phase 11 (attack surface UI)   # depends on 7; UI shell can start earlier on mocks
```

Phases 1–2 unlock safe multi-tenant agent scale. Phase 6 delivers the MSSP console (can bootstrap UI early with mocks, wire JWT after 2.x). Phase 3 unlocks 50k-asset analytics. Phases 4–5 harden ops and expand discovery/alerting. Phases 7–11 turn the platform into full EASM: a persistent asset inventory, continuous outside-in discovery, exposure fingerprinting, and asset-level change alerting.

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Done** | Merged to `main` (may be ahead of the last tagged release — see [CHANGELOG.md](CHANGELOG.md) `## Unreleased` for what hasn't shipped in a tag yet) |
| **Planned** | Documented here; not started |
| **In progress** | Active branch / PR (update when work starts) |

Phases 1–6 and Phase 7 are **Done** (merged to `main`); Phase 8 is partially done (8.1–8.4); Phase 9 is partially done (9.1–9.2); Phases 10–11 are **Planned**.
