# Shapoclyack Roadmap

For installation and operator guidance, see [docs/README.md](docs/README.md).
This file tracks delivery status and is not a deployment manual.

**Repository:** [`onixus/shapoclyack`](https://github.com/onixus/Shapoclyack)  
**Domain target:** MSSP and Enterprise Vulnerability Management (up to **50,000 assets**)

Visual overview: [shapoclyack.html](shapoclyack.html) · Release history: [CHANGELOG.md](CHANGELOG.md)

---

## How to read this file

The project runs **three tracks**, and this file historically described only the first —
which is why a nearly all-**Done** roadmap can coexist with an installation that is not
yet production-ready.

| Track | What it answers | Where it lives | State |
|-------|-----------------|----------------|-------|
| **A — Platform capability** | *What can the platform do?* | This file: [Phases 1–6](#execution-phases), [7–11](#easm-evolution-phases-711), [P0–P4](#next-priority-order-post-phase-11) | Nearly complete — see [remaining scope](#track-a--what-is-actually-left) |
| **B — Production readiness** | *May it be run for real?* | [EPIC #154](https://github.com/onixus/Shapoclyack/issues/154) → summarized [below](#track-b--production-readiness-ga-blockers) | **Blocking GA** |
| **C — VM/Exposure product** | *Is it a vulnerability-management product, or a scanner?* | [EPIC #134](https://github.com/onixus/Shapoclyack/issues/134), [docs/ui-ux-redesign-roadmap.md](docs/ui-ux-redesign-roadmap.md) → summarized [below](#track-c--vulnerability-management-product) | **Done** — EPIC #134 closed; the historical score snapshots leftover of #144 is merged (migration `0023`, `/api/vulnerabilities/risk-history`) |
| **D — Endpoint inventory (Lariska)** | *What is installed on the endpoints?* | [Agent_plan.md](Agent_plan.md) — its own design record, not a phase | **Done** — S1–S10 merged |

Track A is capability; Track B is operability; Track C is product framing; Track D is a
separate integration contract that deliberately does not reuse the scan-result path. They
are independent — Track A being **Done** says nothing about the others, and a reader who
checked only the phase tables would conclude the opposite. Tracks B and C are tracked as
GitHub issues and Track D in its own file, rather than expanded here, so this file stays a
map and each source stays authoritative for its own scope.

---

## Current baseline (done)

Shipped through **[shapoclyack-0.42-0822](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.42-0822)**.
Includes all capabilities of Phases 1–11 and P0–P4, full EASM lifecycle & NIST risk scoring,
Track B Wave 0 and Wave 1 GA hardening (#151–#159, #185–#188), ClickHouse TTL and run retention (#187),
and multi-replica load validation (#188).
GHCR images are published by the **local Jenkins** job `shapoclyack-publish` (`Jenkinsfile.publish`)
with tag `shapoclyack-0.42-0822`.

**On `main`, merged but not yet tagged** (see [CHANGELOG.md](CHANGELOG.md) `## Unreleased`):
historical risk score snapshots — the last leftover of [#144](https://github.com/onixus/Shapoclyack/issues/144);
a SARIF v2.1.0 exporter with an in-UI viewer; endpoint-inventory NATS events and the
end-to-end lifecycle suite that complete **Track D** (S8/S10); agent fleet monitoring,
UI-driven SSH deployment and auto-update (`scripts/install-agent.sh`, `scripts/update-agent.sh`);
a UX/UI refactor with a redesigned remediation kanban; and JWT-algorithm / request-body
hardening. Local CI `shapoclyack` **#27** (2026-08-24, revision `08b0bd0`) is SUCCESS:
1033 pytest on 3.11 and 3.12, coverage 80.02% against a 74% gate, 142 vitest in 26 files,
load run 16/16 hosts.


| Area | Status |
|------|--------|
| Scanner pipeline (`resolve → discovery → hostnames → ports → NSE`) | Done |
| CVSS v4 + GeoIP enrichment | Done |
| FastAPI API + React dashboard + JWT RBAC | Done |
| Remote agents, DefectDojo, PDF reports | Done |
| Kubernetes (`k8s/shapoclyack/`) + all-in-one compose | Done |
| GHCR images `shapoclyack-{aio,scanner,api}` | Done |
| Nmap made optional / non-default in published images ([#97](https://github.com/onixus/Shapoclyack/issues/97) Phase 1) — Pulse is the default service-probe backend; default `-aio`/`-scanner` images ship Nmap-free; a legacy `-nmap` tag remains opt-in for NPSL-aware users who want classic NSE | Done |

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
| `k8s/shapoclyack/` | Kubernetes deployment manifests |

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
| 1.1 | Deploy NATS JetStream | `k8s/shapoclyack/base/` | StatefulSet + headless/client Services; compose profile `nats` | **Done** |
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
| 2.4 | Kubernetes hardening | `k8s/shapoclyack/examples/networkpolicy-*.yaml`, `externalsecret.example.yaml` | Agent egress NetworkPolicy; ExternalSecrets example for keys via env | **Done** |

### Phase 3 — ClickHouse Analytics Engine

**Goal:** Handle 50k+ assets and generate analytical diff-reports.

**Status:** **Done** — CH tables + NATS→ClickHouse ingest worker; compose auto-wire;
risk scoring model ``mvp-2`` (CVSS4/EPSS/KEV + scanner-supplied EPSS/KEV and confidence →
contextual_score / cisa_decision / risk_explanation);
FS diffs remain default (CH diff helpers available via `ch_diff.py`).

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 3.1 | ClickHouse deployment | `k8s/shapoclyack/base/clickhouse/` | StatefulSet + 50Gi PVC + init SQL | **Done** |
| 3.2 | NATS → ClickHouse consumer | `api/services/ch_ingest_worker.py` | Durable pull on `ingest.>`, bulk insert vulns + ports | **Done** |
| 3.3 | Schema setup | init.sql | `shapoclyack_vulnerabilities` + `shapoclyack_open_ports` (`ReplacingMergeTree`) | **Done** |
| 3.4 | Diff-report logic | `api/services/ch_diff.py` | CH query helpers for CVE/port deltas (scanner FS diff unchanged) | **Done** |


### Phase 4 — Kubernetes Hardening & Auto-scaling

**Goal:** Prevent outages during heavy / unpredictable VM scans.

**Status:** **Done** (merged).

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 4.1 | Agent distribution | `k8s/shapoclyack/base/agents/agent-deployment.yaml` | `topologySpreadConstraints` on zone + hostname | **Done** |
| 4.2 | Vertical Pod Autoscaling | `k8s/shapoclyack/base/agents/agent-vpa.yaml` | VPA Auto (CPU/RAM min-max) for agent pods | **Done** |
| 4.3 | Opt-in overlay | `k8s/shapoclyack/overlays/agents` | replicas=3 + API agent-mode; not in default base | **Done** |

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

**Goal:** evolve Shapoclyack from a run-centric VM scanner into a full External Attack Surface Management platform — continuous outside-in discovery, a persistent asset inventory with identity/lifecycle, exposure fingerprinting, and change-based alerting, on top of the MSSP foundation from Phases 1–6.

**Status:** Phase 7 **done** (MVP); Phase 8 **done** (8.1–8.5); Phase 9 partially done (9.1, 9.2, 9.4) — remainder **Planned**.

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

**Status:** **Done** (8.1–8.6). 8.3's original "public cloud ranges by org tag" half was dropped as not honestly implementable — AWS/GCP publish IP ranges tagged by service+region, not by customer organization; there is no public API that attributes a cloud IP to a specific org.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 8.1 | ASN / WHOIS / BGP org mapping | `scanner/pipeline/asn_discovery.py` (new) | Seed domain → resolved IP → ASN → announced prefixes via RIPEstat's free keyless API; hard-capped at `max_total_ips` (default 4096) since one ASN can span far more than one org's infra | **Done** |
| 8.2 | Expanded subdomain enum | `scanner/pipeline/hostnames.py`, `api/routes/wordlists.py`, `api/services/wordlists.py`, migration `0012`, `web-next/.../wordlists` | Adds an `otx` (AlienVault OTX passive DNS) provider alongside crt.sh/Cert Spotter, plus an opt-in wordlist brute-force pass (`discovery.ct.brute_force`, built-in `scanner/data/wordlists/subdomains-small.txt`, concurrency/candidate-capped). Tenant-uploaded wordlists now live in Postgres per tenant (`POST /api/wordlists` + Wordlists page), selected per scan via `StartScanRequest.wordlist_id`: a `subdomain` list turns on `ct.brute_force`, a `bucket` list turns on cloud discovery, materialized to a job-scoped file and merged **not** fail-soft (a scan that asked for a wordlist must not run without one). Body normalized/de-duped on write, reads return metadata only, capped by `OCTO_WORDLIST_MAX_BODY_BYTES`/`OCTO_WORDLIST_MAX_WORDS`; agent mode 422s `wordlist_id` (materialized on the API pod, unreachable by a remote worker's mounted config) | **Done** |
| 8.3 | Cloud resource discovery | `scanner/pipeline/cloud_discovery.py` (new) | S3/GCS/Azure Blob bucket + container enumeration via unauthenticated HEAD/GET against public provider endpoints; org tokens × wordlist candidates, hard-capped at `max_candidates` (default 500) and `concurrency` (default 10) since checks hit shared third-party cloud infrastructure, not the target's own hosts; findings reported, never merged into scan scope | **Done** |
| 8.4 | Typosquat / domain monitoring | `scanner/pipeline/domain_monitor.py` (new) | Look-alike domain candidates (omission/transposition/keyboard-adjacent/doubling/homoglyph/TLD-swap generators) resolved via passive dnsx A/AAAA lookups only — same risk class as `ct.brute_force`, never merged into scan scope; plus a dangling-CNAME/subdomain-takeover heuristic over the org's own in-scope FQDNs (CNAME target matches a known vulnerable-service suffix AND has no A/AAAA record) that flags the pattern + non-resolution only and never confirms an actual takeover | **Done** |
| 8.5 | Continuous org-level scheduling | `api/db/models.py` (`ScanSchedule`), `api/services/scan_schedules.py`, `api/services/schedule_dispatcher.py`, `api/routes/schedules.py` | Per-tenant `scan_schedules` table (cron or fixed-interval, target set + scan options); an in-process dispatcher thread (started from the API `lifespan`, same pattern as the ClickHouse ingest worker — no per-tenant K8s CronJob) polls due schedules and calls the existing `jobs_service.start_scan`, skipping a tick if the schedule's previous job is still running. `CRUD via `/api/schedules` (operator role; delete is admin-only). API-only this iteration, no web-next UI. The original `scanner/scheduler.py`/static `cronjob.yaml` remain as-is for simple single-tenant self-hosts. | **Done** |
| 8.6 | Scan intents for jobs & schedules | `api/services/scan_intents.py` (new), `api/services/jobs.py`, `api/routes/schedules.py`, `web-next/.../{jobs,schedules}`, [docs/scan-performance.md](docs/scan-performance.md) | Product-level "what work to do", orthogonal to the speed profile (`mode`: safe/balanced/fast = how hard to hit the network). `intent` picks which pipeline stages + nuclei floor run so operators can schedule **inventory** often (ports-only L1, `--skip-nse`, nuclei off, top_ports 100) and **full** assessments rarely (default pipeline, nuclei critical/high/medium) without hand-editing YAML — plus **vuln** (full probe + nuclei critical/high only) and **delta** (full + `--delta` discovery refresh). When set, intent owns `skip_nse`/`delta`/nuclei/top_ports and explicit legacy flags are ignored; when omitted, legacy `skip_nse`/`delta` apply as before. Wired into both ad-hoc jobs and schedules with a human-readable summary in `scan_options` | **Done** |

### Phase 9 — Exposure Fingerprinting

**Goal:** enrich each asset with context beyond ports/CVEs, needed for real prioritization.

**Status:** 9.1, 9.2, 9.3, 9.4 done.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 9.1 | Tech stack fingerprinting | `scanner/pipeline/fingerprint.py` (new) | One HTTP GET per already-open web port (reuses `open_ports.txt`, no new port scan) → small built-in CDN/WAF header signature set (Cloudflare, Akamai, Sucuri, Imperva/Incapsula, CloudFront, Fastly) + CMS/framework header/body markers (WordPress, Drupal, Joomla, Next.js, generic PHP); opt-in (`fingerprint.enabled`), capped by `max_targets`/`concurrency`/`body_max_bytes` (streamed read); findings reported to `fingerprint.json`/`fingerprint_matches.txt`, never merged into scan scope | **Done** |
| 9.2 | TLS / certificate posture | `scanner/pipeline/tls_posture.py` (new) | Parses the free-text `output` of nmap's own `ssl-cert`/`ssl-enum-ciphers` NSE scripts (already written to `nmap/tcp/*.xml` by the `nse` stage) — no new scan, no TLS-handshake dependency. Findings: `cert_expired`/`cert_expiring_soon` (validity window vs. `expiring_soon_days`), `self_signed` (subject/issuer commonName heuristic, tagged `heuristic`, not certain), `weak_protocol`/`weak_cipher_grade`/`weak_cipher_name` (from `ssl-enum-ciphers`, now added to the `vuln`/`service_specific` NSE profiles). Opt-in (`tls_posture.enabled`), capped by `max_targets`; findings reported to `tls_posture.json`/`tls_posture_findings.txt`, never merged into scan scope. Since nmap's script output is free text rather than a stable schema, parsing is fail-soft (unparseable fields/lines are skipped, never raise). Hostname/SAN-CN mismatch checking was deferred here and landed later as [P4.1](#p4-breakdown--differentiating-features) (`cert_name_mismatch`). | **Done** |
| 9.3 | Web asset screenshots | new worker (optional) | Visual inventory for UI review. **Tracked as [P4.4](#p4-breakdown--differentiating-features)**, which owns the scope this row opened — the capture is the easy half, and the retention/redaction/access-control work that makes it shippable is stated there. Kept here as a pointer, not a second work item | **Done → [P4.4](#p4-breakdown--differentiating-features)** |
| 9.4 | Business-context criticality | `api/services/risk_scoring.py`, `api/services/assets.py`, `api/routes/assets.py` | Operator-set `asset_criticality` (0–4) via new `PATCH /assets/{asset_id}`; `ch_transform.vulnerabilities_to_rows` looks it up per host (batched, one query per distinct host per ingest batch) and it wins outright over the port/severity heuristic in `risk_scoring.py` when set; falls back to the existing heuristic when unset or when Postgres/tenant context isn't available (e.g. unit tests, no-DB deployments) | **Done** |

### Phase 10 — Change Detection & Alerting at Asset Level

**Goal:** EASM value comes from tracking change, not one-off reports.

**Status:** 10.1, 10.2, 10.3 done.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 10.1 | Asset-level diff events | `scanner/pipeline/report_diff.py`, `api/services/ch_diff.py`, `api/services/assets.py` | `report_diff.py` emits a normalized `events: [{"kind": ...}]` list (`new_asset`/`new_open_port`/`new_cve` from the existing added-sets, plus a new `cert_expiring` event on a host:port's *first* cert_expired/cert_expiring_soon occurrence across the two most recent runs' `tls_posture.json`); `ch_diff.py`'s tenant-wide ClickHouse path gets the same `new_cve`/`new_open_port` events; `decommissioned_host` is logged when an operator manually transitions an asset via `PATCH /assets/{asset_id}` (`status: "decommissioned"`, the only status an operator may set — active/stale stay system-managed). No NATS/alerting wiring yet — that's 10.2. | **Done** |
| 10.2 | Event bus for alerts | `api/services/asset_events.py` (new), `api/services/nats_bus.py`, `api/services/{jobs,assets}.py`, `api/settings.py` | The 10.1 events are published to JetStream on `events.asset.{tenant_id}.{kind}` (stream `EVENTS`, `LIMITS` retention — one event is meant to reach several independent consumers, so `WORK_QUEUE` would let the first one take it from the rest). Tenant token before kind, so the common per-tenant policy is `events.asset.acme.>` rather than a client-side filter over every other tenant's traffic. **Published from the API, not from `scanner/pipeline/alerts.py` as originally sketched:** the scanner is the agent's payload and has no tenant context — the tenant is a property of the job — so publishing there would mean broker credentials on every remote worker; the API's post-run hook covers local and agent execution from one place. `alerts.py` keeps its per-run SMTP/webhook digest, a human surface rather than the machine stream. Best-effort by design (a scan whose artifacts are on disk must not fail because the broker blinked); `octo_asset_events_published_total{kind,outcome}` records what did not go out, and `diff.json` keeps the payload. Event ids are content-derived (tenant+run+kind+host+port+CVE) so a replayed upload dedupes inside the stream's 24h duplicate window, while the same finding in a *later* run stays a new occurrence. Per-run cap `OCTO_ASSET_EVENTS_MAX_PER_RUN` (default 1000) with the overflow logged, not silently dropped — a first scan of a /16 is otherwise an alert storm. `OCTO_ASSET_EVENTS_ENABLED` silences the stream without disabling job dispatch and ingest on the same broker. No consumer yet — that's 10.3 | **Done** |
| 10.3 | Workflow integrations | `api/services/integrations/{webhooks,delivery,tickets,webhook_worker}.py`, `api/routes/webhooks.py`, migrations `0011`/`0022` | **Done.** Per-tenant subscriptions carry the routing policy (event kinds + a `min_severity` floor that applies only to the kinds that have a severity, so a "critical only" rule cannot silently swallow a decommission). A JetStream durable consumer on `events.asset.>` queues matching events and acks; a separate dispatcher delivers them, so a slow receiver never stalls consumption of the stream. `webhook_deliveries` is queue, DLQ and audit trail in one table. Retries exponential and capped; 5xx/408/429/timeouts retry, every other 4xx is dead-lettered on the first attempt. HMAC-signed webhook POSTs remain the default `transport`. **Ticket transports** (`jira` / `servicenow` / `defectdojo`) reuse that queue: native create-issue POST, no HMAC, then link `ticket_key` on the matching tracked finding without overwriting an operator-set link. Writes need tenant `admin` | **Done** |

### Phase 11 — Web UI v2: Attack Surface View

**Goal:** visualize the attack surface, not just per-run tables.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 11.1 | Asset inventory + detail card | `web-next/src/app/(dashboard)/assets`, `assets/view` | Cross-run asset list (status/criticality columns) + full detail card: edit owner/business-unit/criticality + decommission via `PATCH /assets/{id}`, and per-asset vulnerabilities/ports/OS/GeoIP correlated from the latest run by primary IP | **Done** |
| 11.2 | Attack surface graph | `web-next/src/components/attack-surface-graph.tsx`, `(dashboard)/attack-surface`, `scanner/pipeline/asn_enrich.py` | Hostnames → IPs → ports → **services** as a dependency-free layered SVG graph from `/runs/{id}/hosts`+`/ports` (ports now carry aggregated service names), node caps for scale, run selector. IP nodes cluster/color by **ASN/org** (new offline `enrichment.asn` MMDB enrichment, baked in Docker) when available, else GeoIP country | **Done** |
| 11.3 | Exposure trend & exec dashboard | Tremor charts in `web-next/src/app/(dashboard)/page.tsx` | Exposure trend, findings-by-severity donut, top critical/high findings table, asset-posture (criticality distribution + status counts), vulnerable-hosts KPI — all from existing endpoints | **Done** |
| 11.4 | Reports surface | `web-next/src/app/(dashboard)/reports`, `runs/view` Reports tab, `api/routes/runs.py` | Surface run artifacts + business PDF in the UI (per-run Reports tab with text preview/download + top-level Reports page); new binary-safe `GET /runs/{id}/download/{path}` endpoint | **Done** |
| 11.5 | System status page | `web-next/src/app/(dashboard)/system`, `api/routes/system.py`, `api/services/system_status.py` | Read-only installation configurator: app/tool versions, enrichment-DB freshness, enabled stages, runtime flags, tenant/agent counts via `GET /api/system` (no secrets) | **Done** |
| 11.6 | Editable configurator | `api/routes/config.py`, `api/services/config_override.py`, `config_overrides` table, `web-next/src/components/config-editor.tsx` | Admin-editable stage toggles + per-profile scan tuning via `GET`/`PUT /api/config`; whitelist + full-schema validation; Postgres-persisted overrides deep-merged onto the base config at local scan start | **Done** |
| 11.7 | Geo map | `web-next/src/app/(dashboard)/geo`, `components/geo-map.tsx`, `lib/geo/{aggregate,world-map}.ts`, `scanner/pipeline/geoip.py`, `api/services/runs.py` | Run's alive hosts on a world map by GeoIP position, marker coloured by worst finding and sized by host count. GeoIP now also records **coordinates** (City-edition MMDB `location`) through `alive_hosts.json` → `latitude`/`longitude` on `GET /runs/{id}/hosts`; a country-only record falls back to the country centroid and is drawn dashed, a host with neither is listed as unlocated rather than dropped — a dot on a map reads as more certain than GeoIP is, so the precision is on the marker. Dependency-free SVG with the land outline generated into a committed constant (`scripts/generate-world-map.mjs`), so the page needs no tiles and no network | **Done** |

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

## Next priority order (post-Phase 11)

| Priority | Est. effort | Theme | Scope |
|----------|-------------|-------|-------|
| **P0** | 1–2 sprints | Tenant-aware IAM | **Done** — user memberships (`user_tenants`, migration `0007`), server-derived tenant context (`require_tenant`), scoping for jobs/agents/assets/schedules/endpoint inventory **and runs/run artifacts** (`tenant.json` run marker), the header tenant switcher, and negative cross-tenant tests are merged |
| **P1** | 2–4 sprints | Durable control plane | **Done** — jobs/agents in PostgreSQL (1.1/1.2), formal state machine (1.3), leases + reaper (1.4), idempotency keys (1.5), scheduler leader election (1.6) — see [breakdown](#p1-breakdown--durable-control-plane) |
| **P2** | 2–3 sprints | Asset event workflows | **Done** — ~~`events.asset.*` bus~~ ([10.2](#phase-10--change-detection--alerting-at-asset-level)); ~~routing policies, webhooks, retries, DLQ, audit trail~~; ~~Jira/ServiceNow/DefectDojo ticket creation~~ as further transports over the same delivery queue ([10.3](#phase-10--change-detection--alerting-at-asset-level)) |
| **P3** | parallel track | Scale & observability | **Done** — ~~Prometheus~~ (3.4/3.5), ~~OpenTelemetry~~ (opt-in OTLP HTTP on the API; empty endpoint = no TracerProvider), ~~SLOs~~ (3.6), ~~server-side pagination~~ (3.2/3.3), ~~1k/10k/50k-asset test fixtures~~ (3.7), ~~ClickHouse/API profiling~~ (3.8), ~~coverage gate + frontend tests in CI~~ (3.0/3.1) |
| **P4** | 3–5 sprints | Differentiating features | **Done** — ~~TLS hostname/SAN-CN mismatch check~~ (4.1); ~~IP↔FQDN↔certificate correlation~~ (4.2); ~~ownership graph~~ (4.3); ~~web screenshots with retention/redaction~~ (4.4, closes [9.3](#phase-9--exposure-fingerprinting)); ~~risk-priority explanation~~ (`risk_explanation` from scoring model `mvp-2`, see [docs/pulse-backend.md](docs/pulse-backend.md)) — see [breakdown](#p4-breakdown--differentiating-features) |

P0 and P1 are complete — a second API replica is now safe to run; P2 completes the EASM alerting loop already scaffolded in Phase 10; P3 is a parallel hardening track, not a blocking dependency; P4 is scope already flagged as deferred/out-of-scope in Phases 9–10. P4.1 landed ahead of the P0–P2 ordering because it needed nothing from either — it reads certificates the scanner had already collected — but the rest of P4 keeps it: 4.2 feeds asset identity and 4.3 the alerting graph P2 is building.

### P1 breakdown — Durable control plane

**Why this blocks MSSP scale:** every manifest in `k8s/` runs `replicas: 1`, and until 1.1/1.2 that was not a sizing choice but a correctness requirement — the job queue and the agent registry were per-process dicts, so a second replica meant a second control plane. 1.1/1.2 removed that constraint for *state*, 1.4 makes a replica's death recoverable rather than permanent, and 1.6 gives the one worker that must not run everywhere a leader. `replicas: 1` in `k8s/` is now a sizing default, not a correctness requirement.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 1.1 | `jobs` / `agents` tables | `api/db/models.py`, `api/db/migrations/versions/0008_jobs_agents.py` | Tenant-scoped (FK to `tenants`) with the claim query's exact composite index (`execution, status, tenant_id, queued_at`). Agent `status` stores only what the agent reported; "stale" stays derived from `last_seen_at` on read, so one replica's clock cannot freeze a flag the others read back | **Done** |
| 1.2 | Services over the DB | `api/services/{jobs,agents}.py`, `api/routes/jobs.py`, `api/services/schedule_dispatcher.py`, `api/settings.py` | Both services rewritten against SQLAlchemy; list/search/sort pushed into SQL with the P3.2 query parameters and `Page` envelope unchanged (no API change). `claim_job` takes the candidate row with `SELECT … FOR UPDATE SKIP LOCKED` — the guarantee the per-process `threading.Lock` stopped making the moment a second replica existed. Job gauges are now counted in the table, closing the "single-process gauges" gap in [docs/slo.md](docs/slo.md) (they are cluster-wide, so aggregate with `max()`, not `sum()`). Legacy `state/api_{jobs,agents}.json` are imported once at startup and renamed `*.imported`. New `OCTO_INSTANCE_ID` records which replica owns a local-mode job, so a restart fails only its own orphans instead of every other replica's running scans | **Done** |
| 1.3 | Formal state machine | `api/services/job_states.py` (new), `api/services/jobs.py`, `api/routes/{jobs,agents}.py` | The lifecycle is a transition table, enforced on every status write (`_update_job`), not assigned per call site; an illegal move raises `InvalidJobTransition` instead of overwriting — so a result upload retried after a network timeout can no longer rewrite a job that already finished. Adds `claimed` (an agent holds the job but has not reported starting; its first heartbeat naming the job promotes it to `running`, which is also where `started_at` is now stamped) and `cancelled` via `POST /api/jobs/{job_id}/cancel`. **Cancellation is only legal from `queued`**: an agent that has claimed a job starts scanning without asking the API again, and nothing can stop a scan in flight, so cancelling a `claimed`/`running` job would report a stop that never happened while the targets were still being scanned — the endpoint answers 409, and an abandoned claimed job is the 1.4 reaper's business. `octo_jobs_running` counts `claimed` too. API-only this iteration: the Web UI renders both new statuses but has no cancel action | **Done** |
| 1.4 | Leases + reaper | `api/db/migrations/versions/0009_job_leases.py` (new), `api/services/job_reaper.py` (new), `api/services/jobs.py`, `api/settings.py`, `api/app.py` | `jobs.claimed_until` + `jobs.attempts` (migration `0009`). The deadline is set at the claim, not at the first heartbeat — an agent that dies in between is exactly the case this exists for — and is renewed by the agent heartbeat; **local jobs renew from a thread beside the scan**, which is what finally closes the 1.2 residual (the renewals stop with the replica, so an orphaned local job stops looking attended). A 60s sweep (`OCTO_JOB_REAPER_INTERVAL_SECONDS`) requeues expired **agent** jobs until `OCTO_JOB_MAX_ATTEMPTS` hand-outs are used, then fails them, so a target that kills whatever picks it up cannot cycle the fleet; expired **local** jobs are failed outright, since their only executor was the dead process and requeueing would park them forever. Runs in **every** replica with no leader election (`FOR UPDATE SKIP LOCKED`; expiry is a property of the row) — unlike the 1.6 dispatcher. The claim response carries the `attempt` number as a fencing token, so a straggling upload from an expired lease cannot overwrite the run of the attempt that replaced it (a restarted worker keeps its `agent_id`). The bundled agent now heartbeats for the whole scan — one heartbeat at the start would have let any scan longer than the lease be requeued underneath it. New `octo_job_lease_expired_total{outcome}`; lease-exhausted failures are observed by the duration histogram, so they land on the failure side of the completion SLO; `attempts` is on `JobInfo` | **Done** |
| 1.5 | Idempotency keys | `api/db/migrations/versions/0010_job_idempotency.py` (new), `api/routes/{jobs,agents}.py`, `api/services/jobs.py`, `agent/worker.py`, `api/services/schedule_dispatcher.py` | `jobs.idempotency_key` (unique per tenant, enforced by the index — a read-then-insert loses the race between two replicas serving one retry) and `jobs.results_idempotency_key`. `POST /api/jobs` honours an `Idempotency-Key` header and answers **200** (not 202) with the existing job; `POST /agent/jobs/{id}/results` takes an `idempotency_key` form field and replays the stored outcome instead of the 422 a second completion gets, with **409** when a second upload contradicts the first. Keyless agents still get replay detection from the natural key (same agent + job + exit code), so the agent contract stays backward compatible; the bundled agent derives its key rather than randomising it, so a restarted process computes the same one. A cancelled job is explicitly *not* replayable — cancellation is a decision, not an outcome. Applied to the schedule dispatcher too (keyed on the schedule's due time), which stops duplicate *scans* across replicas without pretending to be 1.6. New `octo_job_idempotent_replays_total{operation}` | **Done** |
| 1.6 | Scheduler leader election | `api/services/leader_lock.py` (new), `api/services/schedule_dispatcher.py`, `api/services/metrics.py` | The dispatcher thread still starts in every replica, but each tick first takes a **session-scoped Postgres advisory lock** and does nothing without it, so exactly one replica polls and writes the schedule's bookkeeping. A session lock rather than a leader row with a lease: it lives in the connection, so a leader that crashes or is partitioned away has it dropped by Postgres when its backend ends — no expiry to wait out, no lease duration to tune wrong, and a follower's next tick simply wins. It is deliberately **not** a fence: a dying leader and its successor can briefly overlap, which is why the 1.5 idempotency key on each dispatch stays load-bearing rather than becoming redundant. Costs one pooled connection per replica; `octo_scheduler_is_leader` is 1 on exactly one replica. SQLite (the fallback URL) has no advisory locks and no second replica, so the process always leads. This retires the "run one API replica or set `OCTO_SCHEDULER_DISPATCH_ENABLED=false` on all but one" rule | **Done** |

Suggested order: ~~1.3 → 1.4 → 1.5 → 1.6~~ — **all of P1 is Done.**

### P3 breakdown — Scale & observability

**Current state:** `GET /metrics` (Prometheus) now exposes HTTP/job/CH-ingest/NATS-lag metrics (3.4), is scrape-wired for both annotation-based and Prometheus-Operator setups (3.5), and has documented objectives in [docs/slo.md](docs/slo.md) (3.6); per-stage scan wall-clock is recorded to `stage_timings.json` (3.9, [docs/scan-performance.md](docs/scan-performance.md)); OpenTelemetry tracing is opt-in on the API (`OCTO_OTEL_EXPORTER_OTLP_ENDPOINT`); server-side pagination landed on all five list endpoints and their UI tables (3.2/3.3); 1k/10k/50k-asset fixtures exist as `tests/fixtures/scale_seed.py` (3.7) alongside the separate network-load harness in `tests/load/`, and the query paths have been profiled through them (3.8, [docs/scale-profile.md](docs/scale-profile.md)) — end-to-end API latency under concurrency has not; frontend Vitest tests exist (`web-next/src/components/*.test.tsx`) and run in CI (3.0); coverage gate wired via `pytest-cov` at `--cov-fail-under=74` (3.1); ClickHouse queries in `ch_diff.py` do full-table scans with no `LIMIT`, and both CH tables lack `PARTITION BY`.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 3.0 | Wire up existing frontend tests in CI | `.github/workflows/ci.yml` (`web` job) | Add `npm test` (vitest run) step — tests already exist, just not invoked | **Done** |
| 3.1 | Coverage gate | `requirements-dev.txt`, `.github/workflows/ci.yml` (`test` job) | Added `pytest-cov==7.1.0`; `--cov=api --cov=scanner --cov-report=xml --cov-fail-under=74` (measured baseline: 76% with NATS+Postgres up); ratchet the threshold up over time | **Done** |
| 3.2 | Server-side pagination — API | `api/routes/_pagination.py` (new), `api/services/pagination.py` (new), `api/routes/{assets,runs,jobs,agents,schedules}.py` + matching services | Uniform `offset`/`limit`/`q`/`sort`/`order` and a `Page` envelope (`items`/`total`/`offset`/`limit`/`has_more`) on all five lists — **breaking**: they used to return bare arrays. `total` is counted after filtering; unknown `sort` falls back to the resource default. Assets/schedules filter+count+slice in SQL (the asset identifier search became an EXISTS subquery instead of a post-filter over an already-truncated page); jobs/agents filter+sort+slice in memory; runs slice directory names and read each run's JSON for the requested page only. Run sub-resources (`hosts`/`ports`/`vulnerabilities`) stay `limit`-only by design | **Done** |
| 3.3 | Server-side pagination — UI | `web-next/src/components/data-table.tsx`, `hooks/use-pagination.ts` (new), `lib/api.ts`, `(dashboard)/{assets,runs,jobs,agents,schedules,reports}` | `DataTable` gained a `serverPagination` mode (manual paging/sorting/filtering, debounced server-side search, per-resource sortable-column whitelist); `usePagination` holds the state and rewinds to page 1 on any filter/sort change. The dashboard still aggregates: it requests one max-size page and shows the exact `total` with a note when the posture chart samples the cap | **Done** |
| 3.4 | Prometheus instrumentation | `api/app.py`, new `api/services/metrics.py`, `api/services/jobs.py`, `api/services/ch_ingest_worker.py` | `prometheus_client` registry + unauthenticated `GET /metrics`; HTTP request count/duration by method+route (middleware); job duration histogram + queued/running gauges (`jobs.py` lifecycle hooks); ClickHouse ingest batch duration + message outcome counter + JetStream consumer-lag gauge (`ch_ingest_worker.py`). `scanner/main.py`/`agent/worker.py` deferred — neither runs a persistent HTTP server today, so there's no natural scrape target for process-level metrics from them; their contribution (scan duration) is already captured via the job-duration histogram above | **Done** |
| 3.5 | K8s scrape wiring | `k8s/shapoclyack/base/api-deployment.yaml`, `examples/servicemonitor.example.yaml` (new), `k8s/README.md` | `prometheus.io/scrape,port,path` annotations on the API pod template (inert without a scraper, works with the common `kubernetes-pods` job) + a Prometheus Operator `ServiceMonitor` in `examples/` — it needs `monitoring.coreos.com/v1` CRDs that base does not install, so base must stay applicable without the operator. README documents both plus a bare `scrape_configs` snippet, and states `/metrics` is unauthenticated by design and must not reach the Ingress | **Done** |
| 3.6 | SLOs | `docs/slo.md` (new) | Seven SLIs with PromQL over the 3.4 series (API availability/latency, job success/duration, ingest lag + correctness, endpoint acceptance), error-budget policy, burn-rate alerting, and a known-gaps section (per-replica in-memory job gauges, no tenant label, no tracing, no scale baseline). Targets are explicitly starting values pending 3.7/3.8. Also fixes `octo_job_duration_seconds`, whose default buckets stopped at 10s and put every real scan in `+Inf` | **Done** |
| 3.7 | Scale test fixtures (1k/10k/50k) | `tests/fixtures/scale_seed.py` (new), `tests/test_scale_seed.py` | Bulk-insert CLI for Postgres `assets`/`asset_identifiers` + ClickHouse `shapoclyack_vulnerabilities`/`shapoclyack_open_ports` at N scale. Every row derives from `--seed` and the asset index, so runs reproduce, reruns are idempotent (`ON CONFLICT DO NOTHING` / `ReplacingMergeTree` dedupe), and a 10k fixture is a byte-identical superset of the 1k one — a 3.8 measurement stays comparable after growing the dataset. Realistic distributions where they affect the queries under test: a shared CVE pool (so CVEs repeat across hosts), a common-port pool (the CH `ORDER BY` key), a status mix, and timestamps spread over `--days-back` (so `PARTITION BY` has something to partition). Row generation is pure — no DB, no clock — and unit-tested in CI; `--purge` is tenant-scoped and defaults to tenant `scale-test`, never `default` | **Done** |
| 3.9 | Per-stage wall-clock timings | `scanner/pipeline/stage_timing.py` (new), `scanner/main.py`, `docs/scan-performance.md` (new), `tests/load/run.sh` | Records each pipeline stage's duration to `stage_timings.json` so a slow scan can be diagnosed by stage without more hardware or the (still-open) OpenTelemetry work — a lighter answer to the same "where does wall-clock go" question. Documents the inventory/vuln/full intents (see [8.6](#phase-8--outside-in-continuous-discovery)) and delta defaults. Also fixes the load-test peak-RSS monitor that exited before the scanner container started and always reported 0 MiB | **Done** |
| 3.8 | ClickHouse/API/UI profiling at scale | `tests/fixtures/scale_profile.py` (new), `docs/scale-profile.md` (new), `api/services/assets.py`, `api/services/ch_diff.py` | Measured at 1k/10k/50k. **(a)** `list_assets` fetched identifiers one query per row — 5002 statements and ~1.1 s for the dashboard's `limit=5000` page; now one batched `IN` per page, 3 statements flat and 77 ms at 50k. **(b)** The CH diff helpers read a tenant's whole history into a Python set (382k rows / ~460 ms at 50k, and growing with history, not just asset count); server time is only 2–5 ms of that, so they are now bounded by `max_rows` (default 500k) which **raises** rather than truncates — a short set would report dropped keys as removed — and `fetch_tenant_ports` gained the `since` filter its CVE counterpart had. Diffing server-side is the real fix and belongs with whatever wires the helper up; nothing calls it today. **(c)** `PARTITION BY` **evaluated and rejected**: `toYYYYMM(timestamp)` is not a tuning change but a semantic one, since `ReplacingMergeTree` dedupes per partition — verified on CH 24.3, the same key across two months collapses to 1 row unpartitioned and 2 partitioned, turning "current state" into monthly history. `PARTITION BY tenant_id` is redundant (already the leading sorting-key column) and would fragment parts. `TTL` is the tool for bounding growth. Both queries read exactly the rows they return, so there is no pruning to win | **Done** |

Suggested order: 3.0 → 3.1 (cheap, CI-only, independent) → 3.4 (metrics — prerequisite for 3.6, useful for 3.8) → 3.2/3.3 (pagination, can run alongside 3.4) → 3.7 → 3.8 → 3.5/3.6 close it out; 3.9 (stage timings) landed later, independent of the ordering. **All of 3.0–3.9 are Done**, including OpenTelemetry on the API
(`OCTO_OTEL_EXPORTER_OTLP_ENDPOINT`; empty = off). 3.9's `stage_timings.json`
is still the scanner's per-stage diagnostic — traces do not cover
`scanner.main`. Note that 3.8 profiled the *query paths* in-process, so it
does not by itself re-derive the API-latency targets in [docs/slo.md](docs/slo.md)
— that needs an end-to-end measurement through FastAPI under concurrency; see
the "What this does not cover" section of [docs/scale-profile.md](docs/scale-profile.md).

### P4 breakdown — Differentiating features

**What ties these together:** everything here turns data the platform *already*
collects into an assertion it cannot make today. 4.1 compares a certificate the
scanner already parsed against the name it was reached by; 4.2 uses those same
certificate names as identity evidence; 4.3 aggregates identity into ownership;
4.4 is the one item that adds a genuinely new collector, and with it the first
artifacts that can contain third-party personal data — which is why retention
and redaction are in its title rather than a follow-up.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 4.1 | TLS hostname/SAN-CN mismatch | `scanner/pipeline/cert_names.py` (new), `scanner/pipeline/tls_posture.py`, `tls_probe.py`, `config_schema.py`, `scanner/main.py` | `cert_name_mismatch` (medium) when a certificate's DNS identities (subject CN + `DNS:` SANs) cover none of the names the scan used to reach the endpoint. RFC 6125 matching (leftmost `*` = exactly one label, never a public suffix; partial-label wildcards do not match). Applied as one pass over the finished findings, so nmap NSE / `pulse-tls` / stdlib probe are checked identically. The expected-name set is the **forward** half of `hostnames.json` plus the host a Pulse/probe record was dialled by; PTR names are excluded on purpose (a reverse name belongs to the address-block owner, not the service owner, so it would fire on most of the internet), and an IP-only endpoint or an unparsed certificate yields no finding rather than a mismatch. `tls_posture.hostname_mismatch`, default true inside the already opt-in stage | **Done** |
| 4.2 | IP↔FQDN↔certificate correlation | `scanner/pipeline/asset_identity.py`, `api/services/assets.py`, migration `0020` | An IP observation and a bare-FQDN observation become one asset only when forward DNS (`hostnames.json` / `dns_resolution.json`) *and* a certificate on that IP (P4.1 name data) cover the FQDN. Shared hosting (two high-confidence FQDNs on one IP) is recorded and **not** merged. PTR is not evidence. `asset_identity_links` is the named trail; IP lookups go through identifiers so a merged survivor still answers. Docs: [docs/asset-identity.md](docs/asset-identity.md) | **Done** |
| 4.3 | Ownership graph | `api/services/runs.py`, `api/services/assets.py`, `web-next/src/components/attack-surface-graph.tsx` | Group the 11.2 graph by operator-set `business_unit` / `owner_email` (joined through P4.2 identifiers). Unowned names cluster by registrable domain and are labelled as a domain — ASN/org stays a topology colour, not an owner. Filter answers "what does this unit expose" | **Done** |
| 4.4 | Web screenshots + retention/redaction | `scanner/pipeline/screenshots.py`, `api/services/screenshot_retention.py`, `api/routes/runs.py`, run view | Closes [9.3](#phase-9--exposure-fingerprinting). Headless capture of already-known open web ports (no new scope), opt-in (`screenshots.enabled`), capped like `fingerprint.py`. Playwright missing → skip, no pixels. DOM overlay redacts obvious form fields before disk; a heading name is not redacted. PNG access is operator-only; viewers 404. A reaper deletes `runs/*/screenshots/*.png` after `OCTO_SCREENSHOT_RETENTION_DAYS` (default 14); `screenshots.json` stays. Unredacted bytes are never written | **Done** |

Suggested order: 4.1 (done) → 4.2 (done) → 4.3 (done) → 4.4 (done; the only item that adds a new data-protection surface).

---

## Track A — what is actually left

The phase tables above are mostly **Done**, so the remaining capability scope is easier to
read as one list than as five *Partial* rows spread over 40 KB:

| Item | Tracked as | Note |
|------|-----------|------|
| Jira / ServiceNow ticket creation + DefectDojo export | [10.3](#phase-10--change-detection--alerting-at-asset-level) = [P2](#next-priority-order-post-phase-11) | **Done** — further transports over the delivery queue; overlaps Track C's ticket *links* ([#138](https://github.com/onixus/Shapoclyack/issues/138)) |
| OpenTelemetry tracing | [P3](#p3-breakdown--scale--observability) | **Done** — opt-in OTLP HTTP on the API; [3.9](#p3-breakdown--scale--observability) stage timings remain the scanner-side answer |
| IP↔FQDN↔certificate correlation | [P4.2](#p4-breakdown--differentiating-features) | **Done** — feeds Track C's asset model ([#146](https://github.com/onixus/Shapoclyack/issues/146)); see [docs/asset-identity.md](docs/asset-identity.md) |
| Ownership graph | [P4.3](#p4-breakdown--differentiating-features) | **Done** — groups the 11.2 graph by operator-set unit/owner; unowned names by registrable domain |
| Web screenshots + retention/redaction | [P4.4](#p4-breakdown--differentiating-features) | **Done** — Phase [9.3](#phase-9--exposure-fingerprinting) is the same work and defers to it |
| Endpoint-inventory NATS event (S8), cross-repo e2e test (S10) | [Agent_plan.md](Agent_plan.md) (Track D) | **Done** — merged |

Everything else in Phases 1–11 and P0–P3 is merged.

## Track B — Production readiness (GA blockers)

**Source of truth:** [EPIC #154](https://github.com/onixus/Shapoclyack/issues/154), milestone `GA`.
Summarized here because Track A's phase tables give no signal about it.

**Why it is a track and not a checklist:** the first four items below share one failure
mode — the installation is **fail-open**. A deployment brought up from the README without
overriding anything starts with a published JWT secret ([api/settings.py:31](api/settings.py:31)),
`CORS=["*"]` ([api/settings.py:38](api/settings.py:38)) and the built-in `admin`/`operator`
accounts ([api/settings.py:10](api/settings.py:10)), and `authenticate_user` accepts a
**plaintext** password whenever the stored string is not a bcrypt hash
([api/auth.py:100](api/auth.py:100)). Nothing about that start is distinguishable from a
configured one. "Forgot to configure" and "configured" must not look alike.

| Issue | Theme | Est. | Note |
|-------|-------|------|------|
| ~~[#155](https://github.com/onixus/Shapoclyack/issues/155)~~ | Fail-closed config — refuse to start on default secrets / `CORS=*` | **Done** | `OCTO_ENV` defaults to `prod`; refuses on the default JWT secret or any `*` in CORS. The accounts half moved to startup with #156 |
| ~~[#156](https://github.com/onixus/Shapoclyack/issues/156)~~ | Users into Postgres, no plaintext passwords | **Done** | `users` table (migration `0013`) with a real FK from `user_tenants`; bcrypt only; `/api/users` + `POST /api/auth/password`; `OCTO_API_USERS` demoted to a one-time bootstrap import |
| ~~[#157](https://github.com/onixus/Shapoclyack/issues/157)~~ | Login brute-force protection + auth audit | **Done** | `auth_events` (migration `0014`) is the audit trail *and* the counter: 5 failures per (username, IP) and 50 per IP across usernames in a 15-min decaying window → `429` + `Retry-After`, identical whether the account exists. `X-Forwarded-For` honoured only behind `OCTO_TRUSTED_PROXIES`; `octo_auth_attempts_total{outcome}`; admin `GET /api/auth/events` |
| ~~[#151](https://github.com/onixus/Shapoclyack/issues/151)~~ | Outbound webhook SSRF / credential-leak hardening | **Done** | Delivery is pinned to the address that was validated (no DNS-rebinding window) with Host/SNI preserved and redirects never followed; header values are write-only on every read path; `enabled=false` is a real kill switch that returns a claimed delivery to pending *without* spending an attempt; error bodies are read streaming behind one wall-clock delivery deadline; a malformed port is refused at subscription time, not retried at delivery time |
| ~~[#158](https://github.com/onixus/Shapoclyack/issues/158)~~ | Automated backup + **rehearsed** restore | **Done** | Infra was already merged. Drill 2026-08-20 on kind `shapoclyack-dev`: dump of the live lab restored into namespace `shapoclyack-restore` (`overlays/kind-restore`); 5 assets matched source; `db_restore_seconds<1`, `recovery_seconds=31`. Measured RPO 3 min for that backup; CronJob still bounds worst-case at 24 h. ClickHouse / artifact PVC snapshots stay install-specific (no in-repo `VolumeSnapshotClass`) |
| ~~[#159](https://github.com/onixus/Shapoclyack/issues/159)~~ | Safe upgrade — one path to the schema, rollback runbook | **Done** | Advisory lock around `python -m api.db.migrate` in the initContainer ([#192](https://github.com/onixus/Shapoclyack/pull/192)); `create_all` is SQLite-only. Expand/contract and the upgrade/rollback runbook live in [docs/operations.md](docs/operations.md). PDB landed with #158. Postgres restore drill (#158) is done separately; rolling-update rollback remains the runbook in docs/operations.md |
| ~~[#174](https://github.com/onixus/Shapoclyack/issues/174)~~ | `OCTO_POSTGRES_URL` falls back to SQLite | **Done** | [#191](https://github.com/onixus/Shapoclyack/pull/191): `OCTO_ENV=prod` refuses an unset URL and any `sqlite://`. Dev/tests keep the fallback |
| ~~[#160](https://github.com/onixus/Shapoclyack/issues/160)~~ | Cut the release, empty `## Unreleased` | **Done** | 0.41-0817 was cut. `Unreleased` is non-empty again because work landed after the tag; the next cut is a new tag, not a rerun of #160 |
| ~~[#152](https://github.com/onixus/Shapoclyack/issues/152)~~ | Webhook delivery state machine | **Done** | Durable `octo-webhook-fanout` created with `DeliverPolicy.NEW` before bind; DLQ replay refuses `delivered`; claim visibility covers the serial batch so concurrent dispatchers cannot double-POST |
| ~~[#185](https://github.com/onixus/Shapoclyack/issues/185)~~ | End-to-end API latency under concurrency | **Done** | `tests/fixtures/api_latency.py`; kind-dev 2026-08-20 at 1k/10k/50k × conc 32: list GET p95 < 500 ms, `/api/system` tight; SLO 4/5 not re-derived |
| ~~[#186](https://github.com/onixus/Shapoclyack/issues/186)~~ | PrometheusRule from SLO + scheduler leadership | **Done** | `examples/prometheus-slo.rules.yaml` + Operator wrapper; `promtool check rules` in CI; `octo_scheduler_is_leader` `> 1` (5 m) and `== 0` (10 m) |
| ~~[#187](https://github.com/onixus/Shapoclyack/issues/187)~~ | Data-growth bounds (ClickHouse TTL + run retention) | **Done** | ClickHouse `TTL timestamp + INTERVAL 90 DAY` in `init.sql` / configmap; in-process `run_retention` worker deletes expired `runs/*` past `OCTO_RUN_RETENTION_DAYS` (30) |
| ~~[#188](https://github.com/onixus/Shapoclyack/issues/188)~~ | Multi-replica load run (≥2 API replicas) | **Done** | `tests/fixtures/multi_replica_load.py` & `tests/test_multi_replica_load.py`; concurrent job claims via `FOR UPDATE SKIP LOCKED`, idempotent job submissions, scheduler leader election and reaper lease sweeps across replicas |

Order: Wave 0 is done (~~#158~~ drill 2026-08-20). Wave 1 follows:
~~#152~~ → ~~#185/#186~~ → ~~#187~~ → ~~#188~~ (**Wave 1 complete**).

**Wave 1** is now filed rather than described here:
~~[#152](https://github.com/onixus/Shapoclyack/issues/152)~~ webhook state-machine
correctness — **Done**;
~~[#185](https://github.com/onixus/Shapoclyack/issues/185)~~ end-to-end API latency
under concurrency — **Done**: GET p95 measured through FastAPI at 1k/10k/50k ×
conc 1/8/32 on kind-dev; list routes stay under 500 ms at 50k × 32, `/api/system`
is the outlier; SLO 4/5 still unmeasured on this stand (no job histogram,
ingest off);
~~[#186](https://github.com/onixus/Shapoclyack/issues/186)~~ alert rules as code —
**Done**: `prometheus-slo.rules.yaml` + Operator wrapper, `promtool` in CI,
scheduler `> 1` and `== 0`;
(with [#153](https://github.com/onixus/Shapoclyack/issues/153) for webhook
configuration and limits);
~~[#187](https://github.com/onixus/Shapoclyack/issues/187)~~ data-growth bounds —
**Done**: ClickHouse `TTL timestamp + INTERVAL 90 DAY` on vulnerabilities and open ports,
plus in-process run artifact reaper (`run_retention.py`, `OCTO_RUN_RETENTION_DAYS=30`);
and ~~[#188](https://github.com/onixus/Shapoclyack/issues/188)~~ a load run at ≥2 API
replicas — **Done**: concurrent claim race elimination (`FOR UPDATE SKIP LOCKED`),
idempotency replay under load, scheduler leadership locks verified.



## Track C — Vulnerability Management product

**Source of truth:** [EPIC #134](https://github.com/onixus/Shapoclyack/issues/134) and
[docs/ui-ux-redesign-roadmap.md](docs/ui-ux-redesign-roadmap.md).

**Why it is not just UI work:** the redesign's premise is that a security manager can
answer "what is our risk, who owns it, what breaches SLA" without starting a scan. The
three backend issues (#144, #145, #146) are the real scope and the five UI issues render
what they produce. All of it is on `main`; EPIC [#134](https://github.com/onixus/Shapoclyack/issues/134) is closed. Historical score snapshots for trend charts — the last leftover of #144 — are merged as well (`risk_score_snapshots`, migration `0023`, `GET /api/vulnerabilities/risk-history`), so Track C has no open scope.

| Issue | Layer | Scope |
|-------|-------|-------|
| ~~[#144](https://github.com/onixus/Shapoclyack/issues/144)~~ | Backend | **Done** — scoring model `nist-1`: NIST SP 800-30 likelihood × impact through Table I-2, exploit maturity (`attacked`/`weaponized`/`proof_of_concept`/`unproven`/`theoretical`/`unknown`) with a named evidence trail, and asset criticality moved onto the impact axis where it can change the verdict. Methodology and its stated limits: [docs/risk-scoring.md](docs/risk-scoring.md). Remaining scope split out as ~~[#171](https://github.com/onixus/Shapoclyack/issues/171)~~ (**done** — host reachability as a likelihood input; public IP is not `external`), ~~[#172](https://github.com/onixus/Shapoclyack/issues/172)~~ (**done** — CVE publication age, raise-only; overlay staleness visible), ~~[#173](https://github.com/onixus/Shapoclyack/issues/173)~~ (**done** — compensating controls as a named −6 when fingerprint saw a CDN/WAF on the same host:port; same-asset path +8 when a local finding shares a P4.2 asset with a network foothold; not a domain-takeover model). Historical score snapshots for trend charts are **done** as well — `api/services/risk_snapshots.py`, `risk_score_snapshots` (migration `0023`), `GET /api/vulnerabilities/risk-history` for the series and an operator `POST .../risk-history/snapshot` to capture one |
| ~~[#145](https://github.com/onixus/Shapoclyack/issues/145)~~ | Backend | **Done** — the finding is an entity now (`vulnerabilities` + `vulnerability_events` + `sla_policies`, migration `0015`), keyed `sha256(asset\|CVE-or-script\|port)` per tenant so it survives runs. Lifecycle `OPEN → ACKNOWLEDGED → PLANNED → FIXING → VERIFYING → CLOSED` with `CLOSED → OPEN` on regression; SLA by (asset criticality, severity) with breach derived on read; expiring risk exceptions; every change audited in the same transaction. Absence is never auto-closed. Docs: [docs/vulnerability-lifecycle.md](docs/vulnerability-lifecycle.md). **Not** included: event retention (score history/trends landed with [#144](https://github.com/onixus/Shapoclyack/issues/144)) |
| ~~[#146](https://github.com/onixus/Shapoclyack/issues/146)~~ | Backend | **Done** — asset business context (`business_service`, `environment`, `data_classification`, `exposure_level`, `context_source`) plus a same-transaction audit trail and a per-asset risk rollup. CMDB/AD use the same PATCH. Exposure is an operator decision, not a scan fact ([#171](https://github.com/onixus/Shapoclyack/issues/171)); identity merge is [P4.2](#p4-breakdown--differentiating-features). Docs: [docs/asset-context.md](docs/asset-context.md) |
| ~~[#135](https://github.com/onixus/Shapoclyack/issues/135)~~ | UI | **Done** — Risk Overview (`/`) on tracked findings: estate NIST verdict, SLA, unassigned work, unowned assets. Trend charts now read persisted snapshots ([#144](https://github.com/onixus/Shapoclyack/issues/144) leftover, merged) |
| ~~[#136](https://github.com/onixus/Shapoclyack/issues/136)~~ | UI | **Done** — asset-centric security view: inventory and `/assets/view` show owner, service, exposure, open tracked risk and the next required action. Scan evidence is secondary. Built on #146 |
| ~~[#137](https://github.com/onixus/Shapoclyack/issues/137)~~ | UI | **Done** — Vulnerability Center (`/vulnerabilities`, `/vulnerabilities/view`) on top of #145: lifecycle stepper, owner, SLA, risk acceptance, audit trail. CWE is copied from the last observation (NVD overlay, else nuclei) |
| ~~[#138](https://github.com/onixus/Shapoclyack/issues/138)~~ | UI | **Done** — Remediation Board (`/remediation`) + comments + ticket *links*. Native Jira/ServiceNow/DefectDojo create is [10.3](#phase-10--change-detection--alerting-at-asset-level)/P2. SMAX was listed in the issue and is **not** implemented |
| ~~[#139](https://github.com/onixus/Shapoclyack/issues/139)~~ | UI | **Done** — MSSP tenant posture comparison, declared-exposure inventory, KEV threat intel. Same-asset path and CDN/WAF compensating controls are [#173](https://github.com/onixus/Shapoclyack/issues/173); internet as a scan fact is [#171](https://github.com/onixus/Shapoclyack/issues/171) |

Backend before UI: #144/#145/#146 → their dependent UI issues. Two overlaps with Track A
are worth resolving before either starts, so the work is not built twice: ticketing
(#138 ↔ 10.3/P2, both done) and asset identity (#146 ↔ P4.2).

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Done** | Merged to `main` (may be ahead of the last tagged release — see [CHANGELOG.md](CHANGELOG.md) `## Unreleased` for what hasn't shipped in a tag yet) |
| **Planned** | Documented here; not started |
| **In progress** | Active branch / PR (update when work starts) |
| **Partial** | Some sub-items merged, named remainder still open |

**Track A status:** Phases 1–11 and P0–P4 are **Done** (OpenTelemetry is
opt-in OTLP on the API). Agent_plan Track D (S8/S10) is merged, so no Track A item is open.

**Track B and C statuses live in their issues**, not here — a status duplicated in two
places is a status that will disagree with itself. This file links; the issues decide.
