# Shapoclyack Roadmap

For installation and operator guidance, see [docs/README.md](docs/README.md).
This file tracks delivery status and is not a deployment manual.

**Repository:** [`onixus/shapoclyack`](https://github.com/onixus/Shapoclyack)  
**Domain target:** MSSP and Enterprise Vulnerability Management (up to **50,000 assets**)

Visual overview: [shapoclyack.html](shapoclyack.html) · Release history: [CHANGELOG.md](CHANGELOG.md)

---

## Current baseline (done)

Shipped through **[shapoclyack-0.33](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.33)**:

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

**Status:** **Done** (8.1–8.5). 8.3's original "public cloud ranges by org tag" half was dropped as not honestly implementable — AWS/GCP publish IP ranges tagged by service+region, not by customer organization; there is no public API that attributes a cloud IP to a specific org.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 8.1 | ASN / WHOIS / BGP org mapping | `scanner/pipeline/asn_discovery.py` (new) | Seed domain → resolved IP → ASN → announced prefixes via RIPEstat's free keyless API; hard-capped at `max_total_ips` (default 4096) since one ASN can span far more than one org's infra | **Done** |
| 8.2 | Expanded subdomain enum | `scanner/pipeline/hostnames.py` | Adds an `otx` (AlienVault OTX passive DNS) provider alongside crt.sh/Cert Spotter, plus an opt-in wordlist brute-force pass (`discovery.ct.brute_force`, built-in `scanner/data/wordlists/subdomains-small.txt`, concurrency/candidate-capped) | **Done** |
| 8.3 | Cloud resource discovery | `scanner/pipeline/cloud_discovery.py` (new) | S3/GCS/Azure Blob bucket + container enumeration via unauthenticated HEAD/GET against public provider endpoints; org tokens × wordlist candidates, hard-capped at `max_candidates` (default 500) and `concurrency` (default 10) since checks hit shared third-party cloud infrastructure, not the target's own hosts; findings reported, never merged into scan scope | **Done** |
| 8.4 | Typosquat / domain monitoring | `scanner/pipeline/domain_monitor.py` (new) | Look-alike domain candidates (omission/transposition/keyboard-adjacent/doubling/homoglyph/TLD-swap generators) resolved via passive dnsx A/AAAA lookups only — same risk class as `ct.brute_force`, never merged into scan scope; plus a dangling-CNAME/subdomain-takeover heuristic over the org's own in-scope FQDNs (CNAME target matches a known vulnerable-service suffix AND has no A/AAAA record) that flags the pattern + non-resolution only and never confirms an actual takeover | **Done** |
| 8.5 | Continuous org-level scheduling | `api/db/models.py` (`ScanSchedule`), `api/services/scan_schedules.py`, `api/services/schedule_dispatcher.py`, `api/routes/schedules.py` | Per-tenant `scan_schedules` table (cron or fixed-interval, target set + scan options); an in-process dispatcher thread (started from the API `lifespan`, same pattern as the ClickHouse ingest worker — no per-tenant K8s CronJob) polls due schedules and calls the existing `jobs_service.start_scan`, skipping a tick if the schedule's previous job is still running. `CRUD via `/api/schedules` (operator role; delete is admin-only). API-only this iteration, no web-next UI. The original `scanner/scheduler.py`/static `cronjob.yaml` remain as-is for simple single-tenant self-hosts. | **Done** |

### Phase 9 — Exposure Fingerprinting

**Goal:** enrich each asset with context beyond ports/CVEs, needed for real prioritization.

**Status:** 9.1, 9.2, 9.4 done; 9.3 Planned.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 9.1 | Tech stack fingerprinting | `scanner/pipeline/fingerprint.py` (new) | One HTTP GET per already-open web port (reuses `open_ports.txt`, no new port scan) → small built-in CDN/WAF header signature set (Cloudflare, Akamai, Sucuri, Imperva/Incapsula, CloudFront, Fastly) + CMS/framework header/body markers (WordPress, Drupal, Joomla, Next.js, generic PHP); opt-in (`fingerprint.enabled`), capped by `max_targets`/`concurrency`/`body_max_bytes` (streamed read); findings reported to `fingerprint.json`/`fingerprint_matches.txt`, never merged into scan scope | **Done** |
| 9.2 | TLS / certificate posture | `scanner/pipeline/tls_posture.py` (new) | Parses the free-text `output` of nmap's own `ssl-cert`/`ssl-enum-ciphers` NSE scripts (already written to `nmap/tcp/*.xml` by the `nse` stage) — no new scan, no TLS-handshake dependency. Findings: `cert_expired`/`cert_expiring_soon` (validity window vs. `expiring_soon_days`), `self_signed` (subject/issuer commonName heuristic, tagged `heuristic`, not certain), `weak_protocol`/`weak_cipher_grade`/`weak_cipher_name` (from `ssl-enum-ciphers`, now added to the `vuln`/`service_specific` NSE profiles). Opt-in (`tls_posture.enabled`), capped by `max_targets`; findings reported to `tls_posture.json`/`tls_posture_findings.txt`, never merged into scan scope. Since nmap's script output is free text rather than a stable schema, parsing is fail-soft (unparseable fields/lines are skipped, never raise). Hostname/SAN-CN mismatch checking is deferred/out of scope. | **Done** |
| 9.3 | Web asset screenshots | new worker (optional) | Visual inventory for UI review | **Planned** |
| 9.4 | Business-context criticality | `api/services/risk_scoring.py`, `api/services/assets.py`, `api/routes/assets.py` | Operator-set `asset_criticality` (0–4) via new `PATCH /assets/{asset_id}`; `ch_transform.vulnerabilities_to_rows` looks it up per host (batched, one query per distinct host per ingest batch) and it wins outright over the port/severity heuristic in `risk_scoring.py` when set; falls back to the existing heuristic when unset or when Postgres/tenant context isn't available (e.g. unit tests, no-DB deployments) | **Done** |

### Phase 10 — Change Detection & Alerting at Asset Level

**Goal:** EASM value comes from tracking change, not one-off reports.

**Status:** 10.1 done; 10.2–10.3 Planned.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 10.1 | Asset-level diff events | `scanner/pipeline/report_diff.py`, `api/services/ch_diff.py`, `api/services/assets.py` | `report_diff.py` emits a normalized `events: [{"kind": ...}]` list (`new_asset`/`new_open_port`/`new_cve` from the existing added-sets, plus a new `cert_expiring` event on a host:port's *first* cert_expired/cert_expiring_soon occurrence across the two most recent runs' `tls_posture.json`); `ch_diff.py`'s tenant-wide ClickHouse path gets the same `new_cve`/`new_open_port` events; `decommissioned_host` is logged when an operator manually transitions an asset via `PATCH /assets/{asset_id}` (`status: "decommissioned"`, the only status an operator may set — active/stale stay system-managed). No NATS/alerting wiring yet — that's 10.2. | **Done** |
| 10.2 | Event bus for alerts | `scanner/pipeline/alerts.py` + NATS | Publish to `events.asset.*` instead of only post-scan summaries | **Planned** |
| 10.3 | Workflow integrations | `api/services/integrations/` (new) | Webhooks, Jira/ServiceNow ticket creation on new critical exposure; extend existing DefectDojo export | **Planned** |

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
| **P1** | 2–4 sprints | Durable control plane | ~~Move jobs and agents into PostgreSQL~~ (done, 1.1/1.2); ~~formal state machine~~ (done, 1.3); leases; idempotency keys; extract the scheduler into its own worker or add leader election — see [breakdown](#p1-breakdown--durable-control-plane) |
| **P2** | 2–3 sprints | Asset event workflows | Finish [Phase 10.2–10.3](#phase-10--change-detection--alerting-at-asset-level): `events.asset.*`, routing policies, webhooks first, retries, DLQ, audit trail; then Jira/ServiceNow |
| **P3** | parallel track | Scale & observability | ~~Prometheus~~ (done, 3.4/3.5), OpenTelemetry, ~~SLOs~~ (done, 3.6), ~~server-side pagination~~ (done, 3.2/3.3), ~~1k/10k/50k-asset test fixtures~~ (done, 3.7), ~~ClickHouse/API profiling~~ (done, 3.8), ~~coverage gate + frontend tests in CI~~ (done, 3.0/3.1) |
| **P4** | — | Differentiating features | Web screenshots with retention/redaction (closes [9.3](#phase-9--exposure-fingerprinting)); TLS hostname/SAN-CN mismatch check; improved IP↔FQDN↔certificate correlation; ownership graph; ~~risk-priority explanation~~ (done — `risk_explanation` from scoring model `mvp-2`, see [docs/pulse-backend.md](docs/pulse-backend.md)) |

P0 is complete; P1 is in progress and remains a prerequisite for safely running the platform at MSSP scale; P2 completes the EASM alerting loop already scaffolded in Phase 10; P3 is a parallel hardening track, not a blocking dependency; P4 is scope already flagged as deferred/out-of-scope in Phases 9–10 and can start once P0–P2 land.

### P1 breakdown — Durable control plane

**Why this blocks MSSP scale:** every manifest in `k8s/` runs `replicas: 1`, and until 1.1/1.2 that was not a sizing choice but a correctness requirement — the job queue and the agent registry were per-process dicts, so a second replica meant a second control plane. 1.1/1.2 removed that constraint for *state*; leases (1.4) and dispatcher leader election (1.6) are what make a second replica actually safe to run.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 1.1 | `jobs` / `agents` tables | `api/db/models.py`, `api/db/migrations/versions/0008_jobs_agents.py` | Tenant-scoped (FK to `tenants`) with the claim query's exact composite index (`execution, status, tenant_id, queued_at`). Agent `status` stores only what the agent reported; "stale" stays derived from `last_seen_at` on read, so one replica's clock cannot freeze a flag the others read back | **Done** |
| 1.2 | Services over the DB | `api/services/{jobs,agents}.py`, `api/routes/jobs.py`, `api/services/schedule_dispatcher.py`, `api/settings.py` | Both services rewritten against SQLAlchemy; list/search/sort pushed into SQL with the P3.2 query parameters and `Page` envelope unchanged (no API change). `claim_job` takes the candidate row with `SELECT … FOR UPDATE SKIP LOCKED` — the guarantee the per-process `threading.Lock` stopped making the moment a second replica existed. Job gauges are now counted in the table, closing the "single-process gauges" gap in [docs/slo.md](docs/slo.md) (they are cluster-wide, so aggregate with `max()`, not `sum()`). Legacy `state/api_{jobs,agents}.json` are imported once at startup and renamed `*.imported`. New `OCTO_INSTANCE_ID` records which replica owns a local-mode job, so a restart fails only its own orphans instead of every other replica's running scans | **Done** |
| 1.3 | Formal state machine | `api/services/job_states.py` (new), `api/services/jobs.py`, `api/routes/{jobs,agents}.py` | The lifecycle is a transition table, enforced on every status write (`_update_job`), not assigned per call site; an illegal move raises `InvalidJobTransition` instead of overwriting — so a result upload retried after a network timeout can no longer rewrite a job that already finished. Adds `claimed` (an agent holds the job but has not reported starting; its first heartbeat naming the job promotes it to `running`) and `cancelled` via `POST /api/jobs/{job_id}/cancel`. **`running → cancelled` is deliberately not in the table**: nothing can stop an in-flight scan — a local job is a subprocess owned by one replica's thread, an agent job runs in another process — so the endpoint answers 409 rather than record a stop that never happened; that needs the 1.4 lease/heartbeat channel. `octo_jobs_running` counts `claimed` too. API-only this iteration: the Web UI renders both new statuses but has no cancel action | **Done** |
| 1.4 | Leases + reaper | `api/services/{jobs,agents}.py` | `claimed_until` extended by agent heartbeat; a sweep returns expired jobs to `queued` with an attempt counter and a retry cap. Also closes the 1.2 residual: a local job orphaned by a replica that never returns under the same `OCTO_INSTANCE_ID` currently stays `running` forever | Planned |
| 1.5 | Idempotency keys | `api/routes/{jobs,agents}.py` | Idempotent result upload (a retried `/results` after a network timeout must not double-ingest a run) and idempotent scan start, so a client retry cannot queue the same scan twice | Planned |
| 1.6 | Scheduler leader election | `api/services/schedule_dispatcher.py` | The dispatcher runs in-process in **every** replica with no coordination, so N replicas dispatch a due schedule N times. Postgres advisory lock (or extract the dispatcher into its own single-replica worker). Until this lands, run one API replica or set `OCTO_SCHEDULER_DISPATCH_ENABLED=false` on all but one | Planned |

Suggested order: ~~1.3~~ (done) → 1.4 (the state machine gives the reaper legal transitions to make) → 1.5 → 1.6 (independent of the rest; can run in parallel).

### P3 breakdown — Scale & observability

**Current state:** `GET /metrics` (Prometheus) now exposes HTTP/job/CH-ingest/NATS-lag metrics (3.4), is scrape-wired for both annotation-based and Prometheus-Operator setups (3.5), and has documented objectives in [docs/slo.md](docs/slo.md) (3.6); no OpenTelemetry tracing; server-side pagination landed on all five list endpoints and their UI tables (3.2/3.3); 1k/10k/50k-asset fixtures exist as `tests/fixtures/scale_seed.py` (3.7) alongside the separate network-load harness in `tests/load/`, and the query paths have been profiled through them (3.8, [docs/scale-profile.md](docs/scale-profile.md)) — end-to-end API latency under concurrency has not; frontend Vitest tests exist (`web-next/src/components/*.test.tsx`) and run in CI (3.0); coverage gate wired via `pytest-cov` at `--cov-fail-under=74` (3.1); ClickHouse queries in `ch_diff.py` do full-table scans with no `LIMIT`, and both CH tables lack `PARTITION BY`.

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
| 3.8 | ClickHouse/API/UI profiling at scale | `tests/fixtures/scale_profile.py` (new), `docs/scale-profile.md` (new), `api/services/assets.py`, `api/services/ch_diff.py` | Measured at 1k/10k/50k. **(a)** `list_assets` fetched identifiers one query per row — 5002 statements and ~1.1 s for the dashboard's `limit=5000` page; now one batched `IN` per page, 3 statements flat and 77 ms at 50k. **(b)** The CH diff helpers read a tenant's whole history into a Python set (382k rows / ~460 ms at 50k, and growing with history, not just asset count); server time is only 2–5 ms of that, so they are now bounded by `max_rows` (default 500k) which **raises** rather than truncates — a short set would report dropped keys as removed — and `fetch_tenant_ports` gained the `since` filter its CVE counterpart had. Diffing server-side is the real fix and belongs with whatever wires the helper up; nothing calls it today. **(c)** `PARTITION BY` **evaluated and rejected**: `toYYYYMM(timestamp)` is not a tuning change but a semantic one, since `ReplacingMergeTree` dedupes per partition — verified on CH 24.3, the same key across two months collapses to 1 row unpartitioned and 2 partitioned, turning "current state" into monthly history. `PARTITION BY tenant_id` is redundant (already the leading sorting-key column) and would fragment parts. `TTL` is the tool for bounding growth. Both queries read exactly the rows they return, so there is no pruning to win | **Done** |

Suggested order: 3.0 → 3.1 (cheap, CI-only, independent) → 3.4 (metrics — prerequisite for 3.6, useful for 3.8) → 3.2/3.3 (pagination, can run alongside 3.4) → 3.7 → 3.8 → 3.5/3.6 close it out. **All of 3.0–3.8 are Done.** The remaining P3 scope is OpenTelemetry tracing, which stays open. Note that 3.8 profiled the *query paths* in-process, so it does not by itself re-derive the API-latency targets in [docs/slo.md](docs/slo.md) — that needs an end-to-end measurement through FastAPI under concurrency; see the "What this does not cover" section of [docs/scale-profile.md](docs/scale-profile.md).

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Done** | Merged to `main` (may be ahead of the last tagged release — see [CHANGELOG.md](CHANGELOG.md) `## Unreleased` for what hasn't shipped in a tag yet) |
| **Planned** | Documented here; not started |
| **In progress** | Active branch / PR (update when work starts) |

Phases 1–8 are **Done** (merged to `main`); Phase 9 is partially done (9.1, 9.2, 9.4); Phase 10 is partially done (10.1); Phase 11 is **Done** (11.1–11.6 — asset card, attack-surface graph, exec dashboard, reports, system status, editable configurator).
