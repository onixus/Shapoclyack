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
| `web/` | React/Vite frontend (**current** dashboard, v1) |
| `web-next/` | Next.js 14 App Router dashboard (**Web UI v2**, planned) |
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

| ID | Task | Dir / surface | Action |
|----|------|---------------|--------|
| 1.1 | Deploy NATS JetStream | `k8s/octo-man/base/` | Create StatefulSet and Service manifests for NATS JetStream |
| 1.2 | Refactor API ingest | `api/services/results_ingest.py` | Convert to an API Gateway: validate payload and `publish` to NATS topic `ingest.raw_results` (idempotency for duplicates) |
| 1.3 | Update agent worker | `agent/worker.py` | Switch from HTTP polling to NATS pull-based consumer for scanning jobs |

### Phase 2 — MSSP Multi-tenancy & Authentication

**Goal:** Secure agent communication and enforce strict tenant isolation.

| ID | Task | Dir / surface | Action |
|----|------|---------------|--------|
| 2.1 | Provisioning | `api/routes/auth.py`, `api/services/auth.py` | Endpoints to generate static Provisioning Keys tied to `tenant_id` |
| 2.2 | JWT exchange | `api/routes/auth.py` | Agents exchange Provisioning Key for a short-lived JWT (`tenant_id` in claims) |
| 2.3 | Gateway JWT validation | `api/services/results_ingest.py` | Enforce JWT before NATS publish; append `tenant_id` to NATS message headers |
| 2.4 | Kubernetes hardening | `k8s/octo-man/base/` | `NetworkPolicy` (agent egress only to API Gateway / Caddy Ingress); ExternalSecrets or `api-secrets.example.yaml` for keys via env (no plaintext keys in manifests) |

### Phase 3 — ClickHouse Analytics Engine

**Goal:** Handle 50k+ assets and generate analytical diff-reports.

| ID | Task | Dir / surface | Action |
|----|------|---------------|--------|
| 3.1 | ClickHouse deployment | `k8s/octo-man/base/` | StatefulSet with `volumeClaimTemplates` on high-IOPS StorageClass |
| 3.2 | NATS → ClickHouse consumer | `api/services/` (or new worker) | Consume `ingest.raw_results`, transform, bulk-insert into ClickHouse |
| 3.3 | Schema setup | ClickHouse DDL | Tables with `ReplacingMergeTree`, keys `(tenant_id, target_ip, port)` for state dedup |
| 3.4 | Diff-report logic | `scanner/pipeline/report_diff.py` | Refactor to query ClickHouse for historical delta (opened/closed ports, new CVEs) |

### Phase 4 — Kubernetes Hardening & Auto-scaling

**Goal:** Prevent outages during heavy / unpredictable VM scans.

| ID | Task | Dir / surface | Action |
|----|------|---------------|--------|
| 4.1 | Agent distribution | `k8s/octo-man/base/agent-deployment.yaml` (from example) | `topologySpreadConstraints` on `topology.kubernetes.io/zone` and `kubernetes.io/hostname` |
| 4.2 | Vertical Pod Autoscaling | `k8s/octo-man/base/` | VPA manifests for agent pods (memory limits on OOM) |

### Phase 5 — Advanced Discovery & Notifications

**Goal:** Autonomous external monitoring.

| ID | Task | Dir / surface | Action |
|----|------|---------------|--------|
| 5.1 | Cloudflare integration | `scanner/pipeline/discover.py` | Cloudflare API for DNS zone import and misconfiguration checks (unproxied A-records) |
| 5.2 | CT logs scanning | `scanner/pipeline/hostnames.py` | Async Certificate Transparency queries for subdomains |
| 5.3 | SMTP alerts via Maddy | `scanner/pipeline/alerts.py` | Outbound SMTP through local Maddy with DKIM/PTR validation |

### Phase 6 — Shapoclyack Web UI v2 (`web-next/`)

**Goal:** Replace the Vite React dashboard with an MSSP / Enterprise Vulnerability Management UI that scales to 50k+ assets (tenants, agents, jobs, runs, asset inventory).

**Stack:** Next.js 14 (App Router), TypeScript, Tailwind CSS, Shadcn UI (Slate), Tremor (charts), TanStack Table, Lucide React, React Query, Zustand, Axios, date-fns.

| ID | Task | Dir / surface | Action |
|----|------|---------------|--------|
| 6.1 | Initialization | `web-next/` | `create-next-app` (TS, Tailwind, ESLint, App Router, `src/`, `@/*`); install React Query / Table / Zustand / Axios / date-fns / Tremor; `shadcn-ui init` + button, card, input, table, dialog, dropdown-menu, tabs, badge |
| 6.2 | Application shell | `web-next/src/components/layout/Sidebar.tsx`, `web-next/src/app/(dashboard)/layout.tsx` | Responsive sidebar (Dashboard, Tenants, Agents, Jobs, Runs, Assets) + top header (profile / logout) wrapping authenticated pages |
| 6.3 | Core pages | `web-next/src/app/(dashboard)/…` | Dashboard (Tremor cards / AreaChart / DonutChart + mock KPIs); Tenants table + “Create Tenant” dialog (Provisioning Key); Assets inventory table (50k+ mock) with Diff-badges |
| 6.4 | API integration | `web-next/src/lib/api.ts`, root layout | Axios + JWT interceptor; React Query provider |

#### Bootstrap notes (Phase 6.1 → 6.2 first)

```bash
npx create-next-app@latest web-next --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
cd web-next
npm install @tanstack/react-query @tanstack/react-table zustand axios date-fns @tremor/react
npx shadcn-ui@latest init   # Style: Default, Base color: Slate
npx shadcn-ui@latest add button card input table dialog dropdown-menu tabs badge
```

Then implement `Sidebar.tsx` and `(dashboard)/layout.tsx` before the remaining pages.

**Migration note:** Keep `web/` (v1) serving production until `web-next/` reaches feature parity with Runs / Jobs / Agents and tenant-aware views; then switch aio / API static serving to the Next build (or reverse-proxy via Caddy).

---

## Suggested delivery order

```text
Phase 1 (NATS + ingest gateway)
    → Phase 2 (tenancy + agent JWT)
        → Phase 6 (Web UI v2 shell + tenants/assets)   # can start shell in parallel after 2.1 APIs exist
        → Phase 3 (ClickHouse + analytical diffs)
            → Phase 4 (spread / VPA)
                → Phase 5 (Cloudflare / CT / Maddy SMTP)
```

Phases 1–2 unlock safe multi-tenant agent scale. Phase 6 delivers the MSSP console (can bootstrap UI early with mocks, wire JWT after 2.x). Phase 3 unlocks 50k-asset analytics. Phases 4–5 harden ops and expand discovery/alerting.

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Done** | Shipped in current `main` / shapoclyack-0.33 |
| **Planned** | Documented here; not started |
| **In progress** | Active branch / PR (update when work starts) |

All platform evolution phases above are **Planned** until work begins.
