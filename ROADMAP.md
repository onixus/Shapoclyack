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
| `web/` | React/Vite frontend (v1) |
| `web-next/` | Next.js 14 App Router dashboard (Web UI v2) |
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

### Phase 6 — Web UI v2 (`web-next/`)

**Goal:** MSSP / Enterprise console on Next.js 14 (App Router) with Tremor charts and TanStack tables. Keep `web/` (v1) until feature parity.

| ID | Task | Dir / surface | Action | Status |
|----|------|---------------|--------|--------|
| 6.1 | Scaffold | `web-next/` | Next.js 14 + Tailwind + Shadcn (Slate) + Tremor + React Query | **In progress** (this branch) |
| 6.2 | Shell | `web-next/src/components/layout/` | Sidebar (Dashboard, Tenants, Agents, Jobs, Runs, Assets) + top header | **In progress** |
| 6.3 | Dashboard | `web-next/src/app/(dashboard)/` | Tremor AreaChart / DonutChart mock KPIs | **In progress** |
| 6.4 | Tenants | `…/tenants/` | TanStack table + Create Tenant dialog (Provisioning Key) | **In progress** |
| 6.5 | Assets | `…/assets/` | Inventory table + Diff-badges (50k+ fleet mock) | **In progress** |
| 6.6 | API client | `web-next/src/lib/api.ts` | Axios + JWT interceptor; wire to live FastAPI | Planned |

---

## Suggested delivery order

```text
Phase 1 (NATS + ingest gateway)
    → Phase 2 (tenancy + agent JWT)
        → Phase 3 (ClickHouse + analytical diffs)
            → Phase 4 (spread / VPA)
                → Phase 5 (Cloudflare / CT / Maddy SMTP)
Phase 6 (Web UI v2) can proceed in parallel with 1–3 (mock data first, then live API).
```

Phases 1–2 unlock safe multi-tenant agent scale. Phase 3 unlocks 50k-asset analytics. Phases 4–5 harden ops and expand discovery/alerting. Phase 6 replaces the operator console for MSSP workflows.

---

## Status legend

| Status | Meaning |
|--------|---------|
| **Done** | Shipped in current `main` / shapoclyack-0.33 |
| **Planned** | Documented here; not started |
| **In progress** | Active branch / PR (update when work starts) |

All platform evolution phases above are **Planned** until work begins.
