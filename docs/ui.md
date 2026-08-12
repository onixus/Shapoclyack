# Web interface

The Next.js 14 interface is built as a static export and served by FastAPI in the all-in-one and API images.

This guide documents **current UI behavior**. Planned VM/Exposure Management screens are tracked separately in [ui-ux-redesign-roadmap.md](ui-ux-redesign-roadmap.md).

## Tenant context

The console has a global tenant switcher for users with more than one allowed tenant. The selected tenant is attached to tenant-scoped API requests and changing it clears cached query data so one customer's data is not reused in another tenant view.

Platform administrators can retain fleet-wide views where the API contract permits them; normal tenant members only see tenants granted by server-side membership rules. Client-side hiding is not an authorization boundary. See [API and RBAC](api-and-rbac.md) for the authoritative tenant model.

## Current surfaces

| Route | Purpose | Minimum role |
|---|---|---|
| `/login` | Create a user session | Public |
| `/` | Exposure KPIs, risk trend, severity, top findings, asset posture | Viewer |
| `/assets` | Cross-run asset inventory | Viewer |
| `/assets/view?assetId=…` | Asset metadata, findings, ports, OS/GeoIP, endpoint software | Viewer; operator for permitted edits |
| `/attack-surface` | Hostname → IP → port → service graph | Viewer |
| `/endpoints` | Endpoint device/software inventory and recent changes | Viewer |
| `/jobs` | Start and monitor scan jobs | Operator |
| `/runs` | Tenant-scoped run history | Viewer |
| `/runs/view?runId=…` | Findings, entities, diff, artifacts, contextual score and risk explanation | Viewer |
| `/reports` | Report and artifact discovery | Viewer |
| `/schedules` | Tenant-scoped recurring scan schedules | Operator |
| `/agents` | Distributed worker fleet | Operator |
| `/tenants` | Tenant provisioning and membership administration | Admin |
| `/system` | Versions, dependencies, stages, runtime, retention state, safe config | Viewer; admin for edits |

## Finding presentation

Run findings may include both confirmed vulnerabilities and lower-confidence exposure/hypothesis records. Where available, the UI displays:

- contextual score;
- CISA-style decision/priority;
- one-line risk explanation;
- KEV marker;
- unconfirmed/confirmation-required state.

Do not equate every row with a confirmed CVE. `finding_class`, `confidence`, `requires_confirmation`, and evidence fields are part of the finding contract and should remain visible enough for an analyst to understand why an item was prioritized.

## Current versus planned UI

The current console still contains scanner- and operations-oriented surfaces such as jobs, runs, agents, and schedules. The target product UX moves toward risk, asset, vulnerability-lifecycle, remediation, and MSSP views. That target is intentionally documented in [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md), not mixed into this current-state guide.

## UI development

```bash
cd web-next
API_PROXY_TARGET=http://127.0.0.1:8080 npm run dev
```

The production export does not use Next.js rewrites. FastAPI serves static files and `/api` on the same origin.

## Documentation rule

When a route, navigation item, role requirement, tenant behavior, or user-visible finding field changes, update this guide in the same PR. Product ideas that are not yet implemented belong in the roadmap, not in the current surface table.
