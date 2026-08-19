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
| `/` | Risk Overview: estate NIST verdict, SLA, unassigned work, unowned assets | Viewer |
| `/vulnerabilities` | Vulnerability Center: tracked findings, lifecycle, owner, SLA | Viewer |
| `/vulnerabilities/view?vulnId=…` | Finding detail, transitions, assignment, risk acceptance, audit trail | Viewer; operator to move/assign; admin to accept risk |
| `/assets` | Cross-run asset inventory | Viewer |
| `/assets/view?assetId=…` | Asset metadata, findings, ports, OS/GeoIP, endpoint software | Viewer; operator for permitted edits |
| `/attack-surface` | Hostname → IP → port → service graph | Viewer |
| `/geo` | World map of a run's hosts by GeoIP position, coloured by worst finding | Viewer |
| `/endpoints` | Endpoint device/software inventory and recent changes | Viewer |
| `/jobs` | Start and monitor scan jobs | Operator |
| `/runs` | Tenant-scoped run history | Viewer |
| `/runs/view?runId=…` | Findings, entities, diff, artifacts, contextual score and risk explanation | Viewer |
| `/reports` | Report and artifact discovery | Viewer |
| `/schedules` | Tenant-scoped recurring scan schedules | Operator |
| `/agents` | Distributed worker fleet | Operator |
| `/tenants` | Tenant provisioning and membership administration | Admin |
| `/system` | Versions, dependencies, stages, runtime, retention state, safe config | Viewer; admin for edits |

## Risk Overview

`/` is the executive view of **current** cyber risk. It reads tracked findings
(`GET /api/vulnerabilities/summary`) and asset posture
(`GET /api/assets/summary`), not the last scan's `vulnerabilities.json`.

Headline tiles:

- **Estate risk** — the worst open NIST SP 800-30 `risk_level` (not an average:
  a hundred Lows must not cancel a Very High);
- open critical/high, SLA breaches, unassigned findings, assets without an
  owner.

"Top business risks" is the open tracked-finding list, worst `contextual_score`
first, with owner and SLA. Click-throughs land on the Vulnerability Center
(`?sla=breached`, `?unassigned=1`) or `/assets?unowned=1`.

Internet-facing exposure is **not** a number on this page. The platform does
not yet know whether a host is on the internet ([#171](https://github.com/onixus/Shapoclyack/issues/171),
[#146](https://github.com/onixus/Shapoclyack/issues/146)); drawing zero would
read as "nothing is exposed".

The scan-activity chart is hosts/findings per recent **run** — volume, not
estate risk over time. Historical risk snapshots are still open on
[#144](https://github.com/onixus/Shapoclyack/issues/144).

## Vulnerability Center

`/vulnerabilities` is the working set of **tracked** findings, not the last
scan's raw list. Each row is the persistent entity from
[vulnerability-lifecycle.md](vulnerability-lifecycle.md): the same
`(asset, CVE-or-script, port)` across runs, with an owner, a lifecycle state
and an SLA reading. Default view is everything not `CLOSED`, worst (contextual
score) first.

Header counts come from `GET /api/vulnerabilities/summary` so they agree with
the filtered table. Filters (`state`, severity, SLA, stale days, search) are
server-side. An asset's Vulnerabilities tab links here when that asset has
open tracked findings (`?assetId=`).

`/vulnerabilities/view?vulnId=…` is the remediation card:

- lifecycle stepper `OPEN → ACKNOWLEDGED → PLANNED → FIXING → VERIFYING → CLOSED`;
- operator **Move lifecycle** (legal transitions only; the API still 409s an
  illegal move) and **Ownership**;
- admin **Accepted risk** (expiry and reason are both required);
- CVSS / risk / owner / first-and-last-seen / SLA, plus EPSS, KEV and the
  risk explanation copied from the last observing run when that run is still
  on disk;
- the audit trail (`observed`, `state_change`, `reopened`, `assigned`,
  `exception_set`, `exception_cleared`).

CWE is not stored on the tracked finding and is shown as empty rather than
inferred. A finding that has gone quiet is not auto-closed; the list's stale
filter is how it gets looked at.

## Geo Map

`/geo` places one run's alive hosts on a world map and colours each marker by
the worst finding on the hosts it covers (critical → no findings). Markers
cluster by position, and marker area is proportional to host count.

What the map claims, and what it does not:

- A GeoIP coordinate is the **registered position of the network** — usually a
  city or country centre — never the machine. Treat a marker as "this network
  is announced from around here", not as an address.
- Hosts whose GeoIP record has a country but no coordinates are plotted at that
  country's centroid and drawn with a **dashed ring**, with a count called out
  above the map. They are a coarser claim than the solid ones, and mixing them
  silently would present a guess as a measurement.
- Hosts with neither — private addresses, or an installation with no GeoIP
  database configured — are listed under **Unlocated hosts** rather than
  dropped, so the map never reads as the whole estate.

Run sub-resources are `limit`-only by design (ROADMAP P3.2), so a run larger
than one page arrives truncated. The page says so in a banner rather than
presenting a partial estate as complete, and a host's finding count always
comes from the server-side per-host total rather than from the truncated
findings page.

The map is a self-contained SVG with no runtime dependency and no external
tiles: nothing on this page calls out of the browser, which also means it works
in an air-gapped install. The land outline and country centroids are generated
into `web-next/src/lib/geo/world-map.ts` by
`web-next/scripts/generate-world-map.mjs` (run by hand; the output is
committed) from Natural Earth 110m data.

Coordinates come from a **City**-edition GeoIP database (`enrichment.geoip`).
With a Country-edition database every marker is country-level, which the page
states rather than hides. See
[configuration.md](configuration.md#enrichment-sources).

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
