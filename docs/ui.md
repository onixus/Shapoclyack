# Web interface

The Next.js 14 interface is built as a static export and served by FastAPI in the all-in-one and API images.

This guide documents **current UI behavior**. Planned VM/Exposure Management screens are tracked separately in [ui-ux-redesign-roadmap.md](ui-ux-redesign-roadmap.md).

## Tenant context

The console has a global tenant switcher for users with more than one allowed tenant. The selected tenant is attached to tenant-scoped API requests and changing it clears cached query data so one customer's data is not reused in another tenant view.

Platform administrators can retain fleet-wide views where the API contract permits them; normal tenant members only see tenants granted by server-side membership rules. Client-side hiding is not an authorization boundary. See [API and RBAC](api-and-rbac.md) for the authoritative tenant model.

## Language and theme

The console ships **English** and **dark** as the defaults. The header (and the login screen) expose a sun/moon toggle and an EN/RU language menu. Both persist in `localStorage` (`shapoclyack.theme`, `shapoclyack.locale`) and are applied before first paint so the page does not flash the other theme.

Russian covers chrome: navigation, page titles, table headers, status badges, login, and empty/loading copy. Scan identifiers, CVE IDs, hostnames and API error strings stay as the backend sent them. Status values (`OPEN`, `critical`, `breached`) are translated at the badge, not in the stored finding.

The light theme remaps the existing slate utility classes rather than rewriting every screen. Default remains dark so existing screenshots and operator muscle memory stay valid until someone picks light.

## Current surfaces

| Route | Purpose | Minimum role |
|---|---|---|
| `/login` | Create a user session | Public |
| `/` | Risk Overview: estate NIST verdict, SLA, unassigned work, unowned assets | Viewer |
| `/vulnerabilities` | Vulnerability Center: tracked findings, lifecycle, owner, SLA | Viewer |
| `/vulnerabilities/view?vulnId=…` | Finding detail, transitions, assignment, comments, ticket link, risk acceptance, audit trail | Viewer; operator to move/assign/comment/link; admin to accept risk |
| `/remediation` | Remediation Kanban — detection to verified closure | Viewer; operator to move/assign/comment/link |
| `/assets` | Asset inventory: owner, service, exposure, open tracked risk | Viewer |
| `/assets/view?assetId=…` | Asset-centric security view: required actions, tracked findings, software, scan evidence, history | Viewer; operator for permitted edits |
| `/exposure` | Operator-declared exposure inventory (not a scan measurement) | Viewer |
| `/threats` | Open tracked findings on CISA KEV | Viewer |
| `/tenants` | MSSP customer posture comparison and provisioning | Operator; admin to create |
| `/attack-surface` | One scan's hostname → IP → port → service graph (not an attack path) | Viewer |
| `/geo` | World map of a run's hosts by GeoIP position, coloured by worst finding | Viewer |
| `/endpoints` | Endpoint device/software inventory, CVE matches and the patch-gap panel | Viewer |
| `/jobs` | Start and monitor scan jobs | Operator |
| `/runs` | Tenant-scoped run history | Viewer |
| `/runs/view?runId=…` | Findings, entities, diff, artifacts, contextual score and risk explanation; operator-only Screenshots tab | Viewer; operator for screenshots |
| `/reports` | Report and artifact discovery, plus the report factory panel (branding, templates, schedules, on-demand generation) | Viewer; operator to generate, admin for branding and delivery schedules |
| `/compliance` | PCI DSS 4.0 / CIS v8 / ISO 27001 control status for the selected tenant, with per-control evidence | Viewer |
| `/schedules` | Tenant-scoped recurring scan schedules | Operator |
| `/wordlists` | Tenant-uploaded subdomain/bucket wordlists | Operator |
| `/service-tokens` | Non-interactive API credentials for the selected tenant | Admin |
| `/agents` | Distributed worker fleet: live health tiles, agent drawer, SSH deploy dialog and on-request provisioning keys | Operator |
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

Internet-facing exposure is **not** a number on this page. An operator can
mark an asset as internet-facing ([asset-context.md](asset-context.md));
whether the host is actually on the internet is still
[#171](https://github.com/onixus/Shapoclyack/issues/171). Drawing zero here
would read as "nothing is exposed".

The scan-activity chart is hosts/findings per recent **run** — volume, not
estate risk over time. Estate risk *over time* is the separate trend chart,
which reads persisted snapshots from `GET /api/vulnerabilities/risk-history`
(the most recent 30 by default) rather than recomputing history from the current findings
([#144](https://github.com/onixus/Shapoclyack/issues/144)). Snapshots only
exist from the moment they were recorded, so the chart is empty on a fresh
install and shows a gap for any period nothing was captured — an empty chart
means "not recorded", not "no risk".

## Remediation Board

`/remediation` is the operational workflow for tracked findings. Columns are
the lifecycle states (`OPEN → … → CLOSED`); drag a card onto a legal column,
or use the side panel to move, assign, comment, and link a ticket. Accepted
risk is a badge on the card, not a seventh column — the same rule as the
lifecycle model.

A comment is an audit event (`kind=comment`) and does not change state.
A ticket link (`ticket_system` / `ticket_key` / `ticket_url`) records where
the work lives in Jira, ServiceNow, SMAX or DefectDojo. The platform does
**not** create that ticket from this form: native create is a `transport` on a
webhook subscription (migration `0022`) — the queue opens the ticket over the
same validated wire as the event webhooks and then writes this link back.
Status flows the other way too: syncing a linked ticket reconciles the finding,
and a closure that came from the tracker is recorded as `ticket_resolved`
rather than as verified.

Verification is not a drag: the finding detail page has a **Verify** action that
dispatches a targeted re-scan and parks the card in `VERIFYING`. The card leaves
that column when the run comes back — closed and marked machine-verified if the
finding was not observed, back to `FIXING` if it was. See
[vulnerability-lifecycle.md](vulnerability-lifecycle.md#verification-who-is-allowed-to-say-it-is-fixed).

Evidence on the board is the last observing run. File attachments are out of
scope. The closed column is a recent page, not the full history — the
Vulnerability Center list is the complete working set.

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

CWE comes from NVD (the cvss4 overlay) or nuclei's template classification
on the last observation. Missing is shown as empty, never inferred from
the CVE id. A finding that has gone quiet is not auto-closed; the list's stale
filter is how it gets looked at.

## Asset-centric view

`/assets` is the working set of **assets as security objects**
([#136](https://github.com/onixus/Shapoclyack/issues/136)), not a scan-host
list. Each row shows owner, business service, exposure, open tracked
findings and the worst open NIST `estate_risk`. Search matches identifiers,
owner or service.

`/assets/view?assetId=…` is what an analyst opens to decide what to do:

- headline tiles: asset risk, open / unassigned / SLA-breached findings;
- a required-now banner when work is unassigned or overdue;
- **Findings** — tracked findings with lifecycle, SLA and the next required
  action (assign, acknowledge, …), linking to the finding card and the
  Remediation board;
- **Software** — Lariska inventory when an endpoint is linked;
- **Scan evidence** — last-run ports, host telemetry and raw findings
  (secondary; the working set is the tracker);
- **History** — business-context changes (`GET /api/assets/{id}/events`).

Operators edit owner, service, environment, classification and exposure on
the same page. Exposure is how the asset is *treated*, not a scan fact.
See [asset-context.md](asset-context.md).

## Exposure and MSSP

`/tenants` is the provider comparison ([#139](https://github.com/onixus/Shapoclyack/issues/139)):
each customer row is estate risk, open work, SLA breaches, KEV, unowned
assets, and **declared** internet-facing assets. The same tenant set as
`GET /api/tenants` — an operator of one customer does not see the others.
Open switches the console into that tenant.

`/exposure` lists assets by operator-set `exposure_level`. It is explicitly
not "what the scanner saw on the internet" ([#171](https://github.com/onixus/Shapoclyack/issues/171)).

`/threats` is open tracked findings currently on CISA KEV. `in_kev` and
`exploit_maturity` are copied from the last observation onto the tracker so
the list survives run pruning.

Attack paths (exploit chaining) are not drawn. The attack-surface page is
one run's topology, with an **Ownership** mode (P4.3): operator-set
`business_unit` / `owner_email` first, unowned names clustered by
registrable domain and labelled as a domain. ASN is the network, not the
owner. A filter answers "what does this unit expose".

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

## Run screenshots

`/runs/view` has a **Screenshots** tab for operators and admins only. It lists
the already-redacted PNGs from `GET /api/runs/{id}/screenshots`. Viewers do
not see the tab, do not get the PNG paths in the Artifacts list, and receive
`404` if they request the file.

The capture is opt-in (`screenshots.enabled`) and only visits web ports the
scan already found. Playwright missing is a skip, not a failure. Redaction
covers obvious form fields in the live DOM; a name in a heading is not
redacted. The banner on the tab says so. Pixels older than
`OCTO_SCREENSHOT_RETENTION_DAYS` (14) are deleted; `screenshots.json` stays
in Artifacts.

## SARIF viewer

A run that produced `sarif.json` gets a viewer rather than a raw download.
In the run's **Artifacts** panel that artifact opens a SARIF dialog which
renders the OASIS SARIF v2.1.0 document — rules, `level`, message and the
`host:port` location of each result — in the console's own severity vocabulary.
`/reports` keeps it as a per-run **SARIF** download button. Either way the file
is a normal artifact, so it can be handed to GitHub Code Scanning, GitLab
Security, DefectDojo or a SIEM unchanged.

## Agent fleet and deployment

`/agents` is the worker fleet: status, version, telemetry, deregistration and
remote upgrade. The page takes `operator`; the two actions in the **Deploy
Agent** dialog that hand out a credential — **Generate key** and the SSH push —
take tenant `admin` and answer `403` for an operator
([#231](https://github.com/onixus/Shapoclyack/issues/231)). The page refreshes
on a poll, so it reads as a live view rather than one that needs reloading.

The tiles above the table are `GET /api/agents/summary`: total, online, busy,
stale and **outdated** agents, the last against the server's target version.
A row opens a details drawer with the agent's heartbeat metrics — OS and
architecture, CPU, memory, disk, load and uptime — its capabilities, current
job, and an **Upgrade** action. Upgrade marks the agent (`upgrade_requested`)
and the button then reads as requested; it does not push anything to the host.
The host is upgraded there — see
[operations.md](operations.md#agent-installation-and-upgrade).

The **Deploy Agent** dialog has four tabs. **Remote SSH Push** installs onto a
host the platform connects to itself: host, port, username, either a password or
a private key, an expected SSH host key fingerprint, and optionally Docker. The
dialog polls the deployment and shows the stages (connect → mint credentials →
run installer → verify heartbeat) with the remote installer's output inline.
Credentials are used for that run and not stored, but they do travel to the API.

**Expected SSH host key fingerprint** is required the first time this tenant
deploys to a host, and the deployment is refused without it — the operator's
SSH credentials and a new provisioning key travel over that connection.
**Read from host** reports what the target currently offers; that is a claim by
whoever answered, so the dialog says to confirm it on the host itself before
pressing **It matches — use it**. Once accepted the key is pinned and later
deployments to that host need nothing. If the target ever offers a different
key the push fails with both fingerprints named — see
[operations.md](operations.md#ssh-push-deployment) for what to do about it.

The **Linux One-Liner**, **Docker Container** and **Kubernetes** tabs show
copy-paste snippets, and they open with a `<PROVISIONING_KEY>` placeholder
rather than a live key: opening the dialog must not create a tenant credential.
**Generate key** mints one (`POST /api/agent/deployment-command`) and fills the
snippets in.

The minted key is plaintext in that one response and is hashed at rest, so the
dialog says it cannot be shown again — copy the command before closing. Keys
that were generated and never used are revoked from the tenant's provisioning
keys, not from this dialog.

Removing an agent from this page forgets its registration. A process still
running on the host re-registers on its next heartbeat; stop it there first.

## Compliance posture

`/compliance` reads `GET /api/compliance/frameworks` and
`GET /api/compliance/{framework_id}`, and shows one framework's control table
for the selected tenant. Each row carries its status, the failing and accepted
counts, and expands to the evidence behind it.

Three things on the page are deliberate rather than decorative, and should stay
that way if it is restyled:

- a control with no evidence in this tenant is **`not_assessed`**, shown with
  its reason, and excluded from the score — an empty estate scores nothing, not
  100%;
- accepted risk is counted and shown per control, but does not fail it;
- the score is the share of *assessed* controls passing, and is rendered under
  the catalogue's own scope note, so it cannot be read as compliance with the
  standard.

There is no cross-tenant view here even for a platform admin: a control status
is a statement about one organisation. See
[reports-and-compliance.md](reports-and-compliance.md).

## Report factory

The `/reports` page keeps per-run artifact discovery and adds the report factory
above it: per-tenant branding (`admin`), templates (`operator`), scheduled
delivery (`admin`) and on-demand generation (`operator`). A generated report is
one body rendered as PDF, HTML or JSON, so the JSON an MSSP pipes into its own
portal is the same report as the PDF its customer opens. Delivery is recorded
per recipient rather than per report.

## Endpoint inventory and patch gaps

`/endpoints` lists endpoint devices, their installed software and recent
changes, and — when the software→CVE matcher has vulnerable rows with a
published fix — a **patch-gap panel** that regroups those findings by the
package that actually gets upgraded and names the command. The panel stays
hidden when nothing is outstanding. The asset page's Software tab carries the
same per-device card with a copyable command.

A vulnerable package with no published fix is counted separately and carries no
command. See [software-cve-matching.md](software-cve-matching.md).

## Wordlists and service tokens

`/wordlists` uploads tenant-scoped subdomain and bucket dictionaries
(operator-only; a viewer gets a refusal panel, not an empty table) for selection
per scan — see
[configuration.md](configuration.md#tenant-uploaded-wordlists). Re-uploading
under an existing name replaces it; deleting one does not affect a scan already
running.

`/service-tokens` issues and revokes non-interactive API credentials for the
selected tenant. It is admin-only, and a platform admin has to have a tenant
selected: the token is confined to that tenant, a role, and its scopes. The
secret is shown once, at creation. See
[api-and-rbac.md](api-and-rbac.md#service-tokens).

## Finding presentation

Run findings may include both confirmed vulnerabilities and lower-confidence exposure/hypothesis records. Where available, the UI displays:

- contextual score;
- CISA-style decision/priority;
- one-line risk explanation;
- KEV marker;
- unconfirmed/confirmation-required state.

Do not equate every row with a confirmed CVE. `finding_class`, `confidence`, `requires_confirmation`, and evidence fields are part of the finding contract and should remain visible enough for an analyst to understand why an item was prioritized.

## Not in the console yet

A tenant's **approved scanning scope** (#226) has no console surface: it is
managed over `GET`/`PUT /api/tenants/{id}/scan-scope` by a platform admin, and
`/tenants` neither shows nor edits it. What the console does show is the
consequence — starting a scan outside the scope answers `403` on `/jobs`, with
the offending targets in the error text, and a tenant whose scope was never
approved cannot start one at all. Since #244 saving a **schedule** outside the
scope answers the same `403` on `/schedules` instead of silently never firing,
so the schedule form surfaces the refusal where the operator is standing. See
[api-and-rbac.md](api-and-rbac.md#approved-scanning-scope).

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
