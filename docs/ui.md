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
| `/tenants` | MSSP customer posture comparison, provisioning, and per-tenant scan-scope approval | Operator; admin to create and to approve scope |
| `/attack-surface` | One scan's hostname → IP → port → service graph (not an attack path) | Viewer |
| `/geo` | World map of a run's hosts by GeoIP position, coloured by worst finding | Viewer |
| `/endpoints` | Endpoint device/software inventory, CVE matches and the patch-gap panel | Viewer |
| `/scans` | Scan operations across both surfaces: KPIs, launcher, job list with cancel and per-job record, recent runs. `/jobs` redirects here | Operator |
| `/scans/external` | External scans: internet-facing launcher (domains, public ranges, org profile, wordlists) and the jobs/runs classified `external` | Operator |
| `/scans/internal` | Internal scans: private-range launcher, agent/endpoint context and the jobs/runs classified `internal` | Operator |
| `/runs` | Tenant-scoped run history, filterable by surface (`?surface=external|internal|mixed|unknown`) | Viewer |
| `/runs/view?runId=…` | Findings, entities, diff, artifacts, contextual score and risk explanation; operator-only Screenshots tab | Viewer; operator for screenshots |
| `/reports` | Report and artifact discovery, plus the report factory panel (branding, templates, schedules, on-demand generation) | Viewer; operator to generate, admin for branding and delivery schedules |
| `/compliance` | PCI DSS 4.0 / CIS v8 / ISO 27001 control status for the selected tenant, with per-control evidence | Viewer |
| `/adoption` | Whether the platform produces outcomes: closures in a window, share confirmed by a scan, SLA adherence, median time to fix, owner and context coverage, closed-and-verified per analyst, time to first value, overlay age; plus **Noise** (false-positive verdicts, suppressions in force and lapsed, overrides, noisiest detectors and observers) and **Coverage** (scanned share, vulnerability-assessed share, and how many approved ranges a scan has reached) | Viewer |
| `/usage` | Usage against quota for the selected tenant, 12-month scan volume, and — for a platform admin — every tenant's consumption plus the quota editor | Viewer; admin for the cross-tenant table and quota edits |
| `/schedules` | Tenant-scoped recurring scan schedules | Operator |
| `/wordlists` | Tenant-uploaded subdomain/bucket wordlists | Operator |
| `/users` | Users & access: accounts and roles, tenant membership, provisioning-key revocation, sign-in audit; every role gets **My account** (own password) | Admin; any role for own password |
| `/integrations` | Outbound webhooks and ticket-system transports (Jira, ServiceNow, DefectDojo): subscriptions, test, secret rotation, delivery log with retry | Operator to read; admin to change |
| `/service-tokens` | Non-interactive API credentials for the selected tenant | Admin |
| `/agents` | Distributed worker fleet: live health tiles, agent drawer, SSH deploy dialog and on-request provisioning keys | Operator |
| `/system` | Versions, dependencies, stages, runtime, retention state, safe config | Viewer; admin for edits |

## Application shell

The sidebar is grouped, not flat: **Overview**, **Risk & remediation**,
**External surface** (external scans, exposure, attack surface, org profile,
geo), **Internal surface** (internal scans, endpoints, agents), **Operations**
(all jobs, runs, schedules, reports, wordlists), **Insights**, and
**Administration**. Groups collapse and remember it per browser
(`shapoclyack.nav.collapsed`); a collapsed group still shows the current page.
Entries below the signed-in role are hidden — presentation only, the API
enforces every request (`src/lib/config/nav.ts`).

The header carries **Search & jump** (`Ctrl`/`⌘` + `K`): pages the role may
see, "start an external / internal scan", and typed ids — a run id opens the
run report, a 12-hex job id opens that job's record on `/scans`, a
`vuln_…` / `asset_…` id opens the detail page, anything else becomes a search
on the Vulnerability Center or the asset inventory (`?q=`). For operators the
header also shows the live count of running and queued jobs (from
`GET /api/jobs/summary`, one grouped count every 15 s) and agents online, in
place of the former decorative "Live System" pill. The sidebar
footer shows the API version and the execution mode (local / agent) from
`GET /api/system`.

### Sessions

**Sign out** ends the session on the server as well as in the browser
([#314](https://github.com/onixus/Shapoclyack/issues/314)): it calls
`POST /api/auth/logout`, which denylists that token's `jti` until it expires,
and then forgets the token locally whether or not the API answered. Before
this, "sign out" only meant "forget it in this browser", so a token copied out
of `localStorage` kept working.

Five minutes before the session ends, a banner above the header says how long
is left and offers **Sign in again**. The countdown is read from the token's own
`exp` (`src/lib/session.ts`) and decides nothing — the API verifies signature,
account, generation and denylist on every request. There is no silent renewal
yet: refresh tokens are still open on #314, so the banner says what will happen
rather than quietly preventing it. An expired token still ends in the hard
redirect to `/login` that `src/lib/api.ts` has always done on a `401`.

Changing your own password on **My account** ends every session of the account,
this one included, so the console lands on the login form.

## Scan operations: external and internal

Every job and run carries a **surface** — `external` (domains, public address
space), `internal` (RFC 1918 / loopback / link-local / CGNAT / IPv6 ULA),
`mixed`, or none (started before the field existed, or on the server's
default input files). The server derives it from the targets at start time;
the surfaced launchers send it explicitly, and the explicit value wins
([api-and-rbac.md](api-and-rbac.md), "Scan surface"). The console never
renders an absent value as internal: it shows **Unclassified**.

`/scans/external` and `/scans/internal` share one page body
(`src/components/scans/scan-operations.tsx`):

- KPI row — running / queued (`/api/jobs/summary`, per surface), last
  completed run and success rate over the last 50 started jobs, and one
  surface-specific tile: open findings whose network exposure matches the
  surface (`by_network_exposure_open`; a scan launched from the external page
  declares its surface, and that declaration is exposure evidence — see
  [risk-scoring.md](risk-scoring.md)), agents online (internal), approved
  domains and promoted related domains (external, admin);
- the launcher, shaped by the surface: external leads with domains and offers
  `org_profile` and wordlists; internal leads with private ranges and hides
  both. A live hint classifies what was typed and warns when it contradicts
  the launcher; the confirm dialog names the surface, intent and mode. The
  request carries an `Idempotency-Key` that changes with the form's content,
  so a retry of the same form after a timeout replays instead of queueing
  twice, while an edited form is a new request (the API also compares a
  digest of the body and answers 409 when a key is reused for a different
  scan);
- the job table with a **Cancel** action on queued/claimed jobs (the API
  answers 409 once a job runs) and a per-job drawer: timeline and duration,
  attempts, exit code, error, intent summary, target counts, promoted domains
  admitted and dropped, wordlist, agent, command line, links to the run and
  its findings. `/scans?job=<id>` opens the drawer directly;
- recent runs on that surface, linking to `/runs?surface=`.

The dashboard's **Scan operations** block shows, per surface, the last run's
age (flagged after 30 days — an unobserved surface is not a clean one), what
is running, findings in that run, and a launch button; beside it the open
findings split by observed network exposure. `/schedules` has a surface
selector (or "derive from targets") and column; the Vulnerability Center has
a **Network exposure** filter (`?exposure=`). The Remediation card shows an
unknown exposure as `unknown`, no longer as `internal`.

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
the filtered table. Filters (`state`, severity, **source**, SLA, stale days,
search) are server-side. An asset's Vulnerabilities tab links here when that
asset has open tracked findings (`?assetId=`); `?source=` is a deep link too.

A **Source** badge distinguishes a network-scan finding from one the endpoint
software inventory produced. A software finding has no port by construction, so
its row shows the installed package and the version that closes it
(`curl 7.68.0-1ubuntu2.1 → 7.68.0-1ubuntu2.20`) where a scan finding shows
`port 443`.

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

For an endpoint-software finding the **Verify** button is not shown at all: the
API refuses the dispatch (`409`) because a re-scan does not observe an installed
package, and offering a button that cannot work is worse than offering none. In
its place the card says the finding is verified by the endpoint's next
inventory snapshot and when it was last observed. The Finding card shows the
`device_id` where a scan finding shows the port.

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

**Scan scope** on a tenant row (admin only) opens that customer's approved
scanning scope (#226) — the thing a fresh installation has none of, which is
why its first scan is refused. The dialog shows what is approved now, with the
admin and timestamp each entry was written under, and an editor seeded from it:
per row an effect (`allow`/`deny`), a kind (`cidr`/`domain`), a value and a
note. Approving `PUT`s the whole list, because the API replaces the scope
rather than patching it — a scope is evaluated as a set, so there is no
half-applied state that is safe to enforce. The button stays disabled until
something changes, an empty list is offered with a warning that the tenant will
then not be able to scan anything, and the value checks in the browser are
warnings under the row rather than gates: only an empty value stops the
request, everything else is sent and the API's `422` is shown with its own
text. The scope is re-read at the moment of the write and the approval is
refused if it moved in between — the endpoint replaces the whole list and has
no ETag, so two admins with the dialog open would otherwise silently undo each
other; the editor then starts again from what is approved now. Beneath the
editor the tenant's **promoted related domains** (org_profile M4) are listed
read-only — operators add those underneath the scope and every scan they start
carries them, so the admin approving the scope can see them. An operator never
reaches the dialog: the **Scan scope** action is only on the row for an admin,
and the hint at the foot of the page says who approves a scope.

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

`/adoption` reads `GET /api/adoption?window_days=…` (30/90/180/365 from the page)
and renders it as tiles and three panels. A share the API could not compute —
no closures, no assets — is shown as `n/a`, never as 0% or 100%: an empty
denominator is not a verdict in either direction. Everything on the page is
computed inside the installation from the tenant's own tables; nothing is sent
anywhere, which is what makes it usable as the precondition ROADMAP Track E
names for judging its own features.

Two sections were added with the false-positive loop, and both are there to stop
a number reading better than the estate.

**Noise** counts what was closed as never having been real, apart from what was
remediated. The Closed tile says so in as many words, because the two used to be
one number: a quarter spent marking findings as noise would have read as a
quarter spent fixing them. The section carries the suppressions in force, the
ones that have lapsed and are waiting for a second look, the verdicts the
scanner **broke by evidence** — the number that says whether one was hiding
something — and the median time to a verdict, which is triage speed and is
deliberately not part of MTTR. Two tables split the noise by detector and by
observer (`scan` against `endpoint_software`); a rate needs at least 20 closures
behind it and is shown as `n/a` below that, with the raw counts still on the
row, because one verdict out of one closure is not a 100% error rate. The quiet
observer is listed even with no verdicts — it is the comparison that makes the
other row mean anything.

**Coverage** answers the question underneath every other number on the page: is
the scanner looking at the whole of what it was allowed to look at? The scanned
share is read from a column only the scan-ingest path writes, never from
`last_seen`, which an endpoint agent's inventory check-in also moves — a fleet
of agents reporting on schedule used to make an unscanned estate look fully
covered. There is no backfill, so the columns fill one run at a time after an
upgrade, and both scan shares read `n/a` until enough of the estate has any scan
history for a share to be about the estate rather than about the rollout: no
coverage *data*, which is not the same as no coverage. **Assessed for
vulnerabilities** is a separate reading, because a discovery sweep covers an
asset for inventory and says nothing about its vulnerabilities; it counts a run
only when the run's own stage manifest shows a vulnerability stage that actually
ran, since `vulnerabilities.json` is exported by every run whether or not
anything looked.

**Approved ranges reached** counts approvals, not addresses. A share of the
approved *address space* answered 2.9% for a fully scanned /22 with thirty live
hosts — a statement about how empty IPv4 subnets are — and could not tell an
empty range from one nobody had ever scanned. The unit is now the approval
somebody wrote down: how many approved ranges contain an asset a scan reached
inside the window, with the ranges that contain none listed by name underneath,
which is the part an operator acts on. Deny rows are not approvals and are
counted separately; a wildcard or a domain suffix is no address space at all,
so those entries are named apart rather than counted as missed.

On `/vulnerabilities/view`, an admin gets a **False positive** card beside
Accepted risk: a reason and a suppression length between 1 and 365 days, both
required. A finding under an unexpired verdict wears a `Suppressed until …`
badge in the header next to its closure reason — the badge tracks the
*suppression*, not the verdict, because a lapsed verdict leaves the closure
reason in place and stops holding the finding down, which is the whole point of
the expiry.

`/compliance` reads `GET /api/compliance/frameworks` and
`GET /api/compliance/{framework_id}`, and shows one framework's control table
for the selected tenant. Each row carries its status, the failing and accepted
counts, and expands to the evidence behind it.

Three things on the page are deliberate rather than decorative, and should stay
that way if it is restyled:

- the evidence base says how many findings an unexpired **false-positive
  verdict** is holding out of the assessment. A control can pass because the
  estate was fixed or because the findings behind it were marked as never real,
  and the score is the same number either way; it is not docked for a verdict,
  but the reader of a compliance page is the reader who has to be able to tell
  the two apart;
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

## Usage and quotas

`/usage` is what the tenant has consumed against what was sold (ROADMAP Track E).
It reads `GET /api/usage?history_months=12` for the selected tenant and shows:

- **This period** — assets and scans as used against limit, with the remaining
  count. The period is one UTC calendar month, named on the page with the date
  it resets, because that is what a contract covers.
- **Scan volume** — twelve months of scans per month, oldest first, empty
  months drawn as zero bars rather than skipped, so a quiet quarter does not
  read as missing data.
- Whether the limit is one **sold to this customer** or the **platform default**
  they inherited (`quota_source`), plus the note, who last changed it and when.
  "Unlimited because we sold it" and "unlimited because nobody configured this"
  are not the same answer at renewal.
- Whether enforcement is on at all. With `OCTO_QUOTA_ENFORCEMENT_ENABLED` off
  the page is a meter and nothing is refused.

An unlimited resource shows as **unlimited**, not as a bar at 0% or 100%: the
API sends `null` for the limit and for both derived shares, and the page keeps
that distinction — a full-looking bar against no limit reads as an outage.

For a platform admin the page adds two things a customer never sees: a
**cross-tenant table** (`GET /api/usage/tenants`) of every tenant's assets and
scans this period, so "who is near their limit" is one screen rather than
twelve, and a **quota editor** (`GET`/`PUT /api/tenants/{id}/quota`) with the
two limits and a note. Blank or `0` in a limit field means unlimited for that
tenant. Editing is admin-only for the reason scan-scope approval is: an
operator who could raise their own quota is the control removing itself.

The consequences of a quota show up elsewhere in the console rather than here.
A scan refused because the month's entitlement is spent answers `429` on
`POST /api/jobs` (the launcher on `/scans/*`), with the limit, the count and the reset date in the error text — the
operator sees the refusal where they started the scan. An **asset** limit never
fails a scan and produces no console message at all: the run succeeds, the
assets already in the inventory get its data, and only newly discovered hosts
are left unregistered. That refusal is visible in the API logs and in
`octo_quota_denied_total{resource="assets"}`, not in the UI. See
[api-and-rbac.md](api-and-rbac.md#usage-metering-and-quotas).

## Endpoint inventory and patch gaps

`/endpoints` lists endpoint devices, their installed software and recent
changes, and — when the software→CVE matcher has vulnerable rows with a
published fix — a **patch-gap panel** that regroups those findings by the
package that actually gets upgraded and names the command. The panel stays
hidden when nothing is outstanding. The asset page's Software tab carries the
same per-device card with a copyable command.

A vulnerable package with no published fix is counted separately and carries no
command. See [software-cve-matching.md](software-cve-matching.md).

The **Matched CVEs** panel links each row to the tracked finding it produced, so
the panel and the Vulnerability Center are not two unconnected places talking
about the same CVE on the same host. A row with no finding says **why** rather
than showing a dead link, and the four reasons are four different facts: the
release is already fixed on this host, the release is not affected, the vendor
has published no fix, or the match is below the severity floor (or has not been
folded in yet). Only a `vulnerable` match with a published fix becomes a
tracked finding ([why](software-cve-matching.md#lifecycle-tracked-findings)).
One string covered all four until 2026-09-08, so an operator could read "no
published fix" on a row with the fix printed in the next column.

## Users & access

`/users` is where an installation stops needing curl for onboarding. Tabs:
**Users** (create with role, initial password and optional email — set in the
same transaction, so a refused address leaves no half-created account; change
role, set email, disable, reset password, delete — never offered for the
signed-in account), **Tenant membership** (grant, change, revoke per tenant;
a platform admin needs no rows), **Provisioning keys** (list and revoke; the
key is *created* on `/agents`), **Sign-in audit** (`GET /api/auth/events`,
paged, filter by outcome) and **My account** (own password), which is the
only tab a non-admin sees. The Users table shows each account's tenant
memberships from `UserInfo.tenants`.

## Integrations

`/integrations` exposes the webhook subsystem (`OCTO_WEBHOOKS_ENABLED`; when it
is off the page says so instead of listing nothing). **Subscriptions**: plain
webhooks and the Jira / ServiceNow / DefectDojo transports that open tickets
from the Remediation board and sync status back; per row Test, Rotate secret
(HMAC transports — the new value is shown once), Edit (including a new
tracker token via `secret`, left empty to keep the current one) and Delete.
**Deliveries**: the paged delivery log with Retry on dead deliveries.
Operators read, admins change.

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

## Enrichment freshness on `/system`

The Enrichment Databases table badges each dataset one of four ways, in that
order of precedence:

| Badge | Meaning |
|---|---|
| `missing` | No file at the path |
| `stale` | Older than 30 days, or the API said so |
| `stub` | Present and loadable, but under the size a real feed publishes |
| `fresh` | Present, current, and above that floor |

`stub` reads `usable` from `GET /api/system` — the build's own verdict against
the per-dataset floor in `scripts/enrichment_manifest.py`. It is there because
the other three columns cannot produce it: the committed advisory seed is
present, has the build's own mtime and a non-zero entry count whether it holds
eight advisories or four hundred thousand, so a fresh offline install rendered
green while matching answered `unknown` for everything outside the seed. Hover
gives the reason.

A `usable` of `null` — no manifest beside the data, which is every image built
before the manifest existed — is left to the age check and badges as it did
before. "Nothing recorded" is not "the data is bad". See
[configuration.md](configuration.md#provenance-what-the-image-actually-shipped).

## Scan scope refusals elsewhere

A tenant's **approved scanning scope** (#226) is edited on `/tenants` (above).
The rest of the console shows its consequence: starting a scan outside the
scope answers `403` on `POST /api/jobs` (the launcher on `/scans/*`), with the
offending targets in the error text,
and a tenant whose scope was never approved cannot start one at all. Since #244
saving a **schedule** outside the scope answers the same `403` on `/schedules`
instead of silently never firing, so the schedule form surfaces the refusal
where the operator is standing. See
[api-and-rbac.md](api-and-rbac.md#approved-scanning-scope).

## Current versus planned UI

The shell now follows the roadmap's information architecture: risk workflows first, then the two scanning surfaces, then the operations that serve both (runs, schedules, agents, reports) and administration. What is still planned — attack paths, ticket views beyond the link, role-specific dashboards — is documented in the [UI/UX redesign roadmap](ui-ux-redesign-roadmap.md), not mixed into this current-state guide.

## UI development

```bash
cd web-next
API_PROXY_TARGET=http://127.0.0.1:8080 npm run dev
```

The production export does not use Next.js rewrites. FastAPI serves static files and `/api` on the same origin.

## Documentation rule

When a route, navigation item, role requirement, tenant behavior, or user-visible finding field changes, update this guide in the same PR. Product ideas that are not yet implemented belong in the roadmap, not in the current surface table.
