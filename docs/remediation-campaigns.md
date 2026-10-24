# Problems and remediation campaigns

Refs [#579](https://github.com/onixus/Shapoclyack/issues/579). Two layers over
the findings the platform already tracks ([vulnerability-lifecycle.md](vulnerability-lifecycle.md)):

1. **Problems** — an aggregated, read-only view of the findings list: "which
   shared problem do we fix first?".
2. **Remediation campaigns** — a durable effort over a *frozen* set of
   findings, with an owner, a target date, the description of the shared action,
   a per-category progress and a history.

Neither is a second state machine. A finding's state, owner, SLA, exception,
ticket and verification stay on the finding and move only through the existing
operations (`/api/vulnerabilities/...`, [bulk actions](api-and-rbac.md),
the per-finding verify). Source observations and their identity belong to
[#449](https://github.com/onixus/Shapoclyack/issues/449); `finding_key` is not
changed. Ticket transports and field mappings are
[#353](https://github.com/onixus/Shapoclyack/issues/353) and are not touched.

## Problems (`GET /api/problems`)

A problem is **a view**, not a stored object: the tracked findings that share one
typed key (`api/services/problem_identity.py`).

| Key | Meaning |
|---|---|
| `cve:CVE-2024-0001` | normalised CVE (trimmed, upper-case); every finding with that CVE, any asset or port |
| `tpl:<detector>:<template_id>` | a non-CVE finding of a detector template (e.g. `tpl:nuclei:exposed-panel`); the detector is part of the key |
| `script:<script_id>` | a non-CVE finding with only a script id |
| `unknown:<vuln_id>` | no CVE, template or script: the finding is its own problem — **unknown identities are never merged** |

Not a key: the recommendation text (identical advice does not prove a shared
fix). Grouping by advisory/package/fix is only valid when that context is known;
findings do not store it, so it is not offered — put the related problems into
one campaign instead (a campaign takes several problem keys).

Query parameters are the findings list's own (`state`, `open_only`, `severity`,
`asset_id`, `finding_type`, `detector_source`, `source`, `network_exposure`,
`assignee`, `unassigned`, `sla`, `exception_state`, `stale_days`, `in_kev`, `q`,
`sort`, `order`, `offset`, `limit`), so the console carries one filter state
across the **Проблемы / Экземпляры** switch. `sort` is one of `risk` (default),
`severity`, `instances`, `assets`, `breached`, `kev`, `last_seen`, `due`.

Every number is computed in SQL over the **whole filtered selection**, not the
page. The response carries `items` (one row per problem), `total` (problems),
`aggregates` (`problems`, `instances`, `assets`, `breached_instances`,
`kev_instances`, `unassigned_instances`, `machine_verified_instances`), `as_of`
and `semantics`. A row shows:

- `instances` (findings) and `assets` (distinct assets) **separately**;
- `severity`, `contextual_score`, `cvss`: the **worst instance** (maximum), never
  an average. `epss` is always `null` — EPSS is not stored with findings; absent
  data is unknown, not zero. `in_kev` / `kev_instances`, `first_seen_at` /
  `last_seen_at`;
- `owners` (unassigned instances, top assignees and teams), `sla` (breached,
  due soon, earliest due date), `states`, `machine_verified`;
- `exposure`: `external` / `internal` / `unknown` counts, the per-source counts
  (`operator-set`, `scan-surface`, `finding`, `address-space`, `none`) and a
  `basis` roll-up — *declared* (operator-set, scan-surface), *measured*
  (finding), *inferred* (address-space) or *unknown*.

**Drill-down** — `GET /api/problems/instances?problem_key=…` with the same
filters returns the findings behind the row. Passing the row's `as_of` and
`instances` back as `as_of` / `expected_instances` adds `drift`: whether the
count differs and, if so, how many of the findings changed after the list was
loaded (`changed_since_as_of`). `GET /api/vulnerabilities?problem_key=…` takes
the same key. The filters are one shared implementation
(`vulnerabilities.finding_filters`), so the two cannot disagree on what a filter
means.

Scope is always the caller's own tenant (never the platform admin's
cross-tenant list): an aggregate that summed two tenants under one key would
leak counts. Role: `viewer`.

**Cost.** One grouped query for the page, one for the whole-selection totals, one
count, and one grouped query per facet (owners, teams, exposure sources) bounded
by the page size — six statements whatever the number of problems
(`tests/test_problems.py::test_the_query_count_does_not_grow_…`). Measured on
20 000 findings / 2 000 problems / 1 000 assets (local Postgres 16, no extra
indexes): 45–85 ms per page for the default, `instances`/`breached` sorts,
filtered and deep-offset lists; a drill-down 19 ms.

## Remediation campaigns (`/api/remediation-campaigns`)

### Creating one

1. `POST /preview` with a **selection** — `{"problem_keys": [...], "vuln_ids":
   [...], "filters": {...}}`. Problem keys expand to their *open* findings under
   the optional `filters`; `vuln_ids` add specific findings. The answer is the
   exact composition (`items`, `problems`, `assets`, `composition_hash`), what was
   skipped and why (`not_found`, `closed`), and how many findings already sit in
   other live campaigns. A finding of another tenant is reported exactly like one
   that does not exist.
2. `POST ""` with `name`, `description` (the common action), `owner`, `due_at`,
   the selection and optionally the preview's `composition_hash`. The server
   resolves the selection **again**, under the caller's tenant — nothing from the
   preview is trusted. With a `composition_hash` that no longer matches it answers
   `409` ("preview again"). Limits: 2 000 findings, 100 problem keys.
   `Idempotency-Key` makes a retry replay the first answer (`200`, `replayed:
   true`) instead of creating a second campaign; the same key with a different body
   is `409`; a failed request gives its key back.

The composition is a **snapshot**: findings that match the same filters later are
not added. The only ways in and out are the explicit operations below.

### Membership

`POST /{id}/members` (a selection and a `reason`) and `POST
/{id}/members/exclude` (`vuln_ids` and a `reason`) — a reason of at least three
characters is mandatory. Each answers a per-id report (`added`, `readded`,
`already_member`, `excluded`, `not_member`, `not_found`, `ineligible`); the
others in a batch are never refused because one id was. A (campaign, finding)
pair is one row for life, so excluding and re-including never counts a finding
twice. Each change is an event (author, time, reason, ids) and an `audit_events`
row (`campaign.members`); both live in Postgres and survive a restart.
`GET /{id}/members` lists members (`status=included|excluded`, `category`,
`problem_key`, `sort`), `GET /{id}/events` the history.

### Owner, date, description

`PATCH /{id}` changes `name`, `description`, `owner` and `due_at` (an explicit
`null` clears the last two). **The campaign date never touches a finding**: each
finding keeps its own `due_at`/SLA, assignee, exception and ticket; a
campaign "past due" flag (`past_due`) is informational and never a finding's SLA
breach. To change findings, use the findings' own routes or bulk actions.

### Progress

Computed in SQL from the live findings, mutually exclusive, never summed into
"fixed":

| Category | Which members |
|---|---|
| `open` | OPEN, ACKNOWLEDGED |
| `fixing` | PLANNED, FIXING |
| `awaiting_verification` | VERIFYING — a check was dispatched, no verdict yet |
| `verified` | CLOSED **and** `machine_verified` — a verification run re-checked it |
| `accepted_risk` | an approved, unexpired exception |
| `false_positive` | CLOSED as a false positive |
| `closed_unverified` | CLOSED without a machine verdict (manually or because a ticket was resolved) |
| `unavailable` | could not be verified: closed as unreachable, the campaign's last dispatch was refused/unsupported, or the last verification came back inconclusive (partial coverage / unsupported detector — the gaps are shown per member) |

Plus `total`, `excluded`, `unresolved`, `recurred` (members that were reopened
after they joined), `assets` and `tickets` (`linked_findings`,
`distinct_tickets` — existing links only). A ticket resolution, a manual close and
a finished campaign never set `machine_verified`; and while a finding is
`VERIFYING` behind a dispatched check, ticket sync no longer moves it (the event
records `held_for_verification`) — the run's verdict is the arbiter.

### Completion and recurrence policy

- A campaign is `completed` only when it has included members and **every one** is
  `verified`, `accepted_risk` or `false_positive`. Unverified closures keep it
  open on purpose. An active campaign with no included members does not become
  completed; one that is already completed stays so if its last unresolved member
  is excluded.
- If a member of a completed campaign comes back (the scanner reopens it through
  the standard lifecycle) or unresolved members are added, the campaign returns to
  `active`, `reopen_count` increments and a `reopened` event names the cause.
  Completion and reopening are recorded once, whoever reads the campaign first.
- `POST /{id}/cancel` and `/resume` (a reason each) are the only ways a person ends
  or resumes a campaign; data never changes a `cancelled` campaign, and a cancelled
  campaign takes no edits, members or verifications.

### Verification

`POST /{id}/verify` (`vuln_ids` optional; default: every included member in
`FIXING`, the only state the lifecycle lets move to `VERIFYING`) runs the **existing**
per-finding verification (`trigger_verification`) for each one, so approved scan
scope, scan policy, maintenance windows, admission and sensor-capability checks are
exactly the per-finding button's. The answer is `200` with a result per finding —
`dispatched`, `conflict` (not in FIXING), `unsupported` (an endpoint-software or
retro-matched finding is closed by its own source), `failed` (dispatch refused:
scope, sensors, scanning disabled, an unexpected error), `not_member`, `deferred`
(over the cap of 25 dispatches per request; send the rest). One refusal never
undoes the dispatches that went out. `Idempotency-Key` is honoured. A dispatch is
not a verdict: a member is `verified` only when the run closes the finding as
machine-verified, and timeouts, unsupported detectors and partial coverage appear
as `verification_inconclusive` on the member with what was not covered.

### Roles, tenancy, audit

Reads `viewer`; creating, editing, membership, verification, cancel/resume
`operator` (the floor for moving a finding). Everything is scoped to the caller's
tenant; another tenant's campaign id is `404` for every verb. Audit actions:
`campaign.create`, `campaign.update`, `campaign.members`, `campaign.status`,
`campaign.verify`.

### Data and migration

Migration `0101_remediation_campaigns` is expand-only: three tenant tables
(`remediation_campaigns`, `remediation_campaign_members`,
`remediation_campaign_events`) with tenant row-level security, no change to
`vulnerabilities` and nothing reading them until the new routes are used.
Downgrade drops the three tables (campaign history is lost). Tenant purge and the
data-subject catalogue know the new columns.

### Not included

- Grouping by advisory/package/fix (no such context on findings — see above).
- EPSS on problem rows (not stored; shown as unknown).
- Applying owner/exception changes to all members from a campaign: use the
  existing bulk actions, which are explicit and audited.
- New ticket integrations (#353); campaigns show the links findings already have.
