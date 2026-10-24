# Dynamic asset groups

Dynamic groups classify registered assets within one tenant. Open **Assets →
Dynamic groups**, build an AND/OR rule, preview its effects, and save the group.
Saving versions the rule; applying it is a separate recalculation. Each preview
and recalculation page reports its evaluated count, entrants, exits, changes,
conflicts and continuation cursor. A partial page is not an estate-wide total.

Conditions use registered IP/FQDN identifiers, tags (`tag:<key>`), asset status
and existing business context. No executable expressions or SQL are accepted.
Trees have at most 100 nodes, depth 4 and 50 children/values per branch/condition.
Unknown values remain unknown under negation and do not include an asset.
Observed OS and service fingerprints are deliberately unavailable until their
source, authority and freshness have a separate contract. Exposure can be a
condition but cannot be assigned by a classification rule.

## Context precedence and provenance

Higher numeric priority wins. Equal-priority different values are conflicts;
group ID breaks ties only between equal values. Explicit operator and CMDB
values outrank rules. Values with unknown provenance are protected. An explicit
null or a hand edit equal to the current rule value reclaims ownership as well.
CMDB's existing protection of manual values still applies.

Every actual context change uses the existing asset context history. Managed
fields also retain the rule ID/version, previous value, applied value, time
and match reasons. Predicates see external context, with managed output replaced
by its original value, preventing a rule from matching its own assignments.
Disabling or deleting a rule removes its memberships during reconciliation and
restores only values still owned by the rule. A later manual/import change is
preserved. Deletion retains a tombstone and version history.

Assignment and membership transitions are retained in immutable evaluation
receipts, including rule/version and explanations. Repeated unchanged passes
coalesce their diagnostic row; they do not append duplicate transition history.

Groups are classification, not scan authorization. They do not change scan
scope, deny rules, maintenance checks, finding identity, lifecycle, SLA,
exceptions or recorded risk assessments. Scan requests still use the existing
policy checks. Historical findings are not rewritten.

## API and operations

All paths are under `/api/asset-groups`, with the normal authenticated tenant
context. Viewer reads list/detail/members/evaluations; operator creates, edits,
deletes, previews and recalculates. Foreign tenant IDs return not found.

| Method/path | Purpose |
| --- | --- |
| GET/POST `/` | List/create groups |
| GET/PATCH/DELETE `/{id}` | Read/version edit/tombstone |
| POST `/preview` | Draft dry-run; optional `group_id`, `after_asset_id`, `limit` |
| POST `/{id}/recalculate` | Apply one bounded page, same continuation fields |
| GET `/{id}/members` | Paginated asset IDs, reasons and evaluated rule version |
| GET `/{id}/evaluations` | Persisted outcome and completeness diagnostics |

Example rule and assignments:

```json
{
  "name": "Payments production",
  "priority": 10,
  "enabled": true,
  "rules": {"all": [
    {"field": "ip", "op": "cidr", "value": "192.0.2.0/24"},
    {"field": "tag:service", "op": "eq", "value": "payments"}
  ]},
  "context": {"business_service": "payments", "asset_criticality": 4}
}
```

Apply migration `0100_asset_groups` with the standard serialized migration
command before starting the API. Its additive tables include tenant RLS and
are included in tenant deletion. Roll back the application before downgrading
the schema; schema downgrade removes rule/provenance records, so export them
and review assigned context before doing so.

The API lifespan starts a leader-elected periodic reconciler. Each tenant gets
one bounded asset page per tick and a durable cursor. A completed pass restarts
from the beginning to discover changes made by any inventory producer. A killed
transaction rolls back; a restart resumes the last committed cursor. No external
broker event is required. Processing is eventually consistent; the worst-case
pass latency grows with estate size and batch count.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `OCTO_ASSET_GROUPS_ENABLED` | `true` | Run the background reconciler in this replica |
| `OCTO_ASSET_GROUPS_INTERVAL_SECONDS` | `30` | Poll interval, minimum 5 seconds |
| `OCTO_ASSET_GROUPS_BATCH_SIZE` | `200` | Assets per tenant per tick, clamped 1–500 |

The API remains available with the background worker disabled. Recalculate
manually until `has_more=false`; show each page's result and do not sum counts
across changed inputs as a consistent snapshot. Concurrent rule edits and manual
asset changes are serialized with database locks. Review deployment sizing and
measured query counts before changing the batch limit.

## Validation boundary

The isolated PostgreSQL acceptance fixture processed 503 registered assets in
pages of 500 and 3. Both pages used 10 SELECT statements; the 500-asset page
took approximately 0.175 seconds on the local test machine with one simple
rule. This is a small synthetic fixture, not production sizing or a guarantee
for 100 rules, mixed identities or deployment latency.

Independent integration tests cover concurrent manual edits, transaction
rollback, restart/cursor recovery, replay without duplicate context events,
tenant and role rejection, immutable receipts and bounded queries. The browser
acceptance scenario uses two synthetic RFC5737 assets: CIDR preview → group
save → explicit recalculation → two explained members. No real targets were
scanned. OS-derived conditions and production capacity acceptance remain
outside this initial existing-context implementation.
