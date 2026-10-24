# Dynamic asset groups

Dynamic groups classify registered assets within one tenant. Open **Assets →
Dynamic groups**, build an AND/OR rule, preview its effects, and save the group.
Saving versions the rule; applying it is a separate recalculation. Each preview
and recalculation page reports its evaluated count, entrants, exits, changes,
conflicts and continuation cursor. A partial page is not an estate-wide total.

Conditions use registered IP/FQDN identifiers, tags (`tag:<key>`), asset status,
confirmed endpoint OS and existing business context. No executable expressions
or SQL are accepted.
Trees have at most 100 nodes, depth 4 and 50 children/values per branch/condition.
Unknown values remain unknown under negation and do not include an asset.
Network OS guesses and service fingerprints cannot establish confirmed OS.
Exposure can be a condition but cannot be assigned by a classification rule.

## Confirmed endpoint OS source contract

`os_family` accepts `windows`, `linux` or `macos` with `eq`, `ne`, `in` and
`not_in`. The source is the existing authenticated endpoint-inventory ingestion
path, not network fingerprinting. `EndpointDevice.os_family` and its latest
snapshot pointer are written atomically by that path; exact replays do not
update them and older `collected_at` submissions are rejected. The accepted
snapshot stores its digest and collection/receipt times; the current device
row stores the associated OS fields. Family values are case-insensitive;
`darwin` maps to `macos`. Other names are unknown, without guessing from banners,
service products or the `asset_os` scan-guess table, even at accuracy 100.

Classification joins only endpoint devices explicitly linked to this asset in
the same tenant, and validates the latest snapshot's tenant and device IDs.
Every linked device must have reconciliation status `linked`, a known family,
and a receipt whose **collection and server receipt times** are within
`OCTO_ENDPOINT_STALE_HOURS` (default 48 hours). Times over five minutes in the
future are rejected as stale evidence. Multiple devices must agree; a conflict,
stale/missing receipt, unknown family or unresolved link makes the whole OS
value unknown. The batched query reads at most 17 endpoint rows per asset;
more than 16 linked devices yields `incomplete`, keeps at most 16 explanations
and never matches. Unknown also remains unknown under negative operators/negation.
The existing freshness setting applies to previews and both manual/background
recalculation, so expiration removes matches on the next bounded sweep.

OS explanations retain `evidence.source=endpoint_inventory`, `state`, the
freshness threshold, and the device/snapshot IDs, collection and receipt times,
reported family and reconciliation status. This records why an inclusion was
accepted without claiming that an endpoint agent is a network scan or that a
classification permits scanning. No OS field changes declared exposure.

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

Recalculation resolves context priorities across all active groups for each
processed asset. The selected group's membership counters are separate from
the resulting context changes, which can have a different winning rule.

## Validation boundary

The isolated PostgreSQL acceptance fixture processed 503 registered assets in
pages of 500 and 3. Both pages used 13 SELECT statements; the 500-asset page
took approximately 0.131 seconds on the local test machine with one simple
rule. This is a small synthetic fixture, not production sizing or a guarantee
for 100 rules, mixed identities or deployment latency.

Independent integration tests cover concurrent manual edits, transaction
rollback, restart/cursor recovery, replay without duplicate context events,
tenant and role rejection, immutable receipts and bounded queries. The browser
acceptance scenario uses two synthetic RFC5737 assets: CIDR preview → group
save → explicit recalculation → two explained members. No real targets were
scanned. Confirmed OS scenarios additionally cover fresh, expired, missing,
conflicting and cross-tenant evidence. The measurements describe a synthetic
acceptance fixture; they do not promise unmeasured production capacity.
