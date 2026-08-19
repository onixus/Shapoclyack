# Asset business context

How Shapoclyack records *why this host matters* and *who owns it* —
[#146](https://github.com/onixus/Shapoclyack/issues/146).

Phase 7 already stored `owner_email`, `business_unit` and `asset_criticality`.
That is not a CMDB-shaped record: an enterprise also asks which **service**
runs here, which **environment**, what **data** is on the box, and whether
anyone has **said** it is internet-facing. Those fields live on `assets`
(migration `0017_asset_business_context`) and are written through
`PATCH /api/assets/{id}`.

## What is stored

| Field | Vocabulary | Meaning |
|---|---|---|
| `owner_email` | free text | Who runs the box |
| `business_unit` | free text | Organisational home |
| `business_service` | free text | Named service (payments-api, …) |
| `environment` | `production` `staging` `development` `lab` `other` | Where it lives |
| `data_classification` | `public` `internal` `confidential` `restricted` | What data is on it |
| `asset_criticality` | 0–4 | Impact dial used by scoring ([risk-scoring.md](risk-scoring.md)) |
| `exposure_level` | `internet` `partner` `internal` `unknown` | How we **treat** this asset |
| `context_source` | `operator` `cmdb` `ad` `other` | Who last wrote the context |

Closed lists so a CMDB import cannot invent a fifth environment the UI cannot
render. Unknown values answer `422`.

`exposure_level` is a **decision**, not a scan measurement. Writing a guessed
value from an observed public IP would launder a heuristic as a fact.
Scoring may use `internet` / `internal` as a named `operator-set` source
([#171](https://github.com/onixus/Shapoclyack/issues/171)); a public IP still
does not become `external` on its own. Identity merge (IP↔FQDN↔certificate
becoming one asset) is still P4.2.

Scoring consumes `asset_criticality` (impact) and, since
[#171](https://github.com/onixus/Shapoclyack/issues/171), operator
`exposure_level=internet|internal` as a **named** likelihood source. A public
IP is not treated as internet-facing. Environment and data class still do
not move the verdict.

## CMDB / AD

The same PATCH is how a later importer writes. Send `context_source: "cmdb"`
(or `"ad"`) with the fields; omit it and the write is attributed to
`operator`. There is no second endpoint to keep in sync.

## Audit trail

Every change to the context fields is an `asset_context_events` row written
**in the same transaction** as the PATCH — the same contract as
`vulnerability_events`. A trail reassembled from logs afterwards is an
approximation. Newest first at `GET /api/assets/{id}/events` (`viewer`).
Unchanged values write no row; an explicit `null` is a clear and is audited.

## Risk on the asset

`GET /api/assets/{id}` includes `risk`: the
[tracked-finding summary](vulnerability-lifecycle.md) filtered to that asset.
`estate_risk` is the worst open NIST `risk_level` on this host, not an
average. That is what the asset card uses to answer "why is this risky".
Remediation *ownership* of a finding is `assignee` on the finding, defaulted
from `owner_email` when the finding is created and then independent.

## API

| Route | Role | Notes |
|---|---|---|
| `GET /api/assets/{id}` | viewer | Context fields plus `risk` |
| `PATCH /api/assets/{id}` | operator | Partial; `context_source` defaults to `operator` |
| `GET /api/assets/{id}/events` | viewer | Context history, newest first. `404` if the asset is missing or in another tenant |

## UI

`/assets` and `/assets/view` are the asset-centric security view
([#136](https://github.com/onixus/Shapoclyack/issues/136)): owner, service,
exposure, the per-asset risk rollup, tracked findings with the next required
action, software, scan evidence, and this audit trail. See
[ui.md](ui.md#asset-centric-view).
