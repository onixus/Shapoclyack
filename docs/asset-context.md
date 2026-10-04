# Asset business context

How Shapoclyack records *why this host matters* and *who owns it* —
[#146](https://github.com/onixus/Shapoclyack/issues/146).

Phase 7 already stored `owner_email`, `business_unit` and `asset_criticality`.
That is not a CMDB-shaped record: an enterprise also asks which **service**
runs here, which **environment**, what **data** is on the box, and whether
anyone has **said** it is internet-facing. Those fields live on `assets`
(migration `0017_asset_business_context`) and are written through
`PATCH /api/assets/{id}`, or in bulk from a CMDB/AD export through
`POST /api/assets/import` ([below](#cmdb--ad)).

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
render. Unknown values answer `422` on `PATCH` and make the row `invalid` in an
import. Tags (`asset_tags`, key → value) are written only by the import, and
each tag change is an `asset_context_events` row with `field = "tag:<key>"`.

The attack-surface **Ownership** view (P4.3) groups a scan by
`business_unit`, then `owner_email`. Unowned names cluster by
registrable domain and are labelled as a domain. ASN is not an owner.

`exposure_level` is a **decision**, not a scan measurement. Writing a guessed
value from an observed public IP would launder a heuristic as a fact.
Scoring may use `internet` / `internal` as a named `operator-set` source
([#171](https://github.com/onixus/Shapoclyack/issues/171)); a public IP still
does not become `external` on its own. Identity merge (IP↔FQDN↔certificate
becoming one asset) is [P4.2](asset-identity.md): only when forward DNS
and a certificate on that IP agree, and the IP is not shared.

Scoring consumes `asset_criticality` (impact) and, since
[#171](https://github.com/onixus/Shapoclyack/issues/171), operator
`exposure_level=internet|internal` as a **named** likelihood source. A public
IP is not treated as internet-facing. Environment and data class still do
not move the verdict.

### Scan-tracker criticality (#453)

When `register_findings_from_run` observes a finding, it passes the already
resolved tenant asset's `asset_criticality` to the shared scorer as
`asset_criticality_override`. **Zero is an explicit value**, not a missing
setting; `None` retains the scorer's existing heuristic. A value supplied on
an individual finding does not override an operator-set asset value.

This fixes the scan tracker independently of the wider context alignment in
[#453](https://github.com/onixus/Shapoclyack/issues/453). It adds no database
lookup and does not change the formula. An asset edit alone does not trigger a
mass rewrite: the tracker's latest assessment is refreshed when the finding
is next registered. The stable finding key, remediation owner, active lifecycle
state, existing SLA deadline and accepted exception are not reset by that
refresh. Criticality alone does not override a false-positive suppression;
the existing evidence-based rules for reopening still apply.

Run API/ClickHouse context parity, batch asset resolution and versioned
historical assessment snapshots remain separate work under #453. This fix
does not claim that scores made with different contexts are comparable or
that the existing per-finding identity lookups have been batched.

Regression coverage: `tests/test_scan_risk_criticality.py` runs the real scan
fold, ORM and shared scorer on the SQLite test fallback, without requiring
Postgres or contacting scanned hosts. Production Postgres concurrency is not
validated by that fallback.

## CMDB / AD

Two ways in, and they write the same columns and the same audit trail.

**One asset:** `PATCH /api/assets/{id}` with `context_source: "cmdb"` (or
`"ad"`); omit it and the write is attributed to `operator`.

**A whole export:** `POST /api/assets/import`
([#350](https://github.com/onixus/Shapoclyack/issues/350)) takes a CMDB or
directory export as CSV or JSON and upserts it row by row. What it is and is
not:

- **A file import, not a connector.** There is no ServiceNow (Table API)
  connector and no LDAP/AD computer sync in the platform — those remain open
  under #350 (the LDAP half after
  [#317](https://github.com/onixus/Shapoclyack/issues/317)). A scheduled sync
  today is your job that exports the file and posts it, ideally with a service
  token issued with the `admin` role and an `Idempotency-Key`.
- **Permission `asset.import`** — tenant `admin` and platform admin. The
  operator keeps `PATCH` and `/assets/bulk`; an import also *registers*
  assets, which spends the tenant's asset quota.
- **Dry run by default.** `dry_run` defaults to `true` and writes nothing; the
  answer is the full per-row report. Applying is `dry_run: false`, one
  transaction for the whole file, and one `asset.import` audit row (format,
  SHA-256 of the content, counts, the first 100 created and updated asset ids).

**Body:** `{"format": "csv"|"json", "content": "<file text>", "dry_run": true,
"context_source": "cmdb"|"ad"|"other", "overwrite_operator_edits": false,
"link_new_identifiers": false}`. `operator` is not an import source — it is
what marks a hand edit.

**Columns** (CSV header, or JSON object keys; case-insensitive, spaces and
dashes read as `_`):

| Column | Aliases | Meaning |
|---|---|---|
| `asset_id` | — | An existing asset in this tenant. An unknown id is `invalid` |
| `ip` | `ip_address` | Matched against the registry's `ip` identifiers |
| `fqdn` | `hostname` | Lower-cased, trailing dot dropped; matched against `fqdn` identifiers |
| `owner_email` | `owner` | Must look like an email |
| `business_unit` | `team` | ≤ 200 characters |
| `business_service` | `service` | ≤ 200 characters |
| `environment`, `data_classification`, `exposure_level` | `env`, `classification`, `exposure` | The closed vocabularies above |
| `asset_criticality` | `criticality` | Integer 0–4 |
| `context_source` | — | Per-row override of the request's source (`cmdb`, `ad`, `other`) |
| `tag:<key>` | JSON: `"tags": {…}` | Sets that tag; other tags are left alone |

Other columns are ignored and listed in `ignored_columns`. JSON is an array of
objects or `{"assets": [...]}`.

**Identity is the registry's.** A row needs at least one of `asset_id`, `ip`,
`fqdn`, and is matched through `asset_identifiers` exactly as a scan's host is.
A new asset gets the id a scan would have given it (the IP's identity key, or
the FQDN's when there is no IP), so the first scan that reaches the host lands
on the imported asset rather than opening a second one. An imported asset is
`active`, its `last_seen` is the import time and its coverage columns stay
empty — it reads as "never scanned". The IP is stored in canonical form
(`2001:DB8:0:0::1` → `2001:db8::1`) and the FQDN lower-cased without the root
dot, which is how a scan reports them.

**A known asset gains an identifier only on request.** A row that finds an
existing asset by one identifier and carries another the registry has never
seen — the asset matched by IP, and the row names an FQDN nobody registered —
is a `new_identifier` conflict, and nothing in the row is applied. The file's
word is the only evidence for that link, where the scan's own correlation
needs forward DNS *and* a certificate ([asset-identity.md](asset-identity.md)),
and a wrong link outlives the import: a load-balancer VIP that yesterday's
export paired with `a.corp` and today's with `b.corp` would make `b.corp` an
identifier of `a.corp`'s asset, and every later scan of `b.corp` would land
there. There is no API to unlink an identifier. Send `link_new_identifiers:
true` once you have checked the preview's `new_identifier` rows; a new asset's
own identifiers, and the one an asset was registered under (its identity key),
need no flag.

**Empty means "nothing to say", never "clear".** A missing column, a blank CSV
cell and a JSON `null` all leave the field as it is — in either format there is
no way to clear a field by import. A narrower export, or a nightly sync from a
CMDB with gaps, therefore cannot flatten the context it does not mention.
Clearing is `PATCH` with an explicit `null`.

**Outcomes per row:** `create`, `update`, `unchanged`, `conflict`, `invalid`,
with a `code` for the last two:

| Code | Status | When |
|---|---|---|
| `ambiguous_match` | conflict | The row's IP and FQDN belong to two different assets. The import **never merges** — a merge needs a scan's evidence ([asset-identity.md](asset-identity.md)) |
| `identifier_owned_by_other_asset` | conflict | The row names `asset_id` A but its IP or FQDN belongs to asset B |
| `operator_override` | conflict | A field the row would change was last set by an operator (see below); `conflicting_fields` names them |
| `new_identifier` | conflict | The row matched an existing asset and carries an IP or FQDN the registry does not have; `conflicting_fields` names them (`fqdn:b.corp.example`). Applied only with `link_new_identifiers` (above) |
| `duplicate_in_file` | conflict | An earlier row of the same file already names this asset or identifier |
| `quota_exhausted` | conflict | A new asset past the tenant's `max_assets`; known assets in the same file are still updated |
| `unknown_asset` | invalid | `asset_id` is not an asset of this tenant |
| `invalid_value` | invalid | A cell failed validation; `message` lists every one |

A row is applied **whole or not at all**: a conflict on one field does not
half-update the asset.

**Precedence: the operator's hand edit wins.** For each field a row would
change, the newest `asset_context_events` row of that field decides: source
`operator` means a person set it, and the import reports `operator_override`
instead of overwriting it. A value with no event of its own field behind it
(set before this trail existed, or carried over by an identity merge) counts
as the operator's — always: every import write records an event, so such a
value was not written by an import. The asset-wide `context_source` is not
consulted, because an import rewrites it whenever it changes any field: an
import that only filled an empty owner must not make the hand-set team next to
it fair game for the next one. On a database upgraded from before #146 this
means the first import reports `operator_override` for every field that
already had a value; check them and send `overwrite_operator_edits: true` once.
A value an import wrote (`cmdb`, `ad`, `other`) is the import's to change. To let the CMDB win
anyway, send `overwrite_operator_edits: true`; the field is then the CMDB's
again and the next sync updates it without the flag. `PATCH` and the bulk bar
record `operator` unless the request names another source.

**Limits and hygiene.** 2 MiB of content and 5 000 data rows per request (`413`
past either — split the file). A UTF-8 BOM is dropped; a CSV whose header uses
`;` or tab (Excel in a Russian locale) is read with that separator. Content
holding U+FFFD replacement characters is refused with `422`: it was decoded in
the wrong charset, and storing it would store garbage — the console decodes
UTF-8 and falls back to Windows-1251. A text value starting with `=`, `+`,
`-`, `@`, tab or CR is a spreadsheet formula and makes the row `invalid` rather
than being stored for a later export to hand to Excel; so do control
characters. A file that cannot be read at all (bad JSON, ragged CSV, a column
twice) is `422`.

**Concurrency.** Applies into one tenant run one at a time (a transaction-scoped
Postgres advisory lock per tenant); a second one waits for the first and then
plans against what the first wrote. Nothing else of the tenant waits on an
import: scans, job starts and sensor registration go on. The asset rows in
the file are locked for the length of the apply, so a scan updating one of
those assets waits for it, or the import for the scan — never both, because
the scan ingest and the import take those row locks in the same order (by
asset id). A dry run takes no locks.

**Retries.** On an apply, `Idempotency-Key` works as on the bulk verbs: the
same key and file replay the first report (`replayed: true`), the same key with
a different file is `409`, and an apply that changed nothing gives its key
back. A dry run ignores the key. A `409` that is not about the key has two
causes, and nothing was applied in either: another writer — a scan — registered
one of the file's identifiers (or created the asset under the id the file would
give it) between the plan and the commit; or Postgres aborted the apply as a
deadlock or serialization failure on all three attempts the API makes itself.
Send the file again: it is re-planned against what is there now. Any other
database error is a `500`, and retrying it unchanged will not help.

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
| `POST /api/assets/import` | `asset.import` (tenant admin) | CSV/JSON upsert with a per-row report; dry run by default. See [CMDB / AD](#cmdb--ad) |
| `GET /api/assets/{id}/events` | viewer | Context history, newest first. `404` if the asset is missing or in another tenant |

## UI

`/assets` and `/assets/view` are the asset-centric security view
([#136](https://github.com/onixus/Shapoclyack/issues/136)): owner, service,
exposure, the per-asset risk rollup, tracked findings with the next required
action, software, scan evidence, and this audit trail. See
[ui.md](ui.md#asset-centric-view).
