# Shapoclyack — Endpoint Inventory Integration Backlog

**Status:** S1-S7 **done** (merged to `main`) — contract/schema v1, DB models +
migration `0004_endpoint_inventory`, ingestion API with idempotency/limits,
asset reconciliation, software diff/events, read APIs, and a Web UI
Endpoint/Software section on the asset card. S8 (optional NATS event), S9
(retention job + ops docs), and S10 (cross-repository e2e test) are
**deferred** to a follow-up — see `CHANGELOG.md` `## Unreleased`.

## 1. Goal

Add a secure, tenant-isolated endpoint inventory ingestion path for the Lariska
agent without breaking or overloading Shapoclyack's existing remote
network-scanner agent protocol.

The existing agent API claims scan jobs and uploads scan-result archives.
Lariska submits endpoint identity, OS metadata, and installed-software
snapshots. These are related operationally but must remain separate contracts.

## 2. Definition of done

Server integration is complete when:

- Lariska authenticates using the existing provisioning-key JWT exchange;
- an authenticated agent can submit a versioned inventory snapshot;
- tenant and agent identity come from the verified JWT/registration state;
- duplicate delivery is idempotent;
- endpoint devices link safely to the existing asset inventory;
- the current and historical software inventory can be queried;
- installed, removed, and updated software events are generated;
- the Web UI shows endpoint and software information on an asset card;
- payload limits, retention, authorization, migrations, tests, and operations
  are documented;
- existing scan agents and APIs remain backward compatible.

## 3. Architectural decisions

### 3.1 Keep protocols separate

Do not send software inventory to:

- `/api/agent/jobs/{job_id}/results`;
- `ingest.raw_results`;
- `ingest.results.{tenant}`;

Those carry network scan artifacts. Add a dedicated HTTP contract and, if
needed, a dedicated NATS subject.

### 3.2 API owns tenant identity

Use the existing `require_agent` dependency. Derive `tenant_id` from
`AgentPrincipal`; never accept it from the request body. Resolve or validate
`agent_id` against the JWT and registered agent. Reject cross-tenant access.

### 3.3 HTTP is the endpoint boundary

Lariska sends HTTPS requests only to the Shapoclyack API. If NATS is enabled,
the API publishes a validated internal event. Do not distribute NATS
credentials to endpoints.

### 3.4 Version the contract

Require `schema_version`. Support version `1` initially and return a clear
`422` response for unsupported versions. Keep a shared golden fixture in both
repositories.

## 4. Proposed endpoints

### 4.1 Submit inventory

`POST /api/v1/endpoint/inventory`

Authentication: agent JWT.

Headers:

- `Authorization: Bearer <agent JWT>`;
- `Idempotency-Key: <snapshot_id>`;
- normal JSON content type.

Success:

- `201 Created` for a new snapshot;
- `200 OK` for an already accepted idempotency key with the same digest.

Errors:

- `401` invalid/expired JWT;
- `403` revoked key, disabled tenant, agent mismatch, or cross-tenant access;
- `409` same idempotency key with different content;
- `413` payload/entry limit exceeded;
- `422` schema or identifier validation error;
- `429` ingestion rate limit.

Suggested response:

```json
{
  "snapshot_id": "018f...",
  "status": "accepted",
  "device_id": "dev_...",
  "asset_id": "asset_...",
  "software_count": 123,
  "changes": {
    "installed": 2,
    "removed": 1,
    "updated": 3
  }
}
```

### 4.2 Query device inventory

Minimum read APIs:

- `GET /api/assets/{asset_id}/software`;
- `GET /api/endpoint/devices`;
- `GET /api/endpoint/devices/{device_id}`;
- `GET /api/endpoint/devices/{device_id}/snapshots`;
- `GET /api/endpoint/devices/{device_id}/changes`.

Viewer role may read. Operator/admin mutations, if later added, need explicit
authorization. Apply tenant filters at the service/database layer.

## 5. Proposed data model

Use Postgres, SQLAlchemy, and Alembic, following existing repository patterns.
Names can adapt to established conventions.

### `endpoint_devices`

- `device_id` primary key;
- `tenant_id` indexed foreign key;
- `agent_id`;
- nullable `asset_id` link;
- hostname, OS family/name/version/architecture;
- agent version;
- labels JSON;
- first seen, last seen, last inventory timestamps;
- inventory status and latest snapshot ID;
- unique `(tenant_id, agent_id)`.

### `endpoint_identifiers`

- device foreign key;
- type and normalized value or agreed hash;
- first seen and last seen;
- unique `(tenant_id, identifier_type, normalized_value)`;
- indexes for reconciliation.

### `endpoint_inventory_snapshots`

- snapshot ID supplied by agent;
- device and tenant foreign keys;
- collected/received timestamps;
- schema version;
- canonical payload digest;
- software count;
- collector completeness/warnings summary;
- unique `(tenant_id, snapshot_id)`;
- retention/index fields.

### `endpoint_software_items`

- snapshot foreign key;
- normalized comparison key;
- display name;
- version;
- publisher;
- architecture;
- source;
- optional install location;
- deterministic uniqueness within a snapshot.

### `endpoint_software_changes`

- device, tenant, and snapshot foreign keys;
- event type: installed/removed/updated;
- old/new version and relevant product fields;
- observed timestamp;
- optional normalized event payload.

Do not store a new copy of arbitrary raw request bodies indefinitely unless
there is a documented retention and privacy requirement.

## 6. Asset reconciliation

Endpoint devices must connect to Shapoclyack's cross-run asset inventory.

Matching priority:

1. existing `(tenant_id, agent_id)` device link;
2. strong platform identifier match within the tenant;
3. existing stable asset identifier such as exact FQDN where policy permits;
4. create a new endpoint-backed asset;
5. never auto-merge on hostname alone.

Requirements:

- tenant boundary is part of every lookup;
- conflicting strong identifiers create a reviewable reconciliation state
  rather than silently merging assets;
- store provenance for agent-supplied identifiers;
- preserve existing network identifiers and business metadata;
- asset decommissioning must not automatically erase inventory history;
- update `last_seen` on accepted endpoint inventory.

Add endpoint identifier types to the existing asset identity model only after
reviewing uniqueness and privacy behavior.

## 7. Ingestion service behavior

Implement a service separate from route handlers.

Processing order:

1. authenticate and resolve tenant/agent;
2. enforce content length and rate limits;
3. validate schema version and bounded field lengths;
4. canonicalize and hash the payload;
5. enforce idempotency;
6. resolve/create the endpoint device and asset link;
7. persist snapshot and software rows transactionally;
8. compare against the previous accepted snapshot;
9. persist change events;
10. commit;
11. optionally publish an internal NATS event;
12. return counts and identifiers.

Failure rules:

- database failure returns a retryable server response and does not partially
  accept the snapshot;
- NATS failure is fail-soft after durable database commit;
- duplicate request with the same digest returns the original result;
- duplicate key with a different digest returns `409`;
- malformed software entries do not get silently truncated unless the API
  response explicitly reports partial acceptance. Prefer rejecting the whole
  payload initially.

## 8. Validation and limits

Set explicit configurable limits for:

- compressed and uncompressed request size if compression is supported;
- software entries per snapshot;
- identifiers per endpoint;
- labels and label length;
- individual string length;
- inventory submissions per agent per hour;
- future timestamp skew and maximum snapshot age;
- collector warnings.

Normalize:

- leading/trailing whitespace;
- Unicode according to one documented form;
- OS/architecture/source enums;
- case-insensitive comparison keys while preserving display values;
- duplicate software records.

Never evaluate, execute, or interpolate agent-supplied strings.

## 9. Change calculation

Compare the new snapshot with the last accepted snapshot for the same device.

Use a stable product comparison key based on documented normalized fields,
initially name + publisher + architecture + source. Treat version separately.

Events:

- `software_installed`: key only in new snapshot;
- `software_removed`: key only in previous snapshot;
- `software_updated`: key exists in both and normalized version changed.

Do not infer version ordering unless a source-specific parser exists. Record
old and new versions without claiming upgrade versus downgrade.

Suppress change events for the first snapshot. Preserve the calculated result
so retries cannot generate duplicate events.

## 10. Optional NATS integration

If internal streaming is needed, add:

`ingest.endpoint_inventory.{tenant_id}`

Publish metadata or a bounded event after Postgres commit:

- tenant ID;
- device and asset IDs;
- snapshot ID and digest;
- software count;
- change counts;
- received timestamp.

Use `Nats-Msg-Id` derived from tenant + snapshot ID + digest. Do not publish
provisioning keys, JWTs, raw machine identifiers, or an unbounded full software
list. Keep database persistence authoritative.

## 11. API and schema work

Expected implementation areas:

- `api/schemas.py`: versioned request/response/read models;
- new `api/routes/endpoint_inventory.py`;
- new `api/services/endpoint_inventory.py`;
- asset reconciliation service changes;
- SQLAlchemy models in `api/db/`;
- an Alembic migration;
- app/router registration;
- settings for payload, rate, retention, and feature flags;
- NATS helper only if the optional stream is enabled.

Follow actual repository conventions discovered at implementation time.

## 12. Web UI work

Extend the asset card with an Endpoint/Software section:

- endpoint status and last inventory time;
- OS and Lariska version;
- installed software count;
- searchable/sortable software table;
- software version, publisher, architecture, and source;
- installed/removed/updated changes since the prior snapshot;
- stale/incomplete inventory warning;
- snapshot history link.

Add an endpoint list only if the asset view cannot provide sufficient
operational visibility. Reuse existing data-table, query hook, status badge,
and RBAC patterns.

Do not render arbitrary agent strings as HTML.

## 13. Security and privacy

Required controls:

- existing short-lived agent JWT and provisioning-key revocation;
- strict tenant scoping in every query;
- constant-time/idempotent authorization behavior where practical;
- rate and payload limits;
- audit log for inventory acceptance and reconciliation conflicts;
- no secrets in logs or errors;
- sanitize identifiers in normal logs;
- defined software-inventory retention policy;
- documented data collected from endpoints;
- deletion/export behavior for tenant offboarding;
- dependency and migration security review.

Consider whether install locations or user-scope applications contain personal
data. Allow deployments to disable sensitive optional fields.

## 14. Testing requirements

### Unit tests

- schema validation and bounds;
- canonicalization/deduplication;
- payload digest;
- idempotency branches;
- software diff calculation;
- reconciliation match/conflict behavior;
- tenant filters;
- retention selection.

### API tests

- valid snapshot;
- expired/invalid JWT;
- disabled tenant and revoked provisioning key;
- agent mismatch and cross-tenant attempt;
- duplicate same payload;
- duplicate key/different payload;
- payload too large and too many entries;
- unsupported schema version;
- database rollback;
- read-role authorization and pagination.

### Migration tests

- upgrade from the current head on a database with realistic existing tenants,
  agents, assets, and config overrides;
- downgrade only if project policy requires it;
- indexes and uniqueness constraints are asserted.

### Integration tests

- Lariska golden fixture ingestion;
- first snapshot creates no changes;
- second snapshot produces installed/removed/updated events;
- asset card API returns current inventory;
- optional NATS publish is idempotent and fail-soft.

### Regression tests

Existing remote agent registration, heartbeat, scan-job claim, result archive
upload, local scans, asset ingestion, and Web UI routes must continue to pass.

## 15. Observability

Add structured events and metrics:

- inventory requests accepted/rejected by reason;
- processing latency and database latency;
- entries per snapshot;
- idempotent replay count;
- reconciliation conflict count;
- software change counts;
- NATS publish result;
- latest inventory age and stale endpoint count.

Avoid high-cardinality labels containing agent IDs, asset IDs, or product
names in metrics.

## 16. Rollout and compatibility

Use a feature flag such as `OCTO_ENDPOINT_INVENTORY_ENABLED` during initial
rollout.

Recommended rollout:

1. merge schema, migration, service, and API behind the flag;
2. deploy to a staging tenant;
3. run fixture and real endpoint canaries;
4. validate database growth and query performance;
5. enable the read APIs/UI;
6. define retention cleanup;
7. enable production tenants gradually;
8. enable optional NATS events only after HTTP/database ingestion is stable.

The existing agent endpoints and NATS subjects must remain unchanged.

## 17. Issue/PR breakdown

### S1 — Contract and shared fixtures

Deliver:

- architecture decision record;
- schema v1 request/response definition;
- golden valid/invalid fixtures;
- payload and rate-limit decisions;
- documented compatibility policy.

Acceptance:

- fixtures validate in Python and Rust;
- security and privacy review completed;
- no implementation ambiguity remains for authentication or identity.

Dependencies: none.

### S2 — Database schema and migration

Deliver:

- endpoint device, identifier, snapshot, software item, and change models;
- Alembic migration;
- uniqueness constraints and indexes;
- retention-related timestamps.

Acceptance:

- migration succeeds from current head with existing data;
- constraints prevent cross-tenant/idempotency collisions;
- model tests pass on Postgres.

Dependencies: S1.

### S3 — Inventory ingestion API

Deliver:

- request/response schemas;
- authenticated route;
- validation and configurable limits;
- transactional persistence;
- idempotency behavior.

Acceptance:

- documented status codes match tests;
- tenant and agent identity cannot be spoofed;
- duplicate deliveries are deterministic;
- existing agent API regression tests pass.

Dependencies: S1, S2.

### S4 — Asset reconciliation

Deliver:

- endpoint-to-asset matching;
- strong identifier provenance;
- conflict state/diagnostics;
- asset `last_seen` integration.

Acceptance:

- hostname-only collisions do not merge;
- cross-tenant matching is impossible;
- existing asset business metadata is preserved.

Dependencies: S2, S3.

### S5 — Software diff and events

Deliver:

- deterministic comparison key;
- installed/removed/updated calculation;
- persisted events;
- first-snapshot suppression.

Acceptance:

- replay does not duplicate events;
- versions are not incorrectly ordered;
- large snapshot comparison meets the agreed performance budget.

Dependencies: S3.

### S6 — Read APIs

Deliver:

- asset software endpoint;
- device detail/list/history/change endpoints;
- pagination, filtering, sorting, RBAC, and tenant scoping.

Acceptance:

- viewer read access works;
- unauthorized tenant data is never returned;
- query-count/performance tests prevent obvious N+1 behavior.

Dependencies: S3, S4, S5.

### S7 — Web UI

Deliver:

- endpoint summary on asset card;
- software table;
- change history and stale/incomplete indicators;
- API types and query hooks.

Acceptance:

- loading, empty, error, and large-inventory states render correctly;
- user-controlled strings are escaped;
- frontend lint, tests, and production build pass.

Dependencies: S6.

### S8 — Optional NATS event

Deliver:

- dedicated subject and stream configuration;
- bounded event schema;
- idempotent publish after database commit;
- retry/fail-soft behavior.

Acceptance:

- NATS outage does not reject a committed inventory;
- no endpoint secret or full unbounded inventory is published;
- live broker test passes.

Dependencies: S3, S5. May be deferred.

### S9 — Retention, operations, and documentation

Deliver:

- cleanup/retention job;
- system status fields;
- dashboards/alerts/runbook;
- deployment variables and API documentation;
- tenant deletion/export behavior.

Acceptance:

- retention is safe, tenant-scoped, observable, and tested;
- rollback/incident procedures are documented;
- production sizing guidance includes snapshot frequency and endpoint count.

Dependencies: S3–S6.

### S10 — Cross-repository end-to-end test

Deliver:

- disposable Shapoclyack stack;
- Lariska fixture collector;
- enrollment, inventory, query, update, and event assertions;
- version compatibility test.

Acceptance:

- test proves tenant isolation, idempotency, asset linkage, and change events;
- both repositories pin or validate the same schema fixture.

Dependencies: Lariska L2–L4 and Shapoclyack S3–S6.

## 18. Instructions for the implementing AI

For each issue:

1. Inspect current models, migrations, routes, settings, and test conventions.
2. State the intended schema/API delta and exact files before editing.
3. Keep the existing scan-agent contract backward compatible.
4. Put tenant filtering in reusable service/database queries, not only routes.
5. Add migration, service, API, authorization, and regression tests together.
6. Use Postgres in tests where behavior depends on database constraints.
7. Run Ruff, Python tests, migration checks, frontend checks when applicable,
   and existing agent regression tests.
8. Update OpenAPI-facing models, README/ops documentation, changelog, and the
   shared contract fixture.
9. Report performance/privacy risks and unresolved product decisions.
10. Stop if Lariska's payload diverges from schema v1; update the shared
    contract intentionally rather than accepting undocumented fields.

## 19. Decisions (closed 2026-07-24)

All ten items below are resolved. Several were already fixed by the S1-S7
implementation; this section makes them explicit so S8-S10 build against a
documented decision instead of re-deriving one from code.

1. **Maximum inventory request size and software entry count** — bounded by
   the existing per-field limits already enforced in
   [api/settings.py](api/settings.py:75) /
   [api/services/endpoint_inventory.py:99-138](api/services/endpoint_inventory.py):
   `endpoint_inventory_max_software_items=5000`,
   `endpoint_inventory_max_identifiers=16`, `endpoint_inventory_max_labels=32`,
   `endpoint_inventory_max_string_length=512`. No separate total-byte cap
   exists today; worst case (5000 items x ~6 bounded string fields x 512
   bytes) stays under ~15 MB. Decision: add an explicit
   `OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES` (default `15728640`, 15 MiB) hard
   request-size check as part of S9, rejecting oversized bodies with `413`
   before JSON parsing. Until S9 lands, the per-field limits are the
   effective cap.

2. **Snapshot/history retention period** — not yet implemented (S9, per
   `CHANGELOG.md` Unreleased). Decision: keep full snapshot + software-item
   rows for 90 days (`OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS`,
   default `90`), then prune `endpoint_software_items` rows for snapshots
   older than that while keeping the snapshot summary row (id, digest,
   counts, timestamps) and all `endpoint_software_changes` events for 1 year
   (`OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS`, default `365`) for audit
   history. S9 must implement this as a scheduled cleanup job, tenant-scoped
   and observable per Section 15.

3. **Raw vs. hashed machine identifiers** — already decided and implemented:
   hashed only. `EndpointIdentifier` stores `value_hash`
   ([api/db/models.py:154-172](api/db/models.py)); the API never sees or
   computes a hash from a raw MAC/serial
   ([api/services/endpoint_inventory.py:9-10](api/services/endpoint_inventory.py)).
   Supported types are constrained to `mac_hash`, `serial_hash`,
   `bios_uuid_hash`, `tpm_ek_hash`
   ([api/schemas.py:379](api/schemas.py)). No change needed; documented as
   final.

4. **Software comparison-key policy** — already decided and implemented:
   `name + publisher + architecture + source` (lowercased/stripped, sha256
   hashed), with `version` deliberately excluded from the key and tracked
   separately as `old_version`/`new_version` on `EndpointSoftwareChange`
   ([api/services/endpoint_inventory.py:81-90](api/services/endpoint_inventory.py),
   [api/db/models.py:226-246](api/db/models.py)). No change needed;
   documented as final.

5. **Handling of incomplete/partial collector results** — already decided
   and implemented: accept-with-warnings, no partial-rejection.
   `collector_warnings: list[str]` is stored verbatim as free text on the
   snapshot ([api/schemas.py:399](api/schemas.py),
   [api/services/endpoint_inventory.py:308](api/services/endpoint_inventory.py))
   and returned via `list_snapshots`. There is no completeness score and no
   rejection tied to warning count or an empty `software` list. Decision:
   keep this behavior — a collector that reports warnings still gets a
   durable, queryable snapshot; do not add a hard rejection threshold.

6. **Compression support** — decided: not supported, intentionally. Given
   the bounds in item 1, worst-case payload size is small enough to send
   uncompressed over HTTPS without a meaningful latency or bandwidth cost.
   No `Content-Encoding` handling exists in
   [api/routes/endpoint_inventory.py](api/routes/endpoint_inventory.py) and
   none is planned. Revisit only if real-world snapshot sizes are shown to
   exceed the bound in practice.

7. **Endpoint staleness threshold** — decided: 48 hours. This formalizes the
   value already used for display purposes as `STALE_INVENTORY_HOURS = 48`
   in
   [web-next/src/app/(dashboard)/assets/view/page.tsx:51](web-next/src/app/(dashboard)/assets/view/page.tsx),
   computed client-side from `last_inventory_at`. There is currently no
   server-side equivalent of `asset_stale_days`
   ([api/settings.py:67](api/settings.py),
   [api/services/assets.py:142-163](api/services/assets.py)) for endpoint
   devices. S9 must add a backend `OCTO_ENDPOINT_STALE_HOURS` setting
   (default `48`, matching the existing frontend constant) and a device
   status/staleness field so the threshold is enforced and observable
   server-side rather than only rendered in the UI.

8. **Whether endpoint-only assets appear in all existing asset views** —
   already decided and implemented: yes, unfiltered. `_reconcile_asset()`
   creates an ordinary `Asset` row (id prefix `ep_...`) with no
   distinguishing field
   ([api/services/endpoint_inventory.py:162-194](api/services/endpoint_inventory.py)),
   and `list_assets`/`get_asset`
   ([api/services/assets.py:166-231](api/services/assets.py),
   [api/routes/assets.py:17-40](api/routes/assets.py)) return/query all
   assets identically. No hiding or flagging is planned; documented as
   final.

9. **Tenant export/deletion semantics** — decided: endpoint inventory data
   follows whatever general tenant-offboarding mechanism Shapoclyack adopts;
   it is out of scope for S9 to build a bespoke export/delete flow ahead of
   one. No such mechanism exists today for assets or agents either — the
   only deletion-adjacent code is a test/reset helper in
   `tenants.py:117` and the unrelated `DELETE /schedules/{id}`
   ([api/routes/schedules.py:82](api/routes/schedules.py)). Concrete minimum
   for S9: the migration 0004 foreign keys (`endpoint_devices.tenant_id` ->
   `tenants.tenant_id`, and the identifier/snapshot/software/change tables
   chaining off `device_id`/`snapshot_id`) currently have no `ondelete`
   clause, so a future tenant-delete would fail on FK violation rather than
   cascade. S9 should add `ondelete="CASCADE"` on these FKs in a follow-up
   migration so endpoint data is automatically covered whenever a general
   tenant-deletion flow ships, without needing endpoint-specific deletion
   code.

10. **Minimum supported Lariska schema and agent versions** — already
    decided and implemented: `schema_version` is a hard `Literal[1]`
    ([api/schemas.py:386](api/schemas.py)); any other value is rejected with
    `422` at validation time, with no negotiation. `agent_version` is stored
    on `EndpointDevice.agent_version`
    ([api/db/models.py:141](api/db/models.py)) as informational metadata
    only — no minimum-version gate exists or is needed while schema v1 is
    the only version. Decision: keep `agent_version` informational-only;
    introduce an explicit minimum-agent-version gate only alongside a
    schema v2, not before.
