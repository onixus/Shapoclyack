# Customer-defined compliance catalogues (W11 / #356)

Custom catalogues map the **existing technical evidence signals** to customer
control identifiers. They are not certification, a legal opinion or automated
assessment of organisational duties. The response always prefixes the customer's
scope note with that limitation. Built-in catalogues are unchanged.

This increment implements PostgreSQL-backed catalogues and JSON/CSV import.
BDU enrichment, signed point-in-time evidence packages and any additional
152-ФЗ mapping are **not** implemented by it and remain in #356.

## Import and read

Run the normal migration command (`python -m api.db.migrate`) before deploying
this version. Migration `0068_compliance_frameworks` creates the table, foreign
key and PostgreSQL tenant RLS policies. Import requires **tenant admin**; listing,
definition reads, posture and control evidence require **tenant viewer**. Use the
same tenant selection header as other tenant-scoped API calls. The tenant ID
is resolved from authentication, never accepted inside a definition.

`POST /api/compliance/frameworks/import` accepts a JSON envelope:

```json
{
  "format": "json",
  "content": "{\"framework_id\":\"custom-acme-v1\",\"name\":\"ACME\",\"version\":\"1\",\"scope_note\":\"Technical observations only.\",\"controls\":[{\"control_id\":\"VM.1\",\"title\":\"Known vulnerabilities\",\"signals\":[\"unpatched_cve\"],\"rationale\":\"Open CVEs on the estate.\"}]}"
}
```

The `content` member is the uploaded UTF-8 document as a string, not a URL or a
server file path. A new definition returns **201**, an identical canonical
re-import **200**, invalid content **422**, and a changed definition under an
existing ID or an exhausted tenant catalogue budget **409**. Identifiers are
immutable: use `custom-acme-v2` for a changed mapping. This avoids changing what
an old control identifier meant silently. Re-import does not emit another audit
event. Definition and audit event commit in the same database transaction.

Read APIs:

- `GET /api/compliance/frameworks` includes built-ins and this tenant's custom catalogues.
- `GET /api/compliance/frameworks/custom-acme-v1/definition` returns the normalized definition, SHA-256, creator and creation time.
- Existing `/api/compliance/{framework_id}` and `/controls/{control_id}` assess custom catalogues with the same evidence engine. Report generation includes them too.

The existing compliance selector consumes the list API; this increment adds no
separate browser import editor. Import through the API. Unknown or another
tenant's custom definition returns 404, never a global fallback. Unscoped
internal callers see built-ins only.

## Definition schema

```json
{
  "schema_version": 1,
  "framework_id": "custom-acme-v1",
  "name": "ACME technical controls",
  "version": "1",
  "scope_note": "Only network vulnerability evidence; policy controls are excluded.",
  "controls": [{
    "control_id": "VM.1",
    "title": "Internet-facing known vulnerabilities",
    "combinations": [["unpatched_cve", "internet_exposed_finding"]],
    "severity_floor": "high",
    "rationale": "Both signals must occur on the same finding."
  }]
}
```

`signals` is an OR; each entry of `combinations` is an AND **on one piece of
evidence**, and the groups are ORed. `requires` is inferred from the signals
(`findings`, `assets`, `endpoint_inventory`) when omitted. Explicit requirements
may add prerequisites, not remove them. A conjunction mixing asset and finding
signals is rejected because no evidence item can satisfy it. Missing required
data means `not_assessed`, never `passed`. `severity_floor` defaults to `low`;
allowed values are `info`, `low`, `medium`, `high`, `critical`. Asset/inventory
signals have fixed `medium` severity in the evidence engine: their controls cannot
set a higher floor that would silently discard every possible match.

The signal vocabulary is in `api/services/compliance/signals.py`. No imported
expressions, SQL, Python, new signal names or signal-free manual/legal controls
are executable or automatically assessed. `rationale` and `scope_note` are
mandatory so reviewers can judge the mapping themselves.

## CSV

Use `format: "csv"` with the same string envelope. Each row is one control;
repeat `framework_id,name,version,scope_note` identically on every row. Required
control columns are `control_id,title,rationale`; optional columns are
`signals,combinations,requires,severity_floor`. Array cells contain JSON arrays
with normal CSV quoting:

```csv
framework_id,name,version,scope_note,control_id,title,signals,rationale
custom-acme-v1,ACME,1,Technical only,VM.1,Known CVEs,"[""unpatched_cve""]",Open CVEs
```

UTF-8 BOMs are accepted. Duplicate JSON keys, duplicate CSV headers/control
identifiers, unknown fields, malformed rows and mixed framework metadata are
rejected atomically. Limits: **1 MiB UTF-8 content**, **500 controls per
catalogue**, **32 catalogues / 1000 custom controls total per tenant**; text fields and conjunctions have
additional bounds. Listing reads metadata only, not all definition documents.

## Operations and evidence limits

Definitions are keyed by `(tenant_id, framework_id)` and protected by application
predicates and PostgreSQL RLS. Admission takes the tenant row lock to serialize
quota checks and tenant suspension/purge. Tenant deletion uses the existing
batched purge, including legal-hold checks; audit records retain their existing
retention policy. There is no in-process catalogue cache to become inconsistent
across API replicas.

The digest detects accidental modification; it is **not a signature**, a
trusted timestamp, or a historical evidence snapshot. Posture remains a view of
current evidence. A signed/archivable point-in-time package is separate remaining
work, as is retention/version lifecycle beyond the bounded immutable catalogue.
