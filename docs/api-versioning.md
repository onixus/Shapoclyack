# API v1, exports and generated integrations

All enabled `/api/...` resources also have `/api/v1/...` addresses. Both names
use the same handlers, feature flags, authentication, tenant boundaries,
permissions, MFA, rate limits and request-size checks. Version normalization
runs before those checks. Nested version prefixes are refused. SCIM remains
`/scim/v2`; probes, metrics and documentation keep their own addresses.
The existing `/api/health` also has its v1 alias.
Responses identify `API-Version: 1`.

## Compatibility policy

The current major version N and previous major version N-1 are supported.
N-1 receives security and compatibility fixes for at least twelve calendar
months from its published deprecation announcement. Breaking changes require a
new major address; adding optional fields and new resources is compatible.
The current v1 has no announced sunset. `/api` remains a compatibility alias.
No removal is scheduled merely by installing this release.

Operators announcing retirement of the unversioned alias configure both
`OCTO_API_DEPRECATED_AT` and `OCTO_API_SUNSET_AT` as timezone-qualified ISO 8601
instants. The middleware refuses a partial schedule or a sunset less than
twelve calendar months after the announcement. Configured legacy responses
include `Deprecation: @<unix-seconds>` and an HTTP-date `Sunset` header;
versioned responses do not. The alias also links to `/api/v1/` with
`rel="successor-version"`. These headers communicate the published schedule;
they do not automatically remove routes. A later major release must retain
its N-1 implementation for the policy window. API changes are recorded in
[the API changelog](api-changelog.md).

## Streaming export pages

`GET /api/v1/assets/export` and `GET /api/v1/vulnerabilities/export` require
viewer access and the corresponding `assets:read` or `vulnerabilities:read`
service-token scope. Every export is confined to the selected tenant, including
platform-admin exports. Use the existing `tenant_id` parameter to select a
tenant where authorized. Other tenants' IDs never enter the query results.

Query parameters:

| Parameter | Meaning |
| --- | --- |
| `format` | `ndjson` (default) or `csv` |
| `limit` | 1–1000 rows, default 1000 |
| `cursor` | Signed opaque continuation from `X-Next-Cursor` |

Read one response, then request the next page with its cursor. Stop when
`X-Next-Cursor` is absent. Empty NDJSON is an empty body; empty CSV includes its
column header. The header names are exposed through CORS. Responses are
attachments with `Cache-Control: no-store`. No total-count query is required.

Pagination uses the unique ID in ascending order, not offsets. Cursors bind
the tenant, resource, last ID, format version and 24-hour expiry under an HMAC;
invalid, tampered, expired and cross-tenant/resource cursors return 422. The
format and page size may change between pages. Rotating the JWT secret
invalidates cursors. There are no export filters or alternate sorts in v1.

These are live pages, not a transaction-wide snapshot. A concurrent insert
whose ID sorts before the cursor will not be included; changed rows may reflect
newer values. A consistent point-in-time compliance report needs a separate
snapshot/report workflow. Memory is bounded by one page plus one lookahead row;
SQL sessions close before streaming starts, including when a caller stops
reading. Each yielded chunk contains one record; CSV starts with a header.

The export contract is deliberately explicit. Assets contain asset_id,
tenant_id, status, first_seen, last_seen, owner_email, business_service,
environment, exposure_level and asset_criticality. Vulnerabilities contain
vuln_id, tenant_id, asset_id, title, cve, severity, state, assignee, source,
contextual_score, first_seen_at, last_seen_at and due_at. Raw scanner evidence,
credentials and internal columns are excluded. CSV text that could be interpreted
as a spreadsheet formula is prefixed with an apostrophe, including whitespace
and control-character prefixes. NDJSON preserves original text values.

## Python client and command line

The dependency-free Python package lives in `sdk/`; installing that package
provides the `shapoclyack` command. `Client` exposes one generated method per
v1 OpenAPI operation, and `Client.request(operation, ...)` is the common
transport. `shapoclyack --help` lists the generated operation names. The checked-in
manifest was generated with all shipped feature routers enabled; a disabled
feature still returns the server's usual 404.

```python
from shapoclyack import Client

client = Client("https://scanner.example", token, tenant_id="default")
with client.export_assets_api_v1_assets_export_get(
    query={"format": "ndjson", "limit": 1000}, raw=True
) as response:
    for line in response:
        process(line)
    next_cursor = response.headers.get("X-Next-Cursor")
```

Methods accept `path` and `query` dictionaries, JSON `body`, additional
`headers`, and `raw=True` for a context-managed streaming response. Normal
responses decode JSON. Multipart/form/binary operations accept already encoded
`data` bytes and `content_type` (including a boundary for multipart); the
transport validates the declared request media type against OpenAPI. It does
not construct multipart encodings or typed model objects. Close raw responses
with a `with` block. Redirects are refused so bearer credentials cannot be
forwarded to another origin. A client bound to a tenant rejects conflicting
query parameters.

```sh
# Set SHAPOCLYACK_TOKEN through your existing secret-management environment.
shapoclyack export_assets_api_v1_assets_export_get \
  --url https://scanner.example --tenant default \
  --query '{"format":"csv","limit":1000}' > assets.csv
```

The CLI reads credentials from `SHAPOCLYACK_TOKEN`, not command-line arguments.
`SHAPOCLYACK_URL` and `SHAPOCLYACK_TENANT` provide optional defaults. `--path`
and `--query` accept JSON objects; `--body` reads JSON from a file or stdin (`-`).
`--data` and `--content-type` send an encoded non-JSON body. Response bytes go
to stdout; the next cursor goes to stderr. It streams one page at a time.

To regenerate, obtain `/openapi.json` from an installation with API docs and
the desired features enabled, save the JSON locally, and run:

```sh
python scripts/generate-api-client.py openapi.json
```

The generator only reads the supplied schema: it does not start the API,
load secrets, contact a server or install packages. Output is deterministic;
empty v1 schemas and duplicate/invalid operation IDs are refused. Regeneration
should accompany changes to v1 operation IDs, parameters or request media.
