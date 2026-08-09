# API and RBAC

The API is served under `/api`. The Web UI uses the same API and stores the
access token in browser local storage.

## Authentication

User login:

```http
POST /api/auth/login
Content-Type: application/json

{"username":"operator","password":"..."}
```

Use the returned token:

```http
Authorization: Bearer <access-token>
```

Agents use a separate provisioning flow. A tenant provisioning key is exchanged
for a short-lived agent JWT; the plaintext provisioning key is returned only
when it is created.

## Roles

| Role | Intended capability |
|---|---|
| `viewer` | Read assets, runs, findings, diffs, artifacts, and status |
| `operator` | Viewer plus start jobs and update permitted asset metadata |
| `admin` | Operator plus tenant provisioning, destructive administration, and config overrides |

The route implementation is authoritative. Client-side hiding is usability,
not an authorization control.

## Endpoint groups

| Prefix | Purpose |
|---|---|
| `/api/auth` | Login and current principal |
| `/api/runs` | Run summaries, details, hosts, ports, findings, artifacts |
| `/api/jobs` | Start, monitor, and cancel scan jobs |
| `/api/agents` | Agent registration, heartbeat, claim, and fleet status |
| `/api/assets` | Persistent asset inventory and metadata |
| `/api/endpoint` | Endpoint device and software inventory |
| `/api/tenants` | Tenant lifecycle and provisioning keys |
| `/api/schedules` | Tenant-scoped recurring scans |
| `/api/system` | Non-secret installation status |
| `/api/config` | Validated, whitelisted scanner overrides |

`POST /api/jobs/{job_id}/cancel` (operator) cancels a job that has not started
executing — `queued`, or `claimed` by an agent that has not reported starting.
It answers `409` for a job that is already `running` or finished, because there
is no channel to stop a scan in flight, and `404` for a job in another tenant.
The job's status becomes `cancelled` and the reason is recorded in `error`. See
the job lifecycle in [architecture.md](architecture.md#job-lifecycle) for the
full state set.

`POST /api/endpoint/inventory` is the only agent-authenticated write in that
group and carries contract-specific limits: `411` when `Content-Length` is
absent, `413` when the body or a bounded field exceeds its limit, `429` on the
per-agent hourly rate limit, `409` when a `snapshot_id` is resubmitted with
different content, and `200` (rather than `201`) for an exact replay. Read
routes expose each device's server-derived `status` (`active`/`stale`, from
`OCTO_ENDPOINT_STALE_HOURS`) and accept `device_status=active|stale` as a
filter.

## Pagination

`GET /api/runs`, `/api/jobs`, `/api/agents`, `/api/assets`, and `/api/schedules`
return a page envelope rather than a bare array:

```json
{ "items": [], "total": 0, "offset": 0, "limit": 100, "has_more": false }
```

| Parameter | Meaning |
|---|---|
| `offset` | Rows to skip (default `0`) |
| `limit` | Rows per page (default `100`, maximum `5000`) |
| `q` | Case-insensitive substring filter; applied before `total` is counted |
| `sort` | Sort field; an unknown value falls back to the resource default instead of erroring |
| `order` | `asc` or `desc` (default `desc`) |

Sortable fields per resource: assets — `last_seen`, `first_seen`, `status`,
`asset_criticality`, `asset_id`; jobs — `started_at`, `finished_at`, `status`,
`job_id`, `mode`, `tenant_id`; agents — `hostname`, `agent_id`, `status`,
`last_seen_at`, `registered_at`, `tenant_id`; schedules — `created_at`, `name`,
`next_run_at`, `last_run_at`, `enabled`, `tenant_id`. Runs are always ordered by
`run_id` (the timestamped directory name): sorting on a summary column would
require opening every run's JSON, so only `order` applies there.

Sub-resources of a run (`/hosts`, `/ports`, `/vulnerabilities`) remain
`limit`-only — the graph and detail views consume them whole.

Inspect the generated OpenAPI schema for exact request and response fields:

```bash
curl http://localhost:8080/openapi.json
```

## Tenant rules

- A principal may act only within the tenant scope granted by its token or the
  route's authorization policy.
- Agent claim and completion calls validate job and agent tenant equality.
- NATS messages carry tenant metadata.
- Asset and endpoint-inventory queries require tenant context.
- Do not accept a tenant identifier from a client without server-side
  authorization against the principal.

## Tenant memberships

Console users come from `OCTO_API_USERS`; which tenants they may act in comes
from the `user_tenants` table, managed by a platform admin:

```http
GET    /api/tenants/{tenant_id}/members
PUT    /api/tenants/{tenant_id}/members/{username}   {"role": "operator"}
DELETE /api/tenants/{tenant_id}/members/{username}
```

`PUT` is idempotent and re-grants change the role. Membership rows hold no
credential material.

Every tenant-scoped route resolves its tenant server-side from the
authenticated username. The `tenant_id` query parameter still exists, but it
can now only *select among* tenants the caller already holds, and anything
else is `403`:

| Caller | Tenant used | Notes |
|---|---|---|
| Global role `admin` | Requested, else `default` | Platform admin — memberships do not constrain them; `/jobs`, `/agents`, `/schedules`, and `/runs` stay fleet-wide when no tenant is named |
| Has memberships | Requested (must be granted), else their sole membership / `default` / first by name | Role inside the tenant comes from the membership row, so it can differ from the global role |
| Has no memberships | `default` only | Pre-P0 behaviour, so existing single-tenant installations keep working; granting any membership opts the user into strict scoping |

`GET /api/auth/me` returns `tenants`, `default_tenant`, and
`is_platform_admin` for the caller; `GET /api/tenants` lists only the tenants
the caller may act in, so an MSSP's customer list does not leak to a single
customer's operator.

A resource belonging to another tenant answers `404`, not `403`, on direct id
lookups (`/jobs/{id}`, `/assets/{id}`, `/schedules/{id}`, `/runs/{id}` and its
sub-resources): a `403` would confirm the id exists to someone with no right to
know it.

### Run ownership

The scanner itself has no tenant concept, so the API tags each completed run by
writing `tenant.json` (`{"tenant_id": …}`) into the run directory — from
`_run_job` for local execution and from `complete_job` for agent uploads. Run
listings, sub-resources (`hosts`/`ports`/`vulnerabilities`/`diff`), and both
artifact endpoints are filtered by that marker.

A run **without** the marker reads as belonging to `default`: runs produced
before this shipped, and any run created by invoking `scanner.main` directly
outside the API, stay visible to the default tenant instead of disappearing.
There is no backfill — if pre-existing runs belong to a customer tenant, write
their `tenant.json` by hand before granting that customer access.

## Artifact access

Text artifacts can be previewed through the run artifact endpoint. Binary
downloads use a dedicated path so PDFs and other files are transferred without
text decoding. Artifact paths must be treated as untrusted input and resolved
only inside the selected run directory.

## Automation clients

For scripts:

- authenticate once and refresh/re-login on `401`;
- use idempotency or external coordination before retrying job creation;
- respect API pagination/limits;
- record `job_id`, `run_id`, and tenant together;
- never log bearer tokens or provisioning keys;
- treat `429` and dependency `503` responses as retryable only with bounded
  backoff.
