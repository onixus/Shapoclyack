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

## Login rate limiting and the auth audit trail

Every login attempt is recorded in the Postgres `auth_events` table (migration
`0014`) and counted in `octo_auth_attempts_total{outcome}`. `outcome` is
`success`, `failure` (credentials checked and rejected) or `locked` (refused by
the limiter before they were checked).

Those same rows *are* the limiter. Two counters run over the same window
(`OCTO_LOGIN_RATE_LIMIT_WINDOW_SECONDS`, default 15 minutes):

| Counter | Default | What it stops |
|---|---|---|
| Failures per `(username, client IP)` | 5 | Guessing one account's password |
| Failures per client IP, all usernames | 50 | One address walking a username list |

Either one tripping answers `429` with a `Retry-After` header. The body is the
same text whichever limit tripped and whether or not the account exists — a
refusal is the last place worth confirming that a username is real.

Three properties are deliberate:

- **The counter is a table, not a process.** With more than one API replica an
  in-memory limit is divided by the replica count, and which replica serves an
  attempt is the load balancer's choice.
- **Counting, verification and recording are one serialized operation**, keyed
  on `(username, client IP)` with a Postgres advisory lock. Otherwise a batch
  of parallel guesses all read the same count before any of them writes a
  failure, and a threshold of 5 admits as many attempts as the attacker can
  open sockets.
- **The window decays; nothing is unlocked by hand.** The correct password
  works again once the counted failures age out. A lock an attacker could make
  permanent by failing on purpose would be a denial of service against any
  username they know.
- **`X-Forwarded-For` is read only behind a configured proxy.** The client
  writes that header itself, so trusting it unconditionally would let each
  attempt pick a fresh limiter key. Set `OCTO_TRUSTED_PROXIES` to the ingress
  addresses; unset, the socket peer is used and the header is ignored. See
  [configuration.md](configuration.md#environment-variables).

Reading the trail (platform admin only):

```http
GET /api/auth/events?limit=100&outcome=failure&q=10.1.2.3
```

Newest first, `Page` envelope like the other lists. `q` matches username or
client IP; `outcome` filters to one of the three values. Rows older than
`OCTO_AUTH_EVENT_RETENTION_DAYS` (default 90) are pruned — but never while they
are still inside the limiter's window, since the two settings are chosen
independently and a short retention must not quietly weaken the lockout.

A locked-out client keeps retrying, and recording each retry would make the
audit trail an amplifier for unauthenticated writes — so one `locked` row is
written per window and the rest are counted only in `/metrics`.

## Roles

| Role | Intended capability |
|---|---|
| `viewer` | Read assets, runs, findings, diffs, artifacts (except screenshot PNGs), and status |
| `operator` | Viewer plus start jobs, screenshot PNGs, and update permitted asset metadata |
| `admin` | Operator plus tenant provisioning, destructive administration, and config overrides |

The route implementation is authoritative. Client-side hiding is usability,
not an authorization control.

## Endpoint groups

| Prefix | Purpose |
|---|---|
| `/api/auth` | Login, current principal, and the authentication audit trail (`/api/auth/events`, admin) |
| `/api/runs` | Run summaries, details, hosts, ports, findings, artifacts |
| `/api/jobs` | Start, monitor, and cancel scan jobs |
| `/api/agents` | Agent registration, heartbeat, claim, and fleet status |
| `/api/assets` | Persistent asset inventory, business context and per-asset risk rollup |
| `/api/tenants/posture` | Per-tenant risk comparison (operator; scoped like `GET /tenants`) |
| `/api/endpoint` | Endpoint device and software inventory |
| `/api/tenants` | Tenant lifecycle and provisioning keys. A supplied `tenant_id` must match `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` and must not start with the reserved `h_`, since it doubles as a NATS subject token (422 otherwise) |
| `/api/schedules` | Tenant-scoped recurring scans |
| `/api/vulnerabilities` | Tracked findings: lifecycle, ownership, SLA policy and the audit trail |
| `/api/webhooks` | Outbound webhook and ticket-transport subscriptions, delivery trail, DLQ |
| `/api/system` | Non-secret installation status |
| `/api/config` | Validated, whitelisted scanner overrides |

`POST /api/jobs/{job_id}/cancel` (operator) cancels a `queued` job — one no
executor has taken yet, so refusing to hand it out is a real stop. It answers
`409` once the job is `claimed`, `running`, or finished (an agent that has
claimed a job scans without asking again, so cancelling then would report a
stop that never happened), and `404` for a job in another tenant.
The job's status becomes `cancelled` and the reason is recorded in `error`. See
the job lifecycle in [architecture.md](architecture.md#job-lifecycle) for the
full state set.

`POST /api/jobs` accepts an optional **`Idempotency-Key`** header. A retry
carrying a key an earlier request already used returns that job with **200**
instead of **202** — nothing was accepted this time — so a client that retries
after a timeout cannot queue the same scan twice. Keys are scoped per tenant
and never expire; reuse one only for the request it named.

`POST /api/agent/jobs/{job_id}/results` accepts an optional `idempotency_key`
form field with the same intent on the upload side: repeating an upload that
already landed returns the stored outcome (200), rather than the 422 a second
completion would otherwise get. A second upload that *disagrees* with the
stored one answers **409**, as does a duplicate that arrives while the first is
still being ingested — retry it once the first request finishes. Agents that
send no key still get replay detection from the natural key (same agent, same
job, same exit code).

The same endpoint accepts the `attempt` returned by the claim
(`AgentClaimResponse.attempt`). It is a fencing token: if the job's lease
expired and it was handed out again, an upload carrying the older attempt
answers **409** rather than overwriting the run of the attempt that replaced
it. This matters because a restarted worker keeps its `agent_id`, so the agent
identity alone cannot tell the two apart. Agents that omit it are unfenced,
exactly as before.

`POST /api/endpoint/inventory` is the only agent-authenticated write in that
group and carries contract-specific limits: `411` when `Content-Length` is
absent, `413` when the body or a bounded field exceeds its limit, `429` on the
per-agent hourly rate limit, `409` when a `snapshot_id` is resubmitted with
different content, and `200` (rather than `201`) for an exact replay. Read
routes expose each device's server-derived `status` (`active`/`stale`, from
`OCTO_ENDPOINT_STALE_HOURS`) and accept `device_status=active|stale` as a
filter.

### Agent fleet, deployment and upgrade

| Route | Role | Notes |
|---|---|---|
| `GET /api/agents` | operator | Page of the fleet; unscoped platform admins see it fleet-wide, as for `/jobs` |
| `GET /api/agents/summary` | viewer | Counts only — online, busy, outdated, latest version |
| `GET /api/agents/{agent_id}` | viewer | One agent's telemetry; `404` outside the tenant |
| `DELETE /api/agents/{agent_id}` | operator | Deregisters the worker |
| `POST /api/agents/{agent_id}/upgrade` | operator | **Queues** an upgrade the agent picks up on its next heartbeat |
| `GET /api/agent/install.sh` | public | The installer script itself carries no credential |
| `GET /api/agent/deployment-command` | operator | Renders the systemd / docker / compose / kubernetes snippets with a `<PROVISIONING_KEY>` placeholder. Mints nothing |
| `POST /api/agent/deployment-command` | operator | Mints **one** tenant provisioning key (optional `label`, default `Web UI Deployment Key`) and returns the same snippets filled in. **201**; the plaintext key is in this response only |
| `POST /api/agent/deploy/ssh` | operator | Push-installs over SSH; mints a key for that machine server-side |
| `GET /api/agent/deploy/{deploy_id}/status` | operator | Progress and log tail for one push deployment |

A provisioning key registers an agent into the tenant, so anything that hands
one out is an authorization decision, not a read. Both deployment-command
routes therefore take `operator` — the same bar as the SSH push, which already
mints a key for the host it installs on. Tenant-wide key administration
(listing, revoking, minting against an arbitrary tenant under
`/api/tenants/{tenant_id}/provisioning-keys`) stays `admin`.

The split between GET and POST is deliberate: rendering the snippets is
idempotent, minting is not. Keys are hashed at rest and the plaintext is
returned exactly once, so an existing key cannot be re-embedded in a snippet —
a fresh mint is the only way to fill the placeholder in, and the operator asks
for it explicitly rather than getting one per dialog open. Revoke unused keys
via `POST /api/tenants/{tenant_id}/provisioning-keys/{key_id}/revoke`.

### Vulnerabilities

Reading takes `viewer`; moving a finding through its lifecycle or reassigning it
takes `operator`; **accepting risk and editing SLA policy take tenant `admin`**,
because each commits the tenant to something rather than progressing one
person's work. `POST /{id}/transition` answers `409` on an illegal move (the
request is well-formed; the refusal is about the finding's current state) and
`422` on a state that is not in the model. A finding in another tenant answers
`404`. The states, the SLA resolution order and the exception rules are in
[vulnerability-lifecycle.md](vulnerability-lifecycle.md).

### Webhooks

Reading webhooks and their deliveries takes the tenant `operator` role;
**creating, editing, deleting, rotating a secret, sending a test and replaying
a delivery all take tenant `admin`**. A subscription forwards this tenant's
exposure data to an address of the creator's choosing, so creating one is
closer to granting access than to scheduling a scan.

| Route | Role | Notes |
|---|---|---|
| `GET /api/webhooks` | operator | Page of subscriptions; the signing secret is never included |
| `POST /api/webhooks` | admin | `422` on a malformed URL, an unknown event kind or severity, a target resolving to a non-public address, a missing ticket `transport_config`, or the per-tenant limit. The generated `secret` is in this response only (webhook transport). Ticket transports take `secret` as the tracker token and do not HMAC |
| `PATCH`/`DELETE /api/webhooks/{id}` | admin | Deleting takes that subscription's delivery history with it |
| `POST /api/webhooks/{id}/rotate-secret` | admin | Returns the new HMAC secret once. `422` on a ticket transport — PATCH `secret` with the tracker token instead |
| `POST /api/webhooks/{id}/test` | admin | **202** — a signed `test` delivery is *queued*, not confirmed. Poll the deliveries list for the outcome |
| `GET /api/webhooks/{id}/deliveries` | operator | Audit trail for one subscription |
| `GET /api/webhooks/deliveries?status=dead` | operator | The dead-letter queue (`status` is `pending`, `delivered` or `dead`; anything else is `422`) |
| `POST /api/webhooks/deliveries/{id}/retry` | admin | Requeues a dead delivery with a fresh attempt budget; needs no broker |

A webhook in another tenant answers `404`, not `403` — as for jobs, schedules
and runs, the id's existence is not the caller's business. HMAC receivers verify
`X-Shapoclyack-Signature` (`sha256=` HMAC over `{timestamp}.{body}`, the
timestamp being the `X-Shapoclyack-Timestamp` header) and should treat
`X-Shapoclyack-Event-Id` as the deduplication key.

`transport` selects the wire: `webhook` (default HMAC POST) or `jira` /
`servicenow` / `defectdojo`. Ticket transports POST the native create-issue
body to the instance URL, then link `ticket_key` on the matching tracked
finding. An operator-set link is not overwritten. `transport_config` holds
non-secret knobs (`project_key` / `issue_type`, `table`, `test_id`).
Credentials stay in `secret` or `Authorization`. Needs NATS, like any other
asset-event consumer.

## Pagination

`GET /api/runs`, `/api/jobs`, `/api/agents`, `/api/assets`,
`/api/assets/{id}/events`, `/api/schedules`, `/api/webhooks` and
`/api/vulnerabilities` (plus the delivery and event lists)
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
`asset_criticality`, `asset_id`, `owner_email`, `business_service`; jobs — `started_at`, `finished_at`, `status`,
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

## Console accounts

Accounts live in the Postgres `users` table (migration `0013`). Passwords are
stored as bcrypt hashes and **only** as bcrypt hashes: before #156 the store was
the `OCTO_API_USERS` environment variable and a password was compared as
plaintext whenever the configured value did not start with `$2`.

```http
GET    /api/users                               # admin
POST   /api/users                               # admin  {"username","password","role"}
PUT    /api/users/{username}/password           # admin — reset, no old password needed
PUT    /api/users/{username}/role               # admin
PUT    /api/users/{username}/disabled           # admin  {"disabled": true}
DELETE /api/users/{username}                    # admin
POST   /api/auth/password                       # any role — change your own
```

`POST /api/auth/password` re-verifies the current password even though the
caller already holds a valid token: a token proves "can act as this user right
now", which a stolen one also proves; the password proves rather more.

No response carries a password or a hash — `UserInfo` has no field for one.

**Disabling beats deleting.** A disabled account keeps its tenant memberships
and its history, so revoking access does not silently discard grants that would
have to be recreated from memory. Deleting cascades the memberships (FK from
migration `0013`), so no grant outlives the account it was made for.

**Last-admin guards.** Disabling, demoting or deleting the only remaining
enabled admin answers `409`: the resulting installation can only be recovered by
editing the database by hand. Deleting the account you are signed in as is
refused for the same reason.

`OCTO_API_USERS` survives as a **one-time bootstrap input**: on a first start
with an empty table its entries are imported (plaintext hashed on the way in)
and the variable stops being consulted. A later edit to it is ignored — two
sources of truth is the state this change exists to leave. The built-in demo
accounts are never imported, and exist only under `OCTO_ENV=dev`; a `prod`
install with neither an account nor that variable refuses to start. See
[configuration.md](configuration.md#startup-safety-octo_env).

## Tenant memberships

Which tenants a user may act in comes from the `user_tenants` table, managed by
a platform admin:

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

Screenshot PNGs under `screenshots/` are a separate class (ROADMAP P4.4).
They can still hold personal data after DOM redaction, so:

- `GET /api/runs/{id}` omits those paths from `artifacts`;
- the text-preview endpoint answers `404` for them (they are not source);
- `GET /api/runs/{id}/download/screenshots/…png` is operator-or-higher;
  a viewer gets `404`, same as a missing file;
- `GET /api/runs/{id}/screenshots` (operator) returns the manifest, including
  items whose pixels the retention reaper already deleted (`available: false`).

`screenshots.json` stays a normal text artifact.

## Automation clients

For scripts:

- authenticate once and refresh/re-login on `401`;
- use idempotency or external coordination before retrying job creation;
- respect API pagination/limits;
- record `job_id`, `run_id`, and tenant together;
- never log bearer tokens or provisioning keys;
- treat `429` and dependency `503` responses as retryable only with bounded
  backoff.
