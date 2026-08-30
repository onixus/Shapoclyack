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
`success`, `failure` (credentials checked and rejected), `locked` (refused by
the limiter before they were checked), `denied` — an already-authenticated
principal refused an action, currently a scan outside the tenant's approved
scanning scope (#226) — or `trust_change`, an admin setting or removing an SSH
host-key pin ([#241](https://github.com/onixus/Shapoclyack/issues/241)).
A `denied` or `trust_change` row names what it was about in `detail` and
carries no client IP: those decisions are taken in the service layer, which has
no request to read one from. The limiter counts `failure` rows only, so these
refusals cannot lock anyone out.

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
client IP; `outcome` is one of `success`, `failure`, `locked`, `denied` (an
authenticated principal refused an action — a scan or a deployment target
outside the tenant's approved scope) or `trust_change` (an admin set or removed
an SSH host-key pin, #241 — neither an attempt nor a refusal, and kept out of
`success` so the login counter in `/metrics` keeps answering one question).
Rows older than
`OCTO_AUTH_EVENT_RETENTION_DAYS` (default 90) are pruned — but never while they
are still inside the limiter's window, since the two settings are chosen
independently and a short retention must not quietly weaken the lockout.

A locked-out client keeps retrying, and recording each retry would make the
audit trail an amplifier for unauthenticated writes — so one `locked` row is
written per window and the rest are counted only in `/metrics`.

## Roles

| Role | Intended capability |
|---|---|
| `viewer` | Read assets, runs, findings, diffs, artifacts (except screenshot PNGs and restricted artifacts), and status |
| `operator` | Viewer plus start jobs, screenshot PNGs, restricted artifacts, and update permitted asset metadata |
| `admin` | Operator plus tenant provisioning, destructive administration, and config overrides |

The route implementation is authoritative. Client-side hiding is usability,
not an authorization control.

## Endpoint groups

| Prefix | Purpose |
|---|---|
| `/api/auth` | Login, current principal, and the authentication audit trail (`/api/auth/events`, admin) |
| `/api/runs` | Run summaries, details, hosts, ports, findings, artifacts |
| `/api/jobs` | Start, monitor, and cancel scan jobs |
| `/api/agents` | Agent registration, heartbeat, claim, fleet status and per-agent lifecycle |
| `/api/agent/deploy` | Operator-driven SSH push installation of an agent onto a Linux host |
| `/api/assets` | Persistent asset inventory, business context and per-asset risk rollup |
| `/api/tenants/posture` | Per-tenant risk comparison (operator; scoped like `GET /tenants`) |
| `/api/endpoint` | Endpoint device and software inventory, plus vendor-advisory CVE matches over it (`/api/endpoint/cve-matches`, `/api/endpoint/devices/{id}/cve-matches`). Reads are `viewer`; the `…/refresh` routes that re-run the matcher are `operator`, since a tenant-wide run walks every package on every device — see [software-cve-matching.md](software-cve-matching.md) |
| `/api/tenants` | Tenant lifecycle, provisioning keys, and the approved scanning scope (`/api/tenants/{id}/scan-scope`, admin). A supplied `tenant_id` must match `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` and must not start with the reserved `h_`, since it doubles as a NATS subject token (422 otherwise) |
| `/api/schedules` | Tenant-scoped recurring scans |
| `/api/vulnerabilities` | Tracked findings: lifecycle, ownership, SLA policy and the audit trail |
| `/api/webhooks` | Outbound webhook and ticket-transport subscriptions, delivery trail, DLQ |
| `/api/wordlists` | Tenant-uploaded subdomain wordlists: list, upload, fetch and delete. Reads are `viewer`, writes `operator` — the same bar as starting a scan, since a wordlist is scan input. Selected per scan via `wordlist_id`; caps and normalization are in [configuration.md](configuration.md#tenant-uploaded-wordlists) |
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

### Vulnerabilities

Reading takes `viewer`; moving a finding through its lifecycle or reassigning it
takes `operator`; **accepting risk and editing SLA policy take tenant `admin`**,
because each commits the tenant to something rather than progressing one
person's work. `POST /{id}/transition` answers `409` on an illegal move (the
request is well-formed; the refusal is about the finding's current state) and
`422` on a state that is not in the model. A finding in another tenant answers
`404`. The states, the SLA resolution order and the exception rules are in
[vulnerability-lifecycle.md](vulnerability-lifecycle.md).

**Risk history.** `GET /api/vulnerabilities/risk-history` (viewer) returns the
tenant's persisted risk snapshots — `recorded_at`, estate risk level, open and
total counts, the NIST level breakdown and SLA breaches — filtered by
`since` / `until` and capped by `limit` (default 90, maximum 500). `limit`
takes the **most recent** rows and the series is returned oldest-first, so a
chart asking for 30 points gets the last 30 ([#228](https://github.com/onixus/Shapoclyack/issues/228)).
It is a **read of what was recorded**, not a recomputation: a period with no
snapshots is a gap in the series, not zero risk.

Unlike `/summary`, this route is always scoped to a single tenant, including
for a platform admin who named none: summing several tenants is a number,
interleaving their histories is a sawtooth. A platform admin selects the tenant
with the `tenant_id` query parameter every route accepts; without one they read
their own tenant.
`POST /api/vulnerabilities/risk-history/snapshot` (operator) records one
immediately and answers `201` with it. Snapshots are per tenant and are the
only source the Risk Overview trend chart reads
([#144](https://github.com/onixus/Shapoclyack/issues/144), Track C).

### Agent fleet, deployment and upgrade

| Route | Role | Notes |
|---|---|---|
| `GET /api/agents` | operator | Page of agents; fleet-wide for an unscoped platform admin, as for `/jobs` |
| `GET /api/agents/summary` | viewer | Fleet rollup: total / online / busy / stale / error / outdated, `latest_version`, and a per-tenant count |
| `GET /api/agents/{id}` | viewer | One agent, including heartbeat telemetry (OS, CPU, memory, disk, load, uptime), capabilities and `upgrade_requested`; `404` outside the tenant |
| `DELETE /api/agents/{id}` | operator | Forgets the registration. It does **not** stop the remote process — an agent that is still running re-registers on its next heartbeat |
| `POST /api/agents/{id}/upgrade` | operator | Sets `upgrade_requested` on the agent record and answers `upgrade_queued` with the `target_version`. It is a **flag for the operator surface**, not a command channel: nothing on the host reads it, and the upgrade itself is run on that host (see [operations.md](operations.md#agent-installation-and-upgrade)) |
| `GET /api/agent/deployment-command` | operator | Renders the systemd / docker / compose / kubernetes snippets with a `<PROVISIONING_KEY>` placeholder. Mints nothing |
| `POST /api/agent/deployment-command` | **admin** | Mints **one** tenant provisioning key (optional `label`, default `Web UI Deployment Key`) and returns the same snippets filled in. **201**; the plaintext key is in this response only |
| `POST /api/agent/deploy/ssh/host-key` | **admin** | Reports the target's SSH host key (`key_type`, `SHA256:…` fingerprint, and whether it is already `pinned` for this tenant). Authenticates to nothing and pins nothing — it exists so the fingerprint can be compared against the host before credentials are sent. `403` for a host or port outside the deployment target policy (see below), `502` when the target cannot be read |
| `DELETE /api/agent/deploy/ssh/host-key?host=…&port=22` | **admin** | Removes this tenant's pin for that target and answers with what was removed, so the fingerprint being dropped is in front of the operator. `404` when nothing was pinned. The next deployment needs `expected_host_key` again — a rebuilt machine is re-verified, never silently re-trusted. Both the removal and the next pin are in `GET /api/auth/events?outcome=trust_change` ([#241](https://github.com/onixus/Shapoclyack/issues/241)) |
| `POST /api/agent/deploy/ssh` | **admin** | Starts an SSH push install and returns the run immediately (`deploy_id`, `status=queued`) — the install runs in a background thread and mints a key for that machine server-side. The target's host key is resolved **synchronously first**: `403` if the target is outside the deployment target policy, `409` if the key is unpinned and the request names no `expected_host_key`, or if either the pin or the named fingerprint does not match; `502` if the key cannot be read at all. Nothing is sent to the target in any of those cases |
| `GET /api/agent/deploy/{deploy_id}/status` | operator | Poll for `status`, `stage`, `progress_percent`, the log lines and the resulting `agent_id`. Scoped to the caller's tenant; a run in another tenant answers `404` |
| `GET /api/agent/install.sh` | **none** | Serves `scripts/install-agent.sh` verbatim so the remote `curl … \| bash` can fetch it. Unauthenticated by design — the script itself carries no credential |

An agent id belonging to another tenant answers `404`, exactly as an id that
exists nowhere does, on `GET`, `DELETE` and `upgrade` alike
([#223](https://github.com/onixus/Shapoclyack/issues/223)). Answering `403`
for the former and `404` for the latter told a caller which ids are real
elsewhere in the installation, which is the only thing an opaque id is worth. A
platform admin without a requested tenant sees the whole fleet, the same rule
as `/api/jobs`.

**Who may mint a provisioning key** ([#231](https://github.com/onixus/Shapoclyack/issues/231)).
A provisioning key registers agents into the tenant, which makes handing one
out an authorization decision rather than a read. `POST` on
`/api/agent/deployment-command` and `/api/agent/deploy/ssh` therefore take
tenant **`admin`** — the same bar as
`POST /api/tenants/{tenant_id}/provisioning-keys`, which mints the identical
credential, and the SSH push additionally installs software as root on another
machine.

This replaces the earlier rule, which set both at `operator` on the grounds
that the SSH push already minted a key at `operator`. That reasoned from the
weaker of the two routes: the argument justified `operator` on the
key-minting POST by pointing at a route that should not have been `operator`
either. The alternative considered was a separate `agent_provisioner`
capability; it was rejected because roles here are a three-step ladder
(`viewer` < `operator` < `admin`) that every route and the console's role
gating read, so one capability would mean a second authorization model for one
pair of endpoints. If per-capability grants arrive for other reasons, this is
the first pair worth revisiting.

Reading the snippets stays `operator`: `GET` mints nothing and returns a
`<PROVISIONING_KEY>` placeholder. Tenant-wide key administration (listing,
revoking, minting against an arbitrary tenant under
`/api/tenants/{tenant_id}/provisioning-keys`) is `admin`, as before.

The split between GET and POST is deliberate: rendering the snippets is
idempotent, minting is not. Keys are hashed at rest and the plaintext is
returned exactly once, so an existing key cannot be re-embedded in a snippet —
a fresh mint is the only way to fill the placeholder in, and the operator asks
for it explicitly rather than getting one per dialog open. Revoke unused keys
via `POST /api/tenants/{tenant_id}/provisioning-keys/{key_id}/revoke`.

Three further properties of this group are worth knowing before it is used:

- **Deployment runs are rows** in `agent_deployments`, keyed by tenant, so the
  status poll answers on any replica and survives a restart. The last 100 runs
  per tenant are kept and each run keeps its last 500 log lines.
- **The target's host key must be known before a deployment runs.** The first
  deployment to a host needs `expected_host_key`; read it with
  `POST /api/agent/deploy/ssh/host-key`, **confirm it on the target itself**
  (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`) rather than trusting the
  probe, and send it back. It is then pinned for that tenant and target, and
  later runs need nothing. A key that no longer matches the pin is a `409` that
  reports both fingerprints; if the host really was rebuilt, remove the pin with
  `DELETE /api/agent/deploy/ssh/host-key` and pin the new key deliberately on
  the next run.
- **Where a deployment may point is a policy, not the request's choice**
  ([#240](https://github.com/onixus/Shapoclyack/issues/240)). Both the probe and
  the run open a TCP connection to a host and port from the request body, so
  both are checked first. The check is deliberately *not* the webhook boundary:
  an agent belongs inside a private network, so RFC1918 is the ordinary answer
  here and refusing it would refuse the product. What is refused is this
  platform's own reflection — loopback, link-local (`169.254.169.254` is a
  metadata service, not a Linux box), multicast, the unspecified address — a
  port outside `OCTO_AGENT_DEPLOY_SSH_PORTS`, and any host the tenant's
  approved scan scope **denies**
  ([#226](https://github.com/onixus/Shapoclyack/issues/226)): a prohibition that
  stopped a scan but not an SSH connection from the same API would not be
  recording anything. Containment in the *allowed* scope is opt-in
  (`OCTO_AGENT_DEPLOY_ENFORCE_SCAN_SCOPE`), because where an agent lives is not
  the same question as what it is approved to scan. Every refusal is a `403`
  and a row in `GET /api/auth/events?outcome=denied`.
- **SSH credentials are request data.** The password or private key in
  `POST /api/agent/deploy/ssh` is used for the run and never stored, but it does
  cross the API. Prefer a key with a purpose-built account. The minted
  provisioning key reaches the installer on stdin and lives on the target only
  in `/etc/shapoclyack/agent.env` (`0600`); revoke it if the host is shared.

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

## Approved scanning scope

What a tenant may point the platform at is a stored, approved list rather than
a syntax check (#226). Both endpoints are platform admin, for the same reason
provisioning-key creation is (#231): deciding that a tenant may scan a network
is an administrative act, and an operator who could widen their own scope
would be the control removing itself.

```http
GET /api/tenants/{tenant_id}/scan-scope
PUT /api/tenants/{tenant_id}/scan-scope   {"entries": [{"effect": "allow", "kind": "cidr", "value": "203.0.113.0/24"}]}
```

`PUT` replaces the whole scope in one transaction and stamps the caller as
`approved_by` on every resulting row; `entries: []` is accepted and means the
tenant scans nothing. A malformed entry is `422`, an unknown tenant `404`.

An out-of-scope scan is refused with **`403`, not `422`** — the target is
well-formed, the tenant is simply not entitled to it — and the refusal is
recorded in the access-decision journal above. Since #244 the same `403` comes
from `POST /api/schedules` and `PATCH /api/schedules/{id}`, checked against the
targets that would be stored: a schedule is a scan asked for in advance, and
until then the only refusal happened at dispatch, so an operator learned their
schedule was out of scope by noticing hours later that no scan had run. The
dispatch-time check stays — a scope narrowed after the schedule was written
still has to stop it. The model, the third barrier inside the run, and the
grandfathering migration `0025` applies on upgrade are described in
[operations.md](operations.md#approved-scan-scope-per-tenant).

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

### Restricted artifacts

Two artifact classes are not covered by the viewer's blanket artifact access,
because they carry data about people rather than about open ports.

**Screenshot PNGs** under `screenshots/` (ROADMAP P4.4).
They can still hold personal data after DOM redaction, so:

- `GET /api/runs/{id}` omits those paths from `artifacts`;
- the text-preview endpoint answers `404` for them (they are not source);
- `GET /api/runs/{id}/download/screenshots/…png` is operator-or-higher;
  a viewer gets `404`, same as a missing file;
- `GET /api/runs/{id}/screenshots` (operator) returns the manifest, including
  items whose pixels the retention reaper already deleted (`available: false`).

`screenshots.json` stays a normal text artifact.

**Owner-identity artifacts** — `ownership.json` and `ownership_findings.txt`
(org profile M1, [#182](https://github.com/onixus/Shapoclyack/issues/182)).
They carry the RDAP registrant organization and the abuse contact address, i.e.
a contactable human at the target organization. The predicate is
`api/services/runs.py::is_restricted_artifact`, an explicit list of run-relative
names — a new stage has to opt in deliberately:

- `GET /api/runs/{id}` omits them from `artifacts` (as with PNGs, unconditionally
  — an operator fetches them by name, they are not discovered through the list);
- the text-preview endpoint answers `404` for a viewer and serves the JSON to an
  operator (unlike PNGs these are readable text);
- `GET /api/runs/{id}/download/ownership.json` is operator-or-higher; a viewer
  gets `404`, same as a missing file.

`resolve_artifact` refuses a restricted name too, not just the two routes:
callers pass `allow_restricted=True` once the role check has passed, the same
belt-and-braces as `allow_screenshots`. Without it the next endpoint that
reaches for an artifact would inherit no protection at all.

The same predicate will cover `credential_leaks.*` when org profile M5 lands.

## Automation clients

For scripts:

- authenticate once and refresh/re-login on `401`;
- use idempotency or external coordination before retrying job creation;
- respect API pagination/limits;
- record `job_id`, `run_id`, and tenant together;
- never log bearer tokens or provisioning keys;
- treat `429` and dependency `503` responses as retryable only with bounded
  backoff.
