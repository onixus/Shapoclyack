# API and RBAC

The API is served under `/api`. The Web UI uses the same API and stores the
access token in browser local storage.

## Request correlation

Every response carries an **`X-Request-Id`** header
([#330](https://github.com/onixus/Shapoclyack/issues/330)). Send one and it is
echoed back, provided it is at most 128 characters of `[A-Za-z0-9._:@=+/-]` —
a uuid, a ULID, a W3C `traceparent` or nginx's `$request_id` all qualify. Send
anything else, or nothing, and the API mints a uuid4 and returns that instead:
an id it had to rewrite would not correlate anyway.

Every response means every response, the `500` for an unhandled exception
included: the middleware wraps the whole ASGI stack rather than being added to
it, so the error response Starlette itself writes still goes out through this
layer. The header is named in the CORS `expose_headers`, so a console served
from another origin can read it — it appends the id to the error toast for a
server-side failure.

The same value appears in the `request_id` field of every log line the request
produces — the record about that `500` included — and, when tracing is enabled,
on the span as `shapoclyack.request_id`, so an id from a user's bug report is
enough to find the request in the logs. See
[operations.md](operations.md#logs-and-observability).

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

The two token families are signed with **different keys**
([#312](https://github.com/onixus/Shapoclyack/issues/312)). A console session is
signed with `OCTO_JWT_SECRET`; an agent JWT is signed with
`OCTO_AGENT_JWT_SECRET`, or — when that is unset, which is the default — with a
key derived from `OCTO_JWT_SECRET` via HKDF-SHA256. Both families still carry a
`typ` claim and both are still checked, but the signature alone now separates
them: an operator token does not verify on an agent route and an agent token
does not verify on `/api/auth/me`, so no single missed `typ` check is enough to
turn one into the other. The agent key sits on every scanner host, which is a
much wider blast radius than the API's own secret — see
[configuration.md](configuration.md#environment-variables) for rotating it.

## Sessions, logout and revocation

A console token is no longer believed on its own
([#314](https://github.com/onixus/Shapoclyack/issues/314)). Every request
verifies the signature and then reads the account row: the session dies the
moment the account is disabled, deleted, demoted or has its password changed —
"a disabled user loses access in under a minute" is in practice "on the next
request". The role that reaches the request is the one in the table, not the
one in the claim, so a demotion applies immediately rather than at the next
login. The claim is still parsed, and a token naming a role that does not exist
is still refused.

Two claims and one header carry this:

| Field | Where | What it does |
|---|---|---|
| `ver` | claim | The account's `token_version` when the token was minted. A mismatch is a 401 |
| `jti` | claim | Per-token id. What `POST /api/auth/logout` puts on the denylist |
| `kid` | header | Which signing key signed it — see [Key rotation](#jwt-signing-key-rotation) |

```http
POST /api/auth/logout                           # any role — ends this session only
POST /api/auth/sessions/revoke-all              # any role — ends every session of your account
POST /api/users/{username}/sessions/revoke-all  # admin   — ends every session of that account
```

All three answer `204`. Logout writes the token's `jti` to `revoked_tokens`
until its own `exp` and is idempotent; the two `revoke-all` routes increment
`users.token_version`, which invalidates every token quoting the old value —
including the caller's own, which is the point. `revoke-all` on an account that
does not exist is a `404`.

Tenant memberships need no version bump: the role *inside* a tenant is
resolved from `user_tenants` on every request and was never in the token, so
granting or revoking a membership already applies immediately.

`PUT /api/users/{username}/role` and `PUT /api/users/{username}/disabled` bump
the version only when the value actually moves. Re-asserting the state an
account is already in — what a reconciling IaC run or a directory sync does on
every pass — is a no-op and leaves that account's sessions alone.

When Postgres is unreachable the check cannot be made, and an authenticated
request answers `503` with `Retry-After`, not `401`: the session was not
refused, it was undecided. See
[operations.md](operations.md#sessions-and-revocation).

A session with no `jti` cannot be logged out one at a time and says so with a
`400` rather than a `204` that did nothing. That is only reachable for tokens
minted before #314; `revoke-all` ends those.

Service tokens are not sessions. They never reach these routes at all — `auth`
is a resource no service token may touch — and are revoked as credentials with
`POST /api/tenants/{tenant_id}/service-tokens/{token_id}/revoke`.

Changing your own password (`POST /api/auth/password`) ends **every** session
of the account, the one making the request included: the console lands back on
the login form. That is deliberate — a rotation is usually "somebody may have
my password", and the session that survives it is the one that mattered.

### JWT signing key rotation

`OCTO_JWT_SECRET_PREVIOUS` is a comma-separated list of retired keys that are
still accepted while the tokens they signed expire. Nothing is ever signed with
one. Every token carries a `kid` — a domain-separated `sha256` prefix of the
key — so the verifier tries the named key rather than each in turn; a token
naming one key of the window and signed with another is refused, and a token
with no `kid` (anything minted before #314) is tried against the whole window.

While `OCTO_AGENT_JWT_SECRET` is unset the agent key is derived from the
operator key, so the same list rotates both audiences and an agent fleet is not
locked out mid-rotation. The OIDC login state (`api/services/oidc.py`) is
signed with the same key and verified against the same window, so an SSO login
started just before a rotating deploy still completes on a replica that has
already moved on. When it is set explicitly the two are independent and
so are their windows — see `OCTO_AGENT_JWT_SECRET_PREVIOUS` in
[configuration.md](configuration.md#environment-variables) and the procedure in
[operations.md](operations.md#rotating-the-jwt-signing-key).

## Multi-factor authentication

A console account can carry a second factor: a TOTP authenticator (RFC 6238,
HMAC-SHA-1, six digits, thirty seconds) plus ten single-use recovery codes
([#315](https://github.com/onixus/Shapoclyack/issues/315)). It is **off by
default and enrolled by the account itself** — an upgrade changes nothing until
somebody enrols or an operator sets `OCTO_MFA_REQUIRED_ROLES`.

WebAuthn / passkeys, the other half of #315, are **not** implemented.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/auth/mfa` | session | The caller's own state: enabled, setup pending, recovery codes left, whether policy requires it |
| `POST /api/auth/mfa/totp/setup` | session | Mints an unconfirmed secret and returns it with its `otpauth://` URI. Nothing is enabled yet |
| `POST /api/auth/mfa/totp/confirm` | session | `{"code":"123456","password":…}`. Turns the factor on and returns the ten recovery codes **once**. The password is required for any account that has one — enrolling a factor must cost what removing one does, or a stolen session could enrol its own and lock the owner out |
| `POST /api/auth/mfa/verify` | challenge token *or* session | Second leg of a login, or a step-up on a live session |
| `POST /api/auth/mfa/disable` | session | `{"password":…, "code"\|"recovery_code":…}`. Both are required |
| `POST /api/users/{username}/mfa/reset` | platform admin + step-up | Clears the factor, bumps `token_version` (ends the account's sessions), audited as `user.mfa_reset` |

### The two-leg login

`POST /api/auth/login` answers 200 with one of two shapes. For an account with
no second factor it is the object it has always been. For an enrolled account
there is **no** `access_token`:

```json
{"username":"admin","mfa_required":true,"mfa_token":"<challenge>","expires_in":300}
```

The challenge token is `typ=mfa`, lives five minutes, carries no role, and is
accepted by `POST /api/auth/mfa/verify` and by nothing else — `decode_token`
allowlists `typ=user`, so presenting it as a session is a 401. It carries the
account's `token_version`, so revoking sessions kills an in-flight challenge
too.

Every password or code check in this module runs inside the login limiter
(#157) under the account's own key and lands in `auth_events`: `confirm` and
`disable` are reachable by a session, and an uncounted password check behind a
stolen token would be a password oracle. An account that cannot be asked for a
password — provisioned by the identity provider, or one whose password
`OCTO_LOCAL_LOGIN` no longer accepts — is asked only for the factor
(`MfaStatus.password_required` says which). That is a real, deliberate
weakening of `disable` for those accounts, and a small one: the thing the
password-plus-code pair defends against is a stolen session, which holds
neither half.

`POST /api/auth/mfa/verify` takes `{"mfa_token":…, "code":…}` or
`{"mfa_token":…, "recovery_code":…}` and returns the ordinary session token.
Refusals go through the same limiter as a password (#157) under the account's
own key and land in `auth_events` with `reason=mfa_failed`.

**SSO is not an exemption.** `GET /api/auth/oidc/callback` makes the same
decision: an account that has enrolled gets the challenge where the session
would have been — `mfa_token` in the redirect fragment, or in the JSON body for
an API-only install. The provider proved an identity; it did not prove
possession of the authenticator this installation holds a seed for. The
callback's response model is therefore the same `LoginResponse` password login
uses (`access_token` is now nullable on it).

A TOTP code is accepted within ±1 step (±30 s) and **spent**: the step it
belonged to is written to `users.mfa_last_step` in the same transaction, and a
step at or before it is refused, so an observed code cannot be replayed inside
its own thirty seconds. A recovery code is bcrypt-hashed like a password and
stamped `used_at` when it is spent.

### Required roles, and the confined session

`OCTO_MFA_REQUIRED_ROLES` (empty by default) names roles that must carry a
factor. An account in such a role that has not enrolled still signs in — a
refusal would leave nobody able to enrol — but the session is `mfa_pending`,
and `get_current_user` then answers **403** on everything except
`/api/auth/mfa*`, `/api/auth/me`, `/api/auth/logout` and
`/api/auth/sessions/revoke-all`. `GET /api/auth/me` reports `mfa_enabled`,
`mfa_required` and `mfa_pending` so the console can say why.

`mfa_pending` is **derived on every request** from the policy and the account
row, not carried as a token claim — the same rule the role follows. Turning the
policy on is a redeploy, not a sign-out, so a claim minted at login would have
exempted every administrator already signed in for the rest of their eight
hours; a promotion into a covered role would have done the same. It also means
finishing an enrolment lifts the confinement on the *existing* token, with no
sign-out in the middle.

### Step-up

Operations that create or destroy a credential, or widen what a tenant may
scan, require a second factor proved within the last `OCTO_MFA_STEPUP_MINUTES`
(default 15):

- `POST`/`DELETE /api/tenants/{id}/service-tokens…`
- `POST`/`DELETE /api/tenants/{id}/provisioning-keys…` **and**
  `POST /api/agent/deployment-command`, which mints the same key and is the one
  the console uses
- `PUT /api/tenants/{id}/scan-scope`
- `POST /api/users`, `PUT /api/users/{u}/password`, `PUT /api/users/{u}/role`,
  `PUT /api/users/{u}/email` and `POST /api/users/{u}/mfa/reset` — each of them
  a way to end up holding an admin account that carries no second factor
  (a verified address is what an SSO identity is linked to an account by),
  which would otherwise be a one-request path around every line above

A **service token** is exempt from step-up: there is no human at one to
challenge. That is why every route in the list above must also be refused a
service token by scope — `auth`, `users`, `tenants` and `audit` are forbidden
outright, `config` and `agent` for writes — and why adding a route here means
checking that list too.

The check applies **only to accounts that have MFA enabled**; an installation
that has not adopted MFA behaves exactly as before. A stale session gets a 403
naming `POST /api/auth/mfa/verify`; calling it *without* `mfa_token` while
signed in returns a fresh session token whose `mfa_verified_at` restarts the
window. The console raises a code dialog on that 403 and asks the user to
repeat the action — the refused request is **not** replayed, because it never
reached the server and silently repeating a `POST` nobody saw succeed is worse
than asking again.

### Break-glass local login

`OCTO_LOCAL_LOGIN` decides what password login is for once SSO is configured.
It is **ignored entirely when no identity provider is set** — an installation
with neither SSO nor password login is one nobody can reach.

| Value | Effect |
|---|---|
| `enabled` (default) | Password login for everyone, as before |
| `break-glass` | Only the accounts in `OCTO_BREAK_GLASS_USERS` may present a password. Each such login is audited as `auth.break_glass_login`, recorded in `auth_events` with `reason=break_glass_login`, counted in `octo_break_glass_logins_total` and logged at WARNING |
| `disabled` | No password login at all |

A refusal is the same `401 Invalid credentials` a wrong password gets: naming
the policy to an unauthenticated caller would hand over the shortlist of
accounts worth attacking. The *mode* is public in `GET /api/auth/sso` as
`local_login`, which names nobody, so the login form knows what to offer. The
reason (`local_login_disabled`, `local_login_not_break_glass`) is in
`auth_events`.

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

## Administrative audit trail

`auth_events` above answers "who signed in and what was refused". `audit_events`
answers the other half — **what was changed** ([#327](https://github.com/onixus/Shapoclyack/issues/327)).
One row per administrative change, with the resource before and after it:

| Action | Recorded on |
|---|---|
| `user.create`, `user.role_change`, `user.disable`, `user.delete` | `POST /api/users`, `PUT /api/users/{u}/role`, `PUT /api/users/{u}/disabled`, `DELETE /api/users/{u}` |
| `user.password_reset` | `PUT /api/users/{u}/password` — an admin resetting someone else's password is one request away from acting as them. `before`/`after` carry the `password_changed_at` that moved, never the password |
| `user.password_change` | `POST /api/auth/password` — the owner rotating their own, kept a separate action so a reset performed *on* an account is not buried under everyone's routine rotations |
| `membership.grant`, `membership.revoke` | `PUT`/`DELETE /api/tenants/{id}/members/{u}` |
| `service_token.create`, `service_token.revoke` | `POST /api/tenants/{id}/service-tokens[…/revoke]` |
| `provisioning_key.create`, `provisioning_key.revoke` | `POST /api/tenants/{id}/provisioning-keys[…/revoke]` |
| `agent.register` | `POST /api/agent/register`, **first registration only** — a restart re-registers, and that is uptime rather than an administrative change |
| `agent.disable`, `agent.enable`, `agent.quarantine` | `PATCH /api/agents/{id}` — one action per resulting state, so "who took this host out of the fleet" is a filter on the action rather than a read of every lifecycle row. `before` carries the state the agent was moved out of, `after` the new state and the operator's reason |
| `agent.delete` | `DELETE /api/agents/{id}` — `before` holds the hostname, the lifecycle state, the `provisioning_key_id` on record and `other_agents_on_key`. With `?revoke_key=true` a second row, `provisioning_key.revoke`, follows under the same actor and `X-Request-Id`: two acts on two resources, and the key survives the agent |
| `report.download` | `GET /api/reports/{id}/download` — a report is the tenant's findings leaving it |
| `scan_scope.replace` | `PUT /api/tenants/{id}/scan-scope`. `before` holds the entries that went (`removed`), `after` the ones that arrived (`added`), each with the scope's `entry_count` — a diff rather than two full scopes, so the record is bounded by the change and not by a tenant with 3 000 entries |
| `config.update` | `PUT /api/config`, as the dot-paths whose value changed: `before` and `after` hold the same key set, and `"[unset]"` on one side means the path was not overridden |
| `maintenance_window.create`, `maintenance_window.update`, `maintenance_window.delete` | `POST`/`PATCH`/`DELETE /api/maintenance-windows[/{id}]` — the window as stored, so "who moved the blackout off Saturday night" has an answer |
| `tenant.change_freeze` | `PUT /api/change-freeze`. `before`/`after` carry the flag, the note and the stamp, so both the freeze and the thaw are rows — the thaw is the one that precedes the scan somebody did not expect |
| `scan.maintenance_block` | Not an edit: the platform refusing a scan because a window or a freeze said so ([#352](https://github.com/onixus/Shapoclyack/issues/352)). Written by `jobs_service.start_scan`, so the console's `POST /api/jobs` and the recurring dispatcher leave the same row, with the `reason`, the `window_id` that refused and the `retry_at` it will lift at. Best-effort like the scope denial above: the scan is already refused, and losing the row must not turn a clean `409` into a `500` |

Every row carries the actor and what kind of principal it is (`user`,
`service_token`, `agent`, `system`), the client address resolved the same way
the login limiter resolves it, the user agent, and the `X-Request-Id` of the
request when it carried one — nothing invents one, so the value in a row always
matches a value that was on the wire.

**The row is written in the transaction that makes the change.** A membership
granted but not recorded is a silent change; a membership recorded but not
granted is a trail that lies. Both are impossible for every action that *is* a
database write. `report.download` is the exception, and the only one: a download
is a file read with no transaction to join, so its row is committed on its own
before the streaming response starts. A transfer that dies mid-stream therefore
leaves a row saying the report was downloaded — which is the direction that
error should point.

**Secrets never reach `before`/`after`.** Every field whose name reads like a
credential — `password`, `*_hash`, `token`, `*_secret`, `*_key` — is replaced by
`[redacted]` before storage, so a table every tenant admin can read cannot be
mined for one. Login attempts stay in `auth_events` and are not mirrored here:
they are the same fact in two tables, and the login trail is the one the rate
limiter counts.

```http
GET /api/audit?action=user.role_change&resource_id=amy&from=2026-09-01T00:00:00Z
GET /api/audit?tenant_id=acme&format=csv
```

| Parameter | Meaning |
|---|---|
| `tenant_id` | Narrows to one tenant. A tenant admin may only name their own (403 otherwise); a platform admin who names none reads every tenant |
| `actor`, `action`, `resource_type`, `resource_id` | Exact matches — "every change to *this* token" is the question, and a substring match is how the wrong row gets read as the right one |
| `from`, `to` | ISO instants, inclusive; an offset is honoured and converted to UTC |
| `offset`, `limit` | `Page` envelope like the other lists. Always newest first: this is a log, so there is no `sort`/`order` |
| `format=csv\|ndjson` | Streams **every** matching event rather than the current page, as an attachment. An export bounded by `limit` would be a page with a filename |

Reading requires **admin in the tenant**: the people who administer a customer
are the ones who have to review its changes. Rows with no tenant at all —
creating a console account, editing the installation-wide scanner config — are
platform-level acts and appear only in the platform admin's answer.

A service token can never read this endpoint, whatever role or scopes it was
minted with (`audit` is in `FORBIDDEN_RESOURCES` alongside `auth`, `users` and
`tenants`): the trail records the acts of the humans who administer the
installation, addresses included, and `?format=ndjson` makes a year of that one
request.

`before`/`after` are capped at 16 KiB of serialised JSON each. Past that the
side is stored as `{"truncated": true, "bytes": …}` and the API logs a warning
naming the resource — the two actions that could plausibly reach it record a
diff rather than a snapshot, so this is a backstop rather than the normal case.

The rows are **append-only in the database itself**
([#329](https://github.com/onixus/Shapoclyack/issues/329)): triggers refuse
every `UPDATE`, `DELETE` and `TRUNCATE`, so a bug in the API cannot rewrite
history. Whether *an operator holding the API's credentials* can is a
deployment question, not a code one — it depends on `audit_events` being owned
by a role the API does not run as, which the shipped `k8s/` manifests do **not**
do and the GRANT layout in
[operations.md](operations.md#audit-trail-immutability-and-retention) does.
Retention is a separate privileged job, documented in the same place.

**Getting the trail out of the API.** This endpoint is the read model, not a
feed. Each committed row is also published to the JetStream subject
`events.audit.{tenant}` (`events.audit._platform` for a platform-level act) —
after the commit, so a change that rolled back announces nothing, and not at all
when `OCTO_NATS_URL` is unset. From there a webhook subscription on `audit.*`
delivers it signed, and `python -m api.services.audit_syslog_forwarder` ships it
to a SIEM as CEF over RFC 5424 syslog. Subjects, field mapping and the
Splunk/QRadar/MaxPatrol parsers are in
[operations.md](operations.md#audit-events-to-siem-328)
([#328](https://github.com/onixus/Shapoclyack/issues/328)).

## Single sign-on (OIDC)

Authorization code with PKCE against a generic OpenID Connect provider
(ROADMAP Track E). SSO is **off** unless `OCTO_OIDC_ISSUER`,
`OCTO_OIDC_CLIENT_ID` and `OCTO_OIDC_CLIENT_SECRET` are all set — a
half-configured provider is a misconfiguration, not a partly enabled feature,
so it is reported as off rather than failing at the first redirect.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/auth/sso` | none | `{"enabled": …, "login_url": …, "local_login": …}`. The login form has to render before anyone is signed in. Also embedded in `GET /api/health` as `sso`. `local_login` is the `OCTO_LOCAL_LOGIN` mode and names no account |
| `GET /api/auth/oidc/login` | none | 307 to the provider's authorize URL. `?redirect=false` returns the URL as JSON; `?next=/path` is carried through the flow and is dropped unless it is a path on this console |
| `GET /api/auth/oidc/callback` | none | Exchanges the code and issues **the platform's ordinary session token** — same JWT, same claims, same expiry as password login |

Everything about the provider except the issuer and the client credentials
comes from its `.well-known/openid-configuration`, cached for
`OCTO_OIDC_CACHE_TTL_SECONDS`. The ID token is verified, never merely read:

- signature against the published JWKS, with the algorithm intersected against
  an **asymmetric allowlist** (`RS*`, `ES*`, `PS*`). Neither `none` nor an HMAC
  algorithm keyed on the client secret can ever be selected;
- `iss`, `aud` (and `azp` when present), `exp`/`iat` with 10s of leeway;
- the `nonce`, compared against the one this installation generated.

An unknown `kid` refetches the JWKS **once** — that is key rotation — and then
refuses. Retrying without a bound would turn an invented key into a request
amplifier against the provider.

State is signed *and* single-use: the signed half (an HS256 JWT over the
platform's own secret) proves this installation issued the request and bounds
its lifetime; a server-side record proves it has not been answered yet. The
nonce and the PKCE verifier live only in that record, so the browser carries
neither. **The record is a row in `oidc_pending_states`**, keyed on a hash of
the state's id and spent by a single `DELETE … RETURNING` — so a callback may
land on any replica, and two replicas answering the same callback cannot both
exchange the code. It expires after `OCTO_OIDC_STATE_TTL_SECONDS`; no session
affinity is required.

### Which account a login resolves to

In order, and stopping at the first match:

1. the stored `(issuer, subject)` pair. Once linked, that is the identity — it
   survives a renamed account and a changed address;
2. a **verified** email match: the provider must assert `email_verified` *and*
   the local account must already carry the same address marked verified by an
   admin (`PUT /api/users/{username}/email`, `{"email": …, "verified": true}`).
   An unverified address on either side is a string somebody typed, and linking
   on it would hand the console account to whoever can register that address at
   the identity provider;
3. just-in-time provisioning, **only** when `OCTO_OIDC_JIT_PROVISIONING=true`.
   The account is created with no password hash — it can only ever sign in
   through the provider — at the role `OCTO_OIDC_ROLE_MAP` produces for its
   claims, defaulting to `OCTO_OIDC_DEFAULT_ROLE` (`viewer`). It is never
   created over an existing local username.

A disabled account is refused at every step: SSO proves who you are, it is not
a way around a revocation.

Every outcome lands in the auth trail (`GET /api/auth/events`): `success` with
reason `sso_signin` / `sso_linked` / `sso_provisioned`, and `denied` with
`sso_denied` (a refused callback) or `sso_not_provisioned` (an identity this
installation has no account for).

## Service tokens

Non-interactive API credentials, admin-issued per tenant, so an integration
stops running under a person's password (ROADMAP Track E). Format:
`octo_st_<16 hex>_<secret>`. The first two segments are the **prefix** — public,
unique, indexed, and what the console shows; the secret is stored only as a
bcrypt hash, so the plaintext exists once, in the create response, and cannot
be read back.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/tenants/{tenant_id}/service-tokens` | admin | Issue. Returns `token` — the only time it exists |
| `GET /api/tenants/{tenant_id}/service-tokens` | admin | List, without secrets. Revoked and expired ones stay listed |
| `POST /api/tenants/{tenant_id}/service-tokens/{token_id}/revoke` | admin | Kill immediately. Idempotent |

A token is presented on the ordinary `Authorization: Bearer` header; which
credential it is, is decided by its own shape, never by anything the caller
asserts. Authorization is **two independent limits and a request must pass
both**:

- the **role** it was issued with, inside its own tenant, which is the ceiling.
  No membership row raises it, and an `admin`-role token is never a *platform*
  admin — it administers its tenant, not the fleet, and naming another tenant
  in `tenant_id` is a 403 rather than an ignored parameter;
- its **scopes**: `resource:action`, where `resource` is the first path segment
  under `/api` (`runs`, `assets`, `vulnerabilities`, `jobs`…) and `action` is
  `read` for `GET`/`HEAD`/`OPTIONS` and `write` for everything else. `*` matches
  either half, so `runs:*`, `*:read` and a bare `*` are all expressible. At
  least one scope is required — a token created with none by accident would
  otherwise be the most powerful credential in the installation.

Three resources are closed to every service token whatever its role or scopes:
`auth`, `users` and `tenants`. A credential that can create users, rotate
passwords, grant memberships, widen a scan scope or mint further tokens is one
that outlives its own revocation.

`config` is readable but never writable by a service token, for a different
reason: `PUT /api/config` replaces the **installation-wide** scanner overrides
and is authorized by role alone, not per tenant. The tenant a token is pinned to
therefore buys nothing there, so an admin-role token issued for one customer
would otherwise decide how every other customer scans. `config:write` in a
token's scopes is accepted at creation and refused at request time.

`expires_at` is always set (`OCTO_SERVICE_TOKEN_DEFAULT_TTL_DAYS`, capped by
`OCTO_SERVICE_TOKEN_MAX_TTL_DAYS`) — a credential with no expiry is one nobody
rotates. `last_used_at` is written at most once per
`OCTO_SERVICE_TOKEN_LAST_USED_INTERVAL_SECONDS` so a busy integration does not
turn every request into a write.

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
| `/api/auth` | Login, single sign-on (`/api/auth/sso`, `/api/auth/oidc/*`), current principal, and the authentication audit trail (`/api/auth/events`, admin) |
| `/api/audit` | Administrative audit trail: what was changed, by whom, with the value before and after (admin in the tenant; CSV/NDJSON export) |
| `/api/runs` | Run summaries, details, hosts, ports, findings, artifacts |
| `/api/jobs` | Start, monitor, and cancel scan jobs |
| `/api/agents` | Agent registration, heartbeat, claim, fleet status and per-agent lifecycle |
| `/api/agent/deploy` | Operator-driven SSH push installation of an agent onto a Linux host |
| `/api/assets` | Persistent asset inventory, business context and per-asset risk rollup |
| `/api/tenants/posture` | Per-tenant risk comparison (operator; scoped like `GET /tenants`) |
| `/api/endpoint` | Endpoint device and software inventory, plus vendor-advisory CVE matches over it (`/api/endpoint/cve-matches`, `/api/endpoint/devices/{id}/cve-matches`). Reads are `viewer`; the `…/refresh` routes that re-run the matcher **and fold the result into the vulnerability lifecycle** are `operator`, since a tenant-wide run walks every package on every device — see [software-cve-matching.md](software-cve-matching.md) |
| `/api/tenants` | Tenant lifecycle, provisioning keys, and the approved scanning scope (`/api/tenants/{id}/scan-scope`, admin). A supplied `tenant_id` must match `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` and must not start with the reserved `h_`, since it doubles as a NATS subject token (422 otherwise) |
| `/api/schedules` | Tenant-scoped recurring scans |
| `/api/vulnerabilities` | Tracked findings: lifecycle, ownership, SLA policy and the audit trail |
| `/api/webhooks` | Outbound webhook and ticket-transport subscriptions, delivery trail, DLQ |
| `/api/wordlists` | Tenant-uploaded subdomain wordlists: list, upload, fetch and delete. Reads are `viewer`, writes `operator` — the same bar as starting a scan, since a wordlist is scan input. Selected per scan via `wordlist_id`; caps and normalization are in [configuration.md](configuration.md#tenant-uploaded-wordlists) |
| `/api/adoption` | Adoption metrics for this tenant over `window_days` (7–365, default 90): closures, share confirmed by a scan, share closed within SLA, median time to fix overall and by severity, reopen share, open findings per asset; active assets with an owner / business context / a scan in the last 30 days / an endpoint inventory too; closed-and-verified per analyst; time to first successful scan and first tracked finding; enrichment overlay age. Two additive blocks: `false_positives` (verdicts in the window, their share of all closures, by severity, by detector and by observer, suppressions active and lapsed, overrides, median hours to a verdict) and `coverage` (assets with any scan history, scanned and vulnerability-assessed shares, and how many of the tenant's approved ranges contain an asset a scan reached — with the unreached ones named in `scope_uncovered_entries`). **False-positive closures are excluded from `closed_in_window`, `machine_verified_share`, `closed_within_sla_share` and every `mttr_hours*`** and reported as `false_positive_in_window` instead, so the quarterly control question cannot be answered by relabelling noise. Read-only, `viewer`, one tenant — a cross-tenant MTTR would be true of nobody. Shares are `null` when there is nothing to divide by — including while the coverage columns are still filling after the upgrade that added them (`scan_history_reason`) — and a per-detector rate is additionally `null` below 20 closures |
| `/api/compliance` | PCI DSS 4.0, CIS Controls v8 and ISO/IEC 27001:2022 control status over this tenant's findings, asset context and endpoint inventory. Read-only, `viewer`. A platform admin gets no cross-tenant view here: a control status is a statement about one organisation — see [reports-and-compliance.md](reports-and-compliance.md) |
| `/api/reports` | Report factory: branding (`admin`), templates (`operator`), scheduled delivery (`admin` — it sends this tenant's findings outside the installation), on-demand generation (`operator`) and downloads (`viewer`) |
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

The key is checked against the *request*, not only against itself: the fields
that define the scan (`mode`, `intent`, `delta`, `skip_nse`, `notify`,
`export_defectdojo`, `surface`, `ranges`, `domains`, `ports`, `ports_udp`,
`wordlist_id`) are digested and stored on the job, and a key sent with a
different body answers **409** (`Idempotency-Key already used for a different
scan request (job …)`) rather than replaying. Replaying would report a scan of
targets this caller never asked about; starting a second scan would break the
promise the key was given for. `tenant_id` and `run_id` are not part of the
digest — the route decides the first and the second only names the output — and
target texts are compared line by line, so re-serialised but identical targets
still replay. Jobs created before this shipped carry no digest and keep
replaying on the key alone.

`GET /api/jobs/summary` (operator) is the queue depth behind the job list, in
one grouped query: `by_status` (all six lifecycle states, zero-filled),
`running`, `queued` (queued **plus** claimed — a job an agent holds but has not
started is still work waiting), `by_surface` (`external` / `internal` / `mixed`
/ `unknown`, each with `running`, `queued`, `total`) and `generated_at`.
Tenant-scoped exactly like `GET /api/jobs`: fleet-wide for a platform admin who
named no tenant, the caller's own tenant otherwise. Note the `queued`/`running`
split here differs from the `octo_jobs_*` gauges in [slo.md](slo.md), which
count `claimed` as running because they measure executor occupancy instead.

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
different content, and `200` (rather than `201`) for an exact replay. Since
[#308](https://github.com/onixus/Shapoclyack/issues/308) it also answers `403`
for a `disabled` or `quarantined` agent, like the job routes: quarantining a
host is meant to stop it writing, not to stop only the half of its traffic that
carries a job id. Read
routes expose each device's server-derived `status` (`active`/`stale`, from
`OCTO_ENDPOINT_STALE_HOURS`) and accept `device_status=active|stale` as a
filter.

### Vulnerabilities

Reading takes `viewer`; moving a finding through its lifecycle or reassigning it
takes `operator`; **accepting risk, marking a false positive and editing SLA
policy take tenant `admin`**, because each commits the tenant to something
rather than progressing one person's work. `POST /{id}/transition` answers `409` on an illegal move (the
request is well-formed; the refusal is about the finding's current state) and
`422` on a state that is not in the model. A finding in another tenant answers
`404`. The states, the SLA resolution order and the exception rules are in
[vulnerability-lifecycle.md](vulnerability-lifecycle.md).

**Two sources.** `GET /api/vulnerabilities?source=` narrows to `scan` (the
network scanner) or `endpoint_software` (a software→CVE match on a managed
endpoint); an unknown value is `422`. `POST /{id}/verify` answers `409` for
every `endpoint_software` finding: a port scan does not observe an installed
package, so a "machine verified" closure from one would be false. Those
findings are verified by their device's next accepted inventory snapshot — see
[software-cve-matching.md](software-cve-matching.md#lifecycle-tracked-findings).
**False positives.** `POST /api/vulnerabilities/{id}/false-positive` (admin)
closes a finding as never having been real and suppresses its re-opening for
`suppress_days` (1–365, default 90); `reason` is required and `evidence` is a
free-form object recording what the verdict was made on. It answers `409` when
the finding is already closed — the same illegal-move refusal as any other
transition — and `422` without a reason or with an out-of-range expiry.
`DELETE` on the same path takes only `operator`: withdrawing a suppression can
only put work back on the queue, and a control that is harder to release than
to apply is one people stop applying. It answers `409` when the finding carries
no verdict to withdraw, rather than a `200` for a call that changed nothing. See
[vulnerability-lifecycle.md](vulnerability-lifecycle.md#false-positives).

**Network exposure.** `GET /api/vulnerabilities?network_exposure=` narrows to
`external`, `internal` or `unknown` — where the finding sits relative to the
perimeter, as resolved when it was scored; any other value is `422`. `unknown`
also matches findings written before the signal existed, which store `NULL`:
those are the ones an operator most needs to see, so they are not filtered out
by asking for what is not yet known. `GET /api/vulnerabilities/summary` carries
the same split as `by_network_exposure_open` — open findings only, the three
keys always present and always summing to `open_total`.

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
| `GET /api/agents/{id}` | viewer | One agent, including heartbeat telemetry (OS, CPU, memory, disk, load, uptime), capabilities, `upgrade_requested`, and `other_agents_on_key` — how many other agents share its provisioning key, which is what `?revoke_key=true` below would stop; `404` outside the tenant |
| `PATCH /api/agents/{id}` | **admin** | Moves the agent between `active`, `disabled` and `quarantined` (`{"status": …, "reason": …}`), and answers the agent as it now stands. A non-`active` agent is refused job claims and result uploads with `403`; its heartbeat is still accepted so the reason reaches it. The state survives re-registration — a restart is not an appeal ([#308](https://github.com/onixus/Shapoclyack/issues/308)) |
| `DELETE /api/agents/{id}?revoke_key=false` | operator | Forgets the registration. It does **not** stop the remote process, and on its own it does **not** revoke anything: the host still holds its provisioning key and a live JWT, so it re-registers on its next heartbeat. `?revoke_key=true` revokes the key the agent registered with, which also invalidates the JWTs already minted from it. The response reports which happened — `provisioning_key_id: null, key_revoked: false` means there was no key on record (an agent registered before [#308](https://github.com/onixus/Shapoclyack/issues/308), or a legacy shared-token one) — and `other_agents_on_key` says how many *other* agents that revocation stopped |
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

**An agent token may only act as itself**
([#308](https://github.com/onixus/Shapoclyack/issues/308)). The JWT a
provisioning key is exchanged for carries an `agent_id`, and every agent route
that takes one from the caller — `agent_id` in the body of
`/api/agent/register`, `/api/agent/heartbeat` and `/api/endpoint/inventory`, in
the query string of `/api/agent/jobs/claim`, in the form of
`/api/agent/jobs/{id}/results` — now requires it to be the token's own, or
answers `403`. Before this the id was
checked only against the tenant, so one compromised agent could heartbeat as,
claim for and upload results as every other agent in the tenant, which for an
MSSP customer is its whole fleet. Registering with no `agent_id` uses the
token's rather than minting a random one, so a restarted agent comes back as
itself.

**And a valid key is not a right to be a particular agent.** The check above
runs after the token exists, which left the exchange itself open: `POST
/api/auth/agent/token` (and `/api/auth/exchange`) minted a token for whatever
`agent_id` was asked for. Two things followed from that, and both are now
`403` — a *different* status from the `401` a bad key gets, because the key is
fine and the identity is not available:

- **Impersonation by a peer.** A holder of any valid key in the tenant could
  ask for a live agent's id and get a token that passes every check above,
  rewriting that agent's hostname and labels. An `agent_id` already registered
  with a *different provisioning key that is still active* is refused.
- **Walking out of quarantine.** A `disabled` or `quarantined` agent could
  exchange for a token under a fresh id and register as a second, `active` row.
  The exchange now reads the lifecycle state and answers with the same sentence
  the claim does, so the agent's own loop recognises it and backs off.

Rotating a key is still one procedure and not a trap: **revoke the old key
first**, which already stops the JWTs minted from it, and the id is released to
whichever key re-provisions the host. An `agent_id` that has never registered
is always free — that is how every agent starts.

**The boundary this does not fix.** Two of them, and both are the shape of the
credential rather than an oversight:

- A legacy `OCTO_AGENT_TOKEN` agent has *no* identity to bind to — the shared
  token is one credential for every agent in the `default` tenant by
  construction — so it keeps behaving exactly as before, and the tenant check
  remains the only boundary it has. That is another reason the variable is
  deprecated and refused in `prod` from 2027-03-01
  (see [configuration.md](configuration.md)).
- **One provisioning key deployed to several hosts is one identity for all of
  them.** The exchange refuses a *different* key asking for an agent's id, but
  not the key that agent registered with — it cannot, because that is the same
  key the host itself re-exchanges on every refresh. Whoever holds a fleet key
  can therefore be any agent provisioned from it. Mint a key per host (`POST
  /api/tenants/{tenant_id}/provisioning-keys` is cheap, and the SSH deployment
  already does exactly that) where that matters.

**A verified signature is not the whole check.** Every authenticated agent
request re-reads two things from the database, so revocation lands at once
instead of after the token's remaining lifetime: the provisioning key behind
the token must still exist, be unrevoked and be unexpired (`401` otherwise),
and the agent row, when there is one, must belong to the token's tenant
(`403`). A *missing* row is not refused — the first request an agent ever makes
is the registration that creates it, and a deleted agent is indistinguishable
from a never-registered one. Making a delete permanent is therefore
`?revoke_key=true`, not the delete alone.

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

**Keys expire** ([#308](https://github.com/onixus/Shapoclyack/issues/308)). A
key minted from now on carries an `expires_at`, set at mint time from
`OCTO_PROVISIONING_KEY_TTL_DAYS` (90 days by default; `0` mints perpetual
keys). An exchange after that time answers `401`, with the same message as an
unknown or revoked key — presenting a guessed key learns nothing about which
half was wrong. The key list reports `expires_at` and an `expires_soon` flag,
`true` within 14 days of the expiry and `false` once the key is already expired
or revoked: those are conclusions, not deadlines.

**Keys minted before this are perpetual and stay perpetual** — `expires_at` is
`null` on every one of them and nothing back-dates it. Stamping a TTL onto keys
an operator was never told had one would strand whichever fleets are already
past it; expiring an old key is a deliberate revoke, and the list is what finds
the ones still carrying no expiry.

**Agent version, and the floor** ([#363](https://github.com/onixus/Shapoclyack/issues/363)).
The agent ships in the same release as the API and carries the same version, so
`latest_version` in `GET /api/agents/summary` is the app version and
`is_outdated` means "not on the current release". It used to be a separate
constant that no release ever produced, which reported every agent in every
installation as outdated and made `upgrade_requested` permanent — the flag
clears when the agent reports a *different* version, and no upgrade could reach
the version the constant wanted.

`OCTO_AGENT_MIN_VERSION` (empty by default) turns that reporting into a rule.
An agent below the floor is answered **`426 Upgrade Required`** on
`POST /api/agent/jobs/claim`, with the required version in the detail.
`register` and `heartbeat` keep working on purpose: a gated agent that
disappeared from `GET /api/agents` would be a host nobody can find to upgrade.
The heartbeat response carries `min_version`, `upgrade_required` and a
human-readable `upgrade_message`, which is the only channel that reaches a
running agent — `agent/worker.py` logs it once per change rather than once per
poll. Note the two are different questions: `upgrade_requested` is an
operator's wish recorded by `POST /api/agents/{id}/upgrade`, `upgrade_required`
is the installation's floor and is what refuses work.

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
| `POST /api/webhooks` | admin | `422` on a malformed URL, an unknown event kind or severity, a target resolving to a non-public address, a missing ticket `transport_config`, or the per-tenant limit. The generated `secret` is in this response only (webhook transport). Ticket transports take `secret` as the tracker token and do not HMAC. `event_kinds` accepts the five asset kinds, `audit.*` (the whole administrative trail) and one exact `audit.<action>`, e.g. `audit.user.role_change` ([#328](https://github.com/onixus/Shapoclyack/issues/328)); an empty list still means every *asset* kind — the trail is opt-in, so an existing unfiltered subscription does not start receiving it on upgrade — and `min_severity` does not apply to audit kinds |
| `PATCH`/`DELETE /api/webhooks/{id}` | admin | `PATCH` also takes `secret` — the only way to rotate a tracker API token — and never echoes it back; an empty string clears signing. Deleting takes that subscription's delivery history with it |
| `POST /api/webhooks/{id}/rotate-secret` | admin | Returns the new HMAC secret once. `409` on a ticket transport: a random value is an HMAC key, not a tracker token, so PATCH `secret` instead |
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

## Operational endpoints

Outside `/api`, unauthenticated by default and deliberately outside the
console's RBAC: a probe runs before anything can log in.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /livez` | none | Liveness. `200 {"status":"ok"}` with no dependency touched at all — it answers "should this process be restarted", and restarting every replica is not how an unreachable database gets fixed |
| `GET /readyz` | none | Readiness. `200 {"status":"ok","checks":{…}}` while every **configured** dependency answers. Postgres answers `SELECT 1`, NATS completes a round trip, ClickHouse answers a query; NATS and ClickHouse are named only where their URL is set, since an absent sidecar is not a failing one. Only Postgres and NATS decide the status code — `503 {"status":"degraded",…}` when either is down. ClickHouse is advisory: it is a single pod with no PDB, so a `200 {"status":"degraded",…}` names it without taking every replica out of the Service at once |
| `GET /api/health` | none | The console-facing form of the same sweep: `version`, `nats`, `clickhouse`, the ingest worker's counters, `sso`, and since [#331](https://github.com/onixus/Shapoclyack/issues/331) a `checks` map and a `status` of `ok` / `degraded` that reflects it. **Always `200`** — clients parse the body, and both container `HEALTHCHECK`s point here |
| `GET /metrics` | none, or bearer | Prometheus exposition. Open unless `OCTO_METRICS_TOKEN` is set; with it, anything but `Authorization: Bearer <token>` is `401` and the token is compared in constant time ([#319](https://github.com/onixus/Shapoclyack/issues/319)) |
| `GET /docs`, `/redoc`, `/openapi.json` | none | The interactive schema, **mounted only when `OCTO_API_DOCS=enabled`** — the default under `OCTO_ENV=dev` and not under `prod`. Disabled, the routes do not exist rather than being guarded |

Neither `/livez`, `/readyz` nor `/metrics` appears in the OpenAPI schema: they
are how the platform is operated, not API surface a client programs against.
Keep all of them off the public Ingress. `examples/ingress.example.yaml`
publishes the API under a `/` prefix and therefore reaches them: the snippet
documented in that file refuses the three at the edge.

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

## Scan surface

Every scan is classified as **external** (internet-facing: domains and public
address space) or **internal** (RFC1918, loopback, link-local, RFC6598 shared
space, IPv6 ULA/link-local/loopback), and **mixed** when its targets are both.
The classification is derived from the targets at the moment the job is
created; `POST /api/jobs` and the schedule endpoints also accept an explicit
`surface` (`external` | `internal` | `mixed`) in the body, which wins over the
derived value — a tenant whose internal estate is a block of public addresses
is not wrong, and no address-based rule can know that.

It is stored on the job's `scan_options` and, once the run lands, in the run's
`tenant.json` marker; no column and no migration. `JobInfo.surface` and
`RunSummary.surface` mirror it at the top level.

Which of the two produced the value is recorded alongside it, as
`JobInfo.surface_source` (`operator` | `derived`, `null` when there is no
surface at all). Risk scoring treats only an operator-*declared* external scan
as network-exposure evidence: a derived surface is the address-space rule read
back, and scoring it would turn a routing fact into a decision.

| Where | Field / parameter |
|---|---|
| `POST /api/jobs`, `POST`/`PATCH /api/schedules` | `surface` in the body (optional) |
| `GET /api/jobs`, `GET /api/runs` | `surface=external\|internal\|mixed\|unknown` |
| `GET /api/jobs/{id}`, `GET /api/jobs` items | `surface` and `surface_source` (may be `null`) |
| `GET /api/jobs/summary` | `by_surface` counts per surface |
| `GET /api/runs` items | `surface` (may be `null`) |

`null` — selected by `surface=unknown` — is "not recorded", not a fourth
surface: jobs and runs created before this shipped carry nothing, and neither
does a scan of the server's default input files, whose contents the API never
reads. The four values therefore partition each list, so no job or run is
invisible under every filter.

On runs the filter reads one small `tenant.json` per run before slicing, the
same cost class as the tenant filter, and it is paid only when asked for.

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
POST   /api/users                               # admin  {"username","password","role","email"?}
PUT    /api/users/{username}/password           # admin — reset, no old password needed
PUT    /api/users/{username}/role               # admin
PUT    /api/users/{username}/email              # admin  {"email": …, "verified": bool}
PUT    /api/users/{username}/disabled           # admin  {"disabled": true}
DELETE /api/users/{username}                    # admin
POST   /api/users/{username}/sessions/revoke-all # admin — sign that account out everywhere
POST   /api/auth/password                       # any role — change your own
```

Disabling, demoting and resetting a password already end that account's
sessions (see [Sessions, logout and revocation](#sessions-logout-and-revocation)).
`POST /api/users/{username}/sessions/revoke-all` is for the case where none of
those is the right answer — a laptop left in a taxi, a token pasted into a chat
— and the account should simply start over.

`POST /api/auth/password` re-verifies the current password even though the
caller already holds a valid token: a token proves "can act as this user right
now", which a stolen one also proves; the password proves rather more.

No response carries a password or a hash — `UserInfo` has no field for one.

`email` on `POST /api/users` is written in the same transaction as the account,
so a rejected address (one another account already uses — `422`) leaves no
half-created user. It is always stored **unverified**: `verified` is what makes
an account linkable to an SSO identity by address, and that stays the separate,
deliberate `PUT /api/users/{username}/email`.

`UserInfo` carries `tenants` — the tenant ids this account holds an explicit
membership row in, sorted — and `is_platform_admin`. An empty `tenants` never
means "no access": a platform admin acts in every tenant without a grant row,
and an account with no rows keeps pre-P0 access to `default` (see
[Tenant memberships](#tenant-memberships)). `GET /api/users` fills them for the
whole list in one query.

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
a syntax check (#226). All three endpoints are platform admin, for the same reason
provisioning-key creation is (#231): deciding that a tenant may scan a network
is an administrative act, and an operator who could widen their own scope
would be the control removing itself.

```http
GET /api/tenants/{tenant_id}/scan-scope
PUT /api/tenants/{tenant_id}/scan-scope   {"entries": [{"effect": "allow", "kind": "cidr", "value": "203.0.113.0/24"}]}
GET /api/tenants/{tenant_id}/promoted-domains   # related domains the tenant's operators promoted under that scope
```

The tenant's own view of the same list is tenant-scoped rather than admin:
`GET /api/promoted-domains` (viewer) and `DELETE /api/promoted-domains/{domain}`
(operator, the role that promotes). The undo is keyed on the tenant and needs no
run — the run that proposed a domain expires with retention, the promotion does
not. Both directions are journalled as `trust_change` events
(`promoted_domain_added` / `promoted_domain_withdrawn`) with the actor, like
the SSH host-key pins.

```http
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

## Maintenance windows and the change freeze

The approved scope above says *what* a tenant may scan. The calendar says
*when* ([#352](https://github.com/onixus/Shapoclyack/issues/352)). Until it
existed, honouring a customer's change window meant an operator disabling the
schedules by hand and remembering to switch them back on.

```http
GET    /api/maintenance-windows            # operator: the calendar + the verdict right now
POST   /api/maintenance-windows            # tenant admin
PATCH  /api/maintenance-windows/{id}       # tenant admin
DELETE /api/maintenance-windows/{id}       # tenant admin
GET    /api/change-freeze                  # operator
PUT    /api/change-freeze  {"change_freeze": true, "note": "migration weekend"}   # tenant admin
GET    /api/tenants/{tenant_id}/maintenance-windows   # platform admin: one customer's calendar
```

**Tenant admin, not platform admin** — the opposite of the scan scope. A scope
is the provider deciding what a customer may aim the platform at; a calendar is
the customer's own operational knowledge, and a control they have to raise a
ticket for is a control that gets bypassed by disabling the schedules instead.
A platform admin still reaches any tenant with `?tenant_id=`, and reading the
calendar is `operator` because somebody about to press *start scan* should be
able to see why it will be refused.

A window carries a `kind` (`blackout` — no scan may start while it is open;
`allowed` — scans may start **only** while one is open, so a single such window
turns the tenant opt-in), an IANA `timezone`, a wall-clock `dtstart_local`
carrying **no offset**, `duration_minutes`, and an RFC 5545 `rrule` restricted
to a documented subset. `scope_kind` is `tenant` or `asset_group`; a group is
named by `asset_group` and defined by the CIDRs and domains in `scope_targets`,
which are matched against a scan's targets *by overlap*. A scan with no explicit
targets runs on the installation defaults and is covered by every window of its
tenant — the control plane cannot tell what it will touch, and a blackout that
could be dodged by leaving the target boxes empty is not a blackout. The subset,
the DST rules and the operator's procedure are in
[operations.md](operations.md#maintenance-windows-and-the-change-freeze).

`GET /api/maintenance-windows` answers the list and the verdict in one
response — `admission.allowed`, its `reason`
(`maintenance_blackout` / `outside_allowed_window` / `change_freeze`), the
window that refused and the `retry_at` it lifts at — because a console showing
the banner and the table from two requests can show them disagreeing.

### What the calendar refuses, and how

A scan the calendar forbids is **`409`, with `Retry-After` when the block has a
knowable end**. Neither `403` (the caller is entitled to this scan) nor `429`
(they have asked for nothing too often): the tenant's own state forbids it, and
that state changes. Under a change freeze the header is deliberately absent —
a freeze ends when somebody lifts it, and a retry time there would be an
invention an integration would believe. Every refusal is checked inside
`jobs_service.start_scan`, so the route, the recurring dispatcher and the
platform's own re-scans are held to the same calendar; a verification re-scan
is **not** exempt the way it is from the quota, because it still reaches the
customer's network.

The check runs when a scan is **accepted**. In agent execution mode the job
then waits in the queue, and `claim_job` does not re-check the calendar: a
worker that was busy at 21:50 can claim that job at 22:30, inside a blackout
that opened at 22:00. Admission is a control over what the platform accepts,
not a kill switch over queued work — see
[operations.md](operations.md#maintenance-windows-and-the-change-freeze).

A blocked *schedule* is deferred, not dropped: `next_run_at` moves to the
moment the block lifts, so a nightly scan blacked out tonight runs when the
window closes. A freeze has no such moment, so the schedule advances by its own
cadence instead — which keeps the dispatcher from re-refusing the same tick
every 30 seconds for as long as the freeze lasts. Neither writes `last_run_at`:
no scan ran.

## Usage metering and quotas

An MSSP sells capacity — "up to 2,000 assets, 40 scans a month" — and Track E
makes that number readable and enforceable. Two properties of the design show
through the API and are worth stating before the routes.

**Usage is counted, never accumulated.** There is no `used` column anywhere:
assets are counted from `assets` and scans from `jobs` at the moment of the
read. A counter row would eventually disagree with the asset list the same
customer is looking at, and in that argument the customer is right and the
invoice is wrong.

**Quotas fail open; the approved scan scope does not.** Migration `0025`
grandfathered every tenant into an explicit allow-all because an absent scope
must never mean "scan anything". Migration `0030` inserts nothing at all, on
purpose: a tenant with no `tenant_quotas` row inherits the platform default,
which ships as unlimited. A scope is a security boundary and a quota is a
commercial one — refusing customers' scans after an upgrade because nobody had
yet typed a number would be an outage caused by billing.

### Reading the meter

```http
GET /api/usage?history_months=12
```

Viewer, and single-tenant like every other tenant-scoped read: the tenant is
resolved server-side from the caller. This is the customer's own view of their
consumption, deliberately not admin-gated — a number the person doing the work
cannot open is a number that gets estimated in a slide at renewal.
`history_months` is `1..36` (default `12`); anything else is `422`.

```json
{
  "tenant_id": "acme",
  "period_start": "2026-09-01T00:00:00",
  "period_end": "2026-10-01T00:00:00",
  "quota_source": "tenant",
  "enforced": true,
  "note": "Renewal 2027-01, 2k assets",
  "updated_at": "2026-08-14T09:12:33",
  "updated_by": "platform-admin",
  "assets": {"used": 1840, "limit": 2000, "remaining": 160, "used_ratio": 0.92, "over_limit": false},
  "scans":  {"used": 31, "limit": 40, "remaining": 9, "used_ratio": 0.775, "over_limit": false},
  "scan_history": [{"month": "2025-10", "scans": 0}, {"month": "2025-11", "scans": 18}]
}
```

- The period is one **UTC calendar month**, `[period_start, period_end)`, because
  that is what a contract says and what an invoice covers. A rolling 30-day
  window would make "how many scans do I have left this month" unanswerable
  without a chart.
- `quota_source` is `tenant` when somebody wrote a row for this customer and
  `default` when they merely inherited the platform setting. The distinction
  matters most when the answer is "unlimited", because only one of the two is a
  decision.
- `enforced` mirrors `OCTO_QUOTA_ENFORCEMENT_ENABLED`. Metering always runs; a
  provider that has not switched enforcement on is looking at consumption
  without refusing anything.
- **`limit: null` means unlimited**, and then `remaining` and `used_ratio` are
  `null` too — the same rule the Adoption page follows. A share with nothing to
  divide by is `null`, never `0` or `1`: a bar at 0% against no limit reads as
  "plenty left" and one at 100% reads as an outage.
- `scan_history` is oldest-first and includes **empty months as zeroes**. A gap
  a chart has to guess at is how a customer's quiet quarter becomes a missing
  bar somebody reads as missing data.

What counts: assets in status `active` or `stale` (a `decommissioned` asset is
inventory history, not capacity in use — billing for it would make deletion the
customer's only way to stop paying for a machine they already retired), and
jobs by `queued_at`, so a job still sitting in the queue counts. A limit that
only counted finished scans could be walked past by starting a thousand.

```http
GET /api/usage/tenants
```

Platform admin. The provider's side of the same meter: every tenant's
consumption in the current period, so "who is near their limit" does not
require opening twelve customers in turn. Returns `period_start`, `period_end`
and `tenants[]`, each row `tenant_id`, `name`, `status`, `quota_source` and the
same `assets`/`scans` shapes. Rows are sorted by display name.

### Setting a limit

```http
GET /api/tenants/{tenant_id}/quota
PUT /api/tenants/{tenant_id}/quota   {"max_assets": 2000, "max_scans_per_month": 40, "note": "Renewal 2027-01"}
```

Platform admin, for the reason scan-scope approval is: a tenant operator who
could raise their own quota is the control removing itself. `PUT` replaces
whatever applied before and stamps the caller and the moment on the row, so
"who sold them 5,000 assets" has an answer that is not a memory. An unknown
tenant is `404`; a value outside `0..10000000` (assets) or `0..1000000`
(scans), or a `note` over 500 characters, is `422`.

`null` — or `0`, accepted as the same thing — is **unlimited**. Both fields are
spelled explicitly rather than by omission: a `PUT` that dropped a limit because
a client forgot to send the field would be a silently widened contract. A stored
row wins over the platform default *including when its columns are null*, which
is how one customer is exempted from a default everybody else is metered
against, rather than by turning metering off globally. `DELETE
/api/tenants/{tenant_id}/quota` (204, platform admin) drops the row and returns
the tenant to `quota_source: "default"` — deliberately distinct from a `PUT` of
nulls, which stores "unlimited *for this tenant*" and keeps that answer when
the platform default later changes.

### What a quota refuses, and how

Scans are refused **at admission**, inside `jobs_service.start_scan` rather
than in the route, because the recurring-scan dispatcher and every other caller
reach that function and none of them reach the route — a quota only one entry
point honours is not a quota.

```http
POST /api/jobs   →  429 Too Many Requests
Retry-After: 1209600
{"detail": "Scan quota reached for tenant acme: 40/40 scans this month; resets 2026-10-01"}
```

**`429`, not the `403` an out-of-scope scan gets.** A scope refusal is a
standing fact; this one stops being true on its own, so the answer can say
when. `Retry-After` is the seconds remaining until the period rolls over, and
an integration that already retries on `429` does the right thing without being
taught anything about quotas. Verification re-scans
([#183](https://github.com/onixus/Shapoclyack/issues/183)) are exempt: refusing
the machine check that closes a finding would strand it in `VERIFYING` and turn
a billing limit into a correctness bug. The exemption travels on the job
(`jobs.quota_exempt`), stamped by the caller that dispatches the scan, and such
a scan is left out of the count as well as out of the refusal. It is
deliberately not keyed on a username: the verification path carries the
*analyst's* name into the dispatch, so a name-based exemption would never fire
for the one case it exists for — and a console account someone named
`system:verification` would inherit an unlimited quota.

Assets are capped **at ingest**, and an asset quota never fails a scan. The
ingest path asks how many *new* assets it may create and honours the answer
partially: assets that already exist keep getting this run's data, and only
newly discovered hosts are dropped (`quota_skipped` in the upsert stats).
Refusing the whole result set would throw away findings for the assets inside
the quota as well, which punishes the wrong thing. An endpoint-inventory
snapshot from an agent is accepted for the same reason — the device is left
`reconciliation_status: "unlinked"` and links itself on a later submit once the
limit is raised, because losing software and patch data over a *registry* limit
is not a trade anybody asked for.

That refusal is the one in this feature nobody sees interactively: the operator's
scan succeeded and some discovered hosts are simply not in the inventory. It is
therefore loud where machines look — a `WARNING` naming the tenant and the
count, and `octo_quota_denied_total{resource="assets"}`. The scan refusal
increments the same counter with `resource="scans"`.

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
- prefer a **service token** over a human account: it is scoped, it expires,
  and revoking it locks nobody out (see [Service tokens](#service-tokens));
- never log bearer tokens, service tokens or provisioning keys;
- treat `429` and dependency `503` responses as retryable only with bounded
  backoff.
