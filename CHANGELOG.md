# Changelog

All notable changes to Shapoclyack are documented in this file.

## Unreleased

### Security

- **Named permissions, an auditor role, and a tenant admin that is not the
  platform admin** ([#318](https://github.com/onixus/Shapoclyack/issues/318)).
  Three ranked roles could not express "reads the audit trail and writes
  nothing" or "approves what we may scan but runs no scans", and every
  tenant-administration route belonged to the global admin alone. A role now
  carries a set of named permissions alongside its rank (`api/core/permissions.py`,
  published by `GET /api/rbac/permissions` and `GET /api/rbac/roles`, seeded by
  migration 0049), and five roles join the original three: `auditor`,
  `scan-operator`, `scope-approver`, `token-admin` and `risk-approver` (defined
  for #348; the approval workflow itself is not implemented here). The existing
  three keep exactly the authority they had, so no administrator has to do
  anything after the upgrade. A tenant's own admin now manages its members,
  provisioning keys and service tokens and reads its quota and scope, while
  approving the scope (`scan_scope.approve`) and changing the quota stay
  platform admin — an administrator who could widen their own scope is the
  control removing itself. `GET /api/config` needs `config.read`, so a viewer
  no longer reads the installation's scanning posture, and the cross-tenant
  counters in `GET /api/system` need `platform.fleet.read`. A suspended tenant
  now refuses its people and not only its agents — including in
  `GET /api/tenants` and `GET /api/tenants/posture`, which resolve their own
  tenant set and so had kept answering with a suspended tenant's risk metrics.
  The word for that state is **`suspended`** everywhere: the column, the
  `TenantInfo` schema, the refusal and the docs. `disabled` is an account and an
  agent, never a tenant, and the `TenantInfo` literal that still said so turned
  the console's tenant switcher into a `500` the moment anything wrote the real
  value. `GET /api/auth/me` now takes `tenant_id` and echoes `scoped_tenant`,
  so `tenant_role`/`permissions` describe the tenant the console is acting in
  rather than always the default one — the console re-reads the principal when
  its switcher moves, and `/service-tokens` is gated on
  `tenant.credential.manage` instead of on the global admin role, which had
  hidden the page from the tenant admins and token-admins it is for.
  **Custom roles per tenant are not implemented** — the schema and the read
  side hold them, there is no way to create one — so #318 stays open, and the
  console's own copy of the role table means the five new roles can only be
  granted over the API.

- **A `token-admin` can no longer mint a credential stronger than itself**
  ([#318](https://github.com/onixus/Shapoclyack/issues/318)). Handing
  `tenant.credential.manage` to a rank-1 role opened an escalation with it:
  `POST /api/tenants/{id}/service-tokens` took the requested `role` on trust,
  so an account that could not start a scan could issue itself a `role: admin`
  service token and then start one — plus assets, reports, webhooks and
  wordlists — with a credential that needs no password and outlives the session
  that minted it. The requested role is now capped at the caller's own role in
  that tenant, on rank *and* on permission set, and over the cap is a `403`. A
  tenant `admin` keeps the whole ladder and a platform admin has no cap.
- **Run alerts and the DefectDojo bulk export are per tenant, not per
  installation** ([#351](https://github.com/onixus/Shapoclyack/issues/351)).
  The scanner's alert stage read `OCTO_SLACK_WEBHOOK` / `OCTO_TELEGRAM_*` /
  `OCTO_SMTP_*` and the bulk export read `OCTO_DEFECTDOJO_*` — installation-wide
  values, at a point in the pipeline that held no tenant id — so on an MSSP
  installation every tenant's scan announced itself in one Slack channel and
  every tenant's findings were imported into one DefectDojo product. A new
  `notification_channels` table (migration `0047`) holds destinations per tenant
  — `slack`, `msteams`, `mattermost`, `email` and `defectdojo` — managed at
  `/api/notification-channels` (reads `operator`, writes `admin`, audited), and
  the API announces a finished run to *that tenant's* channels only. Credentials
  are envelope-encrypted under #310 (a chat incoming-webhook URL *is* a
  credential, so it lives in `secret`, not in a plaintext column) and are
  covered by `python -m api.db.reencrypt_secrets`. Chat and DefectDojo sends go
  through the webhook SSRF boundary; email uses the tenant's recipients over the
  installation's `OCTO_REPORT_SMTP_*` relay.
  **Breaking:** the global variables and the config file's `alerts:` /
  `defectdojo:` sections are now honoured **only** when
  `OCTO_SINGLE_TENANT_ALERTS=true` — kept rather than deleted because the
  standalone scanner CLI has no API and no database, and that is the
  installation for which they were never wrong. Otherwise both stages skip with
  `skipped_reason: multi_tenant_use_notification_channels` without opening a
  connection. Migration steps are in docs/configuration.md § Notification
  channels. Not done: no console UI (API only), no Telegram channel kind, and a
  channel send is not queued or retried — a failed DefectDojo import waits for
  the next scan.
  Two more limits worth knowing before the migration steps are followed. Only
  runs the API knows about are announced: a `k8s/shapoclyack/base/cronjob.yaml`
  scan creates no job row, so it reaches no channel and the installation-wide
  stages remain its only alerting — `OCTO_SINGLE_TENANT_ALERTS` is read by the
  *scanner* process and belongs on that CronJob, not on the API Deployment.
  And only a **succeeding** run is announced, where the scanner stage fired on
  any outcome; a failed scan going unannounced is left to the `scan_failed`
  event in [#349](https://github.com/onixus/Shapoclyack/issues/349) rather than
  being a second notification path here.

- **Review fixes on #351, before it went anywhere near a release.** A review of
  the change above found five things worth naming. *(1)* The route was the only
  place the tenant boundary was checked on a channel's GET/PATCH/DELETE, and no
  test covered it — a mutation deleting the check passed the entire suite. There
  is now a cross-tenant route test (and one for `webhook_subscriptions`, whose
  template this was copied from and which had the same hole), and
  `channels.update_channel` / `delete_channel` take the tenant as part of their
  predicate, so the boundary has two layers. *(2)* The fan-out ran
  synchronously inside `async def upload_results`, and *before* the job's
  status was written: three channels whose receiver drops packets blocked the
  API's event loop for the full per-channel budget each, which is a failed
  liveness probe and an agent being told 409 for an upload that landed. It now
  runs on a background thread, started after the status write. *(3)* A missing
  or truncated `vulnerabilities.json` was reported as `skipped: no findings ≥
  high` with `ok=True` — indistinguishable, in `last_status`, from a clean
  tenant. It is an `error` now. *(4)* `OCTO_SINGLE_TENANT_ALERTS` was
  documented in the API's variable table although only the scanner reads it, and
  the migration steps told operators to clear `shapoclyack-alerts` without
  saying that CronJob scans get no channels in exchange; both are stated now,
  and the key is in the example Secret. *(5)* `email` ignored
  `OCTO_NOTIFICATION_CHANNEL_TIMEOUT_SECONDS` and used the report relay's
  timeout instead; it takes the documented budget.

- **A console account can carry a second factor, and an admin role can be made
  to** ([#315](https://github.com/onixus/Shapoclyack/issues/315)). A local
  administrator — the account that mints service tokens, approves scanning
  scopes and deploys agents onto somebody else's network — was protected by one
  password, and the trail could only record that the right password had been
  presented. TOTP (RFC 6238, HMAC-SHA-1, six digits, thirty seconds) is now
  enrolled per account through `POST /api/auth/mfa/totp/setup` and `…/confirm`,
  which issues ten single-use recovery codes, hashed like passwords and shown
  once. A code is accepted within ±1 step and **spent** — the step is written in
  the same transaction, so an observed code cannot be replayed inside its own
  thirty seconds. The shared secret is stored envelope-encrypted under its own
  context (#310) and is covered by `python -m api.db.reencrypt_secrets`.
  Implemented without a new dependency and verified against the RFC 6238
  Appendix B vectors. WebAuthn / passkeys, the other half of the issue, are
  **not** implemented and #315 stays open for them.
- **Logging in as an enrolled account is two legs**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)).
  `POST /api/auth/login` answers `mfa_required` with a five-minute `typ=mfa`
  challenge token and **no** session token; `POST /api/auth/mfa/verify`
  exchanges it plus a code (or a recovery code) for the ordinary session.
  `decode_token` now allowlists `typ=user`, so the challenge authenticates
  nothing else. Refused codes go through the existing login limiter under the
  account's own key and land in `auth_events` as `reason=mfa_failed`.
- **`OCTO_MFA_REQUIRED_ROLES` makes a second factor mandatory for a role**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)). Empty by default,
  so an upgrade changes nothing. An account in a listed role that has not
  enrolled still signs in — refusing would leave nobody able to enrol — but its
  session is `mfa_pending` and is answered `403` on everything except the MFA
  routes, `/api/auth/me` and the two ways out. The console shows a banner and
  sends such a session to the new `/security` page. `mfa_pending` is derived per
  request from the policy and the account row rather than carried as a claim, so
  turning the policy on reaches sessions that predate it and finishing an
  enrolment lifts the confinement without a sign-out.
- **Step-up on the operations that issue a credential**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)). Creating or
  revoking a service token or a provisioning key, and replacing a tenant's scan
  scope, now require a second factor proved within `OCTO_MFA_STEPUP_MINUTES`
  (15) — as do creating an account, setting somebody's password, changing a role
  setting a verified address and resetting somebody's MFA, each of which is
  otherwise a one-request way to end up holding an admin account that carries no
  factor. Only for accounts that have MFA enabled, so an installation that has
  not adopted it is unchanged. A service token cannot be challenged and is
  exempt, so the routes behind step-up are refused it by scope instead —
  `agent` joins `config` in `FORBIDDEN_WRITE_RESOURCES`, which closes
  `POST /api/agent/deployment-command` (a provisioning key) to service tokens.
  The console raises a code dialog on that 403 wherever it happens.
- **SSO is not a way around the second factor**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)).
  `GET /api/auth/oidc/callback` challenges an enrolled account exactly as
  password login does, putting `mfa_token` in the redirect fragment where the
  session would have been. Its response model is now the same `LoginResponse`,
  on which `access_token` is nullable.
- **Enrolling a second factor costs the account's password**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)).
  `POST /api/auth/mfa/totp/confirm` verifies it, symmetrically with `disable`:
  without that, a stolen session could enrol its own authenticator and lock out
  an owner who still knows the password. Skipped for an account that cannot be
  asked for one — provisioned by the identity provider, or one whose password
  `OCTO_LOCAL_LOGIN` no longer accepts. Both checks run inside the login limiter
  and land in `auth_events`, so neither endpoint is a password oracle for a
  stolen session.
- **Password login on an SSO installation is a decision, not a default**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)). `OCTO_LOCAL_LOGIN`
  is `enabled` (as before), `break-glass` (only `OCTO_BREAK_GLASS_USERS`) or
  `disabled`. A break-glass login is audited as `auth.break_glass_login`,
  recorded in `auth_events`, counted in `octo_break_glass_logins_total` and
  logged at WARNING — four sinks, because the value of an emergency account is
  in it being noticed. Refusals answer the same `401 Invalid credentials` a
  wrong password does; the *mode* is public in `GET /api/auth/sso`, the account
  names are not. Inert when no identity provider is configured.
- **An admin can clear a lost second factor**
  ([#315](https://github.com/onixus/Shapoclyack/issues/315)).
  `POST /api/users/{username}/mfa/reset` (platform admin) deletes the secret and
  the recovery codes and bumps `token_version`, ending every session that
  account has open — including any opened by whoever has the phone. Its own
  audit action, `user.mfa_reset`, and its own button on `/users`.

- **An agent token can only act as the agent it was minted for**
  ([#308](https://github.com/onixus/Shapoclyack/issues/308)). The `agent_id` in
  an agent JWT was never compared with the one in the request — body, form or
  query string — only the tenant was, so a token lifted off one worker could
  heartbeat as, claim jobs for and upload results as every other agent in that
  tenant, which for an MSSP customer is its whole fleet. All four agent routes
  now answer `403` for a mismatch — including `POST /api/endpoint/inventory`,
  which a quarantined host was otherwise still free to feed — and registering
  without an `agent_id` uses the token's own rather than minting a random one.
  The binding starts one step earlier than the register: `POST
  /api/auth/agent/token` refuses (`403`) to mint a token for an `agent_id` that
  belongs to another tenant, to an agent registered with a *different key that
  is still active*, or to a `disabled`/`quarantined` agent. Without that, a
  holder of any valid key in the tenant could take a live agent's identity, and
  quarantine lasted only until the host restarted and asked for a fresh id.
  Revoking the old key releases the id, which is the documented rotation order.
  A legacy `OCTO_AGENT_TOKEN` agent has no identity to bind to and is
  unchanged — one more reason that variable is deprecated.
- **Agents can be disabled or quarantined, and it survives a restart**
  ([#308](https://github.com/onixus/Shapoclyack/issues/308)). New
  `PATCH /api/agents/{id}` (tenant **admin**) moves an agent between `active`,
  `disabled` and `quarantined`, with a reason that reaches the agent itself.
  A non-`active` agent is refused job claims and result uploads with `403` and
  cannot re-register its way back to `active`; its heartbeat is still answered,
  so it learns why and backs off to one poll every five minutes instead of one
  per second. The state is a new column and does not disturb the reported
  `idle`/`busy`/`error` status. Shown, and settable, in the agent drawer on
  `/agents`.
- **Deleting an agent can now revoke its credential**
  ([#308](https://github.com/onixus/Shapoclyack/issues/308)).
  `DELETE /api/agents/{id}` removed the row and nothing else: the host kept its
  provisioning key and a JWT valid for up to two hours, and re-registered on
  its next poll, so "delete" was a pause. `?revoke_key=true` revokes the key the
  agent registered with — a link that is now recorded — and the response reports
  whether anything was revoked rather than implying it. Both the response and
  `GET /api/agents/{id}` carry `other_agents_on_key`, the number of other agents
  that revocation would stop, and the drawer puts it in front of the operator
  when the checkbox is ticked rather than in the answer afterwards. Every authenticated
  agent request re-checks its provisioning key against the database, so
  revoking a key (by this route or the tenant one) stops the JWTs already
  minted from it at once instead of after their remaining lifetime.
- **Taking an agent out of the fleet is in the audit trail**
  ([#308](https://github.com/onixus/Shapoclyack/issues/308),
  [#327](https://github.com/onixus/Shapoclyack/issues/327)). The lifecycle
  routes above recorded their change in a log line, which is the record that is
  gone with the pod. `PATCH /api/agents/{id}` now writes `agent.disable`,
  `agent.enable` or `agent.quarantine` — one action per resulting state, so
  "who took this host out of the fleet" is a filter rather than a read — and
  `DELETE /api/agents/{id}` writes `agent.delete` with the hostname, the
  lifecycle state and the `provisioning_key_id` that went with it. Each is
  written **in the transaction that makes the change**, like every other action
  in the trail; with `?revoke_key=true` a second row, `provisioning_key.revoke`,
  follows under the same actor and `X-Request-Id`, because the key is a
  separate resource that outlives the agent. `agent.register` also records
  which key bought the place in the fleet. The console's `/audit` filter lists
  the four new actions.
- **Provisioning keys expire** ([#308](https://github.com/onixus/Shapoclyack/issues/308)).
  New `OCTO_PROVISIONING_KEY_TTL_DAYS` (default `90`, `0` = perpetual) stamps
  `expires_at` at mint time; an exchange after it answers `401`, and the key
  list carries `expires_at` and an `expires_soon` flag. **Keys minted before
  this stay perpetual** — nothing back-dates them, because a deadline nobody was
  told about would strand whichever fleets are already past it; the list is how
  they are found and rotated.
  Migration `0039_agent_status_key_expiry` (expand only, nothing backfilled).
  Registration, lifecycle changes, deletion and key revocation are logged with
  their fields today; the audit trail
  ([#327](https://github.com/onixus/Shapoclyack/issues/327)) will pick them up.

- **The agent keeps one identity for its whole life, and refusals back off**
  ([#308](https://github.com/onixus/Shapoclyack/issues/308)). `agent/worker.py`
  exchanged its provisioning key without naming an `agent_id`, so the server
  minted a random one into the token and the register that followed — carrying
  the `OCTO_AGENT_ID` the installer always writes — was refused as
  impersonation. Registration sat outside the loop's error handling, so that
  `403` killed the process and `Restart=always` repeated it every five seconds.
  The id is now sent on every exchange including the periodic refresh, adopted
  from the first exchange when the deployment sets none, and registration
  happens inside the loop: a refused agent — quarantined, disabled, or holding
  a rejected token — waits out the same five-minute backoff every other refusal
  gets, and keeps heartbeating so it stays visible in the fleet view. A claim
  refused over NATS now reaches that backoff too, and NAKs the offer so another
  agent in the tenant can take it, instead of being swallowed as a reconnect.

- **An administrative audit trail, and one the application cannot edit**
  ([#327](https://github.com/onixus/Shapoclyack/issues/327),
  [#329](https://github.com/onixus/Shapoclyack/issues/329)). Creating,
  promoting, disabling and deleting an account; granting and revoking a
  membership; minting and revoking a service token or a provisioning key; a
  password reset and a self-service rotation; an agent's first registration; a
  report download; a scan scope replaced; a config override changed — each is
  now a row in `audit_events` with the actor, what kind of principal it is, the
  resolved client address, the user agent, the request's `X-Request-Id`, and the
  resource before and after the change. Every action that is itself a database
  write records **in the transaction that makes the change**, so a change
  without a record and a record without a change are both impossible;
  `report.download` is the one exception, because a file read has no transaction
  to join and its row is committed before the stream starts. Every
  credential-shaped field (`password`, `*_hash`, `token`, `*_secret`, `*_key`)
  is replaced by `[redacted]` before storage. `GET /api/audit` reads it back —
  admin *in the tenant*, never a service token, filters on actor/action/resource
  and a time window, and `?format=csv|ndjson` streams every matching event
  rather than the page. Migration `0037_audit_events` makes the table
  append-only in Postgres: triggers refuse every `UPDATE`, `DELETE` and
  `TRUNCATE`, and the only way past them is `audit_events_prune`, a `SECURITY
  DEFINER` function the recommended `GRANT` layout in `docs/operations.md`
  withholds from the API's role. That layout — which includes moving the table
  off the API's role with `ALTER TABLE … OWNER TO` — is what makes the trail
  proof against the API's *credentials* rather than only against its bugs; the
  shipped `k8s/` base runs both as one role, and the docs now say so. Retention
  is a separate privileged job, `python -m api.services.audit_retention --days
  365` (`OCTO_AUDIT_EVENT_RETENTION_DAYS`), with a CronJob example in
  `k8s/shapoclyack/examples/audit-retention-cronjob.example.yaml`. The console
  gets `/audit` — the same list with the filters and the two export buttons.
  Login attempts stay in `auth_events` and are not mirrored: they are the same
  fact in two tables, and that one is also the rate limiter's counter.

- **Console sessions can be revoked** ([#314](https://github.com/onixus/Shapoclyack/issues/314)).
  A JWT was believed on its own for its whole eight-hour life: the role came
  out of the claims and the database was never asked, so disabling, deleting or
  demoting an account changed nothing for the token already in that person's
  browser. Every request now verifies the signature and then reads the account
  row — the role comes from the table, and the session ends the moment the
  account is disabled, deleted, demoted or has its password changed. Migration
  `0038` adds `users.token_version` (the generation every token quotes in a new
  `ver` claim) and `revoked_tokens` (one `jti` denied until its own `exp`).
  New routes: `POST /api/auth/logout` (this session), `POST /api/auth/sessions/revoke-all`
  (your account, everywhere) and `POST /api/users/{username}/sessions/revoke-all`
  (platform admin). Service tokens and agent tokens are unchanged — a service
  token was never a session and is still revoked as a credential.
  **On upgrade, tokens minted before this keep working until they expire.**
  They carry no `ver` and the migration backfills every account at generation
  0, which is what those tokens implicitly claim; the alternative — signing the
  whole console out mid-rollout — was the worse default. An operator who wants
  that runs `revoke-all` for every account once the rollout is done
  ([operations.md](docs/operations.md#sessions-and-revocation) has the loop).
- **The JWT signing key can be rotated without a fleet-wide logout**
  ([#314](https://github.com/onixus/Shapoclyack/issues/314)).
  `OCTO_JWT_SECRET_PREVIOUS` is a comma-separated list of retired keys that are
  still verified while the tokens they signed expire; nothing is ever signed
  with one. Every token now carries a `kid` header (a domain-separated `sha256`
  prefix of the key), so the verifier tries the named key rather than each in
  turn — and a token naming one key of the window but signed with another is
  refused. While `OCTO_AGENT_JWT_SECRET` is unset the agent key is derived from
  the operator key, so one list rotates both audiences;
  `OCTO_AGENT_JWT_SECRET_PREVIOUS` covers the case where it is set explicitly.
  A `prod` start refuses a list that carries the shipped development secret or
  repeats the current key. Procedure in
  [operations.md](docs/operations.md#rotating-the-jwt-signing-key).
  The OIDC login state is signed with the same key and is now verified against
  the same window, so an SSO login started just before a rotating deploy still
  completes instead of failing with "invalid or expired login state".
- **A session store that cannot be reached answers `503`, not `401`**
  ([#314](https://github.com/onixus/Shapoclyack/issues/314)). The per-request
  account lookup turns an unreachable Postgres into `503` with `Retry-After`
  rather than into a refusal: a `401` would sign every console in the fleet out
  over a database restart, with no way back in.
- **`PUT /api/users/{username}/role` and `.../disabled` end sessions only when
  they change something** ([#314](https://github.com/onixus/Shapoclyack/issues/314)).
  Re-asserting the role or the disabled flag an account already has used to
  bump its token generation, so a reconciling IaC run or a directory sync
  signed the whole tenant out on every pass.
- **Integration secrets are encrypted at rest**
  ([#310](https://github.com/onixus/Shapoclyack/issues/310)). A webhook's HMAC
  signing key and the header values that carry a Jira / ServiceNow /
  DefectDojo API token sat in `webhook_subscriptions` as typed, so a database
  dump, a base backup or a read replica yielded every tenant's tracker tokens
  at once — the redaction in `secure_webhooks.py` only ever answered what an
  API *caller* may read. Both columns are now envelope-encrypted: a fresh
  256-bit data key per write under AES-256-GCM, wrapped by a KEK from
  `OCTO_MASTER_KEY`, stored as `v1:<kek_id>:<wrapped dek>:<nonce>:<ciphertext>`
  and bound to its column so a ciphertext moved between the two fails its tag.
  The API responses are unchanged: the secret is still write-only and header
  values still redact to `***`. Reading a subscription needs no key at all —
  the values that would be redacted are never decrypted to be redacted — and
  neither does the fan-out, which routes on `enabled` / `event_kinds` /
  `min_severity`. The one function that turns a stored envelope back into a
  credential is `endpoint_credentials`, called by the delivery loop and by the
  ticket reflection immediately before the wire call.

  A row whose KEK is not configured — a rotation window closed one step early,
  a backup restored against another key — is therefore contained: it is listed
  and edited like any other, it does not stop the event that fans out to its
  neighbours, and its deliveries dead-letter on the first attempt with
  `SecretDecryptionError` rather than spending `OCTO_WEBHOOK_MAX_ATTEMPTS` on a
  retry that cannot succeed. `--rotate` leaves such a row exactly as it is,
  counts it, and exits non-zero.

  Nothing is re-encrypted by a migration. The stored form names the key that
  opens it and the read path still accepts plaintext, so encrypting a live
  installation is an online, resumable operator step
  (`python -m api.db.reencrypt_secrets`), and a KEK rotation is
  `OCTO_MASTER_KEY_PREVIOUS` plus the same pass with `--rotate`. Migration
  `0040_encrypted_secrets` only adds `webhook_subscriptions.key_id`, the
  queryable mirror of the id inside each ciphertext.

  Without a key: under `OCTO_ENV=prod` the API **refuses to start** if any
  subscription already holds a secret or a configured header — those rows are
  either plaintext, which is the defect, or encrypted and unreadable — and
  starts with a warning when there are none, so a deployment with no
  integrations is not made to invent a key it does not need. That warning is
  not a licence: an installation which came up with nothing stored and then
  had a webhook created **refuses the write**, because the startup answer is
  about the rows that existed at boot and the first integration is exactly
  what changes it. Under `dev` it is
  always a warning and the values stay plaintext, which is what keeps a laptop
  and the test suite working unchanged. Console passwords, service tokens and
  provisioning keys are unaffected: they are hashes, not secrets we can read
  back. `OCTO_OIDC_CLIENT_SECRET` and `OCTO_REPORT_SMTP_PASSWORD` are also
  unaffected — they never reach the database, and encrypting an environment
  value with a key from the same environment buys nothing.

  `OCTO_MASTER_KEY_PROVIDER` names where the KEK lives. Only `local` ships;
  `vault-transit`, `aws-kms` and `gcp-kms` are the **interface**
  (`KeyProvider`, two methods) and refuse startup rather than falling back to a
  local key. See `docs/operations.md` § Secrets at rest and the
  `OCTO_MASTER_KEY` examples in `k8s/shapoclyack/examples/`.
- **A results upload now confirms the job's `run_id` instead of choosing it.**
  `POST /api/agent/jobs/{job_id}/results` took `run_id` from the multipart
  form and preferred it over the value the server minted at `start_scan` or
  at the claim, then joined it onto `output_dir/runs` unchecked. An upload
  naming a different run — another tenant's, or a path with `..` in it — was
  extracted there and rewrote that run's `tenant.json` to the uploader's
  tenant. The echoed value is now accepted only when it equals the job's own
  (`422` otherwise, and the job stays the agent's to finish), and every run
  id — the operator-supplied one on `POST /api/jobs` included — must be a
  single path segment of `[A-Za-z0-9_-]{1,64}`.
- **Per-tenant job subjects and consumers.** Job offers are published on
  `jobs.scan.{tenant}` instead of a single shared `jobs.scan`, and each tenant
  has its own durable pull consumer `octo-agents-{tenant}` filtered to that
  subject. An agent learns its tenant from the API (`tenant_id` in the
  `POST /api/auth/agent/token` response, or the registration response for an
  agent on the legacy shared `OCTO_AGENT_TOKEN`, tenant `default`) and consumes
  only its own tenant's stream; an offer for another tenant that somehow
  reaches it is terminated rather than NAKed, so it cannot spend one of the
  offer's redelivery attempts. Tenant ids that are not valid NATS subject
  tokens go through the same injective encoder `ingest.results.{tenant}` and
  `events.asset.{tenant}.{kind}` already use. The `agent` NATS permission list
  in `base/nats/configmap.yaml` now allows `octo-agents-*`; the shared
  `octo-agents` consumer is no longer created but is left in place (and still
  permitted) so a rolling agent upgrade works — remove it with
  `nats consumer rm JOBS octo-agents` once the fleet is upgraded. HTTP claim is
  unchanged and remains the fallback when NATS is unavailable.
- **TLS for the NATS connection** ([#309](https://github.com/onixus/Shapoclyack/issues/309),
  [#359](https://github.com/onixus/Shapoclyack/issues/359)). API and agent
  accept `tls://` URLs and `OCTO_NATS_TLS_CA`, `OCTO_NATS_TLS_CERT`,
  `OCTO_NATS_TLS_KEY`, `OCTO_NATS_TLS_HOSTNAME`; certificate and hostname
  verification are always on, and a publicly issued broker certificate needs no
  variable at all. `k8s/shapoclyack/examples/nats-tls-configmap-patch.yaml`
  adds the server-side `tls {}` block and the cert-manager `Certificate` to
  copy. Base is unchanged — the kind stand has no CA and stays plaintext.

### Fixed

- **A running scan can be stopped**
  ([#360](https://github.com/onixus/Shapoclyack/issues/360)). Cancelling was
  legal only from `queued`; once an agent had claimed a job, the only bound on
  it was the agent's own `--scan-timeout` — two hours of traffic at a target an
  operator had already decided to leave alone. `POST /api/jobs/{id}/cancel` now
  puts a claimed or running agent job into the new **`cancelling`** state, the
  request reaches the agent on its next heartbeat response, and the agent
  SIGTERMs its scanner's process group and uploads whatever the run produced
  with `cancelled=true`. Partial results are kept; the job ends as `cancelled`
  rather than `failed`, so an operator's decision is not filed as a defect. A
  job whose agent never confirms (one too old to read the new field, say) is
  finished as `cancelled` after `OCTO_JOB_CANCEL_GRACE_SECONDS` with the
  silence recorded in `error`, and a `cancelling` job is never requeued by the
  lease reaper, so it cannot be handed to a second agent while the first is
  stopping. Gated on the named permission **`scan.cancel`** (migration 0051,
  granted to exactly the roles that could cancel before) and written to
  `audit_events`. The console offers Cancel on running jobs and says plainly
  that a running scan is *asked* to stop. **A local scan that has already
  started still cannot be cancelled** — it is a subprocess inside one API
  replica, which is not necessarily the one answering the request — and the API
  now refuses it with that reason instead of a generic 409.

- **Five defects in that cancellation path, found by review of #360**
  ([#360](https://github.com/onixus/Shapoclyack/issues/360)). Each was
  reproduced against a live Postgres before the fix. (1) A **second Cancel on a
  job already `cancelling`** wrote it `cancelled`: `cancelling` is deliberately
  not "in flight", which made the naive reading of it "queued, so stop it
  outright". Two consoles four seconds apart — the list's own poll interval —
  or one proxy retry were enough, and the job was then terminal with
  `cancel_requested` cleared before the agent had read it, so a scan nobody
  stopped kept running for up to two hours under a row that said it had
  stopped. Asking again is now a no-op that answers the job as it stands.
  (2) **The retry of a confirming upload was refused with a 422.** Confirming a
  cancellation is itself a result upload now, so it inherits the lost-response
  problem P1.5 solved for every other upload; a retry carrying the same
  deterministic `idempotency_key` is answered with the stored outcome. An
  upload that no key ties to the outcome is still refused — and the refusal no
  longer says "cannot move to failed" about an agent that reported a
  cancellation. (3) **`OCTO_JOB_CANCEL_GRACE_SECONDS` was floored at 5s**,
  which protected nothing: the stop reaches the agent on a heartbeat and the
  reaper only looks once a tick, so anything below those two summed guaranteed
  the job was finished as `unconfirmed` before the agent could answer. The
  floor is now `OCTO_AGENT_STALE_SECONDS` + `OCTO_JOB_REAPER_INTERVAL_SECONDS`
  (180s by default) and derived from them rather than written as a constant.
  (4) **The console demanded the operator rank on top of `scan.cancel`**, so a
  `scan-operator` — the tenant role #318 added for exactly this, and a viewer
  in the global role — stopped scans over the API but saw neither the button
  nor the `/scans` pages. Both are gated on the permission now, the rank
  surviving only as the answer for an API too old to send a permission list.
  (5) **The confirming upload erased the reason from `error`**, writing the
  agent's string — or `NULL` — over "Cancellation requested by X" that
  `docs/api-and-rbac.md` promises stays there; the two are joined instead, so a
  finished cancelled job still says who asked for it.

- **Five ways the workflow-event worker under-delivered, found by review of
  #349** ([#349](https://github.com/onixus/Shapoclyack/issues/349)). All five
  were reproduced against a live Postgres before the fix. (1)
  `OCTO_SLA_ESCALATION_MAX_FINDINGS` was a ceiling, not a window: an announced
  finding does not drop out of the candidate query, so a tenant with 600
  overdue findings got 500 events on the first tick and **silence for ever**
  after it. The worker now keeps a per-tenant keyset cursor on
  `(due_at, vuln_id)` and each tick continues after the last deadline the
  previous one reached; the expiring-exception sweep is windowed the same way.
  (2) With `OCTO_NATS_URL` set and the broker down, every emit re-dialled it —
  `nats_bus.get_bus` caches only success — for a measured 10 seconds each,
  inside an operator's `POST /api/vulnerabilities/{id}/transition` and 500
  times per worker tick. An unreachable broker is now remembered for 30
  seconds, the guard #328 wrote for the audit events. (3) The escalation write
  ran on every tick: an operator who assigned a breached finding to themselves
  had it moved back to the escalation address within fifteen minutes, with
  another `escalated` row in the trail each time (4 rows in 3 ticks). It is now
  claimed once per missed deadline under its own marker kind. (4) The owner
  digest claimed the day *before* calling the relay and did not release it, so
  one `421` at 00:07 cost the owner the whole day's mail; a refusal now
  releases the claim and the next tick retries. (5) An `emit_once` whose
  fan-out raised kept its marker, suppressing that breach until the marker was
  pruned — `OCTO_WORKFLOW_MARKER_RETENTION_DAYS` days later, **a year** by
  default. A failed fan-out now releases the claim, which is what the docs
  already promised ("a longer tick delays a notification rather than losing
  it").
- **The workflow-event tests now fail when the marker table stops working**
  ([#349](https://github.com/onixus/Shapoclyack/issues/349)). Review's mutation
  run passed 48/48 with the claim result in `emit_once` ignored: the
  de-duplication was actually being enforced by the unique index on
  `webhook_deliveries`, and the marker table — the heart of the issue — carried
  no test weight. Two tests close that: one emits for a tenant with **no**
  subscription (no unique index to hide behind) and counts the bus copies, and
  one races eight threads onto a single claim and asserts one winner, which is
  the double-leader case three docstrings and `docs/operations.md` promise.
- **"Two-way ticket sync" was one direction plus a refresh button**
  ([#347](https://github.com/onixus/Shapoclyack/issues/347)). Nothing read a
  tracker back unless an operator clicked `POST /api/vulnerabilities/{id}/ticket/sync`,
  so a fix marked Done in Jira stayed `FIXING` here, inside its SLA, until a
  human opened that finding's page. A leader-locked poller now reads every
  linked ticket on a per-subscription cadence
  (`transport_config.sync_interval_seconds`, default
  `OCTO_TICKET_SYNC_INTERVAL_SECONDS`), with per-subscription backoff so a
  tracker that is down is asked once and not once per finding, and
  `octo_ticket_sync_lag_seconds` to say how far behind it is. A suggestion is
  applied only when the tracker's status actually *changes*, so the poller
  cannot re-impose its own verdict every interval on an operator who overruled
  it. The outbound map stopped being a boolean — every lifecycle state now maps
  to the tracker's own states, and a closed Jira issue is reopened through a
  `Reopen` transition instead of failing silently; the maps are constrained so
  that what is pushed cannot read back as a move nobody asked for, which is
  also why an *active* DefectDojo finding no longer suggests `FIXING`.
  `transport_config.auth_mode` adds `basic`, which is what Jira Cloud accepts
  and what previously had to be hand-written into `headers`. Migration `0045`
  adds the poller's cursor; the poller is **on by default**, so the first tick
  after the upgrade reads every linked ticket — see
  `docs/operations.md` § Inbound ticket sync to pace it. Reflecting a
  *machine-verified* closure onto the ticket is still not done — that path
  writes from the run ingest, not from an operator transition — so #347 keeps
  that half open.
- **A webhook delivery whose send raised counted as two attempts** in the
  dispatch tick's own report while the delivery row recorded one
  ([#310](https://github.com/onixus/Shapoclyack/issues/310)). The counter was
  incremented at the wire call and again in the handler that caught it, so the
  `attempted` figure the worker logs disagreed with the queue whenever a
  receiver refused a connection. It is now counted once, where the outcome is
  written back.

### Added

- **Maintenance windows, blackout calendars and a per-tenant change freeze**
  ([#352](https://github.com/onixus/Shapoclyack/issues/352)). The platform could
  say when a scan repeats and nothing about when it must not happen, so
  honouring a customer's change window meant disabling their schedules by hand
  and remembering to switch them back on. `maintenance_windows` (migration
  `0048`, expand-only) stores recurring windows per tenant or per asset group,
  with an RFC 5545 `RRULE` — a documented subset parsed in-repo, no new
  dependency — read in the **tenant's** IANA timezone: a wall clock that stays
  22:00 for the customer across a DST change, with the duration added in
  absolute time so a window over a spring-forward lasts as long as it says.
  `kind=blackout` forbids scanning while open, `kind=allowed` permits it only
  then, and `PUT /api/change-freeze` covers the period with no end date yet.
  Admission runs inside `start_scan`, so the console, the recurring dispatcher
  and the platform's own re-scans are held to the same calendar: a manual scan
  gets `409` with `Retry-After` (absent under a freeze, which has no knowable
  end), a schedule is **deferred to the moment the block lifts** rather than
  dropped, and every refusal lands in `audit_events` as
  `scan.maintenance_block`. `/schedules` shows the calendar, the banner and the
  freeze switch. Two gaps are deliberate and #352 stays open for them: windows
  are created and edited over the API (the console has no window editor), and
  the check runs at admission only — in agent mode a job queued before a window
  opened can still be claimed inside it, because `claim_job` does not consult
  the calendar.
- **The remediation workflow has events, and a missed deadline reaches
  somebody** ([#349](https://github.com/onixus/Shapoclyack/issues/349)). The
  webhook machine carried five discovery kinds; SLA breach was derived on read,
  so it existed only while somebody had the console open on it. Eight kinds
  join it — `sla_due_soon`, `sla_breached`, `exception_expiring`,
  `vuln_state_changed`, `vuln_assigned`, `scan_failed`, `report_generated`,
  `agent_offline` — opt-in per subscription, so an upgrade sends nothing new to
  an existing receiver. A leader-locked worker derives the four that are
  predicates over the clock and claims each occurrence once in
  `workflow_event_markers` (migration `0046`), keyed on the deadline, so a
  15-minute tick announces a breach once and a reopened finding is announced
  again. Per-tenant `sla_escalation_policies` add the optional actions —
  reassign, one severity step, a daily digest to the asset owner — off until a
  tenant admin sets them (`PUT /api/vulnerabilities/sla-escalation`). Workflow
  events queue for webhooks directly, so they work with no broker configured;
  the bus copy goes to `events.workflow.{tenant}.{kind}`. The digest goes
  through the existing report relay: per-tenant notification channels are
  [#351](https://github.com/onixus/Shapoclyack/issues/351) and are **not**
  implemented here. No console UI for the escalation policy yet — it is API and
  docs only.
- **Bulk actions in the console; one request for a whole selection**
  ([#346](https://github.com/onixus/Shapoclyack/issues/346)). Triaging a scan's
  four hundred findings was four hundred clicks and four hundred POSTs. The
  findings and asset tables now have a multi-select whose state is held as ids —
  so it survives paging, the poll and a filter change — and
  `POST /api/vulnerabilities/bulk` applies `assign`, `transition`, `ticket`
  (operator) or `exception`, `false_positive` (tenant admin, exactly as one at a
  time) to up to 200 ids. `POST /api/assets/bulk` does the same for asset
  context. Each id is applied through the *same* service call the single-finding
  route uses and gets its own outcome: the answer is 200 with a per-id report,
  so one finding that has since closed, or one id from a tenant the caller
  cannot write in, no longer refuses the other hundred and ninety-nine. One
  `audit_events` row per request lists the ids — written **before** a 500 when
  a batch dies part-way, since the ids it already applied are committed, and
  filed in the tenant whose findings changed rather than the caller's when a
  platform admin's batch crosses tenants. Ids are capped at 48 characters as
  well as 200 per request, and an oversized request body gives way inside the
  audit document before the ids do: the row names what was touched or it is
  worth nothing. In the console, a blank Assign field is **not sent** — the
  finding keeps what it has — and clearing an assignee or an owning team is its
  own checkbox; the selection is cleared when the tenant changes.
- **`Idempotency-Key` on the bulk write endpoints**
  ([#346](https://github.com/onixus/Shapoclyack/issues/346)). A bulk request is
  the slowest, so it is the one that times out, and a blind retry would apply
  two hundred transitions twice. The new `idempotency_records` table
  (migration `0044`) gives a key the same contract `POST /api/jobs` already had
  — same body replays the stored report, different body is 409, a retry while
  the first is still running is 409 — for the endpoints that create no row of
  their own to hang it on. "Still running" lasts a 15-minute lease and not the
  full retention, so a replica killed mid-batch does not leave the key
  answerable to nobody for a day. A request that *failed* releases its key,
  unless it applied part of itself: then the partial report is stored as the
  answer, because releasing would let the retry re-apply what landed. Records
  self-expire after 24 hours. The console mints one key per submission and holds
  it against that body until it is answered, so clicking Apply again after a
  proxy timeout replays instead of applying the batch twice. The scan-start path
  is unchanged.
- **`overlays/prod-ha` — a Kubernetes profile that survives a node loss**
  ([#335](https://github.com/onixus/Shapoclyack/issues/335)). `overlays/prod`
  ran one API replica pinned to a scanner node, the in-cluster single-pod
  PostgreSQL, and neither NATS nor ClickHouse; there was no second overlay to
  point at. The new one sets API `replicas: 2` with `podAntiAffinity` and
  `topologySpreadConstraints` (with `nodeTaintsPolicy: Honor`, so a cordoned
  node stops counting as a domain and a drain does not strand the replacement
  pod), and an HPA (CPU 70%, 2–6); scales NATS JetStream to three nodes with
  `OCTO_NATS_STREAM_REPLICAS=3` (the `nats-ha` patches moved out of `examples/`,
  where nothing referenced them, into the overlay — kustomize refuses to load a
  patch file from outside its root); fills in `OCTO_NATS_URL` and
  `OCTO_CLICKHOUSE_URL`; and replaces the in-cluster PostgreSQL — StatefulSet,
  Services, NetworkPolicy, `pg_dump` CronJob and dev Secret — with a
  Secret-supplied `?sslmode=verify-full` URL to a managed one (as six
  single-object `$patch: delete` files: the kustomize inside kubectl 1.31,
  which is what CI runs, segfaults on a multi-document delete patch that
  kubectl 1.36 renders happily). It also opens the
  NATS route port 6222 between broker pods, which base's NetworkPolicy denied
  (without that rule a 3-node cluster silently never forms under an enforcing
  CNI), spreads the three broker pods across nodes, and gives them a PDB —
  three pods the scheduler may stack on one node are one failure domain, and a
  parallel drain of two nodes costs the JetStream quorum. The API keeps base's
  `maxUnavailable: 1` budget rather than patching it to `minAvailable: 1`,
  which at six replicas would permit five simultaneous evictions. `k8s/scripts/validate-kustomize.sh` renders the overlay in CI.
  **It is deliberately not appliable as rendered** — the RWX storage class, the
  NATS route password and the external-PostgreSQL Secret are placeholders that
  fail loudly. Requirements, the manual drill, and what the profile does *not*
  cover (single-pod ClickHouse, artifacts still on a shared filesystem
  pending [#336](https://github.com/onixus/Shapoclyack/issues/336), DR beyond
  PostgreSQL pending [#333](https://github.com/onixus/Shapoclyack/issues/333))
  are in the new [docs/high-availability.md](docs/high-availability.md).
- **NATS survives being a cluster** ([#335](https://github.com/onixus/Shapoclyack/issues/335)).
  The broker's probes both asked bare `/healthz`, which is the *full* JetStream
  check: enabled, a meta leader elected, and every stream and consumer on this
  server current. At `replicas: 1` that is roughly "the process is up"; at three
  it fails for as long as a restarted node is catching up, so liveness restarted
  the pod mid catch-up while readiness pulled it from the Service. Liveness now
  asks `/healthz?js-enabled-only=true` and readiness `/healthz?js-server-only=true`,
  which mean the same thing on one node. Separately, `update_stream` — the call
  that pushes `OCTO_NATS_STREAM_REPLICAS=3` onto streams that already exist —
  failed inside a bare `except: pass`: an installation that scaled NATS out kept
  its single-copy streams and nothing said so. It is logged now, along with any
  stream whose actual replica count is not the one this replica asked for.
- **`k8s/scripts/validate-kustomize.sh` discovers overlays instead of listing
  them.** The hand-written list had drifted: `overlays/kind-restore` and
  `overlays/enrichment-advisories` were rendered by nothing, which is exactly
  where a broken patch would have sat unnoticed. Eleven targets now, from a glob.
- **`OCTO_DB_POOL_SIZE`, `OCTO_DB_MAX_OVERFLOW`, `OCTO_DB_POOL_TIMEOUT`**
  ([#335](https://github.com/onixus/Shapoclyack/issues/335)). The SQLAlchemy
  pool was whatever the library chose (5 + 10) and could not be changed. That
  is a per-process figure multiplied by the replica count, while
  `max_connections` on the server is one shared budget — so the profile that
  scales the API is exactly the one that needs to shrink it. Applied in
  `api/db/engine.py` from `create_app()`, before the first session is opened;
  the `dev` SQLite fallback ignores them, having no connection queue. The sum of
  the two is floored at four: the schedule dispatcher, the report dispatcher and
  the software-match worker each hold one connection for the life of the process
  for their session-scoped advisory lock, so a pool of one or two would have
  left a worker unable to become leader at all, in every replica, silently.
- **The audit trail leaves the platform: JetStream, webhooks and a CEF/syslog
  forwarder** ([#328](https://github.com/onixus/Shapoclyack/issues/328)).
  [#327](https://github.com/onixus/Shapoclyack/issues/327) gave the platform an
  administrative trail; nothing could subscribe to it. `GET /api/audit` is a
  paginated console endpoint, and the five asset events were all a webhook could
  filter on — so "alert me when someone changes a role" had no answer and a SIEM
  had no feed at all. Three ways out now, all built on the row staying the
  source of truth:
  - Each committed `audit_events` row is published to `events.audit.{tenant}`
    (`events.audit._platform` for a platform-level act, a subject no tenant id
    can claim). **After the commit, never before it**: a post-commit hook on the
    caller's session snapshots what the flush inserted and a rollback discards
    it, so a change that did not land announces nothing. A broker that is down
    loses the notification and not the row — counted on
    `octo_audit_events_published_total` and logged at WARNING. With
    `OCTO_NATS_URL` unset nothing is published, which the docs say plainly
    rather than implying a feed that is not there.
  - A webhook subscription may name `audit.*` (every action) or one exact
    `audit.<action>`. Signing, retries, the DLQ and the tenant filter are the
    ones Phase 10.3 already had; `min_severity` does not apply, since it is a
    statement about vulnerabilities. The trail is **opt-in**: a subscription
    with an empty `event_kinds` keeps meaning "every asset event", so an
    upgrade does not start posting who reset whose password into a receiver
    somebody configured for CVE alerts. A second durable consumer
    `octo-webhook-audit-fanout` does the fan-out — two consumers rather than
    widening the deployed one, whose filter subject cannot be changed without
    resetting its cursor and replaying a month of asset events (#152). The
    console's event-kind checkboxes gain *Audit trail (every action)*.
  - `python -m api.services.audit_syslog_forwarder` ships events to a SIEM as
    ArcSight CEF inside RFC 5424 syslog, octet-counted, over TCP with TLS
    (`OCTO_AUDIT_SYSLOG_URL=tls://host:6514`, `_CA`, optional client
    certificate). `tcp://` connects and warns; UDP is not implemented, because
    it carries no delivery signal and so nothing could decide when an event may
    be acknowledged — and acknowledgement only after the bytes reached the
    socket is what keeps a receiver going away from silently losing events.
    Reconnects back off 1s → 30s. It reads JetStream by default and, for an
    installation with no broker, `audit_events` directly with a cursor in the
    new `audit_forward_cursors` table (migration `0042`). That cursor is the
    pair `(occurred_at, id)` and the read is ordered by the same pair: keying
    it on the id alone loses a row whose transaction committed after a
    higher-id one, permanently and silently. The mode's one remaining
    visibility window — a transaction outliving
    `OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS` — is documented rather than glossed
    over.
  Escaping is the part a SIEM depends on and nobody can see: `|` in the CEF
  header, `\` and `=` in the extensions, and every line break, so a username or
  user agent someone controls cannot end the syslog message early.
  `docs/operations.md` § "Audit events to SIEM" carries the CEF ↔ `audit_events`
  field table and parser snippets for Splunk, QRadar and MaxPatrol;
  `k8s/shapoclyack/examples/audit-syslog-forwarder.example.yaml` has the
  Deployment, its Secret and a NetworkPolicy that permits egress to the SIEM
  port and nothing else.
- **One outbound HTTP client, with a proxy and an internal CA**
  ([#359](https://github.com/onixus/Shapoclyack/issues/359)). Nothing in this
  repository read a proxy variable, and webhook/ticket delivery on raw
  `http.client` could not have used one anyway — on a network whose only egress
  is a proxy, no webhook ever left and no remote agent ever registered.
  `OCTO_HTTPS_PROXY`, `OCTO_HTTP_PROXY`, `OCTO_NO_PROXY` and `OCTO_CA_BUNDLE`
  now decide the control-plane HTTP calls on both sides: `api/services/egress.py`
  for webhook and ticket delivery, OIDC and advisory feeds, and its deliberate
  mirror `agent/egress.py` for the agent's token exchange, registration,
  heartbeat, claim and results upload (a copy, not an import — the agent ships
  without the `api` package; a test asserts the two agree). The scanner's own
  external lookups — RIPEstat in `asn_discovery`, the three object stores in
  `cloud_discovery` — read the same two variables through
  `scanner/pipeline/egress_env.py`; the remaining outbound stages (`hostnames`,
  `ownership`, `alerts`) do not, and
  [docs/network-requirements.md](docs/network-requirements.md) now lists every
  direction and says which is which rather than claiming all of them. Each
  variable falls back to the conventional `HTTPS_PROXY`/`NO_PROXY`, and for the
  plain-HTTP direction to the **lowercase** `http_proxy` only: a CGI-shaped
  environment derives uppercase `HTTP_PROXY` from an incoming `Proxy:` request
  header, so that is the spelling an untrusted caller can write (httpoxy), and
  curl reads only the lowercase one for the same reason. A proxy URL must
  itself be `http://` — nothing here wraps the hop to the proxy in TLS, so
  `https://` is refused by name instead of promising an encrypted hop that
  `Proxy-Authorization: Basic` would then cross in the clear.
  `OCTO_CA_BUNDLE` is *added* to the system trust store — HTTPS, the SMTP relay
  and the NATS connection on **both** ends read it, so one internal root is
  named once — and a path that does not resolve to a usable PEM is an error
  rather than a silent fallback. The SSRF boundary (#151) is unchanged: a
  proxied webhook target is still parsed, port-checked and address-checked
  before anything is sent, a host whose name resolves to nothing here is
  refused rather than handed to the proxy to resolve, and a host
  `OCTO_NO_PROXY` exempts keeps the pinned direct dial. What proxying
  necessarily gives up is that pinning, which
  [docs/network-requirements.md](docs/network-requirements.md) says plainly.
- **NATS on 443, and an honest answer about proxies**
  ([#359](https://github.com/onixus/Shapoclyack/issues/359)). `wss://` in
  `OCTO_NATS_URL` now works where `aiohttp` is installed — nats-py implements
  the WebSocket transport with it, the agent image does not carry it, and the
  agent refuses at start naming the package instead of failing later inside its
  event-loop thread. `k8s/shapoclyack/examples/nats-443-ingress.example.yaml`
  has both routes onto 443: a raw-TCP (stream) ingress with `tls://`, which
  keeps TLS end to end and is the recommended one, and the `wss://` listener
  with an ordinary Ingress. **No HTTP proxy carries NATS** in any of its
  transports; where the proxy is the only way out, leave `OCTO_NATS_URL` unset
  and the agent polls `POST /api/agent/jobs/claim` — a supported mode, not a
  degraded one. `k8s/shapoclyack/examples/agent-proxy-ca-patch.yaml` is that
  deployment.
- **`OCTO_AGENT_UPLOAD_RATE_LIMIT_KBPS`** ([#359](https://github.com/onixus/Shapoclyack/issues/359)).
  Shapes the agent's results upload to a token bucket, `0` (the default) for no
  limit. The multipart body is now streamed from disk rather than assembled in
  memory, so the limit bounds the wire rate rather than the size of a buffer
  that was already filled — and a run archive stops being why a branch office's
  uplink saturates for two minutes after every scan. `Content-Length` is set
  explicitly so the streamed body does not fall through to chunked encoding,
  which the results route answers `411` to. An upload the API cuts off
  mid-body — how `OCTO_AGENT_RESULTS_MAX_BODY_BYTES` looks from the agent's
  side, since the refusal is decided on `Content-Length` and the status line is
  lost with the socket — is not retried: re-shaping the same archive through
  the token bucket only spends the site's uplink to be refused twice more.
- **[docs/network-requirements.md](docs/network-requirements.md)** — ports,
  directions and protocols for the agent, the cluster and the API's own egress;
  the proxy and CA variables with their exact `NO_PROXY` dialect; what TLS
  inspection does and does not change; and the bandwidth section. Linked from
  [operations.md](docs/operations.md#transport-encryption) and the wiki portal.
  The transport-encryption table in `operations.md` also stops saying NATS is
  unencrypted, which has not been true since `tls://` landed.
- **Structured logging, a request id, and secret redaction**
  ([#330](https://github.com/onixus/Shapoclyack/issues/330)). `OCTO_LOG_FORMAT`
  (`text` by default, `json` for a shipper) and `OCTO_LOG_LEVEL` configure the
  API and the agent alike; the API hands the same formatter to uvicorn, so
  `uvicorn.access` stops being the one stream in a different shape. JSON lines
  carry `ts`, `level`, `logger`, `msg`, `request_id`, and `exc` on a traceback,
  and the formatter is built on the standard library — no new dependency.
  `RequestIdMiddleware` binds a correlation id per request: `X-Request-Id` from
  the caller when it is safe to echo and to log (128 characters of a narrow
  set, so a uuid, a ULID or a `traceparent` passes and a CRLF injection does
  not), a fresh uuid4 otherwise. It wraps the whole ASGI stack — outside
  Starlette's own `ServerErrorMiddleware`, which `add_middleware` cannot reach
  — so the 500 for an unhandled exception carries the header like every other
  response, and the record about it is written under the id rather than by
  uvicorn after the context is gone. The value comes back in the response
  header (named in the CORS `expose_headers`, so the console can read it
  cross-origin and shows it in the toast for a server-side failure), appears in
  every log line the request produces, and is set on the OpenTelemetry span as
  `shapoclyack.request_id`. Both formats print UTC.
  A `logging.Filter` on both processes masks keyed
  `password=`/`token=`/`secret=` pairs (JSON spelling included), the whole
  `Authorization` header whatever its scheme, bare `Bearer` credentials,
  passwords inside `scheme://user:pass@host` URLs — an empty user, as Redis
  writes them, included — and JWTs, in the message and in the formatted
  traceback of either format; `%s` arguments are covered, which is how this
  repository logs. `sqlalchemy.engine`, `paramiko`, `httpx`/`httpcore` and
  `nats` are held at a floor, so `OCTO_LOG_LEVEL=DEBUG` does not turn on the
  SQL statement log with its bound parameters, and `OCTO_LOG_LEVEL=NOTSET` is
  refused rather than silently meaning "everything". `docs/operations.md`
  now describes the filter and its limits instead of instructing operators not
  to log secrets. Head trace sampling is configurable with
  `OCTO_OTEL_TRACES_SAMPLER_RATIO` (default `1.0`, parent-based).

- **The console warns before a session ends, and signing out ends it on the
  server** ([#314](https://github.com/onixus/Shapoclyack/issues/314)). Five
  minutes out, a banner above the header says how long is left and offers "Sign
  in again"; the countdown is read from the token's own `exp` and decides
  nothing. **Sign out** now calls `POST /api/auth/logout` before forgetting the
  token locally, so a copied token stops working rather than outliving the
  sign-out. A sign-out the server did not confirm is retried as "end every
  session" and, if that fails too, said out loud instead of reported as done.
  The account menu gained **End all sessions** for the explicit case. There is
  still no silent renewal — refresh tokens remain open on #314 — so an expired
  session still ends in the redirect to `/login`; the banner now stays and
  turns red at that point rather than disappearing at zero.
- **`OCTO_AGENT_MIN_VERSION` — a version floor for the agent fleet**
  ([#363](https://github.com/onixus/Shapoclyack/issues/363)). Empty by default,
  which changes nothing. Set it and an agent below the floor is answered `426
  Upgrade Required` on `POST /api/agent/jobs/claim`, while `register` and
  `heartbeat` keep working on purpose — a gated agent that vanished from
  `GET /api/agents` would be a host nobody could find to upgrade. The heartbeat
  response carries `min_version`, `upgrade_required` and a human-readable
  `upgrade_message`; `agent/worker.py` logs it once per change rather than once
  per poll, and treats the `426` as a wait rather than a crash. Versions are
  ordered by the dpkg comparator this codebase already uses for package
  matching, so `0.3.2.1` < `0.44-0907` and a `-beta1` of the required release is
  not below it. An unparseable or absent version is below every floor.
- **`OCTO_AGENT_JWT_SECRET`** — see *Security* below.
- **Three gaps the console's Users and Integrations pages ran into.**
  `POST /api/users` now accepts an optional `email`, written in the same
  transaction as the account (always unverified — marking an address verified,
  which is what makes it linkable to an SSO identity, stays
  `PUT /api/users/{username}/email`); `UserInfo` carries `tenants` (the tenant
  ids the account holds an explicit membership in, sorted) and
  `is_platform_admin`, filled for the whole list in one query; and
  `PATCH /api/webhooks/{id}` takes `secret`, the only way to rotate a
  Jira/ServiceNow/DefectDojo API token — it is stored the same way create
  stores it and never echoed back, while `POST /api/webhooks/{id}/rotate-secret`
  now answers `409` on a ticket transport instead of letting the refusal escape
  as a `500`.
- **`GET /api/jobs/summary` — queue depth in one query.** `by_status` over all
  six lifecycle states, `running`, `queued` (queued plus claimed: a job an
  agent holds but has not started is still work waiting) and `by_surface` with
  `running` / `queued` / `total` for `external`, `internal`, `mixed` and
  `unknown`, all zero-filled so a console renders a stable set of tiles.
  Operator, tenant-scoped exactly like `GET /api/jobs`. Jobs also record
  whether their surface was declared by the operator or derived from the
  targets (`JobInfo.surface_source`), which is what lets the scorer treat a
  declared external scan as network-exposure evidence without scoring the
  address-space rule read back to itself. No migration: both ride the job's
  existing `scan_options`.
- **A scan surface the operator declared now counts as evidence of network
  exposure.** The scorer refuses to read a public address as "internet-facing",
  which left nearly every finding at `network_exposure=unknown` and the
  console's external-surface counters at zero. A surface an operator *declared*
  on the scan request is a named decision, like `exposure_level` on an asset,
  so findings from such a run now resolve to `external` / `internal` with
  source `scan-surface` — ranked below the finding's own value, the RFC1918
  rule and the asset's operator-set level. A surface the server *derived* from
  the targets still counts for nothing, and neither does `mixed`. See
  [docs/risk-scoring.md](docs/risk-scoring.md).
- **The console separates external and internal scans and exposes what the
  API already could do.** The flat 22-entry sidebar is now grouped (risk,
  external surface, internal surface, operations, insights, administration)
  and role-aware; `/scans/external` and `/scans/internal` each get a launcher
  shaped for their side of the perimeter, surface KPIs, the job list with
  **cancel** and a per-job record drawer, and recent runs; `/jobs` redirects
  to `/scans`. New `Ctrl/⌘-K` search-and-jump, a live running/queued/agents
  strip in the header, a **Scan operations** block on the dashboard, a surface
  filter on `/runs`, a surface selector on schedules, and a **Network
  exposure** filter on the Vulnerability Center. Two admin pages that had no
  UI at all: **Users & access** (accounts, roles, tenant membership,
  provisioning-key revocation, sign-in audit, own password) and
  **Integrations** (webhooks and Jira / ServiceNow / DefectDojo transports,
  test, secret rotation, delivery log with retry; a tracker token is rotated
  from the edit form). Scan starts now send an `Idempotency-Key` that changes
  with the form's content; the header pulse and surface KPIs read one grouped
  `GET /api/jobs/summary` instead of paging the job list. Fixed: the Remediation card rendered an unknown network
  exposure as `internal`; switching the Source filter in the Vulnerability
  Center served the previous filter's page from cache.
- **Scans are classified as external or internal, and both lists can be
  filtered by it.** An internet-facing scan and a scan of the tenant's own
  network answer different questions — what a stranger sees, versus what an
  intruder already inside would — and until now the two sat in one undivided
  list of jobs and runs. Every job is now classified from its targets at the
  moment it is created: domains and public address space are `external`,
  RFC1918 / loopback / link-local / RFC6598 shared space / IPv6 ULA are
  `internal`, both together are `mixed`. `POST /api/jobs` and the schedule
  endpoints also take an explicit `surface`, which wins over the derived value:
  a tenant whose internal estate is a block of public addresses is not wrong,
  and no address-based rule can know that. `GET /api/jobs` and `GET /api/runs`
  gained a `surface` query parameter, and `JobInfo` / `RunSummary` carry the
  value. No column and no migration — the classification is a property of the
  request, so it rides on the job's existing `scan_options` and on the run's
  `tenant.json` marker. `surface=unknown` selects what carries no
  classification: everything started before this shipped, and any scan of the
  server's default input files, whose contents the API never reads. That value
  is offered rather than hidden, so the four filters partition the list and no
  job or run is invisible under all of them. The private ranges are spelled out
  in `api/services/scan_surface.py` rather than deferred to
  `ipaddress.is_private`, whose membership has moved between CPython releases —
  a base-image bump must not silently reclassify jobs.
- **Findings can be filtered and counted by network exposure.** `GET
  /api/vulnerabilities` takes `network_exposure=external|internal|unknown` and
  `/summary` returns `by_network_exposure_open`; the signal was already scored
  per finding and only unreadable. `unknown` includes the findings scored before
  it existed, which carry `NULL` — asking for what is not yet known must not
  hide them.
- **A tenant's approved scanning scope can be approved from the console.** The
  scope has been enforced since #226 and editable only over curl ever since:
  a fresh installation refused every scan with "tenant default has no approved
  scan scope: an admin must approve one", and the fix was a `PUT` with a bearer
  token pasted by hand. `/tenants` now carries a **Scan scope** action per row
  for a platform admin, over the same admin-only
  `GET`/`PUT /api/tenants/{id}/scan-scope` — nothing on the API side changed.
  It shows what is approved now, with the admin and timestamp each entry was
  written under, and an editor seeded from exactly that: approving sends the
  whole list, because that is what the endpoint does — a scope is evaluated as
  a set (deny beats allow), so there is no per-entry update that is safe to
  enforce halfway, and an editor that started empty would have quietly dropped
  the rest of the scope on the first correction. The button is inert until
  something actually changes, an empty list is offered with a warning that the
  tenant will then not be able to scan anything rather than refused, and the
  browser-side value checks are warnings under the row rather than gates — only
  an empty value stops the request, so the API stays the authority on what a
  value is and its `422` text is what the failure toast says. The scope is
  re-read at the moment of the write and the approval is refused if another
  admin changed it in between, since the endpoint replaces the whole list and
  offers nothing to condition the write on. The tenant's promoted related
  domains (org_profile M4) are listed read-only beside it: operators add those
  underneath the scope and every scan carries them, so the admin approving the
  scope should see them.

- **The advisory datasets behind software→CVE matching now have a way to get
  onto an installation.** The providers, the normalizers and the opt-in fetcher
  all existed, but `api/services/advisories/fetch.py` was called from nothing
  except its own tests: every deployment ran the matcher against the committed
  seed — 8 Debian and 10 Ubuntu statements — and nothing said so, because
  `scripts/enrichment_manifest.py` held both datasets optional with a floor of
  one entry. So the seed passed for coverage in the one place built to catch
  exactly that.
  `scripts/fetch-advisories.py` is the missing CLI, a thin wrapper over
  `refresh()` in the shape of `scripts/fetch-cvss4-db.py`: it stages the
  download beside the destination and promotes it only once it clears the
  dataset's floor — the same number `scripts/enrichment_manifest.py` reports
  `usable` against, so the fetch and the report use one number and not two — so
  a feed answering `200` with an empty or truncated document cannot wipe a
  populated dataset, and it exits `3` for "nobody opted in" rather than
  reporting a failure. `scripts/fetch-enrichment.sh` runs both feeds beside
  cvss4/epss/kev when `OCTO_ADVISORY_FETCH_ENABLED` is set, and floors both
  paths from the committed seed so a freshly provisioned enrichment volume is
  never simply empty. In Kubernetes this rides the enrichment CronJob that
  already exists; the opt-in is one overlay,
  `k8s/shapoclyack/overlays/enrichment-advisories`, which layers the
  `base/enrichment-advisories` component on: the ConfigMap the job reads the
  flag from and the `2Gi` memory limit the Debian tracker parse needs, in one
  place, because taking either without the other is a defect. The base CronJob
  stays at `1Gi`. The Dockerfiles are untouched: a ~50 MB feed that changes
  daily does not belong in an image layer.
  Both datasets now carry a real feed's floor in the manifest — 100k Debian,
  10k Ubuntu — while staying **not required**, which is what lets "this build
  ships a seed" and "this build ships coverage" be different states without
  making an offline build fail. `GET /api/system` carries the difference
  outward in a new `usable` field on every enrichment entry: `entries`, `age`
  and `origin` together still describe a seed and a real corpus identically,
  since the seed's mtime is the build's, and the console was rendering a
  fresh-built seed as a green `fresh`. `usable` is the build's own verdict
  against the floor, and it is `null` rather than `false` when no manifest was
  found. The System page reads it: a dataset the build called unusable is
  badged `stub` and never `fresh`, and a `null` — no manifest, nothing recorded
  — is left to the age check exactly as before.

- **Software→CVE matches are tracked findings** (ROADMAP Track E, M3;
  migration `0032`) — a match lived in `software_cve_matches`, keyed on
  `device_id` and replaced wholesale on every run, so an authenticated finding
  had no `finding_key`, no SLA, no owner, no ticket, no NIST risk and no line
  in `vulnerability_events`; it was absent from the Vulnerability Center,
  every report and the remediation board, and it vanished at the next run.
  Matches now fold into the same `vulnerabilities` table the scanner writes,
  carrying `source = "endpoint_software"` and the `device_id` they were seen
  on. `GET /api/vulnerabilities?source=` narrows to either observer.

  Four decisions are worth naming.

  *The scan `finding_key` is untouched.* Widening that hash to tell the two
  sources apart would have renamed every finding already in the table — every
  open one would look new and every closed one would come back. Software
  findings get their own namespaced key over `(asset, device, CVE)`; `device_id`
  is in it because one asset can carry several endpoints and which host a
  package is behind on is part of what the finding is.

  *Only a `vulnerable` match with a published fix becomes a finding.* `fixed`
  and `not_applicable` are the evidence that the matcher looked and answered,
  and `unknown` is the honest "we could not tell" — a deadline attached to "we
  do not know this endpoint's OS" puts the SLA report behind a non-statement.
  The published-fix rule is not an optimisation: a full feed across a large
  estate produces millions of `vulnerable` matches, and an SLA dashboard with
  a million breaches is unreadable on its first day.
  `OCTO_SOFTWARE_FINDING_MIN_SEVERITY` adds a floor on top.

  *Closure requires an observation, not an absence.* A software finding closes
  as `closure_reason = patched`, `machine_verified = true`, only when the match
  is gone or has become `fixed` **and** the device sent a newer accepted
  snapshot **and** the advisory question could still be put at all — the
  distribution resolved and its provider still has a dataset covering that
  release. A device that went quiet produces exactly the same "no match" as a
  device that was patched, and so does a feed volume that stopped mounting;
  when the finding is not closed its `last_seen_at` does not move either, so
  `?stale_days=` still surfaces it. A match that is still `vulnerable` but no
  longer tracked — the vendor withdrew the fix, or the severity floor was
  raised — leaves the finding open rather than closing it.

  *`POST /api/vulnerabilities/{id}/verify` is `409` for a software finding.*
  The asset has a scannable address and a scan would happily run — and prove
  nothing, because a port scan does not observe an installed package. The
  console hides the button and says what does verify it instead.

  New worker `api/services/software_match_worker.py` keeps the lifecycle
  current: leader-locked, batched, and due-when a device's
  `latest_snapshot_id` differs from the one its matches were written from —
  a durable queue that needs no column and is the same answer in every replica.
  An accepted submission wakes it rather than re-matching inline, which would
  have put a fleet-wide advisory walk on the agent's rate-limited ingest path.
  Both `cve-matches/refresh` routes now fold synchronously and report what they
  did in a `lifecycle` object. `OCTO_SOFTWARE_MATCH_ENABLED`,
  `OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS`, `OCTO_SOFTWARE_MATCH_BATCH_SIZE`.

  A livepatched kernel still reads as `vulnerable` and now gets a deadline —
  there is no signal in the inventory to correct it, and the supported path is
  a risk acceptance with a reason and an expiry rather than a guess.

- **False-positive verdicts, and a suppression that survives the next scan**
  (ROADMAP Track E) — a finding could be closed as noise, but
  `register_findings_from_run` re-opened *any* closed row it saw again, so an
  honest verdict cost a reopen, a restarted SLA clock and a permanent place in
  the breach report. Marking noise correctly was the expensive option, which is
  the wrong incentive to put on triage.
  `POST /api/vulnerabilities/{id}/false-positive` (admin) now records the
  verdict as an expiring attribute of the row — reason, evidence, who, and a
  mandatory `suppress_days` between 1 and 365 (default 90), so "forever" cannot
  be spelled. While it holds, a re-observation leaves the finding `CLOSED` and
  moves `observation_count` and `fp_observations` without touching
  `reopen_count` or the SLA clock. `DELETE` on the same path takes only
  `operator`: releasing a suppression can only put work back on the queue.
  The verdict is overruled by evidence rather than only by time — a higher
  severity, `in_kev` turning true, `network_exposure` becoming `external` or a
  higher `exploit_maturity` re-opens the finding at once and records an
  `fp_overridden` event naming what changed. The finding never disappears: it
  stays in the Vulnerability Center as `CLOSED`, keeps its audit trail, and does
  not touch run artifacts, ClickHouse or `vulnerabilities.json`.
  The rule is one shared entry point rather than a copy per observer. Findings
  are re-observed by two paths — the scan run and the endpoint-software fold,
  which the matcher re-runs on a timer — and only the first knew verdicts
  existed, so a suppressed `endpoint_software` finding came back `OPEN` on the
  next inventory snapshot, with `reopen_count` incremented and the SLA clock
  restarted, while the console still rendered the suppression on it. Both paths
  now weigh a re-observation through `weigh_fp_verdict`, escalation override
  included, and all four re-open paths — run, snapshot, operator transition and
  a resolved ticket coming back — drop the `fp_*` columns as they go, so an open
  finding can no longer advertise a verdict that stopped holding. Withdrawing a
  verdict that is not there answers `409` instead of a `200` for a call that
  changed nothing; the console's Withdraw button reads the closure rather than
  the leftover columns, so it no longer appears on an open finding at all.
  Compliance says what its score was built on. A false-positive closure leaves
  the active population, so it can turn a failing control green — intended, and
  the score is *not* docked for it, because penalising a tenant for correcting
  its own evidence restores the incentive to leave noise open. But every
  guardrail on the verdict constrains who may make one, and none of them is
  visible where the score is read, so each framework's posture now carries
  `suppressed_findings`: how many findings an unexpired verdict is holding out
  of the assessment. It is on the console beside the evidence base and in every
  generated report.
  Migration `0034_vuln_false_positive`; its downgrade is destructive and is
  listed as such in [docs/operations.md](docs/operations.md), as is
  `0035_asset_scan_coverage`'s, for the same reason its own docstring gives:
  there is no backfill and there cannot be one, so an operator who rolls back
  and forward again loses the whole Coverage block until every asset has been
  reached by a new run.
  `fp_marked_at` and `fp_suppress_until` are `timestamp without time zone`, like
  every other lifecycle column on the table and like the naive UTC the services
  write. Declared as `timestamptz`, they were filled with naive UTC that
  Postgres reinterprets by the session `TimeZone` — which nothing here pins — so
  on an installation not running UTC the verdict's timestamp sat hours from the
  `first_seen_at` it is subtracted from, and "median hours to a verdict" read
  `-9.0` for a verdict made the same minute the finding appeared. The same
  correction applies to `0035_asset_scan_coverage`'s three columns, and
  `api/services/assets.py` now writes naive UTC as `vulnerabilities.py` does.
  Both revisions are unreleased, so the types are corrected in place rather than
  by a follow-up `ALTER`; an installation that already ran them off this branch
  should `downgrade 0033` and upgrade again.

- **Adoption's noise and coverage blocks, and the metrics they had to correct
  first** (ROADMAP Track E). Two shares on that page were wrong in the
  direction that flatters the installation.
  `scanned_recently_share` read `assets.last_seen`, which
  `api/services/endpoint_inventory.py` moves whenever an agent checks in with a
  software inventory — so a fleet of endpoint agents reporting on schedule made
  an estate nobody had scanned in months report full coverage, the metric saying
  the opposite of the truth in exactly the case it exists to catch. Migration
  `0035_asset_scan_coverage` adds `assets.last_scanned_at`, `last_scan_run_id`
  and `last_vuln_scan_at`, written **only** by the scan-ingest path in
  `api/services/assets.py`. There is no backfill and there cannot be one —
  nothing in the schema records which past run covered which asset — so coverage
  reads `null` until real runs fill the columns, which is the honest answer
  rather than a zero that reads as an alarm about the upgrade. Because they fill
  one run at a time, the withholding is a floor on the estate's scan history and
  not a check for a clean zero: 50,000 assets with one 500-host subnet scanned
  would otherwise read "Scanned in 30 days: 1%", indistinguishable from scanning
  having collapsed and a statement about the rollout either way.
  `last_vuln_scan_at` is set from what the run actually did, not from the
  presence of `vulnerabilities.json`: `report.py` exports that file
  unconditionally and the `report` stage runs in every pipeline, so an
  installation with `nuclei.enabled: false` and no nmap-vulners — a supported
  opt-out — stamped vulnerability coverage on every host of every run and the
  tile read 100% for an estate nothing had assessed. It now takes findings in
  the file, or a vulnerability stage recorded as `ok` in the run's own
  `stage_timings.json` (with `nuclei.json`'s `skipped_reason` consulted, since
  that stage is invoked even when it is switched off).
  And every remediation metric counted a false-positive closure as a fix:
  `closed_in_window`, `machine_verified_share`, `closed_within_sla_share` and
  the `mttr_hours*` medians now count real closures only, with
  `false_positive_in_window` beside them, so the quarterly control question
  ROADMAP asks cannot be answered by relabelling noise — and honest triage no
  longer drags the verification rate down while doing it.
  On top of that, `false_positives` reports the verdicts' share of all closures,
  their severities, the suppressions in force and lapsed, the ones the scanner
  broke by evidence, the median hours to a verdict, and per-detector and
  per-observer rates. A rate is withheld below 20 closures — one verdict out of
  one closure is not a 100% error rate — and advisory matches, which have no
  `script_id`, go to their own `unknown` bucket instead of being blamed on a
  script. `coverage` adds reach against `tenant_scan_scopes`, counted in
  **approved ranges reached rather than in addresses**: a share of the approved
  address space answered 2.9% for a fully scanned /22 with thirty live hosts,
  could not tell an empty range from one nobody had ever scanned, and
  double-counted overlapping approvals (`10.0.0.0/24` plus `10.0.0.128/25` was
  384 addresses). A range counts as reached when it contains an *active* asset a
  scan touched inside the window — not merely one that was discovered once,
  which is exactly the tenant the block exists to catch — and the ranges nothing
  has reached are listed by name, which is the half an operator can act on. Deny
  rows are counted apart instead of being folded into "approved entries", and
  wildcard and domain approvals are named as unmeasurable rather than counted as
  missed.
  Both blocks are additive on `GET /api/adoption`, and the console grows a
  **Noise** and a **Coverage** section plus a **False positive** card on the
  finding page.

- **`metrics()` stopped reading the tenant's whole history into Python.** It
  issued two unwindowed `select`s — every finding and every asset the tenant had
  ever had — and counted them in a loop, which on a 50k-asset estate was the
  worst read in the product. The point-in-time counts are now SQL aggregates and
  the closure pass is bounded by the window and served by the index
  `0034_vuln_false_positive` adds; only the rows the medians genuinely need are
  materialised. The two new blocks were built on that shape rather than added
  in front of the old one — with one exception worth naming rather than
  implying: scope coverage still does its CIDR membership test in Python, over
  the IP identifiers of active assets a scan reached inside the window. That is
  a bounded fraction of the identifier table rather than the whole of it, but it
  is not SQL, and `inet <<=` would do it better on Postgres; the repo has no
  `inet` usage yet and casting an identifier column that is a plain string is
  its own risk, so it is left as a known read and not claimed as an aggregate.

- **`GET /readyz` and `GET /livez` — two probes that ask different questions**
  ([#331](https://github.com/onixus/Shapoclyack/issues/331)). `/readyz` runs a
  real sweep — PostgreSQL `SELECT 1`, a NATS round trip and a ClickHouse query
  where those are configured — and answers `503
  {"status":"degraded","checks":{…}}` when PostgreSQL or NATS is down, so an
  unservable replica leaves the Service. ClickHouse is reported in `checks` and
  degrades the body, but does not fail the probe: it is a single pod with no
  PDB even in `overlays/prod-ha`, and letting it decide readiness would turn one
  ClickHouse restart into a 503 from *every* API replica at once — a full
  control-plane outage in exchange for analytics that were already down. `/livez` touches nothing: liveness
  decides whether to restart the process, and restarting every replica is not
  how an unreachable database gets fixed. The API Deployment now points its
  readiness probe at `/readyz`, both liveness and a new `startupProbe` at
  `/livez`, and rolls with `maxUnavailable: 0` / `maxSurge: 1`, a 45s
  termination grace period and a 5s `preStop` pause.

### Security

- **Transport encryption is configured explicitly instead of inferred** (#309).
  Report delivery's `starttls()` was called with no SSL context, which is
  `CERT_NONE` with no hostname check — encryption against a passive listener
  and nothing else; it now passes `ssl.create_default_context()`, with
  `OCTO_REPORT_SMTP_VERIFY_TLS=false` as the documented, warned-about way out
  for an internal relay. The ClickHouse client derived TLS from the port, so
  `https://host:8123` — an ordinary URL for a TLS-terminating proxy — sent the
  password and every row of scan data in cleartext; `secure=` now follows the
  scheme on any port. A `prod` start whose `OCTO_POSTGRES_URL` carries no
  `sslmode=` now logs a warning naming `verify-full` (a warning, not a refusal:
  a Unix socket or an operator-owned encrypted link is a legitimate install,
  and refusing would break every deployment on upgrade). The example Ingress
  gained `spec.tls`, a cert-manager issuer annotation and
  `force-ssl-redirect`. NATS TLS is tracked separately under the same issue.

### Docs

- **README and Wiki now say what the build does** (#343). "mTLS" is gone from
  the README, the architecture diagrams and the architect playbook — nothing in
  this repository issues or checks a client certificate; agents connect
  outbound over HTTPS to the API and over NATS (TLS options landed in #372). The
  "CMDB/Active Directory integration" is named for what it is, the asset
  business-context REST contract (`PATCH /api/assets/{id}`) that an external
  sync script drives, with the packaged importer as #350, and "bi-directional"
  ticket sync as push-automatic, pull-on-demand until #347. The implementation
  plan's production topology now matches `overlays/prod` — one API replica,
  NATS and ClickHouse off by empty URL — and points at #335/#336 for HA and
  object storage; Docker Compose is no longer offered, kind replaced it.
  `docs/wiki/README.md` gained a "supported now / in roadmap" table over the
  `enterprise` issues, and the rule it enforces: a claim in the Wiki carries a
  link to a file or a test, or it moves to the roadmap column.
- **`docs/operations.md` gained a "Transport encryption" section** — a per-link
  table of what is encrypted and how it is configured, plus mounting a private
  CA for Postgres `verify-full`. Its NATS permission note now describes the
  per-tenant job stream that #372 introduced.

### Changed

- **The agent's version is the release's version**
  ([#363](https://github.com/onixus/Shapoclyack/issues/363)). `LATEST_AGENT_VERSION`
  was the literal `0.42.0` while the agent shipped `0.3.2.1`, so every agent in
  every installation reported `is_outdated`, `outdated_agents` equalled the
  fleet size, and `upgrade_requested` could never clear — it clears when the
  agent reports a *different* version, and no upgrade could reach a version that
  constant agreed with. `LATEST_AGENT_VERSION` is now `api.__version__`.
  `agent/__init__.py` keeps its own literal because neither container image
  ships both packages; `tests/test_agent_version.py` fails on any drift, and the
  agent's version is now a release bump touch-point.
- **`GET /api/health` tells the truth about its dependencies.** It reported
  `status: "ok"` unconditionally and never touched PostgreSQL — the check was
  effectively "can this process serialize a response". It now runs the same
  sweep as `/readyz`, reports `ok` / `degraded`, and carries a `checks` map
  naming each configured dependency. Still always `200`, and the `nats` /
  `clickhouse` / `sso` fields are unchanged, so existing clients and the two
  container `HEALTHCHECK`s keep working. `nats` is no longer read off a local
  "we connected once" flag, which stayed true over a broker that had gone away.
- **The tenant-wide matcher run is batched** — `run_for_tenant` opened a
  session per device and issued a `DELETE` plus one `INSERT` per row, so its
  cost scaled with the device count rather than the row count. It now walks
  devices in batches, one `DELETE … IN` and one executemany `INSERT` per batch.
- **Endpoint CVE-match rows carry `vuln_id`** — the tracked finding a match
  produced, or null. Without it the console had two unconnected places talking
  about the same CVE on the same host; the Matched CVEs panel now links to the
  finding, and says why there is none where there is none.

### Security

- **`/docs`, `/redoc` and `/openapi.json` are no longer served in production**
  ([#319](https://github.com/onixus/Shapoclyack/issues/319)). The schema names
  every route, its parameters and every field an answer carries — a map of the
  installation for anyone who could reach it. `OCTO_API_DOCS` (`enabled` /
  `disabled`) decides, defaulting to `disabled` under `OCTO_ENV=prod` and
  `enabled` under `dev`; disabled means the routes are not mounted, so they
  answer `404` rather than being guarded by something.
- **`/metrics` can require a bearer token.** `OCTO_METRICS_TOKEN`, compared in
  constant time; unset keeps the endpoint open, which is the Prometheus shape
  most installations scrape with and is true only while the scrape path stays
  inside the cluster — so a `prod` start without it now warns. The Prometheus
  Operator example gained the matching `bearerTokenSecret`, and the Ingress
  example now says out loud that its `/` rule publishes `/metrics`, `/livez`
  and `/readyz` along with the console, and how to refuse them at the edge.

### Fixed

- **SSO needed session affinity to work behind more than one replica (#321).**
  The nonce and the PKCE verifier of an in-flight authorization request lived
  in a dict in the API process, so a callback that reached a replica other than
  the one that issued the state was refused — and a rollout moved the browser
  to such a replica whatever the load balancer had been told. They are now rows
  in `oidc_pending_states` (migration `0036`), keyed on a hash of the state's id
  rather than the id itself, and spent by a single `DELETE … RETURNING`: two
  replicas answering the same callback cannot both go on to exchange the code.
  The 10,000-record per-replica cap is gone with the dict — it did not only
  bound memory, it evicted the *oldest* pending logins, so anyone able to reach
  the unauthenticated login route could push real users' logins out of the
  store; the TTL is now the whole bound, and expired rows are swept
  opportunistically the way `auth_events` are.
- **`Idempotency-Key` on `POST /api/jobs` guarded the key, not the request.**
  A key an earlier call had used replayed that job whatever the body said, so a
  client that reused one — a fixed key per nightly schedule, a retry the caller
  edited before resending — was answered `200` with a job that had scanned
  something else, and the scan it actually asked for was never queued. The
  fields that define a scan are now digested into the job's `scan_options` and
  compared on every key hit, on both the pre-check and the race path: the same
  request still replays (including one whose target list was re-serialised),
  and a different one answers `409` instead. Jobs created before this shipped
  carry no digest and keep replaying on the key alone, so an upgrade does not
  start refusing keys that worked yesterday.
- **A rolling update of the API deadlocked on its own migration lock.**
  `api.db.migrate` serialises schema upgrades with a Postgres advisory lock,
  and its object id was `2` — the id the report dispatcher's `LeaderLock` had
  also been given in the same `LOCK_CLASS_ID` namespace. A leader lock is
  session-scoped and held for the life of the replica, so the running pod held
  the "migration" lock for as long as it ran, the new pod's `migrate`
  initContainer waited on it (`Init:0/1`, "Waiting for the migration lock")
  until its 600 s `lock_timeout`, and the old pod was never terminated because
  the new one never became ready. Reproduced on a kind stand by rebuilding the
  image; `pg_locks` showed the idle leader session granted `(SHAP, 2)` and the
  init container waiting on the same key. The migration id now lives in the
  same registry as the worker ids (`MIGRATION_LOCK_ID = 4` in
  `api/services/leader_lock.py`) and `tests/test_lock_ids.py` fails on the
  next duplicate. An installation stuck this way is unblocked by deleting the
  old API pod: the session goes with it and the waiting migration proceeds.

- **Three ways the provenance could lie, closed before they shipped.**
  A refresh run that did not *attempt* a dataset used to overwrite its `origin`
  with `seed`. That is not a hypothetical path: the API pod's enrichment
  initContainer runs the same script as the CronJob without the advisory
  opt-in, so every API rollout demoted a nightly-fetched corpus, and
  `GET /api/system` answered `{origin: "seed", usable: true, entries: 412000}`
  while `docs/operations.md` told the operator to go read a build log. A run
  that never tried now keeps whatever the last run that did try recorded.
  A refresh that *succeeded* and came back under the floor was the quietest
  outcome of the three — `origin: fetch` is neither `stale` nor `missing`, and
  the advisory datasets are not required, so `verdict()` returned `0` over a
  dataset that had just been replaced by twelve entries. It now exits `1`.
  And `scripts/fetch-enrichment.sh` parsed the opt-in flag with `tr` alone
  where `fetch_enabled()` uses `.strip().lower()`, so `" true"` was on for the
  service and off for the script: a skip printed at an operator who had opted
  in, and a seed that never updated. The shell helper is now a sourceable
  function and a table test drives it and `fetch_enabled()` over the same 29
  spellings.
- **Ubuntu USN normalization emitted every same-named package twice.** A USN
  lists a package in both `sources` and `binaries` whenever the source builds a
  binary of its own name — `curl`, and most of the feed — so each of those
  produced two byte-identical records, doubling a tens-of-thousands-entry
  dataset and putting two copies in the lookup bucket for that package. Found
  by normalizing fragments of the real published dumps, which is also new here:
  the fixtures under `tests/fixtures/advisories/` now carry the shapes the
  feeds actually publish (Debian's `undetermined`, its `fixed_version: "0"`
  sentinel, `nodsa`, `removed`, `high**` urgencies and `TEMP-…` ids; USN's bare
  `5051-2` keys, versionless ESM rows and Launchpad URLs mixed in with the
  CVEs) rather than only the shapes the normalizers were written against.
- **Two normalizer defects the real dumps exposed.** The published USN database
  keys advisories bare — `"5051-2"` — while every human-facing reference, this
  project's seed included, says `USN-5051-2`; a fetched dataset and the
  committed seed were therefore talking about the same advisory under two ids,
  and the generated `ubuntu.com` links were 404s. And the Debian tracker keys
  issues it has no CVE for by an internal `TEMP-0841847-1E6784` id, which the
  normalizer carried straight through — a string that is not a CVE, headed for
  `software_cve_matches` and the console as though it were one, with nothing to
  look it up against. It is now dropped like `undetermined`.

- **Two ways the closure gate closed a software finding as `patched` without
  anybody patching anything** (the asset merge below was a third). Each wrote
  `machine_verified = true` and a `verification_passed` event by
  `system:inventory`, which is the strongest claim this platform makes about a
  closure.

  *The closure gate asked the wrong question.* It read `packages_assessed > 0`
  — "how many packages we could have asked about" — which is counted **before**
  the advisory provider is consulted and stays comfortably positive on a host
  whose feed has gone. An unmounted advisory volume, a `fetch` that wrote an
  empty file or a release dropped from the vendor's export therefore produced
  "assessed, no matches", and the next snapshot from any one device closed that
  tenant's entire software backlog. The gate is now
  `software_findings.assessment_possible`: distribution resolved, provider
  loaded, release present in the dataset. The two fold paths
  (`run_matcher=True` from the worker, `False` from the refresh routes) used to
  compute this gate from different material and answer it opposite ways for the
  same device; they now evaluate the same function.

  *"The match is gone" and "we stopped tracking the match" were one condition.*
  A vendor reissuing a USN as "affected, no fix yet" empties `fixed_version`,
  and raising `OCTO_SOFTWARE_FINDING_MIN_SEVERITY` moves the floor — in both
  cases the match is still `vulnerable` and the host has not moved. Both closed
  the finding as patched; raising the floor closed every software finding below
  it across the tenant. A still-`vulnerable` match now holds its finding open,
  counted separately as `held_open_untracked_match`.

- **An asset merge no longer destroys or orphans a software finding.**
  `_repoint_findings` recomputed every absorbed row's `finding_key` with the
  *scan* key function, which is a different namespace from the software one.
  A software row either collided with a scan finding for the same CVE and was
  deleted along with its ticket, its SLA and its `vulnerability_events`, or it
  survived under a key the next inventory fold cannot look up — so the fold
  created a duplicate and closed the original as `patched`, machine-verified.
  The function now branches on `source` and re-keys a software finding with
  `software_findings.software_finding_key`.

- **The Ubuntu USN converter reads `allbinaries`, not just `binaries`.**
  `binaries` is the headline subset Canonical shows on the notice page;
  `allbinaries` is what the USN actually covers. An inventory reporting
  `libssl-dev` therefore found no advisory for a USN that names it, fell
  through to the binary-name heuristic, derived a source package no dataset
  has, and answered `unknown` — a false negative on a package with a published
  fix. Entries are deduplicated per release, since the groups overlap.

- **The Matched CVEs panel says which reason a row has no tracked finding.**
  "not tracked — no published fix" was printed for every non-`unknown` row
  without a `vuln_id`: for a `fixed` row with the fix in the very next column,
  for a `not_applicable` row about a release the vendor says is not affected,
  and for a match the severity floor filtered out. Four reasons, four strings.

- **The software match queue drains, and can be left** (migration `0033`).
  Three faults, one queue.

  *A host with nothing to report never left it.* The queue was derived from
  the match rows — due when `latest_snapshot_id` differs from the `snapshot_id`
  those rows were written from — and a host where every package is matchable
  and no advisory hits writes no rows at all, not even an `unknown`
  placeholder. It was due on every tick for ever, and with `LIMIT batch_size`
  and no `ORDER BY` a few hundred such hosts permanently starve the devices
  that actually changed. `endpoint_devices.last_matched_snapshot_id` now
  records the snapshot the fold ran over, whatever it concluded; the migration
  backfills it from the existing match rows so nothing re-folds on deploy.

  *One device stopped its whole tenant.* The fold ran a batch in one session
  and the sweep caught at tenant level, so a device that raised failed its
  batch and was re-read at the head of the same batch on the next tick, and
  the next. Each device now folds in its own SAVEPOINT and a failure is held
  off with a capped backoff (60s → 6h) rather than blocking the queue.

  *A tick took one batch.* `OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS` is
  documented as a ceiling on how stale a software finding may be; the real
  ceiling was `due / batch_size × interval`, which for 50k due devices at the
  defaults is nearly five days. A tick now drains until the tenant has nothing
  due or `OCTO_SOFTWARE_MATCH_TICK_BUDGET_SECONDS` (new, default 60) is spent,
  shared across tenants, oldest inventory first.

- **`GET /api/endpoint/cve-matches` pages in SQL.** It read every match row in
  the tenant, sorted them in Python and sliced afterwards, then handed the
  device id of every one of them to the tracked-finding lookup as an
  `IN (...)` list. Past roughly 65k parameters psycopg refuses the statement,
  so the endpoint returned 500 for the whole tenant at the estate size it is
  most needed at. The ordering and the limit are now the database's.

- **`0032`'s downgrade no longer turns software findings into scan findings.**
  It dropped `source` and `device_id`, which are the only two things telling
  the two apart, so a down-then-up left every software finding reading as
  `source = 'scan'`, `device_id IS NULL`: no longer a `409` on `/verify`,
  invisible to the inventory fold's lookup, and duplicated wholesale by the
  next snapshot. The downgrade now deletes the rows it cannot label — which is
  destructive and is now stated as such in the revision docstring and in
  `docs/operations.md`, alongside a list of the revisions whose downgrade
  destroys data.

- **Upgrade note for `0032`: the estate's numbers step on the first matcher
  run.** Every consumer of `vulnerabilities` filters on `state` and not on
  `source`, so the moment software findings land they are counted by the
  compliance evidence pass, the cross-tenant posture list, the per-asset
  counters on the assets page, `estate_risk` and the risk-history snapshots.
  That is intended — a finding found by looking inside a host is the same kind
  of object as one found from outside — but the jump is a change in what is
  measured, not an event in the estate, and the risk-history chart will draw
  it as a step. It was intended only in a commit message until now;
  `tests/test_software_findings_consumers.py` is the statement a future
  `source`-aware filter has to argue with.

- **A finding the scanner re-opened kept claiming it had been verified** — the
  operator reopen in `transition()` cleared `machine_verified` and
  `closure_reason`, but the observer's own reopen path in
  `register_findings_from_run` cleared neither. A machine-verified closure that
  came back stayed `machine_verified=True` while `OPEN`, still asserting that a
  verification run had confirmed a fix for something visibly still there — the
  one claim that column exists to make un-fakeable. Found while auditing the
  reopen path for the false-positive work.

### Security

- **Operator tokens and agent tokens no longer share a signing key**
  ([#312](https://github.com/onixus/Shapoclyack/issues/312)). Both families were
  signed with `jwt_secret`, so the `typ` claim was the only thing separating a
  console session from an agent credential for an arbitrary tenant: any missed
  `typ` check, anywhere, was a full escalation, and the key an agent host could
  leak was the key that signs admin sessions. Agent JWTs are now signed with
  `OCTO_AGENT_JWT_SECRET`. **No action is required on upgrade** — when that
  variable is unset the key is derived from `OCTO_JWT_SECRET` with HKDF-SHA256
  (info `shapoclyack-agent-jwt`), which needs no new configuration and no new
  dependency while still giving the two audiences different key material. Set it
  explicitly to rotate the fleet without invalidating console sessions; see
  *Rotating the agent token signing key* in `docs/operations.md`.

  **On upgrade every existing agent token stops verifying.** An agent
  re-exchanges its provisioning key as soon as it meets a `401` (new: it used to
  wait for its next scheduled refresh), and at worst when its token expires —
  within `OCTO_AGENT_JWT_EXPIRE_MINUTES`, 2 hours by default. Jobs already
  claimed keep running.
- **`get_api_secret_key()` no longer falls back to a published literal.** It
  returned the development secret printed in this repository whenever neither
  `API_SECRET_KEY` nor `OCTO_JWT_SECRET` was set, with no environment check at
  all, so any code path reaching it before `load_settings()` had refused to
  start signed real tokens with a public key. `prod` now raises; `dev` lands on
  the same default `Settings.jwt_secret` uses.
- **`OCTO_JWT_ALGORITHM` has one reader.** It was honoured by
  `api/core/security.py` and ignored by `Settings`, which pinned `HS256`
  regardless — setting it changed what half the codebase signed with and nothing
  that verified it. `Settings` is now the only source, `HS256` is the only
  accepted value, and anything else refuses startup in every environment.

### Fixed

- **The API PodDisruptionBudget no longer blocks every node drain**
  ([#335](https://github.com/onixus/Shapoclyack/issues/335)). `base` and
  `overlays/prod` run a single API replica, and `minAvailable: 1` on one replica
  means no voluntary disruption is ever permitted: `kubectl drain` on that node
  waited forever, so a node upgrade needed the PDB deleted by hand. Base now
  says `maxUnavailable: 1`, which is the honest statement for one replica — the
  rollout strategy is what limits the gap — and `overlays/prod-ha` inherits it
  unchanged: the same rule is correct at one replica (it permits the drain that
  `minAvailable: 1` blocked) and at six (it keeps five available), because its
  meaning scales with the replica count.

## [0.44-0907] — 2026-09-07

### Added

- **`shapoclyack-publish` accepts prerelease tags, and they do not move
  `:latest`** — the job's `TAG` regex allowed only
  `shapoclyack-<MAJOR>.<MINOR>-<MMDD>`, so there was no way to publish a beta
  at all, and every run tagged `:latest` alongside the version. Those two facts
  together meant the only way to ship something for testing was to ship it as
  the release everyone tracking `:latest` picks up. The regex now also accepts
  an `-alpha<N>`, `-beta<N>` or `-rc<N>` suffix, and a tag carrying one is
  published under that tag only. The k8s manifests pin `tag@sha256` and were
  never exposed to this, but they are not the only consumer. Nothing changes
  for a normal release tag: it still gets both its version and `:latest`.

### Fixed

- **Pulse integration polish** — defects in the Shapoclyack ↔ Pulse seam,
  found by reading the adapter against GenDec v1.1.0's own source and then
  reviewing the fix.
  *Pulse checkpoints no longer cross invocations.* `pulse_probe.py` gave each
  chunk a pulse `--checkpoint` named by position (`chunk_0000.ckpt`) while
  `--resume` re-cuts chunks from the hosts still pending, so a resumed run
  could be answered from the previous chunk's file: pulse trusts an existing
  checkpoint over `--targets-file` and replays a finished one — or an
  in-progress one whose hosts are all completed, which a kill during
  enrichment leaves behind — without OS detection, CVE correlation or the TLS
  probe. Content-keyed names and inspecting the checkpoint's status closed
  the resume path but not `run_command`'s own timeout retry, which re-runs
  the same command with the file intact. The adapter now passes no
  `--checkpoint` at all: Shapoclyack's `CheckpointStore` already tracks
  per-host progress and a 64-host chunk is cheap to rescan. Hosts files keep
  a content key (`chunk_<sha256(hosts, ports, mode)[:16]>`) so `chunks[]` in
  `pulse/raw.json` stays attributable.
  *Failures wore the wrong label.* A pulse that exited non-zero without JSON
  was logged as "0 services across N hosts with known-open ports" and given
  the 15-second settle retry. The most common such exit is pulse's `--os`
  capability check, which aborts the whole invocation when raw sockets are
  unavailable — on an unprivileged host install or a pod without `NET_RAW`
  the default configuration produced no services at all. The adapter now
  recognises that refusal, drops `--os` for the rest of the run (the same
  call `nse.py` makes for nmap `-O`), re-runs at once and records
  `adapter.os_detect_degraded` in `pulse/raw.json`. Any other crash is
  logged with its stderr and re-run at once without the settle pause; three
  consecutive crashed chunks raise `PulseCrashLoopError` instead of sleeping
  through the rest of a large run. A missing binary fails fast with an
  install hint. Every chunk is on the `chunks[]` record, failed ones
  included; `stats` is summed across chunks.
  *Installer and images.* `scripts/install-pulse.sh` fetched
  `releases/download/<tag>/<asset>` with a bearer token, which GitHub answers
  with 404 for a private repository — the documented private-repo path had
  never worked. It now resolves assets through the API, downloads
  `checksums.txt` first and checks the tarball's SHA-256 against it (an
  integrity check against a bad download, not provenance — the file comes
  over the same connection; `PULSE_SKIP_CHECKSUM=1` opts out with a warning
  for a release without it), and tells a missing release apart from a failed
  download by HTTP status so a transient error never suggests the override.
  The `pulse-bin` stage of `Dockerfile` and `Dockerfile.allinone` — until now
  a hand-copied second and third implementation of the same logic — runs
  that script, and drops `set -x`, which traced the GenDec token into the
  BuildKit log (masked in Jenkins console output, unmasked in
  `docker buildx history logs`). Also: the `-t` floor matches the schema's
  `timeout_ms ≥ 50`; `docs/pulse-backend.md` documents the resume semantics,
  the failure table, the full `service_probe.pulse.*` block and the build
  args, corrects the `OCTO_PULSE_BIN`-vs-`bin` precedence, and drops a
  `PULSE_REF` build-arg the Dockerfile never had.
- **org_profile polish: nine defects across the module** (EPIC #182). A review
  pass over `ownership.py`, `related_domains.py`, `dns_hygiene.py`,
  `mail_posture.py`, `credential_leaks.py` and `controls.py`.
  Two were disclosure- and severity-level: `org_profile.json` embeds
  `ownership.json` verbatim (registrant organisation, abuse contacts) but was
  not a restricted artifact, so a viewer could download through the artifact
  endpoints exactly what `GET /runs/{id}/org-profile` withholds from them; and
  a breach whose HIBP metadata never arrived (rate limit, transport error) was
  written up with a fabricated `["Email addresses"]` data class, which asserts
  `has_passwords: false` and downgrades a password dump from critical to high.
  Breaches now carry `data_classes_known`, an empty class list means "not
  answered", and the finding says the exposure is unknown instead of implying
  it was harmless.
  Three were honest-reporting bugs of the same family the module's own
  invariant names. The controls matrix returned `ok` whenever any single
  control passed, so one evaluated control alongside five `not_checked` ones
  read as a clean bill of health; the verdict is now `partial`, the ladder
  `credential_leaks.py` already used inside one control, lifted to the matrix
  and carried through the API, ClickHouse and the UI. `soa_mname_not_in_ns`
  fired when the nameserver list had been truncated at `MAX_NS_PER_DOMAIN` —
  a finding about our own cap, not the zone. A DKIM lookup that failed at the
  resolver was reported as `selector_budget_exhausted`, sending the operator to
  the `dkim_selectors` knob instead of the resolver.
  The rest: an SPF diamond (two records both including a shared provider) was
  reported as an RFC 7208 loop, dropping mail_protection to `weak` — only an
  edge back to an ancestor is a cycle now; the crt.sh `O=` query read an
  unbounded response and appended one identical evidence dict per certificate
  row, so a common organisation name could exhaust memory (8 MiB cap,
  deduplicated at the source); `related_domains` took its seed set from
  `ownership.domains`, whose size is an RDAP call budget, so narrowing it to
  save calls silently reclassified the operator's own in-scope domains as
  related candidates — the stage has its own `domains` list now; and
  `auto_merge` logged "Auto-merged N domains into target list" for a file
  nothing reads, written by a stage that runs after the report.
  `related_domains.json` also gains `sources_evaluated`, a per-source candidate
  tally: with the default wiring `reverse_ns`/`reverse_mx` correlate over
  artifacts that cover exactly the seed set, and silence from an enabled source
  should not read as "no relatives exist".

### Added

- **Control matrix trend and an organization-wide view** (`org_profile` M3/M4,
  EPIC #182). The controls matrix existed only as a per-run snapshot: reading
  how a control moved meant opening two runs side by side, and the matrix was
  reachable only from inside a run. Three additions close that.
  `controls.json` now also lands in ClickHouse as
  `shapoclyack.shapoclyack_controls` — one row per control per run, ordered by
  `(tenant_id, control, timestamp, run_id)` so a single control reads as a
  timeline, with the run-level verdict denormalised onto every row and a
  365-day TTL (a control trend is only useful across release cycles). The
  transform normalises anything outside the scanner's own status/impact/risk
  vocabulary into the `not_checked`/`unassessed` bucket rather than widening
  the ClickHouse enums, keeping the module invariant that missing data never
  reads as `ok`. The table is created at worker connect
  (`CREATE TABLE IF NOT EXISTS`), not only by the first-boot init script, so an
  upgraded installation does not start failing every ingest message; where the
  ClickHouse user cannot run DDL the worker skips control rows and vulnerability
  and port ingest continues.
  `/org-profile` is a page of its own — owner, related domains with their
  evidence and the promote action, and the control matrix — defaulting to the
  newest run and pinnable to an older one via `?runId=`, with the attribution
  disclaimer on the page rather than only in the artifact. The dashboard gains
  a posture tile with the newest run's verdict; a run without the stage reads
  `not checked`, never `ok`.

- **Promoted related domains now reach the next scan** (`org_profile` M4,
  EPIC #182). `POST /api/runs/{id}/related-domains/{domain}/promote` used to
  append the domain to `promoted_domains.txt` in the run directory, and that
  was the whole feature: nothing read the file when the next scan started,
  and run retention (#187) deleted it with the run. The decision now lives on
  the tenant (`tenant_promoted_domains`, migration `0031`) and every ordinary
  scan the tenant starts carries those domains in addition to its own targets
  — as a separate `--promoted-domains` input the scanner merges into its name
  scope, so a run on the installation's default target files is widened rather
  than retargeted. Three boundaries: a promotion is checked against the
  approved scan scope (#226) when it is made (403, journalled in
  `auth_events`) and again when a scan starts (a domain the scope no longer
  covers, by suffix or by resolved address, is dropped and recorded on the
  job as `promoted_domains_refused`, not a reason to refuse the operator's
  own targets); a verification re-scan (#183) is never widened
  (`start_scan(widen_with_promoted=False)`, a switch of its own rather than
  the billing exemption); and a promotion can be withdrawn without the run
  that proposed it — `DELETE /api/promoted-domains/{domain}` (operator), the
  same undo from the run's Org Profile tab, whose *Promoted Scope* block
  lists the tenant's whole promoted list because a promoted domain is a seed
  on the next run and is never proposed again. Both directions are
  journalled in `auth_events` as `trust_change` with the actor. The tenant
  reads its own list at `GET /api/promoted-domains`; platform admins see
  what the operators added underneath the scope they approved via
  `GET /api/tenants/{id}/promoted-domains`.
  Nothing is grandfathered: the per-run files were never consumed, so there
  is no behaviour to preserve — domains promoted before this change are
  promoted again from the run's Org Profile tab.

- **Usage metering and per-tenant quotas** (ROADMAP Track E, enterprise
  operations & MSSP). An MSSP sells capacity, and the platform could express
  none of it: a tenant registered assets until the disk filled and started
  scans until the queue was the only limit, so neither the provider nor the
  customer could answer *how much of what we sold is being used*. That question
  is asked at renewal, and being unable to answer it is how a platform gets
  replaced by a spreadsheet.

  `tenant_quotas` (migration `0030`) holds `max_assets` and
  `max_scans_per_month` per tenant, `GET /api/usage` is the customer's own
  consumption against them with twelve months of scan volume,
  `GET /api/usage/tenants` is the provider's view across every tenant, and
  `GET/PUT /api/tenants/{id}/quota` is platform-admin only for the reason
  scan-scope approval is: a tenant operator who could raise their own quota is
  the control removing itself. The console gets a **Usage** page for the same
  two views.

  Three decisions are worth stating, because they are what makes this a
  product feature rather than a counter. **Usage is counted, never
  accumulated** — there is no `used` column; assets come from `assets` and
  scans from `jobs` at read time, so the meter cannot drift away from the
  lists the customer is looking at and be wrong about the invoice.
  **Quotas fail open**, unlike the approved scan scope of migration `0025`
  which deliberately does the opposite: a tenant with no row inherits a
  platform default that ships as unlimited, because an upgrade that started
  refusing customers' scans over a number nobody had typed yet would be an
  outage caused by billing. And the two limits are enforced at different
  moments — a scan is refused at admission with **429** and a `Retry-After`
  naming the reset, while an asset quota **never fails a scan**: the assets
  already inside the quota keep getting that run's data and only newly
  discovered hosts are left unregistered, loudly in the log and in
  `octo_quota_denied_total{resource}` but silently to the operator, because
  discarding a whole result set would punish the findings for the assets the
  customer did pay for. An endpoint agent's inventory is accepted for the same
  reason: the device stays `unlinked` and links itself once the quota is
  raised, and reviving a decommissioned asset spends capacity exactly as
  creating one does, since only `active` and `stale` are billed. Verification
  re-scans (#183) are exempt — quota-refusing the mechanical check that closes
  a finding would strand it in `VERIFYING` — and the exemption travels on the
  job (`jobs.quota_exempt`) rather than on a username, because that path
  carries the analyst's name and a name-keyed exemption would never have fired
  for it. An exempt scan is also excluded from the count: work a customer
  cannot decline is work they should not be billed for.
  Enforcement is separable from metering (`OCTO_QUOTA_ENFORCEMENT_ENABLED`),
  because an MSSP usually wants to watch consumption against the number it
  sold for a period or two before it starts refusing its customer's scans.

- **An Adoption page: is the product producing outcomes, or data?** —
  ROADMAP Track E ends with a list of what would have to be measured before
  any of its features can be called a success, and with the admission that
  none of it was measurable. `GET /api/adoption?window_days=…` (viewer, one
  tenant) and the **Adoption** console page now compute it from tables that
  already existed: closures in the window and the share a scan confirmed
  (`machine_verified`, so the page cannot disagree with the Vulnerability
  Center's summary), the share closed within SLA, median time to fix overall
  and by severity, reopen share, open findings per asset; active assets with
  an owner, with business context, seen by a run in the last 30 days, and
  also reporting an endpoint inventory; closed-and-verified per analyst — the
  quarterly control question, as a table; hours from tenant creation to the
  first successful scan and the first tracked finding; and the age of each
  enrichment overlay. Two rules shape every number: a share with nothing to
  divide by is `null` (rendered `n/a`), never 0% or 100%, and durations are
  medians, so one finding that sat for a year while procurement argued does
  not move the number a security lead is judged on. Nothing leaves the
  installation; the opt-in aggregated export ROADMAP also names is not built.

- **Report factory and compliance mapping** (ROADMAP Track E, Sprint 4). An
  MSSP sells the report, and the platform had one: a per-run PDF with this
  project's name on it. There is now a branded, scheduled, per-tenant report
  factory, and a compliance mapping to put in it.

  *Reports* are built once into a plain body and rendered three ways — PDF,
  HTML, JSON — so the JSON an MSSP pipes into its own portal is **the same
  report** as the PDF its customer opens, rather than a second implementation
  that can disagree with it. Three kinds: executive (KPIs, trend, SLA,
  compliance scores), technical (top findings, asset coverage) and compliance
  (one framework's full control table). Every number comes from the tracked
  findings and the asset registry, never from a run directory, so a report about
  a quarter still renders after that quarter's runs were pruned.

  *Branding* is a per-tenant row: name, colours, a base64 PNG logo, footer.
  Bytes rather than a path or a URL — a path stops resolving on whichever
  replica renders, and a URL would have the renderer fetch from the network at
  render time, which is an SSRF sink reached by editing a settings field.
  Colours and the PNG magic number are validated on write, so a mistake fails
  the operator's request instead of the 03:00 render on the first of the month.

  *Scheduled delivery* (`report_schedules`, cron, admin-only) goes out over SMTP
  or the event webhooks' SSRF-validated, DNS-pinned, no-redirect wire, with the
  target re-validated on every send. Each report records **one delivery entry
  per recipient**: "sent" is not true when three of four bounced. The dispatcher
  is the scan dispatcher's twin — thread per replica, Postgres advisory lock —
  with one deliberate difference: `next_run_at` advances *before* the render,
  because the same PDF cannot be un-sent to a customer. A replica that dies
  mid-render skips the occurrence rather than repeating it. A failed render is a
  `failed` row with the error on it and the schedule still advances; leaving it
  due would retry every tick, to every recipient, for as long as the failure
  lasts.

  *Compliance* classifies findings and estate facts into a closed vocabulary of
  signals, and PCI DSS 4.0, CIS Controls v8 and ISO/IEC 27001:2022 are written
  against that vocabulary rather than against CVEs — so a fourth framework is a
  catalogue entry, not a re-classification of the estate. The honest parts are
  the load-bearing ones: a control this platform cannot observe is **absent from
  the catalogue**, a control with no evidence in a tenant is `not_assessed` and
  excluded from the score (an empty estate scores nothing, not 100%), accepted
  risk is reported per control but does not fail it, and the score is the share
  of *assessed* controls passing — returned with the catalogue's scope note so
  it cannot be presented as compliance with the standard. Downloads re-derive
  the file path from the row's own ids rather than trusting the stored string.

  Console: a Compliance page with per-control evidence, and a report factory
  panel on Reports. Migration `0029`.

- **Patch-gap analysis** (ROADMAP Track E, M2). The software→CVE matcher
  answers "is this package vulnerable", one row per CVE. That is the right
  unit for a finding and the wrong unit for the work: nobody fixes twelve CVEs
  on a host, they run one upgrade that closes twelve CVEs. Patch gap regroups
  the matcher's `vulnerable` rows by the thing that actually gets upgraded —
  the installed package — and names the command.
  `GET /api/endpoint/patch-gaps` for the estate,
  `GET /api/endpoint/devices/{id}/patch-gap` for one host.

  **No table of its own.** A gap is a view over `software_cve_matches`,
  computed on read. The matcher already replaces its rows wholesale per device
  on each run, so a derived gap cannot outlive the snapshot behind it or
  disagree with the finding it came from; a stored one would need its own
  invalidation and would eventually be wrong. No migration.

  **A vulnerable package with no published fix is not a patch gap.** "Affected,
  no fix yet" is an open risk, and putting it under a heading that says "run
  these commands" would be advice that cannot work. Those are counted as
  `unfixed_findings` and carry no command — the same distinction the matcher
  makes with `unknown`.

  **The target version is the highest fix among the package's CVEs**, ordered
  by the distribution's own rules, so one command per package is correct rather
  than convenient: a plain string comparison would rank `2.10` below `2.7` and
  name a target that closes only some of them. When the fixes cannot be ordered
  the gap reports no target and no command, rather than guessing one.

  Package names are shell-quoted. They come from a remote endpoint's inventory
  and the result is rendered for an operator to paste into a root shell, so a
  package name is data there, never syntax.

  In the console: a patch-gap panel on `/endpoints` that stays hidden when
  nothing is outstanding, and a per-device card with a copyable command on the
  asset page's Software tab.

- **Related domains: reverse-MX discovery** (org profile). A fourth discovery
  source alongside cert SAN, reverse-NS and WHOIS: domains that publish the
  same mail exchangers. Public providers are excluded through
  `excluded_mx_providers` — "both use Google Workspace" is not evidence of
  common ownership — and an exchanger only counts when it is shared with a
  seed domain, the same requirement `reverse_ns` carries. The source is
  weighted 0.45 against cert SAN's 0.70, because a shared mail host is weaker
  evidence than a shared certificate.

  `auto_merge` now requires `merge_into_scope` to also be set before anything
  is added to the scan scope. `auto_merge` alone logs that it was asked to
  merge and did not: widening what gets scanned is the one action in this
  module with legal consequences, so it takes a second, explicit switch rather
  than being a side effect of enabling discovery.

- **Credential leaks: identifier reveal is opt-in.** `reveal_identifiers`
  gates whether leaked account identifiers are written to the artifact at all.
  Left off, `domains` is empty and the artifact says so — `revealed: false`
  with `withheld_reason` and `withheld_identifiers` — so a reader can tell
  "we found nothing" apart from "we are not showing you what we found". The
  count survives the withholding because the aggregate is the part that is
  safe to keep.

  The org-profile summary also reports `attempted_domains`, which makes a
  partial run legible: three domains checked out of eight is a different
  statement from three domains clean.

- **Closed-loop remediation: mechanical verification** (#183). "Fixed" was an
  assertion an operator made about their own work. A finding can now be sent
  for a targeted re-scan (`POST /vulnerabilities/{id}/verify`), and the run
  that comes back decides: not observed closes it with
  `closure_reason=verified_remediated` and `machine_verified=true`, still
  observed bounces it `VERIFYING → FIXING` with the reason on the audit trail.

  The closure is gated on `verification_job_id` — the job that was dispatched
  to look for *that* finding — and not on "some scan touched the asset". Any
  weaker gate silently converts a routine recon run into a clean bill of
  health for a finding it never probed. For the same reason the move into
  `VERIFYING` is refused outright when the scan cannot be dispatched
  (`OCTO_ALLOW_SCAN_START` off, dispatcher error): a finding parked there with
  nothing looking at it is exactly what produces a false verified closure
  later. A verification run that finds *nothing at all* still reaches the
  evaluation, because for this feature an empty run is the success case.

  `machine_verified` is never accepted from a request body. Closing by hand
  records `closure_reason=manual` whatever the caller says, and a metric an
  operator can assert about their own work measures nothing. Summary gains
  `closed_total`, `machine_verified_closed`, `manual_closed` and
  `machine_verification_rate`; the Remediation board gains the KPI and a
  Verified badge, and the finding page gains Verify / Sync buttons.

- **Two-way ticket status sync** for Jira, ServiceNow and DefectDojo
  (`api/services/integrations/ticket_sync.py`,
  `POST /vulnerabilities/{id}/ticket/sync`). Inbound polling reconciles the
  tracker's status onto the lifecycle; a state change reflects outbound.

  The tracker is addressed through the tenant's subscription for that
  transport, not by string-splitting the stored `ticket_url`: that is where
  the credential lives, so the requests actually authenticate, and a URL we
  did not configure is one we do not call. The wire is `delivery.request`,
  which is `delivery.post`'s SSRF validation, pinned DNS and no-redirects
  generalised to GET and PATCH. Inbound only applies a *legal* transition, and
  a closure from a tracker is `ticket_resolved` — never machine-verified,
  because a tracker cannot observe a host. A ServiceNow update resolves the
  incident's `sys_id` first; the Table API ignores a PATCH to the collection
  URL. Outbound reflection runs after the transaction commits, so a slow
  tracker cannot hold a row lock for its ten-second budget.

- **Enterprise IAM: OIDC single sign-on and service tokens** (ROADMAP Track E,
  "No SSO"). The platform had exactly two ways to authenticate — a human's
  password and an agent's provisioning key — so a pilot could not be run
  against a corporate identity provider, and every integration ran under
  somebody's console account.

  *SSO* is authorization code with PKCE against a generic OIDC provider
  (`api/services/oidc.py`, migration `0026`). Endpoints and signing algorithms
  come from the provider's `.well-known/openid-configuration`; only the issuer
  and the client credentials are configured here, and SSO stays off until all
  three are set. The ID token is verified rather than read — signature against
  the published JWKS with an **asymmetric-only** algorithm allowlist (so
  neither `none` nor an HMAC keyed on the client secret is selectable), then
  `iss`, `aud`/`azp`, `exp` and the nonce. An unknown `kid` refetches the key
  set exactly once, which is key rotation; more would be a request amplifier.
  State is signed *and* single-use, and the nonce and PKCE verifier stay
  server-side, so a callback cannot be replayed and a stolen state discloses
  nothing. `GET /api/auth/oidc/callback` issues the platform's ordinary session
  token — same JWT as password login, because nothing downstream should care
  how the user proved who they are.

  Account linking is deliberately conservative: a stored `(issuer, subject)`
  first, then a **verified** email that both the provider and an admin vouch
  for, and only then just-in-time provisioning — which is **off by default**,
  never provisions over an existing local username, and defaults to `viewer`.
  Linking on an unverified address would hand a console account to whoever can
  register that address at the identity provider. Every outcome, refusals
  included, lands in the existing `auth_events` trail.

  *Service tokens* (`api/services/service_tokens.py`, routes under
  `/api/tenants/{id}/service-tokens`, admin-only) are `octo_st_…` credentials
  scoped to one tenant. Only a bcrypt hash is stored — the plaintext exists
  once, in the create response — and the public prefix makes verification one
  indexed lookup rather than a bcrypt check per issued token. A token passes
  two independent limits: the role it was issued with inside its own tenant (no
  membership row raises it, and an `admin`-role token is never a *platform*
  admin), and `resource:action` scopes derived from the request path and
  method. `auth`, `users` and `tenants` are closed to every token whatever its
  scopes, because a credential that can mint users or further tokens outlives
  its own revocation. Every token expires, and `last_used_at` is rate-limited
  so a busy integration does not rewrite the same row on every call.

  The console gains a service-token screen and a "Sign in with SSO" button that
  appears only when the API reports a provider is configured (`GET
  /api/auth/sso`, also embedded in `/api/health` because the login form renders
  before anyone is signed in). See
  [docs/api-and-rbac.md](docs/api-and-rbac.md#single-sign-on-oidc) and
  [docs/configuration.md](docs/configuration.md#environment-variables).
- **Endpoint software is matched against vendor advisories** (ROADMAP Track E,
  milestone 1) — Lariska has collected installed software since Agent_plan.md
  S1-S7 and nothing had ever asked whether any of it was vulnerable, which was
  the biggest functional gap on the roadmap and the cheapest to close, because
  the data was already in Postgres. `GET /api/endpoint/devices/{id}/cve-matches`
  and `GET /api/endpoint/cve-matches` now answer that, per endpoint and per
  CVE, and an operator can re-run the matcher with the paired `…/refresh`
  routes. The asset page's Software tab renders the result above the inventory
  it came from. Migration `0027` adds `software_cve_matches`.

  Matching goes through **Debian's Security Tracker and Ubuntu's USN database**
  rather than NVD's CPE version ranges, and that is the whole design rather
  than a detail. Ubuntu 20.04 has shipped OpenSSL `1.1.1f` since 2020 and will
  until it dies; the fixes arrive in the revision (`-1ubuntu2.16`). A matcher
  comparing upstream versions calls every such host vulnerable to every OpenSSL
  CVE forever — thousands of findings per host that never clear — and the
  operator stops reading the output, which is worse than shipping nothing. The
  vendors publish the statement that actually answers the question ("fixed in
  `1.1.1f-1ubuntu2.8` on focal"), so that is what the matcher compares against,
  with pure-Python transcriptions of dpkg's `verrevcmp` and rpm's `rpmvercmp`
  doing the comparison — epochs, `~` and `^` included, tested against the
  tables the package managers themselves ship. No new dependency.

  A match is `vulnerable`, `fixed`, `not_applicable` or **`unknown`**, and the
  last one is not a placeholder. An endpoint whose distribution could not be
  resolved, or software that came from outside a distribution package manager,
  produces an explicit `unknown` row naming the reason — never a silent
  omission, because an unassessable host rendering as clean is the one failure
  mode worse than a false positive. `docs/software-cve-matching.md` states what
  is not covered: language ecosystems, Windows, non-distribution software, and
  every distribution other than these two.

  The advisory datasets are offline-first, exactly like the EPSS/KEV/CVSS4
  overlays: JSON under `scanner/data/advisories/` with the same envelope, the
  same `OCTO_*_DATABASE` overrides, the same build-time manifest, and the same
  provenance row on the System page. The image ships a small seed of real
  advisories, not a feed dump; refreshing from the vendors is opt-in
  (`OCTO_ADVISORY_FETCH_ENABLED`), bounded, and off by default, and nothing on
  a request path ever opens a socket.

- **Shapoclyack is licensed under Apache-2.0** — until now the repository
  carried no licence at all, which meant the default position of "all rights
  reserved" applied while the images were published to a public registry and
  `SECURITY.md` promised version support to people running them. `LICENSE` is
  the verbatim Apache-2.0 text; `NOTICE` carries the attributions that have to
  travel with a redistribution, and both are now copied into all three images
  rather than living only in the repository — the EPSS overlay is CC BY 4.0 and
  is baked into every image as seed data, so the attribution has to travel with
  the bytes. Apache-2.0 rather than MIT for the explicit patent grant, which is
  not a formality for a scanner; and rather than a copyleft licence, which
  would have made the aggregation in the opt-in `-nmap` tag harder to reason
  about for no gain. Nothing in the dependency set required this choice: the
  GPL-3.0 components (nmap-vulners, Vulscan) are opt-in and invoked as separate
  programs, and the LGPL-3.0 libraries (fpdf2, psycopg) are used unmodified
  through their public interfaces. `docs/third-party.md` now states the
  project's own terms alongside everyone else's, and says plainly that an image
  is an aggregate governed by its most restrictive component.

### Changed

- **`python -m scanner.main --validate-config` exists.** Two guides told the
  operator to run it before a first scan; the flag had never been implemented,
  so the documented pre-flight check failed with an argparse error. It now
  parses the file through the same schema the pipeline uses, starts no external
  tool, prints the offending key on failure and exits `2` — which is what
  `docs/getting-started.md` and `docs/configuration.md` already claimed.

- **`Agent_plan.md` records the assessment layer, not just the contract.** The
  endpoint design record ended at S10 while the inventory it defines had grown
  a software→CVE matcher and patch-gap analysis reading from the same
  snapshots. It now carries the `cve-matches` / `patch-gaps` routes and their
  `viewer`/`operator` split, the `software_cve_matches` column contract and the
  `unknown_reason` vocabulary, the console panels, the matcher test suites, and
  five further ADRs — matches are derived and replaced wholesale, `unknown` is
  a result rather than an omission, a patch gap is a view with no table,
  matching is on-demand, advisories are offline-first. Two Prometheus metric
  names in it never matched the code and now do
  (`octo_endpoint_inventory_ingest_duration_seconds`,
  `octo_endpoint_retention_deleted_total`). What is *not* covered is stated as
  its own section rather than left to inference: other distributions, language
  ecosystems, Windows and macOS, the findings lifecycle, kernel livepatching,
  and the fact that nothing re-runs the matcher when a snapshot arrives, so a
  device's matches can be older than its inventory. `ROADMAP.md`'s Track D row
  says the same.

- **Documentation pass over `main`.** Corrections rather than new prose, each
  against the code:
  - `docs/configuration.md` conflated the two profile settings into one table
    that listed a `thorough` speed profile — `runtime.mode` accepts only
    `safe`/`balanced`/`fast`, and `thorough` is a `discovery.profile` preset.
    Both are now documented separately, with the `auto` mapping between them.
  - the protocol example named a `scan:` section that does not exist and a
    `both` value that no code accepts; the key is `ports.protocol`, and the
    combined value is `tcp_udp`.
  - a map of every top-level config section and where it is documented, plus
    the fact that an unrecognized key is *ignored* rather than refused.
  - `docs/ui.md` was missing `/compliance`, `/wordlists` and `/service-tokens`
    entirely, and the report factory, patch-gap panel and the Verify action.
  - `docs/vulnerability-lifecycle.md` still said there was no ticket-status
    sync and that `VERIFYING → CLOSED` was manual; it now documents mechanical
    verification, `machine_verified`, the closure reasons and the new event
    kinds.
  - the Track E gap table still listed SSO and the closed loop as missing after
    both had landed.
  - Node.js is 26, not 24 (`engines.node`, CI, and both builder images).
  - `docs/projectdiscovery-integration-concept.md` linked its own repository
    through `file:///Users/…` absolute paths, and neither Russian-language
    guide was labelled as such in the documentation index.

- **Controls matrix reads versions, not banners.** A banner counts as
  disclosing a version only when it carries a digit-dotted token
  (`nginx/1.24.0`), not a bare product name (`nginx`). The matrix previously
  scored the second as a disclosure, which made "hide your version" advice
  fire against servers that were not publishing one.

### Security

- **Both accepted CRITICALs are fixed at the root, not ignored** —
  `CVE-2025-68121` (Go stdlib `crypto/tls`, certificate validation on TLS
  session resumption) and `CVE-2026-56854` / GO-2026-6303
  (`golang.org/x/crypto/ssh` below 0.55.0, the `source-address` critical option
  not enforced) were exceptions in `.trivyignore` because they lived in
  prebuilt dnsx/naabu/nuclei release archives: the first is fixed only by a
  compiler >= Go 1.24.13, the second by a dependency bump, and neither can be
  applied to a binary someone else built. Checked against the module proxy, no
  upstream release carries the fix even now — the newest dnsx (1.3.1) is on
  x/crypto 0.52.0, naabu 2.6.1 on 0.46.0, nuclei v3.11.1 on 0.53.0 — so
  waiting was the only thing the exceptions were doing.
  `Dockerfile` and `Dockerfile.allinone` now build all three from source in one
  `go-tools` stage on `golang:1.26`, with `GO_SECURITY_PINS` forcing fixed
  dependency versions over each tool's own `go.mod`. The pinned tool versions
  are unchanged (dnsx 1.2.3, naabu 2.6.1, nuclei v3.11.1); each gets its own
  throwaway module so a shared dependency graph cannot silently upgrade one
  tool to another's requirements, and the stage asserts every pin that is
  linked into a binary is at the pinned version (`go version -m`) — the same
  build metadata Trivy reads, so a silent regression fails the image build
  rather than the gate. The tool and its pins go into a single `go get`:
  fetching them one at a time re-resolves the graph per call and leaves go.sum
  without the entries an earlier step had settled (x/exp, via goflags), which
  the build then fails on.
  Beyond x/crypto v0.56.0, the list carries the three fixes nuclei had not
  picked up either — go-git v5.19.2 (CVE-2026-71556), x/mod v0.40.0
  (CVE-2026-56864, CVE-2026-56865) and grpc v1.83.1 (CVE-2026-84304). These are
  HIGH, below the CRITICAL gate, and were found by scanning the built image
  rather than by CI. utls v1.8.2 (CVE-2026-27017) joins them for dnsx — pinned
  at 1.8.2 rather than the 1.8.1 that carries the fix because naabu 2.6.1
  already requires 1.8.2, and `go get` fails the build outright rather than
  downgrading a module a tool pins higher. After the change every Go binary in
  the image reports no vulnerabilities at any severity.

- **The image's base and pip are current again** — a digest pin is
  reproducible, never current, so every Debian security update since it was
  taken was a finding the scan reported against us. `Dockerfile`,
  `Dockerfile.allinone` and `Dockerfile.api` move to the `python:3.12-slim`
  index digest of 2026-09-07, which clears every fixable HIGH in the OS layer
  (30 of them) and all but five fixable MEDIUM. All three then install a
  pinned `pip==26.2.1` before requirements, closing five MEDIUM and one LOW
  the base's bundled pip 25.0.1 carried.
  Two things the bump does *not* fix, both worth knowing. The three CRITICALs
  in `perl-base` (CVE-2026-13221, CVE-2026-42496, CVE-2026-8376) survive it:
  Debian publishes no fixed perl, apt offers no candidate above 5.40.1-6, and
  `perl-base` is Essential so it cannot be removed. They are excluded from the
  gate by `--ignore-unfixed`, not by an exception. And the newer pip makes
  three findings appear that the older one hid — its vendored setuptools
  70.3.0 and msgpack 1.1.2. That is disclosure, not regression: pip 25.0.1
  vendors the *same* setuptools 70.3.0 and an older msgpack 1.1.0, and only
  26.x ships the CycloneDX SBOM that lets Trivy see them. They are inside the
  pip wheel and not separately upgradable. Upstream builds all
  three with `CGO_ENABLED=0 -s -w` (their `.goreleaser.yml` and `Makefile`),
  which is what the stage does, so the binaries differ from the released ones
  only in the toolchain and the x/crypto bump; naabu's SYN path is unaffected
  and still needs no libpcap. The per-arch sha256 pins on the release zips are
  gone with the downloads — module downloads are verified against Go's checksum
  database (GOSUMDB) instead, the trade this file already made for nuclei.
  `.trivyignore` became `.trivyignore.yaml` and now holds no exceptions at all;
  what remains is the format, the rule that any future entry carries an
  `expired_at` review date so it cannot outlive its justification, and the
  standing note that GHSA-r277-6w6q-xmqw must never be added (nuclei v3.11.1
  already pins the fixed kin-openapi 0.144.0). The Jenkins `--ignorefile` mount
  and `SECURITY.md` point at the new file; the (currently dispatch-only) GitHub
  Actions gate names it through `TRIVY_IGNOREFILE` rather than the action's
  `trivyignores:` input, which copies the listed files into one temporary file
  with no extension — and Trivy picks its YAML parser by extension, so the file
  would have been read as plain text, every line taken for an ID, and any
  exception would have stopped applying without an error.

- **An SSH destination can no longer be read as an `ssh` option** —
  `_execute_openssh_command` built its destination as `f"{username}@{host}"`
  and appended it to argv, where neither field was validated beyond a length.
  A `username` or `host` beginning with `-` is parsed by `ssh` as an option
  rather than a destination, and `-oProxyCommand=…` is then run by `/bin/sh`
  **in the API process** — before the host key is compared, so the pin (#232)
  and the outbound-target policy (#240) both sit behind it and neither is
  reached. `ssh-keyscan` took `host` the same way in `_probe_with_keyscan`.
  Two barriers now, because the schema is the kind of thing a later field
  addition quietly loosens: `AgentDeploySSHRequest` and
  `AgentSSHHostKeyProbeRequest` constrain both fields to what a destination
  can legitimately be made of, and both argv builders pass `--` before the
  destination so option parsing has already ended. Not reachable in the
  published images, which ship neither `paramiko` nor `openssh-client` — the
  deployment path fails earlier with `HostKeyUnavailable` — but that is a
  missing dependency, not a control, and it goes away the moment the feature
  is made to work.

- **`CVE-2026-56854` / `GO-2026-6303` accepted as a documented Trivy
  exception** — `golang.org/x/crypto/ssh` failed to enforce the
  `source-address` critical option for `Permissions` returned by the password,
  keyboard-interactive, no-client-auth and GSSAPI callbacks. The affected
  symbols are `ssh.NewServerConn` / `serverAuthenticate` — the SSH **server**
  side. All three bundled Go binaries carry the package below 0.55.0 as an
  indirect dependency (dnsx 1.2.3 on 0.45.0, naabu 2.6.1 on 0.46.0, nuclei
  v3.11.1 on 0.53.0) and none of them accepts an SSH connection: nuclei has an
  SSH *client* for templates, dnsx and naabu never touch the package. No
  upstream release carried the fix at the time, so the gate was failing every
  build on a symbol none of the binaries can reach. Same shape, and the same
  standing obligation, as the `CVE-2025-68121` exception above it in
  `.trivyignore`: bump the pins when upstream rebuilds, and do not extend the
  exception to any *client*-side `x/crypto/ssh` advisory.

### Fixed

- **The SSH push deployment survives a non-POSIX login shell and finds its
  own installer** — the first live run of `POST /api/agent/deploy/ssh`
  against a real host (2026-09-02) stopped twice before reaching `sudo`.
  The remote command was handed to the target user's login shell as-is, and
  under fish `INSTALLER=$(mktemp)` is a syntax error: exit 127 before
  anything ran. It is now `sh -c '…'`, so the login shell only passes one
  argument through and the script's dialect is ours. Then
  `GET /api/agent/install.sh` answered 404 because it read
  `scripts/install-agent.sh` relative to the process's working directory,
  which is `/app` in the images and anything at all for `python -m api`; it
  resolves from the package now, with `OCTO_AGENT_INSTALLER` as an override.
  The installer's `--docker` mode also named an image that does not exist
  (`ghcr.io/onixus/shapoclyack:latest`); it runs `shapoclyack-scanner`
  (`AGENT_IMAGE` overrides) — with `--entrypoint python`, because that
  image's entrypoint is `scanner.main` and `python -m agent` after it was
  parsed as scanner arguments (`unrecognized arguments: python -m agent`,
  restart loop), and with `NET_RAW` and `NET_ADMIN`, because `naabu` in the
  image carries file capabilities and a container without them cannot exec
  the binary at all (`Operation not permitted: 'naabu'`, and the `ports` stage
  fails even in CONNECT mode). Verified by running the container by hand on
  the same host: the agent exchanged its provisioning key, registered, went
  online, claimed a job and completed a scan of its own host. What the same run confirmed and did not change:
  a non-root user needs passwordless sudo, and a native install needs a
  staged agent package — both now stated in
  [docs/operations.md](docs/operations.md#ssh-push-deployment).

- **The SQLite dev fallback brings an existing file up to the models** —
  `create_all` creates absent tables and leaves existing ones alone, so a dev
  database made before a model gained a column kept its old shape and the
  first query naming the column failed (`no such column: users.email` on a
  `scanner/state/octo_man.db` from before OIDC; `test_security_headers_middleware`
  tripped over it on any machine with such a file). Postgres has Alembic for
  this and SQLite had nothing but "delete your database". The engine now adds
  each missing column with `ALTER TABLE … ADD COLUMN` on open — the additive
  case a model change almost always is — and never drops, renames or retypes;
  a NOT NULL column without a default is added nullable, since the rows that
  predate it genuinely have no value for it. A Boolean's `server_default` is
  written as `0`/`1` rather than quoted: the models write
  `server_default="false"`, and `DEFAULT 'false'` stores the *text* in a
  database with no boolean type, which SQLAlchemy's `Boolean` reads back
  truthy — so every backfilled row would have come out `True`.

- **Webhook fan-out and dispatch are switched independently, and the
  per-tenant subscription cap holds under concurrent creates**
  ([#153](https://github.com/onixus/Shapoclyack/issues/153)) —
  `OCTO_WEBHOOK_DISPATCH_ENABLED=false` used to stop the fan-out consumer as
  well, so "confine outbound HTTP to these replicas" also meant "only these
  replicas turn events into deliveries", and a fan-out worker that never
  opens a connection to a third party was not a shape the flags could
  express. `OCTO_WEBHOOK_FANOUT_ENABLED` (default `true`) gates the consumer
  on its own; the four resulting modes — default, API-only, fan-out worker,
  egress worker — are in [docs/architecture.md](docs/architecture.md#webhook-deployment-modes)
  with what each needs and what accumulates when a half runs nowhere.
  The cap on subscriptions per tenant was count-then-insert, which two
  requests could both pass at N-1; creates now lock the tenant row for the
  transaction, so the count the second request sees includes the first's row.
  A Postgres test races eight creates for the last slot and asserts one
  succeeds. Queue depth and consumer lag already had metrics
  (`octo_webhook_delivery_queue`, `octo_nats_consumer_pending`), and the kill
  switch over a queued backlog was pinned by a test in 0.43; those two items
  of #153 needed no code.

- **The api and aio images now ship `openssh-client`, and the SSH push
  deployment is tested against a real `sshd`** — `shapoclyack-0.43-0828`
  documented UI-driven SSH deployment, pinned host keys and a removal route
  for the pin, and none of it could run: `api/services/agent_deployer.py`
  shells out to `ssh` and `ssh-keyscan`, and neither the `api` nor the `aio`
  image installed them, so every deployment failed at the probe with
  `HostKeyUnavailable` before anything reached the target. The package is the
  Debian one (`openssh-client`, the only apt package in the api image);
  `paramiko` stays undeclared, since the OpenSSH path is complete and a
  second SSH implementation is a second place for #272 to happen.
  `tests/test_ssh_deploy_live.py` hands the deployer's argv to that client
  against a real server — ROADMAP recorded that this had never been done, and
  #272 is what the gap cost — and checks the probe's fingerprint against the
  server's own key file, the password through `SSH_ASKPASS`, stdin reaching
  the remote command, a private-key login, and that a wrong pin is refused by
  the client with no prompt. Locally it is `tests/e2e/ssh-deploy.sh`; in CI it
  is the `SSH deploy (live sshd)` stage, with the server pinned by digest.

- **The datastore NetworkPolicies are verified under a CNI that enforces
  them** — #225 shipped `base/networkpolicy-datastores.yaml` reviewed and
  validated as objects, and ROADMAP recorded that enforcement had never been
  exercised: kind's default CNI ignores NetworkPolicy, so nothing in any lab
  had ever dropped a packet because of them.
  `k8s/scripts/verify-networkpolicy.sh` creates a throwaway kind cluster with
  Calico (pinned), deploys the real `kind-dev` overlay, waits for the API to
  come up through the allow rules, then connects from an unlabeled pod, a
  `backup`-labelled pod, an `agent`-labelled pod and the API pod to every
  datastore port. Run 2026-09-02 under Calico v3.30.3: 16 of 16 rows matched
  the manifest, and the datastores' kubelet probes survived the policy as its
  note on host traffic predicted. The result is recorded in
  [docs/operations.md](docs/operations.md#networkpolicy-decision).

- **Migration `0025`'s grandfather path has a test that runs it** — the
  insert that keeps existing tenants scanning after the upgrade to
  fail-closed scopes (#226) is the one line that decides whether an upgrade
  is safe, and it had only ever been checked by hand: the CI database is
  migrated to head before the suite starts, so nothing in it ran `0025` over a
  tenant. `tests/test_migration_0025_grandfather.py` creates a sibling
  database, brings it to `0024`, inserts tenants, upgrades to head and asserts
  the three allow-all rows per tenant stamped `migration-0025`, that
  `load_scope` reads them as allow-all in both address families, that a tenant
  created after the upgrade gets nothing and is refused, and that the
  documented downgrade drops the table and the `auth_events.detail` column
  with it. Postgres only, like the migration.

- **A JetStream stream that cannot be created is a startup failure, not a
  warning** — `NatsBus._ensure_stream` logged `stream INGEST not ready after
  retries` and returned normally, so `_connect` succeeded, the bus came up
  `_started`, and every later publish failed on its own with
  `NoStreamResponseError`. `start()` was already written to disable the bus
  for the process when `_connect` raises, which is the right outcome for an
  unreachable broker; the quiet return is what defeated it. The failure mode
  in production is a replica that starts while JetStream is still opening a
  cold store and then silently publishes nothing for its whole lifetime, on a
  bus reporting itself healthy. The retry budget also grew from five attempts
  over two seconds to eight over twelve, because "no responders" from a cold
  JetStream lasts seconds, and `start()`'s own timeout now covers that budget
  so the error naming the stream is not replaced by a flat timeout. The
  `add_stream` exception is kept separately from the `stream_info` one, which
  used to overwrite it with a `stream not found` that explained nothing, and it
  is rendered with `str()` rather than `repr()` — `nats`' `ServerError` carries
  the server's description in its message and reprs as a bare `ServerError()`.
  What that surfaced immediately: CI asked a throwaway broker for the
  production stream sizes (10 GB for `INGEST`), which JetStream reserves up
  front and refuses with `insufficient storage resources available` once the
  host is full. The test broker is now sized for a broker that lives minutes.

- `Settings.agent_jwt_expire_minutes` defaulted to 60 in the dataclass and 120
  in `load_settings()`; `docs/configuration.md` documents 120. Anything
  constructing `Settings()` directly — tests, scripts — minted agent tokens
  with half the documented lifetime. Both are 120 now.

- The first-scan walkthrough approved a scope that did not cover its own
  example targets: step 2 of [docs/getting-started.md](docs/getting-started.md)
  uses `203.0.113.10`, and step 6 allowed only `198.51.100.0/28`. Scope refusal
  fails the whole job, so a reader who followed every step without a typo still
  met the `403` that step 6 exists to prevent.

- `docs/README.md` claimed the guides described `main` after
  `shapoclyack-0.40-0806`, three releases behind, and pointed at a
  `## Unreleased` section that the 0.43 cut had emptied.

## [0.43-0828] — 2026-08-28

### Added

- **Removing an SSH host-key pin is a route, not a SQL statement**
  ([#241](https://github.com/onixus/Shapoclyack/issues/241)) —
  `DELETE /api/agent/deploy/ssh/host-key?host=…&port=…` (tenant **admin**, the
  same bar as deploying) drops this tenant's pin and answers with what it
  removed, so the fingerprint being dropped is in front of the operator; `404`
  when nothing was pinned. Reinstalling a machine is ordinary, and until now
  the only way through was a `DELETE` against `agent_ssh_host_keys` in
  Postgres — a privilege an order of magnitude above running an agent fleet, so
  the predictable substitute was passing whatever fingerprint the target
  offered as `expected_host_key`, which leaves the check formally on and
  meaning nothing. The next deployment needs `expected_host_key` again: a
  rebuilt machine is re-verified, never silently re-trusted. Setting and
  removing a pin are both journalled with the tenant, target and fingerprint
  under the new `trust_change` outcome
  (`GET /api/auth/events?outcome=trust_change`) — that pair is what separates a
  planned rebuild from a substitution after the fact. No schema change; the
  SQL procedure in [docs/operations.md](docs/operations.md#ssh-push-deployment)
  is replaced by the route.

- **Approved scanning scope per tenant** ([#226](https://github.com/onixus/Shapoclyack/issues/226)) —
  target validation used to be a syntax check, so any well-formed CIDR or FQDN
  from any tenant was accepted: `169.254.169.254/32`, the provider's cluster
  range, or a third party's network, scanned from the platform's own address,
  with nothing recording whether that tenant had been entitled to. The new
  `tenant_scan_scopes` table (migration `0025`) stores allow/deny entries for
  CIDRs and domain suffixes, each with who approved it and when. Deny beats
  allow by *overlap* (`10.0.0.0/8` is not a way to reach a denied
  `10.1.2.0/24`), allow is containment (a partly approved range is not partly
  approved), and a tenant with no entries starts no scan at all — including one
  that would have used the installation's default target files.
  The check runs in `parse_target_payload` when targets are submitted **and**
  again in `jobs_service.start_scan` when the scan starts, which is the barrier
  that covers `schedule_dispatcher` replaying targets stored days earlier
  against a scope that has since been narrowed. Domains are also checked after
  resolution, against deny ranges only (`OCTO_SCAN_SCOPE_RESOLVE_CHECK`), so a
  name inside the scope by suffix is not a way into a denied address.
  Refusals answer `403` and land in the existing access-decision journal
  (`GET /api/auth/events?outcome=denied`, with the offending targets in the new
  `auth_events.detail` column). `GET`/`PUT /api/tenants/{id}/scan-scope` manage
  the scope, platform admin only — the same bar #231 set for minting a
  provisioning key.
  **Breaking for existing installations, with a migration path:** enforcement
  is fail-closed, so `0025` grandfathers every tenant that exists at upgrade
  time with an explicit allow-all scope stamped `approved_by = migration-0025`.
  Nothing stops scanning on upgrade and the permission is a visible row an
  admin narrows, rather than an implicit "no scope means everything" rule;
  tenants created after the upgrade start fail-closed. Narrowing procedure in
  [docs/operations.md](docs/operations.md#approved-scan-scope-per-tenant).

- **Zone hygiene and mail posture — org profile M2** ([#182](https://github.com/onixus/Shapoclyack/issues/182)) —
  two new opt-in scanner stages, both disabled by default and both findings-only
  (neither adds an FQDN or an IP to scope). `scanner/pipeline/dns_hygiene.py`
  (`org_profile.dns_hygiene`) checks the nameserver set and its concentration,
  lame delegation, SOA sanity against RFC 1912, DNSSEC, CAA and a wildcard
  record; `scanner/pipeline/mail_posture.py` (`org_profile.mail_posture`) checks
  MX (including RFC 7505 `null MX`), SPF, DMARC, DKIM, MTA-STS and TLS-RPT. Both
  run after `resolve`, beside `domain_monitor`, so they see the final in-scope
  FQDN list, and both carry a checkpoint and a stage timer.
  A domain with no MX that lacks `SPF -all` **and** `DMARC p=reject` is called
  out separately as `no_mx_domain_spoofable`: it is the cheapest finding in the
  module to fix and the easiest to overlook.
  Sources are named rather than implied. DNSSEC comes from the RDAP
  `secureDNS.delegationSigned` flag M1 already wrote to `ownership.json`
  (`source: rdap_registry`) and is `not_checked` without it — never from a
  resolver's `AD` bit, which is the resolver's opinion and not a validated
  chain. `ds_without_rrsig` is deliberately not emitted: dnsx 1.2.3 has no
  DS/RRSIG flag and `dnspython` is not a dependency, so a broken chain cannot
  honestly be told apart from an unsigned one. Nameserver concentration is
  judged by parent domain and address prefix, not by ASN, and says so
  (`ns_diversity.source: ns_parent_domain_and_ip_prefix`).
  Absence of data never becomes `ok`. For DKIM in particular, "none of the
  configured selectors answered" is `not_checked` with
  `reason: no_known_selector` and no finding — selectors are arbitrary strings,
  so silence is not evidence that a domain does not sign its mail.
  Caps: `max_domains`/`deadline_seconds` per stage, at most 10 NS and 10 MX per
  domain, at most 20 DKIM selectors (each validated as a DNS label, since it is
  interpolated into a query name and passed to dnsx) under an absolute ceiling
  of 500 DKIM lookups per stage, two fixed random labels for the wildcard probe,
  and SPF `include:`/`redirect=` traversal bounded by a visited set plus a depth
  of 10 — enforced as a stop, so two domains that include each other terminate
  instead of recursing. Every cap sets `truncated` and logs the parameter to
  raise.

- **AXFR probe (opt-in, off by default)** — `org_profile.dns_hygiene.axfr_probe`
  is the first and only active check in the org-profile module. Three gates, all
  mandatory: it exists only in the scanner config file (deliberately not in
  `EDITABLE_PATHS`, which is installation-wide rather than per-tenant, and not in
  `StartScanRequest`, which would move the decision onto the `operator` who
  starts a scan rather than whoever authorizes the target); only this run's own
  seed domains are probed, never an attribution candidate; and every nameserver
  address must pass `safe_http.is_public_address`, so an NS record pointing at
  `10.0.0.5` cannot turn the probe into a TCP/53 connection inside the agent's
  network. A successful transfer is recorded as a fact and a record count only —
  the zone reaches neither `dns_hygiene.json` nor `scan.log`, which is why the
  probe drives `subprocess` directly instead of `utils.run_command` (the latter
  logs the child's stdout, and on a transfer that stdout is the whole zone). See
  `docs/operations.md`, "Active checks and target authorization".

- **MTA-STS policy fetch through the SSRF boundary** — the single HTTP request in
  M2, `https://mta-sts.<domain>/.well-known/mta-sts.txt`, goes through
  `scanner/pipeline/safe_http.py` with `max_redirects=0` (RFC 8461 section 3.3
  forbids following 3xx when retrieving a policy, and a redirect is also exactly
  the primitive an SSRF needs) and a 64 KiB body cap. `mta-sts.<domain>` is an A
  record the scanned party writes while the scanner often runs inside that
  party's network, so the address is validated and pinned like any other
  remote-named hop. A body over the cap is reported as
  `reason: policy_too_large`, never parsed halfway.
  `safe_http.is_public_address` is now the single definition of "public
  address" for the scanner, used by both the URL validator and the AXFR gate.

- **Domain ownership via RDAP — org profile M1** ([#182](https://github.com/onixus/Shapoclyack/issues/182)) —
  new opt-in scanner stage `scanner/pipeline/ownership.py` (`org_profile.ownership`,
  disabled by default) resolves each seed domain's registrar, registrant organization,
  abuse contact, lifecycle dates, EPP statuses, DNSSEC flag and nameservers from the
  registry's RDAP object (IANA bootstrap cached in `state_dir` under a one-day TTL,
  matching what IANA serves the document with, `rdap.org` as fallback).
  `registrant_status` keeps apart `public`, `redacted` (registry-masked), `natural_person`
  (`kind: individual`), `unidentified` (a registrant with nothing identifiable as an
  organization) and `unknown`; a vCard `fn` becomes `org_name` only under an explicit
  `kind: org`, so a private person's name is never promoted to an owner identifier. A domain
  with no RDAP answer gets `not_checked`/`error` with a reason — never `ok`. `max_domains`
  and `deadline_seconds` cap the registry query burst; exceeding either sets `truncated`.
  The deadline bounds a single lookup as well as the gap between two — it is checked
  before every attempt, clamps that request's timeout and cuts the retry backoff short,
  so an unresponsive registry cannot spend `(urls x attempts) x timeout` past it.
  The raw RDAP `entities[]`/vCard block (postal address, phone, natural-person name,
  tech/admin contacts) is parsed in memory and never written to disk.

- **SSRF boundary for scanner-side outbound HTTPS** — `scanner/pipeline/safe_http.py`
  is the first outbound client in `scanner/` whose next hop is named by a remote party
  (RDAP bootstrap entry, `rdap.org` 302). HTTPS only, no userinfo, rejected when any
  resolved address is non-global, TCP pinned to the validated IP with SNI and certificate
  verification against the DNS name, 256 KiB body cap, one wall-clock deadline across the
  whole redirect chain, and every `Location` re-validated by the same code as the first
  hop. Certificate verification, pinning and proxy-bypass are not configurable.

- **Restricted run artifacts (operator+)** — `api/services/runs.py::is_restricted_artifact`
  adds a second protected artifact class beside screenshot PNGs. `resolve_artifact`
  enforces it as well as the two routes (`allow_restricted`, mirroring
  `allow_screenshots`), so a future endpoint cannot inherit the name without the gate. `ownership.json` and
  `ownership_findings.txt` carry an abuse contact address, so they are omitted from
  `GET /api/runs/{id}` artifact listings and answer `404` to a viewer on both the
  text-preview and the download endpoint. Org profile M5 will add `credential_leaks.*`
  to the same predicate.

- **Historical risk score snapshots** ([#144](https://github.com/onixus/Shapoclyack/issues/144), Track C) —
  `api/services/risk_snapshots.py` + `risk_score_snapshots` (migration `0023`) persist
  point-in-time estate risk, open/total finding counts, NIST level breakdown and SLA
  breaches per tenant. `GET /api/vulnerabilities/risk-history` (viewer, `since`/`until`/`limit`)
  serves the trend series; `POST /api/vulnerabilities/risk-history/snapshot` (operator)
  captures one immediately. This closes the last leftover of #144 — the trend charts on the
  Risk Overview no longer derive history from the last scan.

- **SARIF v2.1.0 report exporter** — `scanner/pipeline/sarif_report.py` writes OASIS SARIF
  2.1.0 alongside the existing report formats (severity mapped to SARIF `level`), consumable
  by GitHub Code Scanning, GitLab Security, DefectDojo, VS Code and SIEM/VM platforms.
  The Web UI renders it in place: `web-next/src/components/run/sarif-viewer.tsx` in the run
  artifacts panel and on the reports page.

- **Endpoint-inventory NATS events (Track D, Phase S8)** — an accepted inventory submission
  publishes an `endpoint_inventory_accepted` envelope to `ingest.endpoint_inventory.{tenant_id}`
  with a stable JetStream `Nats-Msg-Id` derived from (tenant, snapshot, payload digest).
  Publishing is fail-soft and gated by `OCTO_ENDPOINT_NATS_EVENTS_ENABLED` (default `true`);
  with no `OCTO_NATS_URL` it is a no-op. With the S10 end-to-end lifecycle suite
  (`tests/test_endpoint_inventory_lifecycle.py`), **Track D is complete**.

- **Agent fleet monitoring and UI-driven SSH deployment** —
  `GET /api/agents/summary` (fleet health rollup), `GET /api/agents/{id}`,
  `DELETE /api/agents/{id}`, `POST /api/agents/{id}/upgrade`,
  `POST /api/agent/deploy/ssh` + `GET /api/agent/deploy/{deploy_id}/status`,
  `GET /api/agent/install.sh` and `GET`/`POST /api/agent/deployment-command`.
  `api/services/agent_deployer.py` pushes and installs the agent onto a Linux host over SSH
  from the Web UI (in-memory run registry, staged status, bounded history);
  `scripts/install-agent.sh` (Ubuntu/Debian, RHEL/Rocky/Alma/Fedora, Alpine, Arch; native or
  Docker) is the installer it drives, and `scripts/update-agent.sh` reinstalls the agent
  package on a host from a bundle URL you supply.
  The UI adds a live fleet view, an agent details drawer and a deploy dialog with polled
  deployment progress. **There is no agent self-update**: nothing polls the server for a new
  version, `Upgrade` marks the agent record for operators rather than commanding the host,
  and the API serves no agent bundle — so a native install takes `--bundle-url` or a
  pre-staged package and fails loudly without one. Other known limits, documented in
  [docs/operations.md](docs/operations.md): deployment runs are held in the API process'
  memory, and SSH host keys are not verified.

### Changed

- **A schedule is checked against the approved scan scope when it is written**
  ([#244](https://github.com/onixus/Shapoclyack/issues/244)) — schedules were
  validated only at dispatch, so an operator who saved one outside their
  tenant's scope learned about it hours later, and only by noticing that no scan
  had run: the evidence was an absence. `POST /api/schedules` and
  `PATCH /api/schedules/{id}` now answer `403` with the offending target named,
  the same refusal `POST /api/jobs` gives for the same target, and the decision
  goes to the access-decision journal like every other one. The dispatch-time
  check stays and is still the one that decides — a scope narrowed after the
  schedule was saved has to stop it, which only a check at dispatch can do.
  Names are deliberately *not* resolved at write time: what a record points at
  now says nothing about what it will point at when the schedule fires, and
  that question belongs to dispatch and to the scanner's own filter.

- **The approved scan scope is now enforced on what is scanned, not only on
  what was asked for** ([#244](https://github.com/onixus/Shapoclyack/issues/244)) —
  [#226](https://github.com/onixus/Shapoclyack/issues/226) authorized targets at
  the API's door and named this as the limit it could not reach: both of its
  checks decide about *names*, and the scanner resolves those names again when
  it runs. Minutes later for an ad-hoc scan, hours later for a scheduled one,
  and the record in between belongs to the scanned party — so a name that
  passed admission could be pointing at a denied address by the time the scan
  reached it, and nothing looked. The tenant's scope now travels with the job
  (`state/job_inputs/<job_id>/scan_scope.json`, handed to the pipeline as
  `--scan-scope` and to a remote worker in the claim response beside the target
  files), and the run filters its own resolution before scanning it. The
  matching rules are not restated: `api/services/scan_scopes.ScanScope` is now a
  subclass of the pipeline's, so "deny beats allow" has one implementation
  rather than two that can drift.

  Resolved addresses meet deny entries only, exactly as the API's admission
  check does — approving `customer.example` says nothing about the addresses
  behind it, and demanding they also sit inside an approved CIDR would refuse
  every domain-scoped engagement. Names and ranges get the full check, which
  also covers the targets discovery adds *after* admission (CT subdomains,
  Cloudflare zone imports, ASN ranges) and closes the second gap #226 left open:
  a scan with no target overrides reads the installation's own target files,
  which the API never opens but the scanner does.

  A refused target is dropped, not fatal. This is not the authorization
  boundary — the agent host already runs whatever it is handed — it is the last
  point at which the real target list is known, and failing the whole run would
  let a third party's DNS change end an engagement. A scope with *no entries* is
  the exception and stops the run, because scanning zero targets quietly is
  indistinguishable from a clean empty result. Since the scanner has no database
  and no route to `auth_events`, it writes `scan_scope_denied.json` into the run
  and the API folds it into the same access-decision journal on ingest
  (`GET /api/auth/events?outcome=denied`, attributed to whoever requested the
  scan) — otherwise the refusals made closest to the target would be the only
  ones nobody could audit. A run started outside the API is unfiltered, and so
  are runs from an agent older than this change: upgrade the workers before
  narrowing a scope you intend the runs to respect.

- **The SSH host-key probe is no longer an unrestricted outbound primitive**
  ([#240](https://github.com/onixus/Shapoclyack/issues/240)) —
  `POST /api/agent/deploy/ssh/host-key` opened a TCP connection to a host and
  port taken straight from the request body and reported what answered, which
  over an open port range is a port scanner with a tidy response format: "there
  is SSH here" is what an internal network map is built from. Parsing and
  address validation now live in one module (`api/services/outbound_targets.py`)
  used by both the webhook wire (`delivery.py`) and the deployer, with
  **different policies on purpose**. The webhook boundary from
  [#151](https://github.com/onixus/Shapoclyack/issues/151) is unchanged —
  public addresses unless `OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS`, the validated
  address pinned into the connection, no redirects, no userinfo. The deployer
  *allows* RFC1918, because an agent living inside a private network is the
  product; what it refuses is this platform's own reflection (loopback,
  link-local — `169.254.169.254` is a metadata service, not a Linux box —
  multicast, unspecified), a port outside `OCTO_AGENT_DEPLOY_SSH_PORTS`
  (default `22,2222`, `*` reopens the range), and any host the tenant's
  approved scan scope **denies**
  ([#226](https://github.com/onixus/Shapoclyack/issues/226)) — a prohibition
  that stopped a scan but not an SSH connection from the same API would not be
  recording anything. Requiring the target to be *inside* the allowed scope is
  opt-in (`OCTO_AGENT_DEPLOY_ENFORCE_SCAN_SCOPE`, default off): where a tenant's
  agent lives is not the same question as what it is approved to scan, and as a
  default it would refuse the ordinary MSSP deployment onto a management host.
  Refusals answer `403` and are journalled like every other access decision
  (`GET /api/auth/events?outcome=denied`). The deployment route is checked on
  the same terms — the probe was not the only way to open that connection.

- **UX/UI refactor across the dashboard** — light-theme contrast reworked in `globals.css`,
  redesigned sidebar/top header, KPI cards, data-table and status configuration
  (`lib/config/statuses.ts`), a new `sheet` primitive, and a rebuilt drag-and-drop
  Remediation kanban board.

- **Scanner network hardening** — RIPEstat lookups in `asn_discovery.py` and the crt.sh /
  hostname JSON fetches now retry with exponential backoff on `429/502/503/504` and transient
  transport errors, and send an explicit `shapoclyack/scanner` User-Agent. `nuclei_scan.py`
  hardened alongside them.

### Changed

- **Real enrichment data is committed instead of seed stubs** — `scanner/data`
  carried 3 EPSS entries, 3 KEV ids and 4 exploit-maturity entries, so an image
  built from a clean checkout prioritised findings against data that was
  effectively empty, and said nothing about it. Now: **365,017** EPSS scores
  (FIRST.org, score date 2026-08-26), **1,676** KEV ids (CISA, released
  2026-08-25) and **25,943** exploit-maturity entries (Exploit-DB and
  Metasploit, CVE ids only — no exploit content). `scanner/data` grows from
  8.9 MB to 21 MB, in line with the CVSS v4 overlay that was already committed.
  Refresh with `scripts/fetch-epss-db.sh`, `scripts/fetch-kev-db.sh` and
  `scripts/fetch-exploit-db.py`. Attribution and terms for every bundled
  dataset are now recorded in [docs/third-party.md](docs/third-party.md) —
  EPSS is CC BY 4.0 and requires it.
  This does **not** change what the tests assert: they build their own CVE
  fixtures and never read `scanner/data`. What changes is the image, the E2E
  and load stages, and any dev install working from a checkout.
  Separately from this change, the build-time refresh of these sources is
  currently failing with HTTP 403 for every source
  ([#246](https://github.com/onixus/Shapoclyack/issues/246)) — committing real
  data means a build that cannot reach them now falls back to real data rather
  than to stubs.

### Security

- **SSH push deployment verifies the target's host key**
  ([#232](https://github.com/onixus/Shapoclyack/issues/232)) —
  **breaking for the SSH push: the first deployment to a host now needs a
  fingerprint.** `POST /api/agent/deploy/ssh` accepted any host key it was
  offered (`AutoAddPolicy` on the Paramiko path, `StrictHostKeyChecking=no`
  with `UserKnownHostsFile=/dev/null` on the OpenSSH one), and the operator's
  SSH credentials for the target — often root — plus a freshly minted tenant
  provisioning key went down that channel. The host key is now resolved before
  any credential exists: a key pinned for this tenant and target must match, and
  an unpinned target is refused unless the request carries
  `expected_host_key` (`SHA256:…`), which is then pinned. A changed key is
  reported with both fingerprints and never re-added. Pins live in
  `agent_ssh_host_keys`, per tenant, so one tenant cannot decide what another
  trusts. `POST /api/agent/deploy/ssh/host-key` (admin) reads a target's key
  without authenticating to it, so the operator has something to compare
  against the host before allowing a deployment. The **Deploy Agent** dialog
  grew the field and a **Read from host** control.

- **Credentials no longer travel in a command line**
  ([#232](https://github.com/onixus/Shapoclyack/issues/232)) —
  `sshpass -p <password>` put the operator's SSH password into the API
  container's argv, and the provisioning key was passed to the installer as
  `--key <key>` and then written into the systemd unit's `ExecStart` — argv is
  world-readable through `/proc` on both machines. The password now reaches
  `ssh` through `SSH_ASKPASS` (Paramiko remains the preferred path and never
  had this problem), and the key reaches the installer on stdin via a new
  `--key-stdin`. On the target it lives only in `/etc/shapoclyack/agent.env`
  (`0600`): the unit is `ExecStart=…/python -m agent` with a mandatory
  `EnvironmentFile`, the Docker path uses `--env-file` instead of `-e`, and the
  generated container/Kubernetes snippets pass the key in the environment with
  no arguments.

- **`sudo_password` removed from `POST /api/agent/deploy/ssh`** —
  **breaking for any caller sending it.** The field was accepted and then
  ignored: nothing ever read it, and the installer is now invoked with
  `sudo -n` precisely so a sudo that would prompt fails fast instead of reading
  the provisioning key off stdin as a password guess. An interface that takes a
  credential and does nothing with it is worse than one that does not offer it.
  **The SSH account must reach root without a password prompt** — give it
  NOPASSWD for the installer, or deploy as `root`.

- **The install URL is configuration, not a request header**
  ([#233](https://github.com/onixus/Shapoclyack/issues/233)) — the server URL
  embedded in `curl … | sudo bash`, in the container and Kubernetes snippets,
  and written into the agent's permanent `OCTO_API_URL` came from
  `request.base_url`, i.e. from the caller's `Host` / `X-Forwarded-Host`. New
  **`OCTO_PUBLIC_BASE_URL`**, required under `OCTO_ENV=prod` and checked
  alongside the other fail-closed startup checks. `request.base_url` is no
  longer used for this on any route; under `OCTO_ENV=dev` it is still the
  fallback, since a laptop's own address is not a security decision.

- **Minting a provisioning key takes tenant `admin`**
  ([#231](https://github.com/onixus/Shapoclyack/issues/231)) —
  **breaking: an operator can no longer generate a deployment key or start an
  SSH push.** `POST /api/agent/deployment-command` and
  `POST /api/agent/deploy/ssh` mint the same credential as
  `POST /api/tenants/{id}/provisioning-keys`, which has always been `admin`;
  the SSH push additionally installs software as root on another machine. The
  previous justification — symmetry with the SSH push — reasoned from the
  weaker of the two routes. Reading the snippets stays `operator`: it mints
  nothing and shows a placeholder. The revised decision and its reason are
  recorded in [docs/api-and-rbac.md](docs/api-and-rbac.md).

- **Fail-closed startup covers the rest of the shipped secrets**
  ([#224](https://github.com/onixus/Shapoclyack/issues/224)) — an install that
  overrode `OCTO_JWT_SECRET` and stopped there started silently on the
  Postgres, ClickHouse and NATS placeholder passwords from
  `k8s/shapoclyack/base/kustomization.yaml`. All of them are checked by one
  mechanism — the shipped literals are looked for inside `OCTO_POSTGRES_URL`,
  `OCTO_CLICKHOUSE_URL` and `OCTO_NATS_URL` — so the next generated secret is
  not another check to remember. `OCTO_AGENT_TOKEN` now has an end date:
  **2027-03-01**. Until then a prod start warns and names the date; from that
  date a prod start with it set is refused. One shared token authenticates
  every agent as `tenant_id=default`, which for an MSSP install is the absence
  of the isolation every other route enforces.

- **The Kubernetes data plane now requires credentials** ([#225](https://github.com/onixus/Shapoclyack/issues/225)) —
  **breaking for existing installs; read
  [docs/operations.md](docs/operations.md) § Data-plane credentials before
  upgrading.** The control plane was authenticated and the three stateful
  services behind it were not: ClickHouse ran the `default` user with an empty
  password, `<networks>::/0</networks>` and `access_management=1`, and NATS had
  neither `authorization` nor `accounts`. Any pod in the cluster could read
  every tenant's raw scan results over 8123, create ClickHouse users, subscribe
  to `ingest.results.*` across all tenants and publish forged `jobs.scan`.
  Passwords now come from `shapoclyack-clickhouse` and `shapoclyack-nats`
  (dev placeholders generated the same way Postgres' always were), ClickHouse
  is reachable only from RFC1918 with `access_management=0`, and NATS
  separates an `api` user from an `agent` user that may do nothing but pull
  `jobs.scan`. Separate NATS *accounts* are not used: JetStream streams are not
  shared across accounts without per-subject export/import, which would be a
  code change.
  `base/networkpolicy-datastores.yaml` adds default-deny ingress to Postgres,
  ClickHouse and NATS, allowing only `component: api`. The recorded decision to
  ship no **egress** policy stands unchanged — CNIs and egress topologies
  differ per install; only ingress to the stateful services is revised, where
  the client set is known exactly. Enforcement is a CNI behaviour and has not
  been verified on a live cluster.
  Images are pinned by `@sha256:` digest at `shapoclyack-0.42-0822` across all
  nine manifests, replacing an overwritable tag that still read `0.41-0817`.

- **Static UI fallback no longer serves files from outside the web root**
  ([GHSA-cpcx-h7mr-24pc](https://github.com/onixus/Shapoclyack/security/advisories/GHSA-cpcx-h7mr-24pc)) —
  `spa_fallback` in `api/app.py` built its candidate by joining the URL path
  onto `OCTO_WEB_DIST` and never checked where the result landed. The route is
  unauthenticated and present in every image that ships the console, so a
  request that resolved outside the root read any file the API process could,
  the environment holding `OCTO_JWT_SECRET` and `OCTO_POSTGRES_URL` included —
  which is the whole access model, not one endpoint. All three lookups (the
  file, its `.html` sibling, the directory `index.html`) now resolve the
  candidate and require it to stay under `web_dist.resolve()`, the same
  containment check `runs.resolve_artifact` already used for run artifacts. A
  path that escapes falls through to the SPA shell like any other unknown
  route.

- **Agent results upload is bounded in both directions**
  ([#222](https://github.com/onixus/Shapoclyack/issues/222)) —
  `POST /api/agent/jobs/{job_id}/results` read the whole multipart archive into
  memory before anything inspected it, and `results_ingest._safe_members`
  checked every member's path and link type but never what the members added up
  to. A compromised agent could therefore size a single upload against the API's
  memory, or hand over a gzip bomb that filled the `output_dir` every tenant
  shares. `BodySizeLimitMiddleware` now guards the results path too, with its
  own `OCTO_AGENT_RESULTS_MAX_BODY_BYTES` cap (default 128 MiB) enforced from
  `Content-Length`; the middleware matches this route by pattern rather than
  prefix so `POST /api/agent/jobs/claim` keeps its own limits. `_safe_members`
  sums the declared member sizes and refuses above
  `MAX_UNCOMPRESSED_BYTES` (512 MiB) before extraction writes anything.

- **HSTS can actually be turned on**
  ([#224](https://github.com/onixus/Shapoclyack/issues/224)) —
  `SecurityHeadersMiddleware` had the header, `enable_hsts` defaulted to
  `False`, `create_app()` constructed the middleware with no arguments, and no
  environment variable existed to change any of that, so
  `Strict-Transport-Security` was never sent in any deployment. `OCTO_HSTS_ENABLED`
  now feeds `Settings.hsts_enabled` into the middleware, defaulting to on under
  `OCTO_ENV=prod` and off under `dev`.

- **`GET /api/agent/deployment-command` no longer hands a tenant provisioning
  key to viewers** — the route required only `viewer` while
  `get_deployment_snippets()` minted a fresh provisioning key on every call and
  embedded it in the returned snippets, so a read-only account could obtain a
  credential that registers an agent, and every open of the deploy dialog left
  another key row behind. The GET now takes `operator` and renders a
  `<PROVISIONING_KEY>` placeholder without touching the key table; the new
  `POST /api/agent/deployment-command` (also `operator`, the same bar as
  `POST /api/agent/deploy/ssh`) mints one key on request, with an optional
  `label`. `AgentDeploymentSnippetResponse.provisioning_key` is now nullable and
  carries a `key_minted` flag. The deploy dialog gained an explicit
  **Generate key** action.

- **JWT algorithm allowlist and clock leeway** — `api/core/security.py` refuses any algorithm
  outside `HS256/384/512`, `RS256/384/512`, `ES256/384/512` on both encode and decode (so
  `OCTO_JWT_ALGORITHM=none` cannot be configured), and decodes with a 10 s default leeway.

- **Pre-parse request body cap** — `api/middleware.py` `BodySizeLimitMiddleware` is raw ASGI so
  the `OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES` cap is enforced from `Content-Length` *before*
  Starlette buffers or parses the payload; a body without `Content-Length` is answered
  `411 Length Required`. Rejections increment the same submission-outcome counter as the route.

### Fixed

- **The dev-account seeder no longer races itself** ([#257](https://github.com/onixus/Shapoclyack/issues/257)).
  `_seed_dev_users` checked for each built-in account and then inserted it,
  with nothing in between. Every API replica runs the startup bootstrap, so two
  starting at once both read "absent" and both insert; the loser took a
  `UniqueViolation` that aborted its whole transaction and its start. It now
  goes through `insert_if_absent`, the SAVEPOINT-scoped helper the P1.2 startup
  imports already use, so losing the race is the no-op it should be — the row
  the winner wrote is the same row. In the test suite the second writer was an
  agent-deployment worker left over from an earlier test, which is why this
  surfaced as `tests/test_agent_lifecycle_management.py` failing roughly one run
  in five. Those daemon threads are now registered and joined
  (`agent_deployer.join_workers`) before the next test truncates the database,
  so a worker that outlives its test fails that test instead of a later one.

- **A finished job now takes its input directory with it**
  ([#258](https://github.com/onixus/Shapoclyack/issues/258)).
  `_prepare_target_inputs` created `state_dir/job_inputs/<job_id>/` and nothing
  removed it. Before #244 that directory existed only for a job carrying target
  overrides; #244 writes `scan_scope.json` for every scan, so it was created
  once per run and the growth went from occasional to linear — a few kilobytes
  per scan, on a persistent volume, in one flat tree, for a product that
  advertises 50k assets and continuous schedules. It is now removed on all
  three completion paths (the local worker, the agent's upload, and the
  idempotent-replay branch whose `job_id` never became a row), best-effort and
  idempotent, in the shape `_discard_job_wordlist` already used. Removal happens
  only once the job is terminal: the scanner reads these files while it runs and
  an agent re-reads them on every claim. Whatever never completed — and whatever
  an installation accumulated before this existed — is swept by the existing
  `run_retention` reaper on the same cutoff, so there is no second mechanism and
  no start-up migration. `sweep()` reports three more counters
  (`job_inputs_deleted`/`_errors`/`_kept`); the run-artifact keys are unchanged.

- **A webhook claim expired mid-batch, so a peer re-sent a delivery still in
  flight** ([#255](https://github.com/onixus/Shapoclyack/issues/255)) — the
  visibility window was computed twice with two different answers. The live
  claim (`secure_webhooks._claim_due`, the facade the package exports as
  `webhooks`) used a fixed `max(30, timeout * 3)`, while the batch-aware
  `claim_visibility_seconds` sat on a second, shadowed copy of the dispatch
  loop in `webhooks.py` that nothing called. A batch is POSTed serially, so 50
  deliveries at `OCTO_WEBHOOK_TIMEOUT_SECONDS=10` take up to 500 seconds under
  a 30-second lease: the row became due again while it was still being sent,
  and the next replica claimed and re-sent it — the duplicate POST #152
  forbids, reached without any race on the claim. The window is now computed in
  one place and covers one timeout per claimed row plus two of slack. The
  shadowed `dispatch_once`/`_claim_due` pair is deleted rather than kept in
  sync: editing it fixed nothing, which is time already lost once while
  diagnosing #238.

- **An exception in the middle of a batch left its tail claimed and unsent**
  ([#256](https://github.com/onixus/Shapoclyack/issues/256)) — `dispatch_once`
  guarded the wire call, but a raise from recording an outcome, from a metric
  or from the ticket back-link broke the loop with the whole batch already
  claimed: `attempts` incremented and `next_attempt_at` pushed out by the
  visibility window. Those rows waited out the window unsent, with nothing in
  the log saying a delivery had failed, because none had been attempted. The
  loop now hands the rows it never reached back to the queue through the same
  release path the #151 kill switch uses — pending, due immediately, and with
  the retry budget untouched, since no attempt was made — then re-raises. The
  delivery whose outcome was lost deliberately keeps its claim: its POST may
  have arrived, and re-sending it at once would be the very duplicate above.

- **The test fixtures silently discarded a `Settings` object handed to them**
  ([#254](https://github.com/onixus/Shapoclyack/issues/254)) — `make_settings`
  applied overrides with a bare `setattr`, which on a dataclass invents any
  attribute asked for, and `configured_client` forwarded `**overrides` into it.
  So `configured_client(tmp_path, monkeypatch, settings=settings)` — the form
  24 call sites in `tests/test_agent_lifecycle_management.py` use — set a
  meaningless `settings` attribute on a *fresh* `Settings` and configured the
  services with that one, at its defaults; the object the test had built was
  dropped. A misspelled field name went the same way: applied, never read, test
  green. `make_settings` now raises `TypeError` naming any key that is not a
  declared `Settings` field, and `configured_client` takes a ready object as an
  explicit `settings=` parameter, refusing the contradiction of an object plus
  overrides. Test-only change; no runtime behaviour is affected.

- **Concurrent webhook dispatchers starved each other instead of dividing the
  queue** ([#238](https://github.com/onixus/Shapoclyack/issues/238)) — the
  kill-switch claim added in #151 joins `webhook_subscriptions` so a disabled
  subscription cannot be sent from the backlog, but its `FOR UPDATE SKIP
  LOCKED` locked the joined *subscription* row as well, and every delivery of
  one subscription shares that row. While one replica held it, a peer's scan
  locked each delivery tuple, then hit the locked subscription tuple and had
  the joined row skipped — leaving those deliveries locked by a transaction
  that claimed none of them and invisible to every replica until it ended. The
  batch was neither sent nor marked, nothing raised, and the tick simply
  reported fewer deliveries than were due: the reverse of the "replicas divide
  the queue" guarantee of #152, and the cause of
  `test_concurrent_dispatchers_do_not_double_post` failing in roughly half of
  the full runs. The claim now locks `webhook_deliveries` only (`FOR UPDATE OF
  … SKIP LOCKED`); the enabled-at-claim-time filter is unchanged.

- **Enrichment data failed to download during image builds, and the build said
  so only in passing** ([#246](https://github.com/onixus/Shapoclyack/issues/246)) —
  all eight vulscan CVE databases had been answering `403` since
  `www.computec.ch` moved behind a Cloudflare managed challenge, which rejects
  every non-browser client regardless of User-Agent (`cf-mitigated: challenge`).
  `scripts/fetch-vulscan-db.sh` now reads them from `scipag/vulscan` on GitHub —
  the same maintainer publishing the same files — with computec.ch kept as a
  fallback, `VULSCAN_BASE_URLS` to override the list for closed networks, and a
  content check so a mirror answering `200` with an HTML page can never
  overwrite a good database.
  The larger defect was that the image shipped anyway and was indistinguishable
  from one built with fresh data. Every refresh now writes an
  `enrichment-manifest.json` beside the data recording, per dataset, its source,
  the date the feed stamped on it, its entry count, and whether this build
  actually fetched it (`fetch`) or fell back to what was already there (`seed` /
  `stale` / `missing`). `GET /api/system` reports those four fields on each
  enrichment entry — additive and `null` on images built before the manifest
  existed. `scripts/fetch-enrichment.sh` also separates the two failures it used
  to merge: a source being unreachable stays a warning (exit `1`), while a
  required dataset that is absent or is a stub exits `2` and fails a build with
  `ENRICHMENT_STRICT=1`, which `Jenkinsfile.publish` sets for release images and
  dev builds leave off. The seed floor now also covers `exploit-overlay.json`,
  which a mounted enrichment volume previously shadowed with nothing, leaving
  exploit-maturity scoring reading an absent overlay.
  The same build log's `==> cvss4: FAILED` turned out **not** to be a 403 at
  all: run as a script, `scripts/fetch-cvss4-db.py` had `scripts/` rather than
  the repo root on `sys.path`, so `from scanner.pipeline.cvss4 import …` raised
  before it parsed an argument — every documented invocation of it, the daily
  CronJob included, had been failing this way. The script now puts the repo root
  on the path itself.

- **`python -m agent.worker` started nothing and exited 0** — the module
  defined `main()` but had no `if __name__ == "__main__"` guard, so running it
  directly imported the file, built no parser, contacted no API, and returned
  success. Only `python -m agent` ever worked. The installer's systemd unit
  used the broken spelling, so a native install left `Restart=always` cycling a
  no-op forever while `systemctl is-active` reported nothing wrong. The guard
  is added and the installer now uses `python -m agent`; **an agent installed
  by an older installer needs a re-run of the current one.**

- **Deployment status answered 404 on a successful deployment**
  ([#223](https://github.com/onixus/Shapoclyack/issues/223)) — the run journal
  was a dict in the API process, so with more than one replica (which the prod
  overlay and `api-pdb.yaml` assume) `GET /api/agent/deploy/{id}/status`
  answered only on the replica that started the run, and a restart erased the
  log an operator was reading. Runs are rows in `agent_deployments` now, with
  the tenant on the row: the status route was declaring `require_tenant` and
  then ignoring the tenant it resolved, so any operator could poll any run's
  log by id. A run in another tenant answers `404`, not `403`.

- **Agent ids leaked their existence across tenants**
  ([#223](https://github.com/onixus/Shapoclyack/issues/223)) —
  `GET`/`DELETE /api/agents/{id}` and `POST /api/agents/{id}/upgrade` answered
  `403 Cross-tenant agent access denied` for an id belonging to another tenant
  and `404` for one that existed nowhere, which is an existence oracle over
  every agent id in the installation, and the opposite of what
  `docs/api-and-rbac.md` has promised since the tenancy work. All three answer
  `404` either way now.

- **Risk trend chart froze on the first days of the install**
  ([#228](https://github.com/onixus/Shapoclyack/issues/228)) —
  `risk_snapshots.list_snapshots()` paged with `ORDER BY recorded_at ASC LIMIT n`,
  which returns the *oldest* n rows. A snapshot is recorded on every finished run,
  so the table outgrew the route's default limit of 90 within days and Risk
  Overview kept re-rendering the same first week forever. The query now sorts
  descending, takes the newest page and reverses it, so the API still hands the
  chart a chronological series. The existing test asserted only `len(...) == 1`,
  which is true of either end of the table.

- **`GET /api/vulnerabilities/risk-history` interleaved tenants for a platform admin**
  ([#228](https://github.com/onixus/Shapoclyack/issues/228)) — an unscoped platform
  admin got every tenant's snapshots merged into one chronological list, so a tenant
  with 500 open findings next to one with 3 drew a sawtooth rather than a trend.
  No data crossed a boundary (a viewer was always pinned to their own tenant); the
  series was simply meaningless. The route now follows `principal.tenant_id`: a chart
  is one line, and a platform admin picks the tenant with the `tenant_id` query
  parameter every route already accepts. `/summary` keeps the cross-tenant view —
  summing tenants is a number, concatenating their histories is not.

- **`risk_score_snapshots` grew without bound**
  ([#229](https://github.com/onixus/Shapoclyack/issues/229)) — the table (migration
  `0023`) landed after #187 bounded the other stores, and its `prune_snapshots()` was
  called by nothing but its own unit test: one row per tenant per run, forever. It now
  has the same in-process sweep as the run-artifact reaper —
  `OCTO_RISK_SNAPSHOT_RETENTION_DAYS` (90),
  `OCTO_RISK_SNAPSHOT_RETENTION_INTERVAL_SECONDS` (6h),
  `OCTO_RISK_SNAPSHOT_RETENTION_ENABLED`.

- **ClickHouse ingest worker consumed endpoint-inventory events**
  ([#230](https://github.com/onixus/Shapoclyack/issues/230)) — the durable filtered on
  the stream's whole `ingest.>` tree, so the S8 subject
  `ingest.endpoint_inventory.{tenant}` was fetched one message at a time by the
  single-threaded pull loop, transformed into nothing, acked, and counted as a
  successful ingest: SLO 6 read the empties as successes and improved with every
  endpoint added. The filter is now `ingest.results.>` (consumer renamed
  `octo-ch-ingest` → `octo-ch-ingest-results`, since JetStream will not change the
  filter of an existing durable — see `docs/operations.md`), and `_handle_msg` skips a
  foreign subject without counting it. The legacy `ingest.raw_results` duplicate of
  every result drops out too, so a result is no longer transformed and inserted twice.

- **Uncapped DNS-over-HTTPS read in the alert self-check** —
  `scanner/pipeline/alerts.py::lookup_txt_records` read the resolver's answer with a
  bare `response.read()` and used `urllib.request.urlopen`, which follows redirects
  silently. It now goes through `safe_http` with a 64 KiB cap and zero redirects. One
  DKIM self-check per run made that survivable; org profile M2 would have turned a DoH
  client into a per-domain hot path, so the client is fixed rather than reused.

- **CI:** the synthetic load-test composite action now receives the `github_token` secret
  ([#217](https://github.com/onixus/Shapoclyack/pull/217)).

## [0.42-0822] — 2026-08-22

### Added


- **Multi-replica concurrent load test suite** ([#188](https://github.com/onixus/Shapoclyack/issues/188)) —
  `tests/test_multi_replica_load.py` and `tests/fixtures/multi_replica_load.py` validate
  concurrency across $\ge 2$ API replicas connected to the same PostgreSQL database.
  Verifies race elimination on job claims (`SELECT ... FOR UPDATE SKIP LOCKED`),
  idempotency keys replay across replicas, session-scoped advisory lock leader
  election for scheduler dispatches, and lease reaper sweeps under load.

- **Data-growth bounds: ClickHouse TTL and scan artifact retention** ([#187](https://github.com/onixus/Shapoclyack/issues/187)) —

  ClickHouse tables `shapoclyack.shapoclyack_vulnerabilities` and `shapoclyack.shapoclyack_open_ports`
  now specify `TTL timestamp + INTERVAL 90 DAY` in `init.sql` and k8s ConfigMap.
  An in-process `run_retention` worker sweeps `output_dir/runs/*` every
  `OCTO_RUN_RETENTION_INTERVAL_SECONDS` (1h) and removes expired run directories
  whose age exceeds `OCTO_RUN_RETENTION_DAYS` (30; `0` disables). Deletion is fail-soft
  and safe across multiple API replicas.

- **SLO alert rules as code** ([#186](https://github.com/onixus/Shapoclyack/issues/186)) —

  `k8s/shapoclyack/examples/prometheus-slo.rules.yaml` is the source of
  truth (availability burn rates, GET p95, job completion, ingest lag/staleness,
  endpoint acceptance, login limiter, scheduler split-brain and no-leader).
  Prometheus Operator wrapper is generated beside it. `promtool check rules`
  runs in CI. Base still applies without the operator.

- **End-to-end API latency probe** ([#185](https://github.com/onixus/Shapoclyack/issues/185)) —
  `python -m tests.fixtures.api_latency` hits list/status GET routes under
  concurrency and compares client percentiles with
  `octo_http_request_duration_seconds`. Recorded 2026-08-20 on kind
  `shapoclyack-dev` at 1k/10k/50k assets: list-route GET p95 stays under
  500 ms at 32 concurrent clients on one replica; `GET /api/system` is the
  outlier (~500–580 ms at conc 32). SLO 4/5 were not re-derived (no job
  histogram samples; ingest off).

- **Russian locale and light theme** in the Web UI. Default remains English
  and dark. The header (and login) toggle theme and language; both persist in
  `localStorage` (`shapoclyack.theme`, `shapoclyack.locale`) and apply before
  first paint. Russian covers chrome — navigation, titles, table headers,
  status badges, login — not CVE/host identifiers or API error strings.

### Changed

- **Node.js builder image `node:24-bookworm-slim` → `node:26-bookworm-slim`** —
  aligned `Dockerfile.allinone` and `Dockerfile.api` `web-build` stages with
  `Jenkinsfile` and `web-next/package.json` (`engines.node: ">=26"`), resolving
  engine mismatch errors.

- **Pulse `v0.9.1` → `v1.1.0`** — `PULSE_VERSION` in `Dockerfile` /

  `Dockerfile.allinone`, `Jenkinsfile.publish`, and
  `scripts/install-pulse.sh` (docs had drifted at `v0.8.3`). Linux
  amd64/arm64 tarballs are on the GenDec release. Adapter flags are
  unchanged (`-b --os --cve -f json`); the gain is Pulse's probe-DB
  (product/version). Not wired: `pulse monitor`, `--server`, `--alert-*`,
  `--scripts`, `--inventory`. JARM may appear on `tls[]` as a field; it
  is not scored. `finding_class: tls` still feeds extra vulnerabilities
  because `tls_posture` is opt-in and a different artifact.

- **Backup restore drill** ([#158](https://github.com/onixus/Shapoclyack/issues/158)) —
  2026-08-20 on kind `shapoclyack-dev`. A live-lab `pg_dump` (5 assets) restored
  into namespace `shapoclyack-restore` via `scripts/restore-postgres.sh`.
  `recovery_seconds=31`, `pg_restore` under 1 s. Overlay
  `k8s/shapoclyack/overlays/kind-restore` repeats the isolated stack. RPO/RTO
  table in [docs/operations.md](docs/operations.md) no longer says
  `Not yet measured`.

### Added

- **Webhook delivery state machine** ([#152](https://github.com/onixus/Shapoclyack/issues/152)) —
  the JetStream durable `octo-webhook-fanout` is created with
  `DeliverPolicy.NEW` *before* binding, so a new consumer does not replay
  retained `EVENTS` history. `POST /api/webhooks/deliveries/{id}/retry`
  replays only `dead` rows (409 on `delivered`). A claim's visibility
  timeout covers the whole serial batch so two dispatcher replicas cannot
  POST the same delivery while one is still in flight; a late duplicate
  result cannot un-deliver a row the receiver already accepted.

- **Ticket transports** (ROADMAP P2 / Phase 10.3) — Jira, ServiceNow and
  DefectDojo create issues over the existing webhook delivery queue, not
  a second queue. A subscription's `transport` is `webhook` (HMAC POST,
  default) or `jira` / `servicenow` / `defectdojo`. Native create still
  retries 5xx and dead-letters a 4xx. On success a matching tracked
  finding is linked (`ticket_system` / `ticket_key` / `ticket_url`); an
  operator-set link is not overwritten. HMAC is not applied to those
  APIs. Credentials stay write-only. This is not confirmation the CVE
  is exploitable, and ticket status is not synced back.

- **OpenTelemetry on the API** (ROADMAP P3) — opt-in
  `OCTO_OTEL_EXPORTER_OTLP_ENDPOINT`. Empty means no TracerProvider.
  Spans are HTTP requests, not scan facts. Scanner wall-clock stays
  `stage_timings.json`. `/metrics` and `/api/health` are not traced.

- **CWE on tracked findings** — copied from the last observation: NVD
  weaknesses in the cvss4 overlay, else nuclei `classification.cwe-id`.
  `NVD-CWE-noinfo` is not a CWE and is dropped. Missing stays empty, not
  inferred from the CVE id. `GET /api/vulnerabilities/{id}` carries `cwe`;
  the finding card shows it.

- **Web screenshots** (ROADMAP P4.4 / Phase 9.3) — opt-in capture of
  already-open web ports (`screenshots.enabled`, off by default). Same
  candidates as fingerprint; no new scan. Playwright is optional: missing
  it writes `skipped_reason: playwright.unavailable` and no pixels.
  Obvious form fields are painted over in the live DOM before the PNG is
  taken; unredacted bytes never hit disk. A heading name is **not**
  redacted, so PNGs stay operator-only (`GET /api/runs/{id}/screenshots`,
  download) and a reaper deletes `runs/*/screenshots/*.png` after
  `OCTO_SCREENSHOT_RETENTION_DAYS` (14). `screenshots.json` stays.
  Viewers get 404 on the PNG and do not see those paths in the artifact
  list. The run view **Screenshots** tab is operator-only.

- **Ownership graph** (ROADMAP P4.3) — `/attack-surface` can group one scan
  by operator-set `business_unit` / `owner_email`. Unowned names cluster by
  registrable domain and are labelled `(domain)` so a DNS name is not an
  owner. ASN is not an owner. `GET /api/runs/{id}/hosts` carries the
  fields. Filter answers "what does this unit expose".

- **Same-asset attack path** ([#173](https://github.com/onixus/Shapoclyack/issues/173)) —
  after P4.2, a local finding (`AV:L`/`AV:P`) on the same asset as a
  network foothold (`AV:N` or `exposure`) gets +8 likelihood, named in
  `risk_explanation`. Two Moderates are still two Moderates — this is not
  a domain-takeover model and not a walk across uncorrelated hosts.

- **IP↔FQDN↔certificate correlation** (ROADMAP P4.2) — an IP-only asset and
  a bare-FQDN asset become one row only when forward DNS *and* a
  certificate on that IP cover the name, and the IP is not shared-hosting
  two such names. PTR is not evidence. The trail is
  `asset_identity_links` on `GET /api/assets/{id}` (`identity_links`).
  A CDN SAN list does not invent assets. Docs:
  [docs/asset-identity.md](docs/asset-identity.md).

- **On-path CDN/WAF as a compensating control** ([#173](https://github.com/onixus/Shapoclyack/issues/173)) —
  if fingerprint (Phase 9.1) saw Cloudflare / Akamai / Sucuri / Imperva /
  CloudFront / Fastly on the *same* host:port, likelihood drops by 6 points
  and `risk_explanation` names the vendor and the source. That is not
  evidence the control blocks this CVE, and it is not a qualitative "minus
  a level" rule. A CMS hit, another port, or a missing `fingerprint.json`
  changes nothing. Attack chaining is still not modelled (needs P4.2).

- **CVE age as a raise-only likelihood bump** ([#172](https://github.com/onixus/Shapoclyack/issues/172)) —
  an older CVE with the same evidence is never scored *below* a fresh one.
  Date comes from NVD `published` on `cvss4.json` (now stored by
  `scripts/fetch-cvss4-db.py`) or, if missing, the CVE-ID year. Time never
  lowers the score. Stale EPSS/KEV/exploit overlays are named in the
  explanation and on `GET /api/system` (`stale`, plus the exploit overlay
  itself). How long a finding has been open stays SLA (#145).

- **Network exposure in likelihood** ([#171](https://github.com/onixus/Shapoclyack/issues/171)) —
  the same CVE on an RFC1918 box and on an operator-declared internet-facing
  host no longer share a likelihood. `AV:N` remains a property of the
  vulnerability. `network_exposure` is `external` / `internal` / `unknown`
  with a named source (`address-space`, `operator-set`, `finding`). A public
  IP is not treated as internet-facing. `unknown` does not shift the score.

- **Exposure Management and MSSP views** ([#139](https://github.com/onixus/Shapoclyack/issues/139)) —
  `/tenants` compares customer posture (worst open NIST risk, SLA, unassigned,
  KEV, unowned assets, operator-declared internet). `/exposure` lists assets
  by declared `exposure_level` — a decision, not a scan fact ([#171](https://github.com/onixus/Shapoclyack/issues/171)).
  `/threats` is open tracked findings on CISA KEV (`in_kev` / `exploit_maturity`
  copied onto the tracker, migration `0018`). Attack paths are not modelled
  ([#173](https://github.com/onixus/Shapoclyack/issues/173)); the attack-surface
  graph stays one scan's hostname→IP→port→service map.

- **Asset-centric security view** ([#136](https://github.com/onixus/Shapoclyack/issues/136)) —
  `/assets` and `/assets/view` treat the asset as the primary security object.
  The inventory lists owner, service, exposure, open tracked findings and the
  worst open NIST `estate_risk` (one extra query per page, not per row).
  Search matches owner and business service as well as identifiers. The asset
  card opens on tracked findings with the next required action (SLA / assign /
  lifecycle), KPIs for unassigned and breached work, software inventory, scan
  evidence as a secondary tab, and context history. Assets sit next to
  Vulnerabilities and Remediation in the nav.

- **Asset business context** ([#146](https://github.com/onixus/Shapoclyack/issues/146)) —
  the asset card can explain why a host is risky and who owns it. `PATCH
  /api/assets/{id}` now stores `business_service`, `environment`
  (`production`/`staging`/`development`/`lab`/`other`), `data_classification`
  (`public`/`internal`/`confidential`/`restricted`) and `exposure_level`
  (`internet`/`partner`/`internal`/`unknown`), with `context_source`
  (`operator`/`cmdb`/`ad`/`other`) so a later CMDB/AD importer uses the same
  write. Changes are audited in `asset_context_events` in the same
  transaction (migration `0017_asset_business_context`).
  `GET /api/assets/{id}` includes `risk` — the tracked-finding summary for
  that asset, `estate_risk` being the worst open NIST level, not an average.
  Exposure here is an operator decision, not a scan measurement ([#171](https://github.com/onixus/Shapoclyack/issues/171)
  remains the network fact). Scoring still uses only `asset_criticality`.
  Docs: [docs/asset-context.md](docs/asset-context.md).

- **Remediation Board** ([#138](https://github.com/onixus/Shapoclyack/issues/138)) —
  `/remediation` is the Kanban over the #145 lifecycle: drag (or move) a
  finding from `OPEN` to verified `CLOSED`, assign, comment, and link an
  external ticket. Comments are `vulnerability_events` (`kind=comment`).
  Ticket links (`ticket_system` / `ticket_key` / `ticket_url`, migration
  `0016_vuln_ticket_link`) record Jira/ServiceNow/SMAX/DefectDojo work items;
  the platform does not create them — that is the 10.3/P2 delivery queue,
  built once. Accepted risk stays a badge, not a seventh column.

- **Risk Overview dashboard** ([#135](https://github.com/onixus/Shapoclyack/issues/135)) —
  `/` now answers "what is our risk, who owns it, what breaches SLA" from
  tracked findings, not the last scan. Estate risk is the worst open NIST
  `risk_level` (`GET /api/vulnerabilities/summary` grew `estate_risk`,
  `unassigned`, `by_risk_level_open`). Asset posture is
  `GET /api/assets/summary` (unowned = active/stale with no `owner_email`).
  Internet-facing exposure is not counted on this page: operator-set
  `exposure_level` lives on the asset ([#146](https://github.com/onixus/Shapoclyack/issues/146));
  the network measurement is still [#171](https://github.com/onixus/Shapoclyack/issues/171).
  Drawing zero would read as "nothing is exposed". The run chart is labelled
  scan volume; historical risk snapshots are still
  [#144](https://github.com/onixus/Shapoclyack/issues/144).

- **Vulnerability Center** ([#137](https://github.com/onixus/Shapoclyack/issues/137)) —
  `/vulnerabilities` is the working set of tracked findings (owner, lifecycle
  state, SLA), not the last scan's raw list. Header counts come from
  `GET /api/vulnerabilities/summary`; the table is server-filtered (state,
  severity, SLA, stale days, search) and pages worst-first. The detail card
  (`/vulnerabilities/view?vulnId=`) walks
  `OPEN → ACKNOWLEDGED → PLANNED → FIXING → VERIFYING → CLOSED`, assigns an
  owner, accepts risk (admin; expiry and reason required), and shows the audit
  trail. EPSS/KEV and the risk explanation are pulled from the last observing
  run when it is still on disk. An asset's Vulnerabilities tab links here when
  that asset has open tracked findings.

- **Vulnerability lifecycle, ownership and SLA** ([#145](https://github.com/onixus/Shapoclyack/issues/145),
  Track C) — a finding is an entity now, not a row in whatever the last scan
  wrote. `vulnerabilities`, `vulnerability_events` and `sla_policies` (migration
  `0015_vuln_lifecycle`) hold what people decide about a finding, which neither
  the per-run `vulnerabilities.json` nor ClickHouse's `ReplacingMergeTree`
  could: an owner, a lifecycle state, a deadline.

  Findings are identified by `sha256(asset_id | CVE or script_id | port)` per
  tenant — the triple the report pipeline already de-duplicates on — so the same
  finding is the same row across runs, and it is keyed on the asset rather than
  the observed IP so remediation history survives a DHCP lease.

  Lifecycle `OPEN → ACKNOWLEDGED → PLANNED → FIXING → VERIFYING → CLOSED`, with
  forward skips, fall-backs, and `CLOSED → OPEN` when a closed finding is
  observed again (the SLA clock restarts from the regression, not from the
  original discovery). Same-state moves answer `409`. A finding that stops being
  observed is **never** auto-closed — the same absence is produced by a host
  that was down or a narrowed scan profile, so staleness is surfaced
  (`?stale_days=N`) instead of forgiven.

  SLA deadlines come from `(asset criticality, severity)` policy, that
  severity's tenant fallback, or built-in defaults (critical 15 / high 30 /
  medium 90 / low 180 days); breach is derived on read, so a clock or threshold
  change applies at once. Risk acceptance is an expiring attribute rather than a
  seventh state: `until` and `reason` are both required, the deadline moves to
  the expiry, and withdrawing it recomputes from when the clock started.

  Every observation, transition, assignment and exception is written to the
  audit trail in the same transaction as the change. New endpoints under
  `/api/vulnerabilities` (reads `viewer`, lifecycle/assignment `operator`, risk
  acceptance and SLA policy `admin`). Docs:
  [docs/vulnerability-lifecycle.md](docs/vulnerability-lifecycle.md).

## [0.41-0817] — 2026-08-17

### Added

- **Geo Map (`/geo`)** — a run's alive hosts on a world map, each marker
  coloured by the worst finding on the hosts it covers and sized by how many
  they are. GeoIP already gave country and city; the scanner now also records
  the **coordinates** a City-edition database carries
  (`alive_hosts.json`/`geoip.json`, and `latitude`/`longitude` on
  `GET /api/runs/{id}/hosts` — null for older runs and Country-edition
  databases, which is not an error).

  The page is explicit about the precision of what it draws, because a dot on a
  map reads as more certain than GeoIP is: a coordinate is the registered
  position of the *network*, typically a city or country centre and never the
  machine. Hosts with only a country are plotted at that country's centroid,
  drawn with a dashed ring and counted above the map; hosts with neither —
  private addresses, or an installation with no GeoIP database — are listed as
  **unlocated** rather than dropped, so the map never reads as the whole estate.

  Self-contained SVG with no runtime dependency and no external tiles, so it
  works in an air-gapped install and nothing on the page calls out of the
  browser. The land outline and country centroids are generated from Natural
  Earth 110m data into a committed constant by
  `web-next/scripts/generate-world-map.mjs`, run by hand — the same
  dependency-free approach as the Attack Surface graph.


- **Scan intents on jobs and schedules** — product control for *what work* a
  scan does (`inventory` / `vuln` / `full` / `delta`), orthogonal to speed
  `mode`. Maps to CLI flags and per-job config overlays (nuclei floor,
  top_ports, skip_nse) so operators can schedule fast inventory often and full
  assessments rarely without editing YAML. UI selectors on Jobs and Schedules;
  persisted in `scan_options`. See `docs/scan-performance.md` and
  `api/services/scan_intents.py`.

- **Scanner stage wall-clock timings** — each run writes `stage_timings.json`
  (per-stage duration, skipped/error status, top stages) and a ranked summary
  line in `pipeline.log`. Design notes for scan intents / delta without adding
  hardware: `docs/scan-performance.md`. Load test peak-RSS monitor no longer
  exits before the scanner container exists (was always reporting 0 MiB).

- **Tenant-uploaded brute-force wordlists** (Phase 8.2, UI-managed) — the
  subdomain and cloud-bucket brute-force stages already took a `wordlist_file`
  path, which only an operator with filesystem access to the scanner could set.
  Operators can now upload a wordlist through the API/UI (`POST /api/wordlists`,
  or the new **Wordlists** page) and select it per scan
  (`StartScanRequest.wordlist_id`). The body is normalized to the scanner's own
  on-disk shape (lowercased, de-duplicated, blank/comment lines dropped) and
  stored per tenant in Postgres (migration `0012`), so it survives restarts and
  reaches every replica. At local scan start the selected row is materialized to
  a job-scoped file under the state dir and injected into the job's effective
  config: a `subdomain` list turns on `ct.brute_force`, a `bucket` list turns on
  cloud discovery. Local execution only — a remote agent runs its own mounted
  config, so a `wordlist_id` on an agent-mode scan is rejected rather than
  silently ignored. Caps via `OCTO_WORDLIST_MAX_WORDS` (default 50000) and
  `OCTO_WORDLIST_MAX_BODY_BYTES` (default 8 MiB); reads/lists never expose the
  body, only metadata.

- **Outbound webhooks for asset events** (ROADMAP P2 / Phase 10.3, webhook
  half) — the first consumer of the 10.2 event stream. Per-tenant subscriptions
  (`POST /api/webhooks`) carry the routing policy: which event kinds, and a
  `min_severity` floor that applies to the kinds which actually have a severity
  (`new_cve`) and deliberately does **not** swallow port changes or
  decommissions that have none. A JetStream durable consumer
  (`octo-webhook-fanout` on `events.asset.>`) turns matching events into rows
  and acks; a separate dispatcher drains them. The split is the point: a slow
  receiver can never stall consumption of the event stream, and the POST happens
  outside any transaction so a hanging receiver holds no database connection.

  `webhook_deliveries` (migration `0011`) is retry queue, dead-letter queue and
  audit trail in one table, because those are the same rows under different
  predicates. Retries are exponential and capped
  (`OCTO_WEBHOOK_MAX_ATTEMPTS`, default 6 attempts over ~15 minutes); 5xx,
  timeouts, 408 and 429 are retried, while every other 4xx is dead-lettered on
  the first attempt — replaying an unchanged body that the receiver called
  malformed only spends the retry budget to get the same answer.
  `GET /api/webhooks/deliveries?status=dead` is the DLQ view and
  `POST /api/webhooks/deliveries/{id}/retry` replays one; both work with the
  broker down, since a delivery is a row and carries its own payload. The
  dispatcher runs in **every** replica without leader election, like the P1.4
  reaper: claims are taken with `FOR UPDATE SKIP LOCKED` and each claim pushes a
  visibility timeout forward, so replicas divide the queue and a replica that
  dies mid-POST releases its delivery instead of stranding it.

  Deliveries are signed by default: a secret is generated at creation, returned
  exactly once, and write-only afterwards (`has_secret`, plus
  `POST /api/webhooks/{id}/rotate-secret`). `X-Shapoclyack-Signature` is an HMAC
  over `{timestamp}.{body}` with the timestamp *inside* the MAC, so a receiver
  rejecting stale timestamps cannot be defeated by replaying an old body under a
  new one. Signing is what you opt out of, not into: an unsigned webhook is a
  URL anyone who learns it can forge "this host just grew a critical CVE" into.

  Webhook URLs are operator-supplied and this service sits inside the network it
  scans, so a target resolving to a loopback, private, link-local or otherwise
  non-global address is refused — that is the SSRF shape where an integration is
  really a probe of the cluster's own internals, cloud metadata service
  included. The check runs at write time *and* immediately before every POST (a
  name can start resolving inward later), redirects are not followed, and
  `OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS=true` opts an on-cluster receiver back in.
  Writes need the tenant `admin` role rather than `operator`: sending a tenant's
  exposure data to an address of the creator's choosing is closer to granting
  access than to scheduling a scan. New metrics:
  `octo_webhook_deliveries_total{outcome}`,
  `octo_webhook_delivery_duration_seconds`,
  `octo_webhook_delivery_queue{status}`. Ticketing bridges (Jira/ServiceNow) are
  the remaining half of 10.3 and reuse this queue as another transport.

- **Asset event bus** (ROADMAP P2 / Phase 10.2) — the asset-level events that
  Phase 10.1 normalized into each run's `diff.json` are now published to NATS
  JetStream on `events.asset.{tenant_id}.{kind}`: `new_asset`, `new_open_port`,
  `new_cve`, `cert_expiring` after every successful run, plus
  `decommissioned_host` when an operator decommissions an asset through
  `PATCH /assets/{id}`. Until now those events existed only inside a run
  artifact and a pod log, with nothing able to subscribe to them; this is the
  substrate 10.3 (webhooks, ticketing) consumes.

  The tenant token comes **before** the kind because a routing policy is
  per-tenant first — the common subscription is `events.asset.acme.>`, while a
  cross-tenant consumer still gets `events.asset.*.new_cve`. The new `EVENTS`
  stream uses `LIMITS` retention rather than `WORK_QUEUE`: one event legitimately
  has several independent consumers, and a work queue would let whichever
  connected first consume it away from the others. Defaults: 30d max age, 1GiB
  max bytes, 24h duplicate window (`OCTO_NATS_EVENTS_*`).

  Publishing lives in the API, not in `scanner/pipeline/alerts.py` as the
  roadmap originally sketched. The scanner is also the agent's payload and has
  no tenant context — the tenant is a property of the job, resolved by the API —
  so publishing there would have meant handing broker credentials to every
  remote worker. The API's post-run hook covers local-mode scans and agent
  uploads from the same place. `alerts.py` keeps its per-run SMTP/webhook
  digest; that is a human summary, not the machine event stream.

  Delivery is best-effort and never fails a scan: a run whose artifacts are on
  disk and whose assets are registered must not be reported as failed because
  the broker blinked. What did not go out is visible on the new
  `octo_asset_events_published_total{kind,outcome}` counter, and the payload is
  still in `diff.json`. The publish loop runs inside the agent's upload request,
  so it is bounded twice over: a 30s batch deadline, and an abort after three
  consecutive failures — a broker that accepts connections but fails every
  publish costs the job seconds, not minutes. Event ids are derived from tenant+run+kind+host+port+CVE
  instead of randomised, so a results upload replayed through the P1.5
  idempotency path republishes identical ids and JetStream drops the duplicates;
  the run id is part of that identity on purpose, so the same finding in a
  *later* run stays a new occurrence rather than being suppressed after it comes
  back. A run is capped at `OCTO_ASSET_EVENTS_MAX_PER_RUN` (default 1000) events
  with the overflow logged and counted — a first scan of a fresh /16 is
  otherwise one alert storm. The cap keeps the most actionable kinds first
  (`new_cve`, then `cert_expiring`, then ports, then bare host discoveries),
  because `report_diff.py` emits every `new_asset` ahead of everything else and
  a plain head-cap would let a scope expansion bury the findings the bus exists
  to deliver. `OCTO_ASSET_EVENTS_ENABLED=false` silences the stream without
  disabling job dispatch and result ingest on the same broker.


- **Idempotency keys for scan start and result upload** (ROADMAP P1.5;
  migration `0010_job_idempotency`). The failure worth designing for is not a
  duplicate request but a lost response: the write landed and the client never
  found out. `POST /api/jobs` now honours an **`Idempotency-Key`** header and
  creates at most one job per (tenant, key) — uniqueness is a database
  constraint, since two replicas serving the same retry would both read "no
  such key" — answering **200** rather than 202 for the replay, because nothing
  was accepted that time. `POST /api/agent/jobs/{job_id}/results` takes an
  optional `idempotency_key` form field and replays the stored outcome instead
  of the 422 that P1.3 gives a second completion, with **409** when a second
  upload genuinely contradicts the first. Agents that send no key still get
  replay detection from the natural key (same agent, same job, same exit code),
  so no agent upgrade is required; the bundled agent derives its key from the
  job rather than randomising it, so a restarted process computes the same one.
  An upload for a **cancelled** job is still refused — cancellation is an
  operator decision, not an outcome to replay. A duplicate arriving *while* the
  first upload is still being ingested also answers 409 (retry once it
  finishes) rather than letting two handlers extract into the same run
  directory. New metric `octo_job_idempotent_replays_total{operation}`.
- **Attempt fencing on result upload.** The claim response now carries an
  `attempt` number, which the agent echoes back with its results. A lease that
  expired and was reissued bumps it, so a straggling upload from the previous
  attempt is refused (**409**) instead of overwriting the run the current
  attempt is producing — a restarted worker keeps its `agent_id`, so agent
  identity alone could not tell the two apart. Agents that omit the field are
  unfenced, exactly as before.
- **The bundled agent now heartbeats for the whole scan** rather than once at
  the start. The heartbeat is what renews the server-side lease, so without this
  any scan longer than `OCTO_JOB_LEASE_SECONDS` would be requeued and handed to
  a second agent while the first was still scanning the same targets. Interval
  is 60s against the 300s default lease; a failed heartbeat is retried on the
  next tick rather than aborting the scan.
- The **schedule dispatcher** now keys each dispatch on the schedule's own due
  time, so replicas that all wake for the same tick create one job instead of
  one each. P1.6 (above) means only the leader ticks at all, but this key stays
  load-bearing: leadership is not fenced, so a dying leader and its successor
  can briefly overlap.
- **Job leases and an expiry reaper** (ROADMAP P1.4; migration
  `0009_job_leases`). A job handed to an executor had no deadline, so "the
  worker is still scanning" and "the worker died three hours ago" looked
  identical in the table and the row stayed in flight forever. Every
  claimed/running job now carries `claimed_until`, renewed by the agent
  heartbeat — or, for local jobs, by a thread running beside the scan, which is
  what finally closes the P1.2 residual: the renewals stop with the replica, so
  an orphaned local job stops looking attended. A sweep every
  `OCTO_JOB_REAPER_INTERVAL_SECONDS` (60) puts expired **agent** jobs back on
  the queue until `OCTO_JOB_MAX_ATTEMPTS` (3) hand-outs are used and fails them
  after that, so a target that kills whatever picks it up cannot cycle through
  the fleet; expired **local** jobs are failed outright, since no other replica
  could ever pick them up. The sweep runs in every replica and needs no leader
  election — expiry is a property of the row, and candidates are taken with
  `FOR UPDATE SKIP LOCKED`. New settings `OCTO_JOB_LEASE_SECONDS` (300),
  `OCTO_JOB_MAX_ATTEMPTS`, `OCTO_JOB_REAPER_ENABLED`,
  `OCTO_JOB_REAPER_INTERVAL_SECONDS`; new metric
  `octo_job_lease_expired_total{outcome}`; `JobInfo` gained `attempts`.
  **Set `OCTO_JOB_LEASE_SECONDS` comfortably above your agents' heartbeat
  interval** — too low and healthy scans get requeued underneath a working
  agent.
- **`POST /api/jobs/{job_id}/cancel`** (operator; ROADMAP P1.3) — cancels a
  queued job, which the API previously had no way to do: a queued scan could
  only be waited out. Legal **only** from `queued`, where nothing has taken the
  job and refusing to hand it out is a real stop. A `claimed` or `running` job
  answers **409**: an agent that has claimed a job starts scanning without
  asking the API again, so cancelling then would show a stop that never happened
  while the targets were still being scanned. An abandoned claimed job is the
  lease reaper's business instead. A job in another tenant answers 404. The
  reason is recorded in the job's `error`. API-only for now: the Web UI shows
  the new statuses but has no cancel action.
- **`OCTO_INSTANCE_ID`** — identity of an API replica in the shared job queue,
  defaulting to the hostname. Local-mode jobs run in a thread inside one
  replica, so the row records its owner and a starting replica reconciles only
  its *own* orphaned local jobs instead of failing scans other replicas are
  still running. Jobs orphaned by a replica that never returns under the same
  id need the lease reaper (ROADMAP P1.4).

- **Scale profiling harness and results** — new `tests/fixtures/scale_profile.py`
  and [docs/scale-profile.md](docs/scale-profile.md) (ROADMAP P3.8). Times the
  ClickHouse diff helpers and the Postgres asset list over a P3.7 fixture at
  1k/10k/50k assets, and reports the two machine-independent counts alongside
  wall-clock: ClickHouse rows/bytes read from `system.query_log`, and Postgres
  statements per call. The document records what was measured, the fixes it
  produced, the `PARTITION BY` evaluation, and explicitly what it does not
  cover (no end-to-end API latency, no concurrency, no UI, no ingest path).

- **Scale test fixtures** — new `tests/fixtures/scale_seed.py` (ROADMAP P3.7):
  a CLI that bulk-loads N synthetic assets into the two stores that actually
  grow with asset count — Postgres `assets`/`asset_identifiers` and ClickHouse
  `shapoclyack_vulnerabilities`/`shapoclyack_open_ports`. Every row is derived
  from `--seed` and the asset index, so runs are reproducible, reruns are
  idempotent (`ON CONFLICT DO NOTHING` / `ReplacingMergeTree`), and a 10k
  fixture is a byte-identical superset of the 1k one. `--purge` removes a
  tenant's rows; the default tenant is `scale-test`, never `default`.
  Complements `tests/load/run.sh`, which drives network load against live
  containers and produces one run's worth of hosts, not a populated registry.

- **`overlays/kind-enrichment`** — the local kind lab with real GeoIP/ASN/EPSS/
  KEV/CVSS4 data. Identical to `overlays/enrichment` except the PVC drops to
  `ReadWriteOnce`, since kind only ships the RWO local-path provisioner and an
  RWX claim would stay `Pending` forever. `base/enrichment/` became a kustomize
  Component so both overlays share the same patches instead of copying them.
- **`NVD_API_KEY` wired into the enrichment fetch** from optional Secret
  `shapoclyack-nvd` (key `nvd_api_key`), in both the refresh CronJob and the API
  cold-start initContainer. This is deliberately separate from the key stored
  through the config API (`enrichment.cvss4.nvd_api_key`), which is only ever
  exported into a running scan process and never reached the fetch.
- **Prometheus scrape wiring** (ROADMAP P3.5). The API pod template now carries
  `prometheus.io/scrape` / `port` / `path` annotations, so annotation-based
  scrape configs pick `GET /metrics` up with no extra objects; the annotations
  are inert when nothing scrapes them. For Prometheus Operator installations,
  `k8s/shapoclyack/examples/servicemonitor.example.yaml` is a ready
  `ServiceMonitor` — it stays in `examples/` because it needs the
  `monitoring.coreos.com/v1` CRDs, which no manifest here installs and whose
  absence must not break `kubectl apply` of `base/`. `k8s/README.md` documents
  both paths plus a bare `scrape_configs` snippet, and states explicitly that
  `/metrics` is unauthenticated by design and must stay off the Ingress.
- **Service level objectives** — new [docs/slo.md](docs/slo.md) (ROADMAP P3.6):
  seven SLIs with PromQL over the existing series (API availability and
  latency, job success rate and duration, ClickHouse ingest lag and
  correctness, endpoint-inventory acceptance), an error-budget policy, and
  burn-rate alerting guidance. Targets are labelled as starting values rather
  than measured commitments — there is no scale baseline until P3.7/P3.8 land.
  The known-gaps section records what the metrics cannot currently support:
  per-replica in-memory job gauges, no tenant label on any series, and no
  tracing.

### Changed

- **Risk scoring rebuilt on NIST SP 800-30 Rev. 1** (#144) — scoring model
  `mvp-2` → **`nist-1`**. The old model was a weighted sum
  (`0.55*CVSS + 0.30*EPSS + 0.10*exploit + 0.05*criticality`), which got two
  things wrong that changed what operators saw:

  * **Asset criticality barely counted.** At weight 0.05 over a 0–4 scale, the
    whole difference between a lab VM and a payment gateway was 0.5 points out
    of 10. It is now on the impact axis and shifts it by ±20 semi-quantitative
    points — enough to cross level boundaries in both directions, so business
    context can change the verdict instead of decorating it.
  * **"Exploitable" was one bit.** `exploit_active` was 1 for CISA KEV and 0 for
    everything else, so "a working exploit has been public for years" and
    "nobody has ever demonstrated this" landed in the same bucket.

  Risk is now assessed as `f(likelihood, impact)` through Table I-2, transcribed
  verbatim (the table is deliberately asymmetric, so any smooth formula would
  disagree with the standard somewhere). Likelihood comes from the CVSS vector's
  exploitability metrics blended with EPSS, then **floored and capped by exploit
  maturity**; impact from the vector's impact metrics shifted by asset
  criticality.

  **Exploit maturity** answers "is there a PoC, or is this theoretical":
  `attacked` (CISA KEV) / `weaponized` (Metasploit) / `proof_of_concept`
  (Exploit-DB, or a nuclei template) / `unproven` / `theoretical`. Every level
  carries the named sources that justified it (`exploit_evidence`), and a
  template that *matched during the scan* is recorded distinctly from one that
  merely exists in the corpus — the former means a working check fired against
  that host (`exploit_verified_on_host`).

  A sixth value, **`unknown`**, is deliberately not the same as `theoretical`:
  the former means no exploit-intelligence source is configured, the latter that
  sources were consulted and none knows of exploit code. `unknown` applies no
  bound, so an un-enriched installation falls back to reachability and EPSS
  rather than rating its whole estate low-likelihood and calling that a clean
  bill of health.

  New optional overlay `OCTO_EXPLOIT_DATABASE` with `scripts/fetch-exploit-db.py`
  (Exploit-DB + Metasploit; merges rather than replaces, and refuses to publish
  an empty result). New API fields on vulnerabilities: `risk_level`,
  `likelihood`, `impact`, `exploit_maturity`, `exploit_evidence`,
  `exploit_verified_on_host`. Every `mvp-2` output key is preserved, so
  ClickHouse ingest and the UI are unaffected; `risk_explanation` now states the
  verdict and each axis's reasons rather than listing inputs. Methodology and
  its stated limits: `docs/risk-scoring.md`.


- **`tenant_id` is now validated on tenant creation** — `[A-Za-z0-9]` followed
  by up to 63 more of `[A-Za-z0-9_-]`, and the prefix `h_` is reserved.
  `POST /api/tenants` answers 422 for anything else (it previously accepted any
  non-empty string up to the column width). The id is not just a key: it is a
  token in `ingest.results.{tenant_id}` and now `events.asset.{tenant_id}.{kind}`,
  and the old subject sanitizer mapped every disallowed character to `_`, so
  `acme.eu` and `acme_eu` shared one subject — a subscription or NATS ACL scoped
  to one of them also received the other's messages. Ids that predate the
  validation keep working: they are published under a reserved
  `h_<sha256[:32]>` token instead of being mangled into a neighbour's subject,
  and every conforming id keeps the subject name it has today.

- **TLS certificate name mismatch** (ROADMAP P4.1) — new `cert_name_mismatch`
  (medium) finding in `tls_posture.json`, closing the hostname/SAN-CN gap that
  Phase 9.2 explicitly left out of scope. A certificate is flagged when its DNS
  identities (subject commonName plus every `DNS:` SAN) cover none of the names
  the scan used to reach that endpoint. Name matching follows RFC 6125: a
  leftmost `*` covers exactly one label and never a public-suffix-level one, and
  partial-label wildcards (`www*.example.com`) do not match, since clients
  reject them. The check runs as one pass over the finished findings, so all
  three sources (nmap `ssl-cert`, `pulse-tls`, the stdlib probe) are treated
  identically — they disagree about certificate *formatting*, not about what a
  certificate is for; extraction in the new `scanner/pipeline/cert_names.py`
  handles all three shapes.

  What counts as an expected name is the part that decides whether this is
  signal or noise. It is the **forward** half of `hostnames.json` — the FQDNs
  the operator scanned, which resolved to this IP — plus the hostname the
  record itself was dialled by on the Pulse/probe paths. PTR names are
  deliberately excluded: a reverse name is assigned by whoever owns the address
  block, not whoever owns the service, so `ec2-….compute.amazonaws.com` missing
  from a certificate is the normal case and including it would have made this
  check fire on most of the internet. An endpoint reached only by IP, or a
  certificate whose names did not parse, yields **no** finding rather than a
  mismatch.

  **SNI is treated as part of the evidence.** A server behind virtual hosting
  answers a connection made to an *address* with its default certificate, which
  says nothing about the name that was scanned — so the stdlib probe now sends
  the resolved FQDN in SNI (`probe_tls_endpoints(sni_by_host=…)`) and records it
  on the finding, and its certificate is judged against that name alone. Sources
  that cannot report an SNI (nmap's `ssl-cert` against an IP target, Pulse)
  still report the mismatch, tagged `requires_confirmation: true` — the
  convention already used for Pulse's legacy protocol probe — because a genuine
  misconfiguration and a default-vhost answer are indistinguishable without
  re-probing by name. Controlled by `tls_posture.hostname_mismatch` (default `true`,
  inside the already opt-in `tls_posture` stage, and editable from the admin
  configurator); findings-only as before, never merged into scan scope.
- The optional DER certificate path in `tls_probe.py` now renders SAN entries as
  `DNS:name` / `IP Address:addr` instead of `cryptography`'s
  `<DNSName(value='…')>` repr, so every source hands the name check one shape.
  Wrapper forms that still arrive that way (Pulse emits `DNSName("app.local")`)
  are unwrapped before matching rather than compared verbatim, and a host
  reported in Pulse's display form (`app.local (10.0.0.5)`) is parsed down to
  the name — in both cases the unparsed string would have matched nothing and
  invented a mismatch.
- The admin configurator now renders **any** boolean setting as a checkbox
  instead of only paths ending in `.enabled`. A boolean drawn as a number input
  sends `0`/`1`, which the API's boolean validator rejects, so the setting could
  be displayed but never changed.


- **The schedule dispatcher elects a leader** (ROADMAP P1.6, new
  `api/services/leader_lock.py`). Its thread still starts in every replica, but
  each tick first takes a session-scoped Postgres advisory lock and does
  nothing without it — so exactly one replica polls for due schedules and
  writes their `last_run_at`/`next_run_at` bookkeeping. **This retires the
  operational rule** that you must run a single API replica, or set
  `OCTO_SCHEDULER_DISPATCH_ENABLED=false` on all but one; leave the knob on
  everywhere. A session lock rather than a leader row with a lease because the
  lock lives in the connection: a leader that crashes, is OOM-killed, or is
  partitioned away has it dropped by Postgres when its backend ends, so there
  is no expiry to wait out and a follower's next tick simply wins. It is
  deliberately **not** a fence — a dying leader and its successor can briefly
  overlap — which is why the P1.5 idempotency key on each dispatch stays
  load-bearing. Costs one pooled connection per replica. New
  `octo_scheduler_is_leader`: it is 1 on exactly one replica, so a fleet-wide
  `sum()` other than 1 is the signal something is wrong. On the SQLite fallback
  URL there are no advisory locks and no second replica, so the process always
  leads.
- **Job statuses are now a validated state machine** (ROADMAP P1.3). The
  lifecycle lives in one place (`api/services/job_states.py`) and is enforced on
  every status write, instead of each call site assigning a string: an illegal
  move raises rather than overwriting, so a `/results` upload retried after a
  network timeout can no longer rewrite a job that already finished — and it is
  rejected *before* the archive is extracted and re-published. Two states are
  new. `claimed` covers the window between an agent taking a job and reporting
  that the scan started (its first heartbeat naming the job promotes it to
  `running`); it used to be indistinguishable from `running`, hiding exactly
  the case the P1.4 lease reaper needs to see. `started_at` now records when the
  agent reported starting rather than when it claimed, so job durations no
  longer include the claim-to-heartbeat delay. `cancelled` is terminal and set
  by the new endpoint below. **API consumers:** `JobInfo.status` can now return
  `claimed` and `cancelled`; the Web UI renders both.
- `octo_jobs_running` counts `claimed` jobs as well as `running` ones — a
  claimed job is out with a worker, so leaving it in `octo_jobs_queued` would
  read as a backlog nothing is working on. `cancelled` jobs are not observed by
  `octo_job_duration_seconds`, so an operator's decision does not count against
  the job-completion SLO ([docs/slo.md](docs/slo.md)).

- **Durable control plane: jobs and agents moved into PostgreSQL** (ROADMAP
  P1.1/P1.2). Both registries were module-level dicts in the API process,
  mirrored to `state/api_jobs.json` and `state/api_agents.json`. That gave
  every API replica its own queue and its own view of the agent fleet, lost
  anything not yet flushed when the process died, and serialised job claims
  with a `threading.Lock` that a second replica never saw — two replicas could
  hand the same queued job to two agents. New migration `0008_jobs_agents`
  adds the `jobs` and `agents` tables; `claim_job` now takes the candidate row
  with `SELECT … FOR UPDATE SKIP LOCKED`, so concurrent claims get distinct
  jobs. Job list/search/sort moved into SQL with the same query parameters and
  `Page` envelope as before (no API change). Agent staleness stays *derived*
  from `last_seen_at` instead of being written to the row, so one replica's
  clock cannot freeze a "stale" flag that every other replica reads back.
  **Upgrades need no manual step**: each legacy JSON file is imported once at
  startup and renamed to `*.imported`.
- **`octo_jobs_queued` / `octo_jobs_running` are now cluster-wide**, counted in
  the `jobs` table rather than per-process, and no longer reset to zero on
  restart — the "single-process gauges" gap in [docs/slo.md](docs/slo.md) is
  closed. Every replica exports the same number, so aggregate with `max()`,
  not `sum()`.


- **`GET /api/assets` no longer issues one query per returned row** (ROADMAP
  P3.8). `list_assets` fetched each asset's identifiers in its own `SELECT`, so
  the dashboard's `limit=5000` page cost 5002 statements and ~1.1 s at 50k
  assets; identifiers for the whole page now come from a single `IN` query — 3
  statements regardless of page size, and 77 ms for the same page. The default
  100-row page went from 27.8 ms to 9.3 ms. No response-shape change.
- **`ch_diff.fetch_tenant_cves` / `fetch_tenant_ports` are now bounded** by a
  `max_rows` argument (default 500 000) and **raise** when a tenant exceeds it.
  They materialize a tenant's whole history into a set to compute a set
  difference, so a truncated result would report every dropped key as `removed`
  and every later re-observation as new — failing is the safer outcome.
  `fetch_tenant_ports` also gained the `since` parameter `fetch_tenant_cves`
  already had, since narrowing the window is the remedy when the cap trips.
  Both are helper-only today; the scanner's filesystem diff remains the default
  path, so no runtime behaviour changes.
- **`octo_job_duration_seconds` histogram buckets** are now explicit, spanning
  30s to 8h. The `prometheus_client` default set stops at 10s, so every real
  scan fell into `+Inf` and no duration quantile was computable. Existing
  bucket series (`_bucket{le=...}`) change; `_count` and `_sum` do not.

### Fixed

- **Enrichment volume no longer starts empty, and CVSS v4 is a real database.**
  On Kubernetes the enrichment PVC mounts at `/app/scanner/data` — the same path
  the image bakes the seed data into — so the mount shadowed the seed and
  `scripts/fetch-enrichment.sh`'s "floor" copy silently had nothing to read: its
  source and destination were the same hidden directory. The images now keep a
  pristine copy at `/opt/shapoclyack/seed-data` (override with
  `OCTO_ENRICHMENT_SEED_DIR`) and the floor reads from there.

  `scripts/fetch-cvss4-db.py` gained `--full` (page the whole NVD corpus, keep
  every CVE carrying a genuine `cvssMetricV40`) and `--last-mod-days N`
  (incremental, now what the daily refresh runs). Its previous default — refresh
  a hardcoded 6-CVE list — produced an empty database on a fresh volume and
  reported success, because none of those six have a CVSS v4 score in NVD at
  all. A run that harvests nothing, or a `--full` that fails part-way, now
  refuses to overwrite an existing database and exits non-zero; writes are
  atomic (write-then-rename) so API replicas polling the file by mtime never
  read a partial one. NVD's `cvssV4Severity` filter is unusable for selecting
  v4-scored CVEs, so filtering happens client-side.

  `scan-targets` is mounted as a required Secret by `job.yaml`, `job-resume.yaml`
  and `cronjob.yaml` (unlike the API Deployment, where it is optional). When it
  is missing the pod cannot be created at all and the Job sits in
  `ContainerCreating` until `activeDeadlineSeconds` fails it — deleting the pod,
  its logs and its events, so the only symptom is a bare `DeadlineExceeded` an
  hour later. `scripts/dev-up.sh` now warns when the Secret is absent, and
  `docs/troubleshooting.md` documents the signature.
- **XML parsing hardened** — `scanner/pipeline/report.py`,
  `scanner/pipeline/tls_posture.py`, and `scripts/compare-pulse-nmap.py` parse
  nmap XML, which embeds attacker-influenced banner and NSE text, through
  `defusedxml`. Python's `ElementTree` does not expand external entities, so
  this closed an entity-expansion DoS surface rather than XXE. Two further
  semgrep ERROR findings were reviewed and annotated as verified false
  positives: the unverified JWT decode in `api/auth.py` is a routing peek at
  the `typ` claim (a forged `typ=agent` only routes into `decode_agent_token()`,
  which re-verifies against `jwt_secret`), and the unverified SSL context in
  `defectdojo.py` is an opt-in escape hatch gated on `verify_ssl`, default
  `True`. SAST gate: 5 ERROR findings → 0.

### Fixed

- **`profiles.<mode>.top_ports` now rejects values naabu cannot parse.** The
  field validated as any integer in 1–65535, but naabu's `-top-ports` is a
  named port set, not a count — it accepts `100`, `1000` or `full` and nothing
  else. A profile carrying e.g. `top_ports: 500` passed config validation and
  then aborted every port batch of every run with `could not parse ports:
  invalid top ports option`, before a single host was scanned. It is now
  constrained to `100`/`1000` in the schema and in the config API's editable-path
  whitelist, and the web configurator offers those two values instead of a free
  number input. The shipped profiles only ever used 100 and 1000, so no
  supported configuration changes. A full-range scan is still available through
  `ports.custom_ports_file` (`1-65535`), which reaches naabu as `-p`.

### Security

- **Migrations are serialized, and there is one path to the schema** (#159).
  Every API replica runs `alembic upgrade head` in its init container. While
  `replicas: 1` was a correctness requirement that was safe by construction;
  P1.6 removed the requirement and left the init container unchanged, so a
  scaled Deployment started N concurrent migrations against one database.
  Alembic has no mutual exclusion of its own — both runs read the same
  `alembic_version`, both decide the same revision is pending, and both apply
  it.

  The init container now runs `python -m api.db.migrate`, which takes a
  **PostgreSQL advisory lock** — the primitive P1.6 already uses for scheduler
  leader election — before upgrading. Replicas queue instead of racing.
  Deliberately a blocking lock rather than the `pg_try_advisory_lock` used for
  leadership: a replica that cannot get it must wait for the migration to
  finish, not start against an unmigrated schema. Waiters still run the upgrade
  after acquiring the lock, which is a no-op when the first replica succeeded
  and still correct when it did not.
  `OCTO_MIGRATION_LOCK_TIMEOUT_SECONDS` (default 600) bounds the wait so a stuck
  migration fails the pod with a named cause instead of hanging at `Init:0/1`.

  A lock rather than a separate pre-rollout Job because plain kustomize has no
  ordering hooks: a Job would have to be applied and waited on out-of-band, a
  second deployment step that `kubectl apply -k` does not perform.

  **`models.Base.metadata.create_all` no longer runs on PostgreSQL.** It built
  today's models while writing no `alembic_version` row, so a database it had
  touched looked migrated to no revision at all while carrying columns a
  migration was meant to add — and it silently repaired the one situation worth
  reporting, an API replica started against a database nobody migrated. It
  remains for SQLite, the dev and test fallback, which cannot be shared by
  replicas and where requiring a migration run before `pytest` would buy
  nothing.

  Alembic's `fileConfig` is now called with `disable_existing_loggers=False`.
  Running the upgrade in-process meant it switched off every logger it does not
  name — including `api.db.migrate`, whose next line is the message explaining
  why a migration did not apply.

  [docs/operations.md](docs/operations.md) gains an **Upgrade and rollback**
  section: the expand/contract rule (a release's migration must leave the
  previous release's code working, which is what makes both the rolling update
  and `rollout undo` safe), what to do when a migration fails halfway, why
  `alembic downgrade` is not the routine path back, and the release in which the
  legacy `state/api_{jobs,agents}.json` import is removed.

- **Login rate limiting and an authentication audit trail** (#157).
  `POST /api/auth/login` was unlimited and unrecorded: guessing a password was
  bounded only by network throughput, and a successful guess looked exactly
  like an ordinary sign-in in the logs and in `/metrics`.

  Every attempt is now a row in `auth_events` (migration `0014`) and a tick of
  `octo_auth_attempts_total{outcome}` — `success`, `failure`, or `locked` (the
  limiter refused it before the password was checked). Those same rows *are*
  the limiter: two counters over one window (default 15 min) allow **5**
  failures per `(username, client IP)` and **50** per client IP across all
  usernames, the second being what walking a username list looks like. Either
  tripping answers `429` with `Retry-After`, in the same words whether or not
  the account exists.

  The counter is a table rather than a process because more than one API
  replica is now legal to run (ROADMAP P1.6) — in memory the limit would be
  divided by the replica count and reset on every rollout. The window decays on
  its own, so a correct password works again with no operator involved and an
  attacker cannot lock a known username out permanently by failing on purpose.

  `X-Forwarded-For` is honoured **only** when the immediate peer is listed in
  the new `OCTO_TRUSTED_PROXIES`; otherwise the client would pick its own
  limiter key by writing the header. Unset (the default), the socket peer is
  used — set it when the API sits behind an ingress, or the whole installation
  shares one key.

  New admin endpoint `GET /api/auth/events` (newest first, `Page` envelope,
  filters on username/IP and outcome). Rows are pruned past
  `OCTO_AUTH_EVENT_RETENTION_DAYS` (default 90), and a locked-out client writes
  one `locked` row per window rather than one per retry — otherwise the audit
  trail is an amplifier for unauthenticated writes.

- **Console accounts moved to Postgres; plaintext passwords no longer
  authenticate** (#156) — **breaking.** Accounts live in a `users` table
  (migration `0013`) instead of the `OCTO_API_USERS` environment variable, and
  `authenticate_user` verifies bcrypt only. Previously it compared **plaintext**
  whenever the stored value did not start with `$2`, a password could not be
  rotated without editing a Secret and restarting every pod, nothing recorded
  who changed an account, and disabling one user meant rewriting the whole JSON.

  New admin surface `/api/users` (create, list, reset password, change role,
  disable, delete) plus `POST /api/auth/password`, which any role may call to
  rotate their own password. It re-verifies the current password even though the
  caller holds a valid token: a token proves "can act as this user right now",
  which a stolen one also proves. No response carries a password or a hash.

  Disabling is preferred to deleting — memberships and history survive a
  revocation — and deleting cascades memberships through the new FK, so no grant
  outlives its account. Disabling, demoting or deleting the last enabled admin
  answers `409`; that installation would only be recoverable by hand.

  `OCTO_API_USERS` becomes a **one-time bootstrap input**: imported into an
  empty table on a first start (plaintext hashed on the way in), ignored
  afterwards. The built-in demo accounts are never imported — their passwords
  are published in this repository, so seeding them would re-open through the
  table what #155 closed at the environment level. They are seeded only under
  `OCTO_ENV=dev`. A `prod` install with neither an account nor the variable
  refuses to start, which supersedes #155's "`OCTO_API_USERS` unset" refusal:
  an unset variable is now the normal steady state, and only the database can
  tell an install with a real admin from one with none.

  Migration `0013` backfills a **disabled, password-less** account for every
  username that had a `user_tenants` row but no account, so the new FK can be
  added without either failing on orphans or silently deleting grants an
  operator made deliberately. Those rows cannot authenticate and are visible in
  `GET /api/users`.

  Also fixes an adjacent fault the tests surfaced: passlib *raises* on an
  unrecognisable hash rather than returning false, so a row left over from the
  plaintext era would have produced a `500` on login instead of a `401`.

- **Fail-closed startup configuration** (#155) — **breaking for deployments that
  relied on the built-in defaults.** The API now reads `OCTO_ENV`, defaulting to
  `prod`, and a `prod` process refuses to start while the JWT secret is unset or
  still the value published in this repository, or while `OCTO_API_CORS` allows
  `*`. (The third default of this shape, the built-in demo accounts, is refused
  by #156 above — at startup rather than here, because after that change only
  the database can tell a configured install from an unconfigured one.)
  Previously these were silent defaults, so "forgot to configure" and
  "configured" produced an identical, working start.

  The refusal lists every problem at once — fixing them one restart at a time is
  the failure mode a per-variable check would create — and names variables
  rather than printing values, since the text lands in logs and terminals. A
  `*` listed *beside* real origins is refused too: the wildcard matches every
  origin regardless of what sits next to it.

  `OCTO_ENV=dev` allows the defaults and is set by the `dev` overlay (inherited
  by `kind-dev`, so `scripts/dev-up.sh` is unaffected) and by the test suite,
  which uses the demo accounts by design. `base` and the `prod` overlay
  deliberately do not set it. An unrecognised `OCTO_ENV` is rejected rather than
  guessed in either direction. A set `OCTO_AGENT_TOKEN` warns but does not
  refuse — the legacy shared token still works, and breaking a running install
  over a design preference is not the same as refusing a published credential.

  Migrations are unaffected (the Alembic initContainer does not import API
  settings), as are the agent and scanner. See
  `docs/configuration.md#startup-safety-octo_env`.

- **nuclei bumped v3.9.0 → v3.11.1**, and the `GHSA-r277-6w6q-xmqw` exception
  dropped from `.trivyignore`. That advisory (kin-openapi fail-open auth bypass)
  was suppressed in CI because no nuclei release had shipped the fix yet;
  v3.11.1 pins `kin-openapi` 0.144.0, so the vulnerable dependency is gone from
  the image instead of hidden from the Trivy gate.

### CI

- Jenkins pipeline fixes: kustomize validation installs `kubectl` into the
  Jenkins image (`bitnami/kubectl:1.31` stopped resolving on Docker Hub, and
  `registry.k8s.io/kubectl` is distroless and cannot run the bash validator);
  the pytest stage no longer installs `gcc`/`libpq-dev`/`curl` via apt
  (`psycopg[binary]` ships libpq, readiness waits use the stdlib), removing a
  network dependency that broke the 3.12 matrix branch; the e2e and synthetic
  load stages set `TMPDIR` into the workspace so `mktemp -d` produces a path
  that resolves identically inside the Jenkins container and on the host the
  Docker daemon runs on; and the synthetic load test now calls
  `tests/load/run.sh` directly with the parameters the GitHub composite action
  used (16 hosts, 2400s timeout, 0.95 pass fraction) and gates the stage on the
  parsed metrics JSON.

## [0.40-0806] — 2026-08-06

### Changed

- **Pulse `v0.2.7` → `v0.8.3`** — `PULSE_VERSION` in `Dockerfile` and
  `Dockerfile.allinone`, plus `scripts/install-pulse.sh`, which had drifted a
  release behind the images at `v0.2.6`. All three now name the same tag.

  The pin had been stuck since July because GenDec's release pipeline stopped
  attaching Linux tarballs: `v0.6.0` published no assets at all and
  `v0.7.0`/`v0.8.0` only macOS ones, so there was nothing for the image build
  to download. Fixed upstream in GenDec (onixus/GenDec#6 and follow-up), and
  `v0.8.3` is the first release with the full asset set again.

  Pulse's JSON contract is unchanged across the jump (`pulse.scan.v2`, same
  top-level keys), and every flag the probe adapter passes still exists — but
  the findings now carry **`epss` and `in_kev` per finding**, which the
  `mvp-2` scoring below prefers over the local overlay stubs. On `v0.2.7`
  those two fields were simply absent and scoring fell back to the overlays.

  Not yet wired up from the six releases this skips: the Rhai audit-plugin
  engine, Shodan/Censys threat intel, `--stream` NDJSON progress, and
  `--diff-against` drift comparison.

### Added

- **Finding taxonomy and risk-priority explanation** (scoring model `mvp-1` →
  **`mvp-2`**; closes the ROADMAP [P4](ROADMAP.md) "risk-priority explanation"
  item). Pulse labels every finding as observation or hypothesis, and
  Shapoclyack was throwing those labels away at the adapter boundary.
  - `octo.cve.v1` gained `finding_class`, `confidence`,
    `requires_confirmation`, `evidence`, `ruleset_version`, `epss`, and
    `in_kev`, all carried into `vulnerabilities.json`.
  - **CVE-less findings are no longer dropped.** `exposure` (reachable
    service, no CVE claimed) and `tls` findings used to be discarded by the
    parser; they now survive with a synthetic `script_id`
    (`pulse:<class>:<port>:<slug>`) so each stays a distinct row in the report
    dedupe and in ClickHouse instead of collapsing per host.
  - Scoring prefers the finding's own EPSS/KEV data over the local
    `OCTO_EPSS_DATABASE` / `OCTO_KEV_DATABASE` overlays, whose committed
    defaults are seed stubs. The overlays still cover nuclei/NSE findings.
  - Unconfirmed findings (`exposure`, `keyword_cve`, or anything the scanner
    marks `requires_confirmation`) are discounted by their confidence and
    capped below the `Act` decision, so an unverified keyword hit no longer
    outranks a confirmed, KEV-listed vulnerability.
  - Every finding now carries `contextual_score`, `cisa_decision`, and a
    one-line `risk_explanation`; `GET /runs/{id}/vulnerabilities` returns them
    (and orders by score), and the run's Findings tab renders the score,
    decision, explanation, and `unconfirmed` / `KEV` badges.

  **Expected change in numbers:** `potential_vulnerabilities` rises on Pulse
  runs, because exposures that were silently discarded are now reported. The
  new `summary.json` key `unconfirmed_findings` breaks out how much of the
  total is hypothesis rather than confirmed vulnerability. No ClickHouse
  schema change — the existing `cve_id` column already falls back to
  `script_id` for findings without a CVE.

- **Tenant-aware IAM — completed** (ROADMAP [P0](ROADMAP.md)) — runs are the
  last resource to gain tenant scoping, and the console gained a tenant
  switcher.
  - The API tags each completed run with its owning tenant by writing
    `tenant.json` into the run directory — from `_run_job` for local execution
    and from `complete_job` for agent uploads (the latter already wrote the
    file; both paths now share `runs_service.write_run_tenant`).
  - `GET /api/runs` and every run sub-resource (`hosts`, `ports`,
    `vulnerabilities`, `diff`, `artifacts/*`, `download/*`) moved from
    `require_role` to `require_tenant` and are filtered by that marker. A run
    in another tenant answers `404`, matching jobs/assets/schedules. A platform
    admin who names no tenant keeps the fleet-wide view.
  - `RunSummary`/`RunDetail` now carry `tenant_id`.
  - Web UI: a tenant switcher in the header (`TenantSwitcher`) drives an
    `activeTenant` in the auth store; an axios request interceptor attaches it
    as `tenant_id` to every call that does not already name one, and switching
    clears the React Query cache. The Endpoints page dropped its own
    page-local tenant selector in favour of the global one.

  **Compatibility:** a run without the marker reads as belonging to `default`,
  so pre-existing runs and runs produced by invoking `scanner.main` outside the
  API stay visible to the default tenant. There is no backfill — write
  `tenant.json` by hand for historical runs that belong to a customer tenant.

## [0.39-0805] — 2026-08-05

### Changed

- **Retired the legacy `octo-man` product name.** Nothing of that product
  remained apart from its name, so it is gone from code, manifests, docs, and
  runtime strings: loggers (`octo-man.*` → `shapoclyack.*`), the FastAPI title,
  NATS/agent client names, scanner User-Agents (`shapoclyack-octo-man/*` →
  `shapoclyack/*`), DefectDojo product/engagement/test defaults, the PDF report
  title, alert subjects, the Web UI sidebar, and `octo_man.html` →
  `shapoclyack.html`. Kubernetes moved from `k8s/octo-man/` to
  `k8s/shapoclyack/` with every `octo-man-*` object and
  `app.kubernetes.io/{name,part-of}` label renamed, and the Postgres database
  is now `shapoclyack`.
  **Operator action, existing clusters only:** resource and database renames
  create new objects, so run the one-time migration in
  [k8s/README.md](k8s/README.md#upgrading-a-cluster-deployed-before-the-octo-man--shapoclyack-rename)
  (`ALTER DATABASE octo_man RENAME TO shapoclyack;` plus an orphan-cascade
  delete of the old objects). Self-hosted installations need nothing: the
  sqlite default is now `shapoclyack.db` but falls back to an existing
  `octo_man.db`. **Deliberately unchanged** (not product naming, and renaming
  them would break running deployments): the `OCTO_*` environment variables,
  the `octo_*` Prometheus metric names, the `network-scan` namespace, the
  `octo` database user, and the already-Shapoclyack GHCR image names.
  DefectDojo exports land under the product name `Shapoclyack` from now on —
  set `defectdojo.product_name` back to `Octo-man` if you need findings to keep
  flowing into the existing product.

### Added

- **Tenant-aware IAM — foundation** (ROADMAP [P0](ROADMAP.md)) — new
  `user_tenants` table (migration `0007_user_tenants`) binds console usernames
  to tenants with a per-tenant role, managed by a platform admin via
  `GET/PUT/DELETE /api/tenants/{tenant_id}/members[/{username}]`. Every
  tenant-scoped route now derives its tenant from the authenticated user
  instead of trusting the `tenant_id` query parameter, which can only select
  among tenants the caller holds; anything else is `403`. Covers assets,
  jobs, agents, schedules, and endpoint inventory, including the request
  bodies of `POST /jobs` and `POST /schedules`. Cross-tenant lookups of a
  known id answer `404` rather than `403` so the id's existence stays
  private. `GET /api/auth/me` now returns `tenants`/`default_tenant`/
  `is_platform_admin`, and `GET /api/tenants` lists only the caller's tenants
  so an MSSP customer list cannot leak to one customer's operator.
  **Behaviour change**: a user with memberships is confined to them; a user
  with none keeps pre-P0 access to the `default` tenant, so existing
  single-tenant installations are unaffected. Runs and their artifacts are
  **not** scoped yet — run directories carry no tenant — and remain visible to
  any authenticated viewer.

- **Server-side pagination on every list endpoint** (ROADMAP
  [P3.2](ROADMAP.md)/[P3.3](ROADMAP.md)) — `GET /api/runs`, `/jobs`, `/agents`,
  `/assets`, and `/schedules` now take `offset`/`limit`/`q`/`sort`/`order` and
  answer with `{items, total, offset, limit, has_more}`. **Breaking**: these
  five routes previously returned a bare JSON array; clients must read
  `.items`. Filtering happens before `total` is counted, and an unknown `sort`
  falls back to the resource default rather than erroring. `jobs`/`agents`/
  `schedules` were fully unbounded before this. Asset listing pushes the
  identifier search into an EXISTS subquery, so `q` no longer post-filters an
  already-truncated page; run listing slices directories first and reads
  `run_meta.json`/`summary.json` for the requested page only.
- Web UI tables (assets, runs, jobs, agents, schedules, reports) drive paging,
  search, and sorting from the server instead of loading whole lists and
  filtering in the browser; search is debounced and any filter/sort change
  rewinds to the first page. The dashboard keeps aggregating and now shows the
  exact asset `total` alongside a note when its posture chart samples the cap.
- **Endpoint inventory retention, staleness, and operations (Agent_plan.md S9)**
  — an in-process sweep (`api/services/endpoint_retention.py`, started from the
  API lifespan like the schedule dispatcher) prunes `endpoint_software_items`
  for snapshots older than `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS`
  (90d, snapshot summary rows kept) and deletes `endpoint_software_changes`
  older than `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` (365d). Deletes
  are tenant-scoped, batched, and idempotent; a device's current snapshot is
  never pruned, since it backs the next submission's software diff.
- Server-side endpoint staleness (`OCTO_ENDPOINT_STALE_HOURS`, default 48):
  devices now carry a derived `status` (`active`/`stale`), read routes accept
  `device_status=` as a filter, and the Web UI uses the server value instead of
  recomputing the threshold client-side.
- Hard request-body cap on `POST /api/endpoint/inventory`
  (`OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES`, default 15 MiB) enforced from
  `Content-Length` before JSON parsing — oversized bodies get `413`, bodies
  without `Content-Length` get `411` and are never buffered.
- Endpoint-inventory Prometheus series (submission outcomes, ingest latency,
  entries per snapshot, change events, active/stale device gauge, retention
  deletions and sweep duration) plus an "Endpoint Inventory & Retention" panel
  on the System page and `endpoint_inventory` in `GET /api/system`.
- Migration `0006_endpoint_fk_cascade` — the endpoint FK chain now cascades from
  `tenants` (and nulls `asset_id` when an asset is deleted), so a future
  tenant-offboarding flow removes endpoint data without bespoke deletion code.
- **Cross-device software-changes feed** ([#98](https://github.com/onixus/Shapoclyack/issues/98)
  Phase 3) — `GET /api/endpoint/changes` returns recent installed/removed/
  updated software events across all endpoints for a tenant (joined with
  device hostname/asset), and the `/endpoints` page now shows a "Recent
  software changes" panel above the device table. Completes the one item
  left open from the Phase 3 endpoint-inventory plan (per-device history
  already existed on the asset view; this adds the global view).

### Changed

- **Nmap removed from default published images** ([#97](https://github.com/onixus/Shapoclyack/issues/97)
  Phase 1) — `docker-publish.yml` now builds the default `shapoclyack-scanner`/
  `-aio` GHCR images with `INSTALL_NMAP=0`; Pulse is already the default
  `service_probe.backend`, so this closes the actual NPSL redistribution risk
  in the distributed artifacts (previously only the config default was
  Pulse-first — the published images still bundled Nmap). A separate
  `-nmap` tag is published alongside for anyone who wants classic NSE.
- `docker-publish.yml` no longer hardcodes `PULSE_VERSION` as a build-arg —
  it now always follows the Dockerfiles' own `ARG PULSE_VERSION` default, so
  a Dockerfile version bump can't be silently overridden by a stale CI pin
  (this is what happened with the v0.2.7 bump below before this fix).

### Fixed

- **Pulse v0.2.7** — pin `PULSE_VERSION=v0.2.7` (fixes the `CVE-2024-6387`
  regreSSHion banner regex, which only matched OpenSSH 9.0-9.5 and silently
  missed the rest of the officially affected range, 8.5p1-9.7p1).
- **Endpoint software-change events had a blank name for removals** —
  `ingest_snapshot`'s diff only looked up display names from the *new*
  snapshot's software list, which doesn't contain removed items; both
  `GET /endpoint/devices/{id}/changes` and the new `/endpoint/changes` feed
  showed an empty name for every `removed` event. Now looked up from the
  previous snapshot instead. Found while building the changes feed above.

## [0.38-0729] — 2026-07-29

### Added

- **Pulse v0.2.6** — pin `PULSE_VERSION=v0.2.6` (fixes `pulse --cve` silently
  missing `version_cve` matches for services on non-standard ports; adds a
  Windows CLI build plus a native Windows GUI, `pulse-gui`, with the same
  glass-neon look as the macOS app).
- **Pulse v0.2.3** — pin `PULSE_VERSION=v0.2.3` (fingerprints/KEV feed/UDP + macOS GUI release assets).
- **Pulse v0.2.2** — pin `PULSE_VERSION=v0.2.2` (H2: HTTP probes, KEV/scope, weak TLS; `tls_posture` prefers `pulse/tls.json`).
- **Pulse service probe backend (opt-in)** — `service_probe.backend`:
  `nmap` (default) | `pulse` | `hybrid`. When `pulse`/`hybrid`, open ports
  from naabu are enriched via [Pulse](https://github.com/onixus/GenDec)
  (OS/banner/CVE → `services.json` / `os.json`). Override with
  `OCTO_SERVICE_BACKEND`. Scanner and all-in-one images multi-stage-build
  Pulse and install `/usr/local/bin/pulse` with raw-socket caps. System
  status lists `pulse --version`. Docs: `docs/pulse-backend.md`.
- **Pulse/Nmap shadow diff** — `service_probe.shadow` or `OCTO_PULSE_SHADOW=1`
  runs both backends and writes `diff_pulse_nmap.json` (endpoint Jaccard +
  OS family agreement). With `backend: nmap`, report still prefers nmap XML;
  Pulse CVEs can still attach when present.
- **TLS posture probe fallback (Phase 4)** — when nmap has no
  `ssl-cert`/`ssl-enum-ciphers` output, `tls_posture` can handshake open TLS
  ports via stdlib `ssl` (`probe_fallback`, default on). Writes
  `tls_probe.json` and fills `tls_posture.json` with `source: pulse-tls-probe`
  (cert expiry, self-signed heuristic, weak negotiated protocol/cipher).
- **Pulse default service probe (Phase 4.1)** — `service_probe.backend`
  defaults to `pulse` (OS/banner/CVE; no nmap NSE). Per-profile Pulse knobs
  under `profiles.<safe|balanced|fast>.pulse.*`. Full NSE via
  `backend: nmap|hybrid` and `nse_profiles.vuln_legacy`. `--skip-nse` remains
  ports-only L1 (skips Pulse and nmap).
- **CVE stack without nmap-vulners (Phase 4.2)** — default path is Pulse
  `--cve` + Nuclei (now **enabled by default**) + CVSS4 enrichment.
  Vulns tagged `source: pulse|nuclei|nmap-nse`; host:port:CVE deduped in
  reports. nmap-vulners only via `vuln_legacy` when backend is nmap/hybrid.
- **Optional nmap (Phase 5)** — `INSTALL_NMAP=0` build arg for lean
  Pulse-only images; `run_nse` skips cleanly if nmap is missing. System
  status marks nmap optional and surfaces `service_backend`. UI: “Ports
  only (skip service probe)” and “Legacy nmap NSE profiles”.
- **Pulse v0.2.1** — pin `PULSE_VERSION=v0.2.1` (findings taxonomy H1, TLS, fingerprint).
- **Pulse from GenDec releases** — Docker installs Pulse via
  `PULSE_VERSION` GitHub Release assets (no vendored Rust tree). CI uses
  optional `GENDEC_READ_TOKEN` for private GenDec. See GenDec
  `docs/release.md`.

## [0.37-0727] — 2026-07-27

### Fixed

- Shut down the dedicated NATS event loop cleanly so pending client tasks do not
  survive until pytest closes the loop.
- **NSE host batching could fail an entire group over one slow host** —
  `nse_hosts_per_scan` (nmap processes now scan one host each instead of
  batching up to 8 per invocation, `scanner/config/default.yaml` and
  `k8s/shapoclyack/base/config/k8s.yaml`). Bundling several hosts into one nmap
  invocation meant they shared the `nse_timeout_seconds` budget (hard-capped
  at 600s); a single host doing heavy `vulners`/`ssl-enum-ciphers` NSE work
  could blow that shared budget and fail every other host in the group, even
  though they would have finished fine scanned individually.
- Accepted `GHSA-r277-6w6q-xmqw` (kin-openapi fail-open auth bypass, pulled in
  transitively by the `nuclei` binary's OpenAPI spec parser) as a documented
  Trivy CI exception — no nuclei release has shipped the fix yet, and the
  vulnerable code path (`openapi3filter.ValidationHandler`) is unreachable in
  how nuclei actually uses the dependency.

### Changed

- Refactored the documentation into task-oriented guides under `docs/`, reduced
  the root English and Russian READMEs to stable project entry points, and
  aligned the Web UI, Kubernetes, roadmap, security, and endpoint-inventory
  documents with the current platform.
- Added a documented, privacy-safe interface screenshot inventory and
  reproducible capture procedure in `docs/ui.md`.

### Added

- **Endpoint inventory ingestion (Lariska agent integration, S1-S7)** — a new
  `POST /api/endpoint/inventory` contract (schema v1) lets the separate
  Lariska endpoint agent submit device identity/OS metadata and installed-
  software snapshots, authenticated via the existing agent-JWT/legacy-token
  `require_agent` dependency and kept fully independent of the network-scan
  agent protocol (`ingest.raw_results`, job claim/upload). New Postgres tables
  (`endpoint_devices`, `endpoint_identifiers`, `endpoint_inventory_snapshots`,
  `endpoint_software_items`, `endpoint_software_changes`, migration `0004`)
  back idempotent snapshot ingestion (natural-key digest, replay-safe),
  tenant-scoped asset reconciliation (exact-FQDN link, new endpoint-backed
  asset, or a reviewable `conflict` state — never auto-merged), and
  installed/removed/updated software-diff events (suppressed on first
  snapshot). Only agent-hashed platform identifiers are ever stored, never a
  raw MAC/serial. New read APIs (`GET /api/endpoint/devices[/…]`,
  `GET /api/assets/{id}/software`) and an Endpoint/Software section on the
  Web UI asset card. Gated by `OCTO_ENDPOINT_INVENTORY_ENABLED` (default on).
  NATS event publish (S8), retention/ops (S9), and the cross-repo e2e test
  (S10) are deferred to a follow-up.

- **Continuous org-level scan scheduling (Phase 8.5)** — a new per-tenant
  `scan_schedules` table (cron or fixed-interval cadence, target set + scan
  options) managed via `/api/schedules` (`GET`/`POST`/`PATCH` for operators,
  `DELETE` for admins). An in-process dispatcher thread, started from the API
  `lifespan` alongside the existing ClickHouse ingest worker, polls due
  schedules every 30s and starts jobs through the existing `jobs_service.start_scan`
  — skipping a tick if the schedule's previous job is still running. No new
  K8s CronJob/Deployment needed; the original single-tenant `scanner/scheduler.py`
  and static `k8s/shapoclyack/base/cronjob.yaml` are unchanged for simple
  self-hosted deployments.

## [0.36-0723] — 2026-07-23

### Fixed

- **OS detection (`nmap -O`) silently failing as the non-root container user**
  — `docker-compose.yml`'s `shapoclyack` service only granted `NET_RAW`
  (missing `NET_ADMIN`, which nmap's libcap-ng-based privilege drop needs
  alongside `NET_RAW` for `-O`), and `k8s/shapoclyack/base/api-deployment.yaml`'s
  `api` container plus `k8s/shapoclyack/base/agents/agent-deployment.yaml` set
  `allowPrivilegeEscalation: false`, which sets Linux's `no_new_privs` flag —
  this blocks the `setcap` file-capability grant on `nmap`/`naabu` outright,
  regardless of what's listed under `capabilities.add`. Brought all three in
  line with `job.yaml`/`cronjob.yaml`'s already-working
  `allowPrivilegeEscalation: true` + `capabilities.add: [NET_RAW, NET_ADMIN]`,
  and `Dockerfile`/`Dockerfile.allinone`'s `setcap` step now grants
  `cap_net_admin` in addition to `cap_net_raw` on both binaries. Every place
  this image actually runs scans (`docker-compose.yml`, `tests/e2e/run.sh`,
  the k8s manifests) already grants `NET_ADMIN` at the container level to
  match — `ci.yml`'s image smoke-check was the only place still invoking the
  image with zero `--cap-add`, which broke outright once the binaries carried
  a file capability outside that empty bounding set (a file capability beyond
  the runtime bounding set fails the whole `execve()` with `EPERM` rather than
  being silently dropped); fixed by adding the same `--cap-add` flags there.
- **Stale `shapoclyack-0.33` image tags across every k8s manifest** —
  `api-deployment.yaml`, `agent-deployment.yaml`, `cronjob.yaml`, `job.yaml`,
  `job-resume.yaml`, `enrichment/cronjob.yaml`, both overlay patches, and the
  agent example manifest all still pointed at the pre-fix `0.33` image, so
  `kubectl apply -k` deployments silently ran stale code even after pulling
  the latest release. Bumped all references to `shapoclyack-0.36-0723`.

### Added

- **Editable configurator** — the System page gains an admin-editable scanner
  config panel (`GET`/`PUT /api/config`): pipeline-stage toggles
  (`fingerprint`/`tls_posture`/`nuclei`/`reporting.pdf_summary`), nuclei
  severities/exclude-tags, and per-profile scan tuning (`discover_rate`,
  `port_rate`, `top_ports`, `nmap_timing`). Only a strict whitelist of paths is
  editable and the merged result is validated against the full `AppConfig`
  schema before it can be saved. Overrides persist in a new Postgres
  `config_overrides` table (migration `0002`) and are deep-merged onto the base
  config into a job-specific file at **local** scan start — so operators can
  tune scans without editing the (often read-only) config file. Agents keep
  their mounted config (documented limitation). Viewers see the effective
  values read-only; only `admin` can edit.
- **Services layer on the attack-surface graph** — the graph gains a fourth
  column, so it now maps **hostnames → IPs → ports → services**. The
  `/runs/{id}/ports` API aggregates distinct service names per port from
  `findings.json` (new `services` field on `PortAggregateItem`), and the graph
  draws port → service edges (capped like the other columns).
- **ASN/org enrichment + attack-surface clustering** — alive hosts are now
  annotated with their Autonomous System number and holder/org name via a new
  offline `scanner/pipeline/asn_enrich.py` (`enrichment.asn`, MaxMind
  GeoLite2-ASN / DB-IP ASN Lite `.mmdb` or a JSON overlay, fail-soft — mirrors
  the GeoIP path and is distinct from the opt-in scope-expanding
  `asn_discovery` stage). Docker builds bake a real ASN `.mmdb`
  (`scripts/fetch-asn-db.sh`, wired into `fetch-enrichment.sh`). The
  `/runs/{id}/hosts` API and the **Attack Surface** graph pick this up: IP
  nodes now **cluster/color by network (ASN/org)** when available, falling
  back to GeoIP country — closing the ASN/org clustering deferred from the
  initial attack-surface work.
- **Attack surface graph** — a new **Attack Surface** page renders a run's
  hostnames → IPs → ports as a three-column layered graph, with IP nodes
  colored by GeoIP country and ports flagged when they carry findings. Built
  as dependency-free SVG (no graph library, static-export safe) from the
  existing `/runs/{id}/hosts` and `/runs/{id}/ports` endpoints; node counts are
  capped (IPs ranked by finding count) so large fleets stay legible, and a run
  selector switches between runs. ASN/org clustering is deferred — that data
  needs the opt-in `asn_discovery` stage, so country is used for now.
- **Executive dashboard** — the home dashboard is now an exec-level exposure
  view: added a findings-by-severity donut, a "top critical & high findings"
  table (sorted by CVSS v4/v3) for the latest run, an **asset posture** panel
  (business-criticality distribution + active/stale/decommissioned counts from
  the asset inventory), and a "vulnerable hosts" KPI, alongside the existing
  exposure trend and top-ports charts. All derived from existing endpoints
  (runs, latest-run findings/ports, assets) — no new backend.
- **Asset detail card** — a full asset page (`/assets/view`) replaces the cramped
  dialog: it shows the cross-run asset (status, business criticality, owner,
  business unit, identifiers, tags) alongside its most recent per-run
  observation — vulnerabilities, open ports, and OS/GeoIP — correlated by the
  asset's primary IP against the latest run. Operators can edit
  `owner_email`/`business_unit`/`asset_criticality` and one-way **decommission**
  an asset inline (wiring the already-shipped `PATCH /api/assets/{id}`, which had
  no UI before); the edit panel is hidden for viewers. The Assets list now links
  rows to the card and shows a criticality column. `api.ts` gains
  `asset_criticality` on the asset types plus an `updateAsset()` call.
- **System status page (read-only installation configurator)** — a new
  `GET /api/system` endpoint (`api/services/system_status.py`, viewer role)
  and a **System** page in `web-next/` surface, at a glance: the app version;
  scanner tool versions (nmap/naabu/nuclei/dnsx, probed via subprocess,
  cached, fail-soft when a tool is absent); enrichment-database freshness
  (EPSS/KEV/GeoIP/CVSS4 — present/size/age at their effective env-or-config
  paths, with fresh/stale/missing badges); enabled pipeline stages and scan
  profiles parsed from the effective scan config; runtime flags
  (`allow_scan_start`, job execution mode, Postgres/ClickHouse/NATS/ingest
  enablement as booleans); and tenant/agent counts. Exposes no secrets — URLs,
  tokens, and the JWT secret are reduced to booleans and never serialized.
- **Reports in the Web UI** — run artifacts (including the business `summary.pdf`)
  are now surfaced in `web-next/`: a new **Reports** tab on the run detail page
  lists every artifact with inline preview for text (JSON/TXT/MD, pretty-printed
  for JSON) and one-click download, and a new top-level **Reports** page lists
  runs with a direct PDF download. Previously `RunDetail.artifacts` came back
  from the API but was never rendered, and the PDF was effectively
  unreachable. Backend: a new binary-safe `GET /runs/{id}/download/{path}`
  endpoint (`FileResponse` with an extension-derived content-type and an
  attachment disposition) — the existing `artifacts/{path}` endpoint
  UTF-8-decodes and truncates to 1 MB, which is fine for previewing text but
  corrupts binaries like the PDF. The shared path-traversal guard is factored
  into `runs_service.resolve_artifact()` and reused by both endpoints.
- **Nuclei template-based vulnerability/misconfig scanning** — a new opt-in
  stage (`scanner/pipeline/nuclei_scan.py`, `nuclei` config key) runs the
  `nuclei` engine against the same already-open web ports as `fingerprint`
  (no new port scan), covering HTTP-specific CVEs/misconfigs/exposed panels
  that `nmap-vulners`/`vulscan` (version-detection-driven) don't reach.
  Conservative by default: `severities: [critical, high, medium]` and
  `exclude_tags: [intrusive, fuzz, dos]` keep nuclei's more aggressive
  template categories (active SQLi/RCE-style payloads) off unless explicitly
  widened. CVE-tagged matches merge into `vulnerabilities.json`
  (`source: "nuclei"`, feeding CVSS4/EPSS/KEV enrichment, risk scoring, and
  report diffs via `report.py`'s new `extra_vulnerabilities` parameter);
  everything else (exposed panels, misconfig, tech detection) is
  findings-only in `nuclei.json`. Never fails the scan: a missing
  `templates_dir`, missing `nuclei` binary, or a failed/timed-out invocation
  all degrade to a clean `skipped_reason`.
  `Dockerfile`/`Dockerfile.allinone` build the `nuclei` binary from source in
  a dedicated `golang` stage (`go install` at a pinned version tag — verified
  by Go's own module checksum database rather than a hand-copied release
  sha256, since nuclei has no per-arch prebuilt archive to pin the
  dnsx/naabu way) and clone `nuclei-templates` pinned to a release tag, with
  a new `scripts/fetch-nuclei-templates.sh` best-effort refresh step
  matching the vulscan/enrichment fetch scripts' fail-soft philosophy.

## [0.35-0722] — 2026-07-22

### Changed

- **Node.js 22 → 24** across the project: `Dockerfile.allinone`/`Dockerfile.api`'s
  `web-build` stage base image, `.github/workflows/ci.yml`'s `actions/setup-node`
  step, and a new `engines.node: ">=24"` in `web-next/package.json` (Node 24
  is the current Active LTS; Node 22 moves to Maintenance).
- **Enrichment data baked into Docker builds** — `Dockerfile`/`Dockerfile.allinone`
  now run `scripts/fetch-enrichment.sh` (GeoIP via the keyless DB-IP provider,
  CVSS4, EPSS, KEV) as a best-effort build step, and `Dockerfile.api` runs the
  EPSS/KEV fetches it actually uses; a fresh image now ships with real
  enrichment data instead of only the committed seed stubs (a 5-IP GeoIP demo
  overlay, a handful of seed CVEs). Never fails the build — an
  offline/network-restricted build just keeps the seed data, same as before.
  `scanner/config/default.yaml`'s `enrichment.geoip.database` default now
  points at the baked-in `.mmdb` path instead of the JSON demo overlay (which
  remains in the repo for hand-editable lab/test use via an explicit config
  override).
- **vulscan offline CVE databases refreshed at build time** — new
  `scripts/fetch-vulscan-db.sh` (mirrors vulscan's own `update.sh`, fetching
  the same computec.ch-published CSVs with per-database non-fatal error
  handling). `Dockerfile`/`Dockerfile.allinone` clone `scipag/vulscan` pinned
  to a specific commit for reproducible builds, which also freezes its
  bundled CVE/exploit-db/openvas/etc. CSVs at that commit's snapshot; this
  script refreshes them in place as a best-effort build step (never fails
  the build) so the `vuln-offline` NSE profile matches against current data.

### Added

- **OS fingerprint surfaced in the API/UI** — nmap's `-O` OS detection already
  ran on every scan and `os_findings.json` was already written per run, but
  the best-match-by-accuracy result was only ever counted
  (`summary.json`'s `os_detected_hosts`), never attached to a host record.
  `scanner/pipeline/report.py` now stamps `os_name`/`os_accuracy` onto each
  `alive_hosts.json` entry (same pattern as the existing GeoIP `country`/`city`
  fields); `AliveHostItem` (`api/schemas.py`) and `GET /runs/{id}/hosts` expose
  it, and the Hosts tab in `web-next`'s run view shows it inline.

- **Phase 10.1 asset-level diff events** — `scanner/pipeline/report_diff.py`
  already diffed hosts/ports/vulnerabilities between two runs but only as
  three separate added/removed lists, with no cert-expiry or asset-lifecycle
  awareness and no shape a generic event bus could consume. Added a
  normalized `events: [{"kind": ...}]` list to its output: `new_asset` (from
  the existing host-added set), `new_open_port` (host/port/protocol, parsed
  via the existing `parse_endpoint` helper), and `new_cve` (the existing
  added-vulnerability dicts, tagged with a `kind`) — plus a genuinely new
  `cert_expiring` event, fired the run a host:port's `tls_posture.json`
  *first* shows a `cert_expired`/`cert_expiring_soon` issue (not on every run
  it's still present). `diff.md` gained a matching `## Events` section.
  `api/services/ch_diff.py`'s tenant-wide ClickHouse diff path (Phase 3.4,
  previously unused/dead code) gets the same `new_cve`/`new_open_port` event
  shape. `decommissioned_host` is handled separately since it's Postgres
  `Asset.status` data the scanner package can't see: `PATCH /api/assets/{id}`
  now accepts `status: "decommissioned"` (the only status an operator may set
  manually — active/stale stay system-managed) and logs the transition once,
  not on a repeat PATCH. No NATS/alerting wiring yet — event *publishing* is
  Phase 10.2.
- **Phase 9.4 business-context criticality** — `api/services/risk_scoring.py`'s
  `asset_criticality` was purely a per-vulnerability heuristic (severity/CVSS
  band, bumped for a hardcoded high-value-port set) with no awareness of
  which asset actually matters to the business. The Phase 7 `Asset` table
  already had an `asset_criticality` column scaffolded for exactly this but
  nothing wrote to it. Added `PATCH /api/assets/{asset_id}` (operator role)
  so an operator can set `asset_criticality` (0–4), `owner_email`, and
  `business_unit` directly on an asset; `api/services/ch_transform.py`'s
  `vulnerabilities_to_rows` now looks up the stored criticality per host
  (one DB read per distinct host per ingest batch, not per vulnerability row)
  and passes it into `RiskScoring.score_vulnerability` as an override that
  wins outright over the heuristic. Falls back to the existing heuristic
  unchanged whenever an asset has no criticality set, or when Postgres/tenant
  context isn't available (e.g. unit tests, no-DB deployments) — non-breaking
  by construction.

## [0.34-0722] — 2026-07-22

### Added

- **Production enrichment data pipeline (GeoIP / EPSS / KEV / CVSS4)** — the
  `shapoclyack-0.33-0507` release shipped with only tiny seed stubs for these
  four datasets (5 hardcoded IPs for GeoIP, 2–3 CVEs for EPSS/KEV) and no way
  to get real data into a running deployment. Added `scripts/fetch-epss-db.sh`
  (FIRST.org, keyless, ~350k CVEs) and `scripts/fetch-kev-db.sh` (CISA KEV,
  keyless, ~1.6k CVEs), plus `scripts/fetch-enrichment.sh` orchestrating all
  four sources (GeoIP auto-selects MaxMind GeoLite2-City when
  `MAXMIND_LICENSE_KEY` is set, else keyless DB-IP City Lite) with per-source
  non-fatal failure handling. `k8s/shapoclyack/overlays/enrichment` adds a shared
  ReadWriteMany PVC refreshed by a daily CronJob and mounted read-only into
  API/scan pods (plus a cold-start initContainer); `docker-compose.enrichment.yml`
  mirrors this for compose. `api/services/risk_scoring.py`'s EPSS/KEV scorer —
  previously a process-global singleton loaded once at startup with no reload
  path — now hot-reloads when the overlay files' mtimes change on disk,
  gated by `OCTO_ENRICHMENT_RELOAD_SECONDS` (default 60s) so replicas pick up
  the CronJob's refresh without a restart or per-request stat() overhead.
  `scanner/main.py` gained `OCTO_GEOIP_DATABASE` / `OCTO_CVSS4_DATABASE` env
  overrides so the shared-volume path can win over the baked-in config default.
- **Phase 9.1 tech stack fingerprinting** — `scanner/pipeline/fingerprint.py`
  (new): runs after the ports/NSE stages against endpoints already found open
  in `open_ports.txt` filtered to configurable web ports (`http_ports` /
  `https_ports`, default 80/8080/8000/8008/8888 and 443/8443) — no new port
  scan happens here, and unlike a naive add-on this issues exactly one
  streamed, size-capped (`body_max_bytes`, default 64 KiB) GET per endpoint
  rather than a second independent HTTP pass duplicating NSE's own
  `-sV`/script checks (NSE doesn't currently emit structured, parseable
  header/body data this module could reuse). That single response is
  classified against a small, intentionally non-exhaustive signature set:
  CDN/WAF detection from headers (`cf-ray` → Cloudflare, `x-akamai-*` →
  Akamai, `x-sucuri-id`/`x-sucuri-cache` → Sucuri, `x-iinfo`/`incap_ses`
  cookies → Imperva/Incapsula, `x-amz-cf-id`/`via` → CloudFront,
  `x-served-by`/`x-fastly-request-id` → Fastly) and CMS/framework detection
  from header + lightweight body/meta-tag markers (WordPress, Drupal,
  Joomla, Next.js, generic PHP). New `fingerprint.*` config block
  (`FingerprintConfig` in `config_schema.py`), opt-in and disabled by
  default like `discovery.cloud`/`discovery.asn`, with `concurrency` and
  `max_targets` hard caps — past the cap the run is flagged `truncated`
  rather than silently fingerprinting every open port. Findings are written
  to `fingerprint.json` / `fingerprint_matches.txt` and, matching
  `cloud_discovery.py`'s non-escalation principle, are never merged into
  scan scope or asset identity.
- **Phase 9.2 TLS / certificate posture** — `scanner/pipeline/tls_posture.py`
  (new): rather than adding a second scan pass or a Python TLS-handshake
  dependency (`cryptography`/`pyopenssl`), this parses the free-text `output`
  nmap's own `ssl-cert` / `ssl-enum-ciphers` NSE scripts already write into
  `nmap/tcp/*.xml` via the `nse` stage — the same XML `report.py`'s
  `_parse_nmap_xml`/`_script_record` already walk generically. `ssl-cert`
  output yields subject/issuer/SAN/signature algorithm/public key
  size/validity window, driving `cert_expired` (critical) and
  `cert_expiring_soon` (medium, within `expiring_soon_days`, default 30)
  findings, plus a `self_signed` (medium) heuristic — subject/issuer
  commonName match, case-insensitive, always tagged `heuristic` since it is
  a signal and not chain verification. `ssl-enum-ciphers` output yields
  per-TLS-version cipher lists and nmap's own letter grade, driving
  `weak_protocol` (high; SSLv2/SSLv3/TLSv1.0/TLSv1.1), `weak_cipher_grade`
  (medium; nmap grade C/D/E/F), and `weak_cipher_name` (medium; RC4/DES/3DES/
  NULL/EXPORT/anon/MD5 substrings) findings. `ssl-enum-ciphers` was added by
  name to the `vuln` and `service_specific` NSE profiles' `scripts` in
  `scanner/config/default.yaml` (cert expiry/self-signed already work off
  `ssl-cert` alone via nmap's default/safe categories; `baseline` and
  `vuln-offline` are untouched). New `tls_posture.*` config block
  (`TlsPostureConfig` in `config_schema.py`), opt-in and disabled by default,
  capped by `max_targets` (default 2000) with the run flagged `truncated`
  past the cap. Since nmap's script output is free text rather than a
  stable, versioned schema, all parsing is fail-soft (unparseable
  fields/lines are skipped or `None`, never raise). Findings are written to
  `tls_posture.json` / `tls_posture_findings.txt` and, matching
  `fingerprint.py`'s non-escalation principle, are never merged into scan
  scope or asset identity. Hostname/SAN-CN mismatch checking is out of scope
  for this module.
- **Phase 8.4 typosquat / domain monitoring** — `scanner/pipeline/domain_monitor.py`
  (new): two independent, opt-in sub-checks. (1) Typosquat/look-alike domain
  detection generates candidates of the org's seed domains across six
  generator classes (character omission, adjacent transposition,
  keyboard-adjacent substitution, doubling/de-doubling, homoglyph
  substitution, TLD swap), interleaved round-robin across classes and capped
  at `max_candidates` (default 150) per seed, then resolves each candidate's
  A/AAAA records via the already-vendored `dnsx` binary (no new dependency) —
  passive DNS only, same risk class as `ct.brute_force`'s wordlist brute
  force. A candidate that resolves is reported as a `typosquat_registered`
  finding (someone else has registered it); these domains are never owned by
  the org and are never merged into scan scope. (2) A dangling-CNAME /
  subdomain-takeover heuristic resolves the CNAME chain for the org's own
  already-in-scope FQDNs and flags targets whose CNAME matches a curated,
  non-exhaustive list of commonly-abused service suffixes (`github.io`,
  `herokuapp.com`, `s3.amazonaws.com`, `azurewebsites.net`, `cloudfront.net`,
  etc.) AND have no A/AAAA record of their own — a conservative "looks
  abandoned" gate. This only flags the heuristic pattern match plus
  non-resolution; it never attempts to confirm an actual takeover (no
  requests to the third-party service, no claiming/registering anything),
  matching `cloud_discovery.py`'s findings-only, non-escalating posture. New
  `discovery.domain_monitor.*` config block (`DomainMonitorConfig` in
  `config_schema.py`: `enabled`, `domains`, `typosquat_enabled`,
  `dangling_cname_enabled`, `max_candidates`, `concurrency`,
  `timeout_seconds`, `retries`), disabled by default, runs as its own
  `domain_monitor` pipeline stage right after `resolve` so the dangling-CNAME
  check sees the final in-scope FQDN list. Findings are written to
  `domain_monitor.json` / `domain_monitor_findings.txt`.
- **Routine dependency/image maintenance bump.** Python pins: `PyYAML`
  6.0.2→6.0.3, `pydantic` 2.10.6→2.13.4, `nats-py` 2.9.0→2.15.0 (all in
  `requirements.txt`); `fastapi` 0.115.12→0.139.2, `uvicorn` 0.34.2→0.51.0,
  `PyJWT` 2.10.1→2.13.0, `cryptography` 44.0.2→49.0.0, `python-multipart`
  0.0.20→0.0.32, `clickhouse-connect` 0.8.17→1.5.0, `SQLAlchemy`
  2.0.36→2.0.51, `alembic` 1.14.0→1.18.5, `psycopg` 3.2.3→3.3.4 (all in
  `requirements-api.txt`); `pytest` 9.0.3→9.1.1, `ruff` 0.15.20→0.15.22 (in
  `requirements-dev.txt`). `fpdf2` and `httpx` were already at PyPI latest
  (2.8.7 / 0.28.1) and left as-is. `geoip2` (4.8.1) and `bcrypt` (4.2.1) were
  left pinned: their latest releases (5.3.0 and 5.0.0 respectively) cross a
  major version boundary, which is out of scope for a routine maintenance
  bump. Full suite re-verified at 224 passed / 28 skipped after the bump
  (unchanged from the pre-bump baseline), plus a clean `ruff check` and
  `compileall` pass. `clickhouse-connect` 1.x is a major bump from the
  previous 0.8.17 pin; it installed and the full test suite passed against
  it, so it was kept — no clickhouse-connect-specific behavior surfaced in
  tests, but this is worth a closer look at the next opportunity given it
  crosses a major version.
- **web-next npm dependencies** — ran `npm update`, which bumped several
  `@radix-ui/*` packages, `@tanstack/react-query`, and their transitive
  dependencies to the latest versions satisfying their existing `package.json`
  semver ranges (only `package-lock.json` changed; no `package.json` ranges
  needed adjusting). Left `next` (14.2.35), `react`/`react-dom` (18.x),
  `date-fns` (3.6.0), `eslint` (8.x), `tailwindcss` (3.x), and `typescript`
  (5.x) pinned as-is: their available updates (`next`/`react`/`react-dom` 16.x
  / 19.x, `date-fns` 4.x, `eslint` 10.x, `tailwindcss` 4.x, `typescript` 7.x)
  are all major-version jumps, out of scope for this routine bump. `npm run
  lint` and `npm run build` both pass clean after the update.
- **Docker image / tool pins left unchanged.** Attempted to verify newer
  `dnsx`/`naabu` releases (projectdiscovery) and a newer `python:3.12-slim`
  digest, but this environment's egress policy blocks `github.com` /
  `api.github.com` (403 from the pre-configured agent proxy) and the Docker
  Hub CDN blob host used by `docker manifest inspect` (also 403), and no
  Docker daemon is available to `docker pull`/`docker build` for an
  independent check. Per the "never fabricate a checksum/digest" rule, the
  `DNSX_VERSION`/`NAABU_VERSION` pins, their per-arch sha256 checksums, the
  `python:3.12-slim` base image digest, and the `NMAP_VULNERS_REF`/
  `VULSCAN_REF` NSE script commit pins are all left untouched in `Dockerfile`,
  `Dockerfile.api`, and `Dockerfile.allinone`.

## [0.33-0507] — 2026-07-21

### Added

- **Phase 8.3 cloud resource discovery** — `scanner/pipeline/cloud_discovery.py`
  (new): org tokens derived from scan domains × a built-in wordlist
  (`scanner/data/wordlists/bucket-names-small.txt`) → candidate bucket/container
  names, checked via unauthenticated HEAD/GET against S3, GCS, and Azure Blob's
  public REST endpoints (`discovery.cloud`, opt-in; `azure` excluded from the
  default `providers` list — its two-level namespace and GET-only list API make
  it the least reliable of the three). Hard-capped at `max_candidates` (default
  500) and `concurrency` (default 10), more conservative than
  `ct.brute_force`'s DNS-query defaults since this hits shared third-party
  cloud infrastructure. Findings are reported (`cloud_discovery.json` /
  `cloud_discovery_public.txt`) and never merged into scan scope — a
  discovered bucket is a finding, not a port-scan target. The original
  roadmap line's "public cloud ranges by org tag" half was dropped: AWS/GCP
  publish IP ranges by service+region, not by customer org, so there's no
  honest way to attribute a cloud IP to a specific organization.
- **Web UI v2 full cutover (Phase 6.6)** — legacy Vite dashboard (`web/`) removed
  from the repo; `web-next/` is now the only web UI. CI's `web` job was still
  building/caching `web/` and never built `web-next/` at all — fixed to
  `npm ci && npm run lint && npm run build` inside `web-next/`. The Assets page
  (`web-next/src/app/(dashboard)/assets/`) previously aggregated the *latest
  run's* hosts/ports/vulns client-side (leftover Phase 6 code) despite being
  named "Assets" — it now calls the real Phase 7 cross-run registry
  (`GET /api/assets`, `GET /api/assets/{id}`) with status filtering and an
  identifier/tags detail view. Removed now-dead `buildAssetRows` and friends
  from `lib/run-data.ts`, plus the unused `diff-badge.tsx` and `mock-data.ts`.
  `Dockerfile.api`/`Dockerfile.allinone` already built `web-next/` exclusively
  before this change — only CI and the repo tree were still lagging.
- **Phase 8.1–8.2 outside-in discovery** — `scanner/pipeline/asn_discovery.py`
  (new): seed domain → resolved IP → ASN → announced prefixes via RIPEstat's
  free keyless API (`discovery.asn`, opt-in), hard-capped at `max_total_ips`
  (default 4096) since a single ASN can span far more than one org's
  infrastructure — results are flagged `truncated` rather than silently
  scoping up. `scanner/pipeline/hostnames.py` gains an `otx` (AlienVault OTX
  passive DNS) provider alongside crt.sh/Cert Spotter, plus an opt-in
  concurrency/candidate-capped wordlist brute-force pass
  (`discovery.ct.brute_force`, built-in `scanner/data/wordlists/subdomains-small.txt`).
  Both stages are checkpoint/resume-aware and merge into scan scope only when
  explicitly enabled. Adds `httpx` as a scanner-side dependency (previously
  API-only) for RDAP/BGP calls.
- **`api/app.py` lazy app construction** — the module-level `app` singleton is
  now built on first attribute access (PEP 562 `__getattr__`) instead of at
  import time. Phase 7 made `create_app()` fail fast without a reachable
  Postgres; building `app` eagerly meant a bare `from api.app import
  create_app` (every API test file) required Postgres just to import the
  module. `uvicorn.run("api.app:app", ...)` / `python -m api` are unaffected —
  they still resolve `app` (and its fail-fast check) the same way.
- **Phase 7 asset inventory (Postgres PRIMARY_DB)** — first SQL database in the
  repo (SQLAlchemy + Alembic, `api/db/`). `tenants`/`provisioning_keys` moved
  off JSON files onto Postgres behind the same `api/services/tenants.py`
  function signatures (zero caller changes); `resolve_provisioning_key` is now
  O(1) via an indexed `key_lookup` prefix instead of scan-and-bcrypt-verify-all.
  New cross-run asset registry (`assets`/`asset_identifiers`/`asset_tags`) with
  stable identity via `scanner/pipeline/asset_identity.py` (tenant+IP or
  tenant+FQDN sha256 keys), `first_seen`/`last_seen`/`status` lifecycle
  (`OCTO_ASSET_STALE_DAYS`), and new `GET /api/assets` / `GET /api/assets/{id}`
  endpoints — hooked from both local-mode and agent-upload scan completion in
  `api/services/jobs.py`. **Postgres is a hard dependency, not opt-in** like
  NATS/ClickHouse — API startup fails fast if `OCTO_POSTGRES_URL` is empty.
  `k8s/shapoclyack/base/postgres/` + `docker-compose.postgres.yml` mirror the
  ClickHouse deployment pattern; an `initContainer` runs `alembic upgrade head`
  before API replicas start.
- **Phase 1 NATS retention + HA** — JetStream `JOBS`/`INGEST` streams now bound
  storage by default (`OCTO_NATS_JOBS_MAX_AGE_SECONDS`,
  `OCTO_NATS_INGEST_MAX_AGE_SECONDS`, `OCTO_NATS_INGEST_MAX_BYTES`; applied on
  redeploy via `update_stream`, not just first creation); `k8s/shapoclyack/base/nats/`
  ships a cluster-ready config (safe at `replicas=1`) — scale to 3 nodes with
  `examples/nats-ha-patch.yaml` + `OCTO_NATS_STREAM_REPLICAS=3` for JetStream R3
- **Phase 1 NATS harden** — `docker-compose.nats.yml` auto-wires `OCTO_NATS_URL` + NATS
  health wait; agent uses a long-lived JetStream pull session; live broker tests
  (`tests/test_nats_live.py`, CI starts `nats:2.10.24` with JetStream)
- **Phase 3 ClickHouse compose auto-wire** — `docker-compose.clickhouse.yml` sets
  `OCTO_CLICKHOUSE_URL` + health wait for the NATS→CH ingest worker
- **Phase 3 risk scoring (mvp-1)** — ClickHouse vuln rows fill `epss_score`,
  `asset_criticality`, `exploit_active`, `cisa_decision`, `contextual_score` via
  `api/services/risk_scoring.py` (optional EPSS/KEV JSON overlays; prefers CVSS4)
- **Phase 6 aio Web UI v2** — `web-next` static export (`output: "export"`) is built into
  `Dockerfile.allinone` / `Dockerfile.api` (`out/` → `/app/web/dist`); FastAPI serves
  `/_next` and directory `index.html` routes; run detail at `/runs/view?runId=`
- **Phase 6 run detail** — `web-next` `/runs/view?runId=` with hosts / ports / severity
  findings + diff counts; Runs table links into detail
- **Phase 6 live Dashboard / Assets** — KPIs and inventory from latest run API
  (`runs` / `hosts` / `ports` / `vulnerabilities`)
- **Phase 6.4 (Web UI v2 API wire)** — `web-next` JWT login + AuthGate; live
  React Query pages for Runs / Agents / Jobs / Tenants (create + provisioning key);
  Axios client helpers; `/api` rewrite proxy for local Next dev
- **Phase 5 (advanced discovery & notifications)** —
  - Cloudflare DNS zone import + unproxied A/AAAA misconfig findings
    (`discover.import_cloudflare_dns_targets`, `OCTO_CLOUDFLARE_API_TOKEN`)
  - Async CT subdomain discovery via crt.sh / Cert Spotter (`hostnames.discover_ct_subdomains`)
  - SMTP alerts via local Maddy/relay with optional DKIM TXT + PTR pre-send checks
    (`alerts.smtp`, `OCTO_SMTP_*`); example `maddy-compose.example.yaml`
- **Phase 4 (agent topology spread + VPA)** — `base/agents/` Deployment with
  zone + hostname `topologySpreadConstraints`; VPA Auto (`agent-vpa.yaml`);
  opt-in overlay `overlays/agents` (replicas 3, API `OCTO_JOB_EXECUTION_MODE=agent`);
  example YAML updated; agents stay out of default base apply
- **Phase 3 (ClickHouse ingest)** — NATS→CH worker (`ch_ingest_worker`), transforms
  archives into `shapoclyack_vulnerabilities` + `shapoclyack_open_ports`;
  `OCTO_CLICKHOUSE_URL` / `OCTO_CH_INGEST_ENABLED`; CH diff helpers (`ch_diff.py`);
  health reports NATS/CH/worker stats
- **API gateway ingest** — publish validated results to `ingest.results.{tenant_id}`
  (plus legacy `ingest.raw_results`); NATS bus starts on FastAPI lifespan
- **`POST /api/v1/auth/exchange`** — provisioning key → 2h agent JWT (`tenant_id` + `agent_id`);
  `api/core/security.py` (`API_SECRET_KEY` / `OCTO_JWT_SECRET`)
- **Deps:** `cryptography`, `clickhouse-connect` (ready for Phase 3 queries)
- **Compose:** optional `clickhouse` profile + local `init-local.sql`
- **Phase 2 (MSSP tenancy)** — JSON-backed tenants + provisioning keys; agents exchange
  keys for short-lived JWTs (`tenant_id` claims); cross-tenant claim/upload denied;
  NATS messages carry `tenant_id` headers; NetworkPolicy + ExternalSecrets examples
- **Phase 1 (NATS JetStream)** — opt-in via `OCTO_NATS_URL`:
  - k8s StatefulSet/Services `shapoclyack-nats` (+ client Service)
  - API publishes agent jobs to `jobs.scan` and raw archives to `ingest.raw_results`
    (JetStream `Nats-Msg-Id` idempotency); filesystem extract unchanged for UI
  - Agent pull consumer (durable `octo-agents`) when NATS URL set; HTTP claim remains default
  - Compose profile `nats`; example patches under `k8s/shapoclyack/examples/nats-*.yaml`

### Changed

- Promoted discovery completeness knobs from `discovery-bench-realistic` into
  prod configs (`scanner/config/default.yaml`, `k8s/shapoclyack/base/config/k8s.yaml`):
  `discovery.verify` on, `adaptive.wave2_rate: 2500`, `batching.ipv4_prefix: 24`,
  smaller `max_targets_per_batch`; default `balanced.discover_rate` 6000 → 4000
- Documented platform evolution roadmap ([ROADMAP.md](ROADMAP.md)): NATS JetStream,
  MSSP multi-tenancy, ClickHouse analytics, K8s autoscaling, Cloudflare/CT/Maddy,
  Shapoclyack Web UI v2 (`web-next/` — Next.js 14)
- Updated [shapoclyack.html](shapoclyack.html) roadmap infographic to match

## [0.33] — 2026-07-16

GitHub release / tag: [`shapoclyack-0.33`](https://github.com/onixus/Shapoclyack/releases/tag/shapoclyack-0.33).

### Added

- **CVSS v4 enrichment** (`enrichment.cvss4`): local CVE → CVSS 4.0 JSON map
  (`scanner/data/cvss4/`); refresh with `scripts/fetch-cvss4-db.py`
- **GeoIP enrichment** (`enrichment.geoip`): country/city per host via MaxMind GeoLite2
  `.mmdb` or JSON overlay; always export `alive_hosts.json` / `geoip.json`
- **Run results explore UI**: click **Alive hosts** / **Open ports** to list targets
  (with GeoIP) and port aggregation; filter findings by host or port
- API endpoints `GET /api/runs/{id}/hosts` and `GET /api/runs/{id}/ports`
- **Severity dashboard** in the Web UI (grouped, scrollable vulnerability lists)
- Test fixture `tests/data/geoip/GeoIP2-City-Test.mmdb` for the `.mmdb` reader path

### Changed

- **Container images are Shapoclyack-scoped** and no longer published under the legacy
  `ghcr.io/onixus/shapoclyack*` package names:
  - `ghcr.io/onixus/shapoclyack-aio`
  - `ghcr.io/onixus/shapoclyack-scanner`
  - `ghcr.io/onixus/shapoclyack-api`
- Compose service renamed to `shapoclyack`; Dockerfiles carry OCI source labels for this repo
- Vulnerability API backfills GeoIP from `geoip.json` / `alive_hosts.json` when missing on a finding

### Images

| Image | Tag |
|-------|-----|
| `ghcr.io/onixus/shapoclyack-aio` | `shapoclyack-0.33`, `latest` |
| `ghcr.io/onixus/shapoclyack-scanner` | `shapoclyack-0.33`, `latest` |
| `ghcr.io/onixus/shapoclyack-api` | `shapoclyack-0.33`, `latest` |

### Upgrade notes

- Pull `shapoclyack-*` images (do not use bare `ghcr.io/onixus/shapoclyack`)
- Update any local `image:` overrides to the new names
- For production GeoIP: `MAXMIND_LICENSE_KEY=… ./scripts/fetch-geoip-db.sh` and point
  `enrichment.geoip.database` at the `.mmdb`
- Existing scan runs without GeoIP fields need a new scan after enrichment is configured

## [0.3.2.1] — 2026-07-16

All-in-one release: Web UI can start scans by default.

### Added

- **All-in-one image** (`Dockerfile.allinone`): scanner tools + API + React UI + agent client
- **`docker-compose.yml`**: one-command local stack with Jobs UI scan start enabled
- Kustomize overlay `overlays/api-readonly` for the thin results-only API image

### Changed

- Default API Deployment uses **aio** image with `OCTO_ALLOW_SCAN_START=true`, writable PVC mounts, `NET_RAW`, and optional `scan-targets` inputs
- GHCR publish matrix builds scanner, api, and aio (tag matching supports `v0.3.2.1`)
- Phase 3 items (DefectDojo, PDF, remote agents, scan targets / UDP ports) are included in this release train

### Images (historical; superseded by `shapoclyack-*` in 0.33)

| Image (historical) | Tag |
|-------|-----|
| `ghcr.io/onixus/shapoclyack-aio` | `0.3.2.1`, `latest` |
| `ghcr.io/onixus/shapoclyack-api` | `0.3.2.1`, `latest` |
| `ghcr.io/onixus/shapoclyack-scanner` | `0.3.2.1`, `latest` |

### Upgrade notes

- Preferred local path: `docker compose up --build` → http://localhost:8080
- Preferred cluster path: `kubectl apply -k k8s/shapoclyack/overlays/dev` (aio + UI job start)
- For results-only API (no local scans): `kubectl apply -k k8s/shapoclyack/overlays/api-readonly`
- Change default API demo passwords / set `OCTO_JWT_SECRET` before any real use

## [0.3.0] — 2026-07-16

First Shapoclyack-hosted product release after Phase 1–2 and the Kubernetes cutover.

### Added

- **Phase 1 — quick wins**
  - Report diffs between runs (`diff.json` / `diff.md`, `--compare-run-id`, `--no-diff`)
  - Slack / Telegram alerts (`alerts.*`, `--notify`, env credentials)
  - In-process scheduler (`python -m scanner.scheduler`) for labs
- **Phase 2 — interface & API**
  - FastAPI control plane (`api/`) with JWT RBAC (`viewer` / `operator` / `admin`)
  - React dashboard (`web/`) served from the API image
  - Run catalog, vulnerabilities, diffs, artifacts, optional scan jobs
- **Kubernetes primary runtime**
  - kustomize under `k8s/shapoclyack` (Job, CronJob, API Deployment/Service, PVC)
  - `dev` / `prod` overlays; Secrets and Ingress examples
  - `./k8s/scripts/validate-kustomize.sh` + CI kustomize job

### Changed

- Retired `docker-compose.yml` as the deploy path (Dockerfiles remain for image builds)
- Scanner and API container UIDs pinned to `1000` for Kubernetes `securityContext`
- Restored GHCR publish workflow for both product images
- Extracted reusable composite action `.github/actions/synthetic-load-test` for CI / heavy load workflows

### Images (historical)

| Image | Tag |
|-------|-----|
| `ghcr.io/onixus/shapoclyack` | `0.3.0`, `0.3`, `0`, `latest` |
| `ghcr.io/onixus/shapoclyack-api` | `0.3.0`, `0.3`, `0`, `latest` |

### Upgrade notes

- Deploy with `kubectl apply -k k8s/shapoclyack/overlays/dev` (or `prod`)
- Change default API demo passwords / set `OCTO_JWT_SECRET` before any real use
- Prefer cluster `CronJob` over the in-process scheduler

## [0.2.1] — 2026-07-15

Inherited from the pre-rename history (NSE `-Pn` fix, docs/infographic).
