# Data retention, legal hold and personal-data requests

This document states what Shapoclyack stores, for how long, how that is changed
per tenant, how a legal hold suspends deletion, and how a request about a
console user's personal data is answered. It is written to be attached to a
data-processing agreement (DPA) as the technical annex on retention and
deletion; every number in it is a shipped default with the variable that
changes it, and every mechanism names the code that performs it.

Terms: the **installation** is one deployment of the platform, run by its
**operator** (an MSSP, or the customer's own IT). A **tenant** is one
customer inside it. A **platform admin** holds the global `admin` role; a
**tenant admin** holds an `admin` membership in one tenant. Permissions are the
named authorities of [API and RBAC](api-and-rbac.md#permissions).

- [1. What is stored and for how long](#1-what-is-stored-and-for-how-long)
- [2. Per-tenant retention](#2-per-tenant-retention)
- [3. Legal hold](#3-legal-hold)
- [4. Console users: export and erasure](#4-console-users-export-and-erasure)
- [5. Backups, replicas and copies outside the platform](#5-backups-replicas-and-copies-outside-the-platform)
- [6. Subprocessors](#6-subprocessors)
- [7. Operating it](#7-operating-it)
- [8. Limits of this implementation](#8-limits-of-this-implementation)

## 1. What is stored and for how long

### 1.1 Data deleted on a retention window

Each row is a **category**: a kind of data with a window of its own. The
platform default is the setting in the second column; a tenant may override it
within the bounds in the third (section 2). `0` as a platform default means the
data is kept until deleted by hand.

| Category (API name) | What it is | Platform default | Override bounds | Deleted by, how often |
|---|---|---|---|---|
| Scan runs (`runs`) | Every file a scan produced: hosts, ports, banners, findings, evidence, `run_meta.json`; and the inputs of scans that never finished (`job_inputs/`) | 30 days, `OCTO_RUN_RETENTION_DAYS` | 1–365 | `api/services/run_retention.py`, hourly, in every API replica |
| Screenshots (`screenshots`) | PNG images of web services found by a scan. Redacted in the DOM before capture, but may still show personal data | 14 days, `OCTO_SCREENSHOT_RETENTION_DAYS` | 1–90 | `api/services/screenshot_retention.py`, hourly. The run's own window removes them too, whichever comes first |
| Generated reports (`reports`) | Rendered report files and their rows, including the per-recipient delivery log | 365 days, `OCTO_REPORT_RETENTION_DAYS` | 1–3650 | `api/services/reports/store.py:prune_reports`, hourly, by the report dispatcher's leader |
| Endpoint software lists (`endpoint_snapshots`) | The software rows of endpoint inventory snapshots that a newer snapshot superseded. The snapshot summary and each device's *current* list are kept | 90 days, `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` | 1–730 | `api/services/endpoint_retention.py`, every 6 hours |
| Endpoint change history (`endpoint_changes`) | Installed / removed / updated events derived from the snapshots | 365 days, `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` | 30–3650 | same |
| Risk history (`risk_snapshots`) | Per-tenant risk posture counters behind the trend charts | 90 days, `OCTO_RISK_SNAPSHOT_RETENTION_DAYS` | 1–3650 | `api/services/risk_snapshots.py`, every 6 hours |
| Webhook deliveries (`webhook_deliveries`) | Delivered and dead outbound webhook calls, **payloads included**. Pending ones are never pruned | 30 days, `OCTO_WEBHOOK_DELIVERY_RETENTION_DAYS` | 1–365 | `api/services/integrations/webhooks.py:prune_deliveries`, hourly, by the webhook dispatcher |
| Workflow event markers (`workflow_markers`) | Proof that an SLA or exception event was already announced. Expiring one re-announces an unresolved breach | 365 days, `OCTO_WORKFLOW_MARKER_RETENTION_DAYS` | 30–3650 | `api/services/workflow_events.py:prune_markers`, hourly, by the SLA escalation worker's leader |
| Audit trail (`audit_events`) | Every administrative change: who, what, before and after (secrets redacted), from which address and client. Append-only in the database (#329) | 365 days, `OCTO_AUDIT_EVENT_RETENTION_DAYS` | **365**–3650 | `python -m api.services.audit_retention`, a privileged CronJob with its own credentials — the API cannot prune its own trail |

The floors above one day are argued, not arbitrary. The audit floor is a year
because that is what PCI DSS 10.5.1 and most ISMS policies ask of an
administrative log, and a tenant admin must not be able to shorten the trail
that records what they did. The endpoint change history is the audit history of
an endpoint's software and keeps at least thirty days. The workflow-marker
window is also how often a breach still open is raised again, and a tenant
admin should not be able to turn escalations into a daily page.

### 1.2 Data kept for the life of the tenant

The tenant's working records are not on a window: they are what the service is
*for*, and they leave with the tenant (tenant offboarding, #325) or by an
operator's explicit, audited deletion of one object. That is: the tenant row
and its settings, assets and their business context, tracked findings
(vulnerabilities) and their remediation history, scan scopes and policies,
schedules and maintenance windows, endpoint devices and snapshot summaries,
sensors and agent groups, service tokens and provisioning keys (which expire on
their own), integrations, report templates and schedules, and memberships.

Console accounts are installation-level, not tenant-level: they are deleted or
erased by a platform admin (section 4).

### 1.3 Operational data that expires by itself

| Data | Lifetime |
|---|---|
| Sign-in trail (`auth_events`): username tried, client address, outcome | 90 days, `OCTO_AUTH_EVENT_RETENTION_DAYS`, pruned on the login path. Installation-wide: an attempt has no tenant until it succeeds. Sign-ins of the members of a tenant on legal hold are kept (section 3) |
| Idempotency records | 24 hours |
| SSO authorisation requests in flight | `OCTO_OIDC_STATE_TTL_SECONDS` (10 minutes) |
| WebAuthn challenges | until spent or expired, minutes |
| Sign-in sessions and refresh tokens | until their absolute end, `OCTO_JWT_EXPIRE_MINUTES` |
| Logout denylist | until the token it refuses would have expired |
| SSH push-deployment journal | the last 100 deployments per tenant, kept whole while the tenant is on legal hold |
| NATS JetStream: job offers / raw ingest results | 24 hours / 7 days, `OCTO_NATS_JOBS_MAX_AGE_SECONDS` / `OCTO_NATS_INGEST_MAX_AGE_SECONDS` |
| ClickHouse analytics copies | table TTL: 90 days (findings, ports), 365 days (control matrix). Installation-wide, see section 8 |

## 2. Per-tenant retention

A tenant's windows are one row in `tenant_retention_policies` (migration
`0065`), one nullable column per category. `NULL` inherits the platform
default, so a tenant without a row — every tenant on the day this shipped — is
swept exactly as before.

```http
GET    /api/tenants/{tenant_id}/retention   # tenant.retention.read
PUT    /api/tenants/{tenant_id}/retention   # tenant.retention.manage, step-up
DELETE /api/tenants/{tenant_id}/retention   # tenant.retention.manage, step-up
```

```json
PUT /api/tenants/acme/retention
{"overrides": {"runs": 90, "audit_events": 730, "screenshots": null},
 "note": "DPA annex 2, clause 4.1"}
```

- **Who.** `tenant.retention.read` is held by the tenant's `admin` and
  `auditor` and the platform admin: the customer's DPO can read the answer in
  the console (*Administration → Data retention*). `tenant.retention.manage`
  is held by the tenant's `admin` and the platform admin. Both are
  tenant-scoped: naming another tenant in the path is `403`, and service tokens
  cannot reach `/api/tenants/*` at all.
- **Bounds.** A value outside the category's bounds is refused with `422`
  naming them — never clamped, because an admin who asked for 30 days and
  silently got 365 would believe the shorter window is in force. The bounds are
  platform configuration, not a column the console can write, and they bind the
  platform admin's requests too: they change by deploying
  `OCTO_RETENTION_BOUNDS`, a JSON object merged over the defaults in section
  1.1, e.g. `{"audit_events": {"min": 1095}}` for a three-year audit floor. A
  malformed value, an unknown category, a `min` below 1 or a `max` above 3650
  stops the API at startup rather than quietly lowering a floor.
- **Whole document.** `PUT` replaces the policy; a category left out goes back
  to the default. `DELETE` puts every category back on the default.
- **Audit.** Every change is `retention_policy.update` in the tenant's own
  audit trail, with the policy before and after. Shortening a window is a
  deletion scheduled for the next sweep; the step-up (a recent second factor,
  for accounts that have one) and the audit row are there because of that.
- **Kill switches.** `OCTO_*_RETENTION_ENABLED=false` stops a sweep on the
  installation for every tenant, overrides included. An installation that turns
  one off must say so in its own DPA annex: the windows above are what the
  sweeps apply, not a promise made by the table.

## 3. Legal hold

A hold is one row in `tenant_legal_holds`: the tenant, the reason, who placed
it and when. While it exists:

- **no retention sweep deletes any of the tenant's data** — every category in
  section 1.1, the SSH deployment journal, and the sign-in trail of the
  tenant's members. The sweeps read the hold table at the start of every pass;
  one that cannot read it deletes nothing that pass. For the audit trail the
  hold is also enforced **inside the database**: `audit_events_prune` and
  `audit_events_prune_tenant` skip a held tenant themselves, so a retention job
  given a wrong plan, or built from an image older than the hold, still cannot
  delete its trail;
- **the tenant cannot be deleted.** The hold's foreign key to `tenants` is
  `ON DELETE RESTRICT`: any `DELETE` of a held tenant fails in PostgreSQL,
  whichever code path issued it. Tenant offboarding (#325) checks the hold first
  and answers `409` naming it; the key is the backstop;
- **its console accounts cannot be erased** (section 4.2): data needed for
  legal claims is exempt from erasure (GDPR Art. 17(3)(e)), and erasure destroys
  exactly the link from a username in the tenant's records to a person.

A hold covers the whole tenant. It is not scoped to categories: the platform
cannot know which of a tenant's data a claim will turn on, and a hold that lets
some of it age out fails exactly when it is tested. It does not stop an
operator's explicit, audited deletion of one object (a report, an asset), nor
the recomputation of derived state (software→CVE matches are replaced by each
re-match of the snapshot they describe); it suspends automated disposition and
purge.

```http
PUT    /api/tenants/{tenant_id}/legal-hold   {"reason": "Preservation order, matter 2026-17"}
DELETE /api/tenants/{tenant_id}/legal-hold
```

Both need `platform.legal_hold.manage` — platform admins only — and a step-up.
A tenant that could release its own hold could let evidence age out
mid-litigation. Placing a hold that exists amends its reason and keeps when and
by whom it was first placed.

**Confidentiality.** A hold can be placed over a matter the tenant must not
learn of from its own console. The tenant's readers therefore see that a hold
is in force and since when, and not who placed it or why; the audit rows
(`legal_hold.place`, `legal_hold.release`) are platform-level (`tenant_id`
empty, the tenant in `resource_id`) and do not appear in the tenant admin's
trail.

**When it takes effect.** Each sweep reads the holds when a pass starts. A pass
already running when a hold is placed finishes on the plan it started with —
minutes for the hourly artifact sweeps — so place a hold before the data is due,
not in the last hour of its window. The audit trail is the exception: its prune
functions read the hold at the moment they delete.

**Release.** Deleting the hold resumes the sweeps on their next pass, and they
delete everything the hold kept past its window. The released hold is kept in
the audit row's `before`.

## 4. Console users: export and erasure

Console accounts are the one place the platform itself holds personal data
about identifiable people by design: a username, an address, an identity at the
customer's identity provider, the addresses they signed in from, what they
changed. Both requests are platform-admin acts (`/api/users` is platform
account administration) and both are in the console under *Administration →
Data retention → Personal data requests*.

### 4.1 Export (access, portability)

```http
GET /api/users/{username}/export
```

One JSON document (`"format": "shapoclyack.data-subject-export"`):

| Section | Contents |
|---|---|
| `account` | username, role, created/updated/disabled/erased timestamps and who created it, whether a password is set and when it changed, address and whether it is verified, the identity-provider issuer and subject, when a second factor was enrolled, how many recovery codes remain. Never a password hash, TOTP secret or code hash |
| `memberships` | tenant, role, when and by whom granted |
| `security_keys` | name, created, last used, device type, whether synced |
| `sessions` | when each sign-in session started, was last used, expires, how it ended |
| `sign_in_history` | every row of the sign-in trail for the username: time, client address, outcome, reason |
| `administrative_activity` | every audit row the account performed: time, tenant, action, object, client address and user agent, request id |
| `changes_to_account` | every audit row about the account itself |
| `report_recipient_of` | report schedules that mail the account's address |
| `attributions` | per table and column, how many records elsewhere name the account (who approved a scope, who accepted a risk, who started a scan …) |

Audit rows are exported **without** their `before`/`after` documents: those
describe what the account did *to other accounts and tenants*, and other
people's data stays out of one person's copy (GDPR Art. 15(4)). Attributions are
counted, not copied: they are the tenants' operational records, and the
controller answering the request decides which of them to disclose. Every
export is recorded as `user.export`.

### 4.2 Erasure, and why the actor stays a pseudonym

```http
POST /api/users/{username}/erase
```

The audit trail is append-only in the database (#329) and names every actor by
username; so do some thirty `*_by` columns — who approved a scan scope, who
accepted a risk, who requested a scan. None of them can be rewritten, and most
must not be: "who accepted this risk" is the control. So erasure keeps the
**username** and removes everything that ties it to a person. The account row
stays as a tombstone (`users.erased_at`) holding the name and its timestamps,
which is what makes the name a *stable* pseudonym: it can never be issued to
somebody else, so the trail can never start attributing a stranger's history to
it. Every write to a tombstone — password, role, address, re-enabling, a
membership, deletion — is refused.

In one transaction with its audit rows, erasure:

| Removes | Details |
|---|---|
| Credentials and identity | password hash, address and its verified flag, identity-provider issuer and subject, TOTP secret, recovery codes, enrolment time, security keys and passkeys, pending WebAuthn challenges |
| Access | all memberships (each recorded as `membership.revoke` in *that* tenant's trail, so its admin sees the member leave), all sign-in sessions and refresh tokens, the logout denylist entries; the account is disabled, lowered to `viewer`, and every token it holds is refused |
| Future processing of the address | the address is taken off every report schedule's recipients |

| Keeps | Why (legal basis) |
|---|---|
| The username, in the tombstone and in every attribution column | the pseudonym; required so the records it attributes stay correct |
| `audit_events` rows the account performed or that concern it, including the client address and user agent recorded with them, and the `after` document of the account's own `user.create` row, which holds the address it was created with | append-only security log: legal obligation (Art. 6(1)(c)) and legitimate interest in the security of the service (Art. 6(1)(f)); ages out with the audit window of each tenant (section 1.1) |
| The sign-in trail for the username | security log (Art. 6(1)(f)); the rate limiter reads it; ages out after `OCTO_AUTH_EVENT_RETENTION_DAYS` |
| Delivery logs of reports already sent to the address | the record of a disclosure that happened; ages out with the report (section 1.1) |
| Free text an operator typed that happens to name the person (an asset owner's address, a finding comment) | tenant business data, edited or deleted by the tenant through the ordinary console |

The pseudonym is only as good as the username. An installation whose usernames
**are** addresses — `OCTO_OIDC_USERNAME_CLAIM=email`, or local accounts named
after people — keeps that name in the trail until the trail ages out. Prefer an
opaque username claim (an employee number, the IdP's `sub`) where erasure
requests are expected.

The erasure's own audit row, `user.erase`, records counts and flags only: what
kinds of data were removed, never the removed values. Writing the address into
an append-only table at the moment of erasing it would make the trail the one
copy nobody can remove.

**Guard rails.** Nobody erases their own account. The last active admin with a
password — the break-glass door — cannot be erased. An account that belongs to,
belonged to, or acted in a tenant on legal hold cannot be erased (`409` naming
the hold).
The route needs a recent second factor for accounts that have one. Erasing an
account already erased changes nothing and says so.

### 4.3 People in scan results

Scan results can contain personal data about people who are not console users:
a name in a TLS certificate, an address in a banner, a face in a screenshot.
That data belongs to the tenant's scan evidence. It ages out with the `runs` and
`screenshots` windows; a request about it is answered by the tenant (the
controller) by shortening those windows or deleting the affected assets and
runs, not by the console-user procedure above.

## 5. Backups, replicas and copies outside the platform

- **Backups.** A PostgreSQL dump or an artifact-store snapshot contains the data
  as it was when it was taken, erased accounts and expired runs included. Data
  in backups ages out with the backup store's own retention (the bucket's
  lifecycle rule or the backup tool's), which the operator sets and must state
  in its DPA annex. A shortened window or an erasure does not reach into
  existing backups. **After a restore**, re-apply every erasure performed since
  the backup was taken: the list is the `user.erase` rows in the audit trail
  *as forwarded to the SIEM* (#328) or the DPO's own request register — the
  restored database's trail predates them.
- **Legal hold and backups.** A hold stops deletion in the running installation.
  It does not stop the backup store from expiring old backups; if a claim needs
  a point-in-time copy, take one and exempt it from the lifecycle rule.
- **Copies the platform sends out.** Audit events forwarded to a SIEM, webhook
  payloads, tracker tickets, mailed reports and scheduled exports are copies
  under the recipient's retention, chosen by the tenant or the operator when it
  configured the destination.
- **Logs.** API and worker logs (usernames, client addresses, request ids) are
  retained by the cluster's log pipeline, not by the platform.

## 6. Subprocessors

The software does not send data to any third party of its own accord. Every
component that stores data — PostgreSQL, the artifact store (a volume or an
S3-compatible bucket), NATS JetStream, the optional ClickHouse — is part of the
installation, run where the operator runs it. Outbound destinations exist only
where a tenant or the operator configured them (webhooks, Jira / ServiceNow /
DefectDojo, SMTP, the SIEM forwarder, OIDC); whoever operates those is a
subprocessor of whoever configured them, not of the platform. Optional threat
intelligence and vulnerability datasets are downloaded *to* the installation
and carry no customer data out.

## 7. Operating it

**Checking a tenant.** `GET /api/tenants/{id}/retention` lists every category
with its default, override, effective window and bounds, and the hold.

**Audit actions.** `retention_policy.update`, `legal_hold.place`,
`legal_hold.release`, `user.export`, `user.erase` — filterable on the audit page
and in the export.

**The audit retention job needs two more grants.** The CronJob in
[`k8s/shapoclyack/examples/audit-retention-cronjob.example.yaml`](../k8s/shapoclyack/examples/audit-retention-cronjob.example.yaml)
builds its plan from the policy and hold tables and calls a second function for
tenants with an audit window of their own. With the
[GRANT layout](operations.md#recommended-grant-layout) applied, add:

```sql
-- The job reads whose trail is on which window, and who is on hold.
GRANT SELECT ON TABLE tenant_retention_policies, tenant_legal_holds
  TO shapoclyack_audit_retention;
-- The per-tenant prune, owned like the first one so it runs as the table's
-- owner — and granted to the retention job only.
ALTER FUNCTION audit_events_prune_tenant(text, timestamp without time zone)
  OWNER TO shapoclyack_audit_owner;
GRANT EXECUTE ON FUNCTION audit_events_prune_tenant(text, timestamp without time zone)
  TO shapoclyack_audit_retention;
-- Both functions read the hold and policy tables as their owner.
GRANT SELECT ON TABLE tenant_retention_policies, tenant_legal_holds
  TO shapoclyack_audit_owner;
```

Migration `0065` revokes `EXECUTE` on the new function from `PUBLIC`, like
`0037` did for the first. Run the job's image at the API's version: a job older
than `0065` calls only `audit_events_prune`, which after `0065` keeps held and
overridden tenants' rows — it errs on the side of keeping, but those tenants'
own windows are then not applied until the job is upgraded.

**Rolling upgrade.** Until every API replica runs the release with `0065`, an
old replica keeps sweeping on the global window. For a tenant with a *longer*
window of its own, or on hold, that replica can delete what the new ones would
keep, for as long as the rollout lasts. Place holds after the rollout
completes, or disable the retention workers (`OCTO_*_RETENTION_ENABLED=false`)
for its duration.

## 8. Limits of this implementation

- **ClickHouse** analytics copies (findings, open ports, control matrix) expire
  on a table-level TTL evaluated by ClickHouse at merge time. It is not
  per-tenant and does not honour a legal hold: per-tenant TTLs would need one
  TTL clause per tenant or a dictionary lookup inside ClickHouse. The rows are
  derived from scan results that the platform also keeps in PostgreSQL and the
  artifact store; when a hold must cover the analytics copies too, raise the
  TTL (`ALTER TABLE … MODIFY TTL`, [operations](operations.md#clickhouse-analytical-data-retention-roadmap-187)) for the hold's duration.
- **NATS** streams expire by age on the installation's settings above; they hold
  jobs in flight and raw results waiting for ingest, not records.
- **Tenant offboarding** — deleting a tenant and purging its data — is #325. It
  is built on the hold described in section 3 and cannot delete a held tenant.
