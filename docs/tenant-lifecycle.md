# Tenant lifecycle: suspension, deletion, purge

How a platform admin takes a customer out of service, puts it back, and deletes
it with everything it had — and what "everything" means, store by store (#325).
The legal hold that can stop a deletion is [data-retention.md](data-retention.md)'s;
this page covers what the lifecycle does with it.

## 1. States

| `tenants.status` | Who gets in | How it gets there |
|---|---|---|
| `active` | members, their service tokens and agents | created; resumed |
| `suspended` | platform admins only | `POST /api/tenants/{id}/suspend`; a cancelled deletion |
| `pending_deletion` | platform admins only | `POST /api/tenants/{id}/deletion` (step one) |
| `deleting` | platform admins only | `POST /api/tenants/{id}/deletion/approve` (step two) |
| *(no row)* | nobody; `GET …/lifecycle` answers `status: deleted` from the journal | the purge completed |

Every gate refuses anything but `active` with the same 403 (`Tenant acme is
suspended`). The `default` tenant can be neither suspended nor deleted: accounts
without a membership and legacy shared-token agents act in it.

All routes need `platform.tenant.lifecycle` (platform admins only; a service
token never has it) and every change needs a recent second factor (step-up,
[api-and-rbac.md](api-and-rbac.md)).

## 2. Suspension

`POST /api/tenants/{id}/suspend` with `{"reason": "...", "revoke_credentials": true}`
changes the status and, **in the same transaction**, cuts every path in that
would otherwise outlive a status check:

| Path | What suspension does | What refuses it afterwards |
|---|---|---|
| Console sessions | Members that can act in **no other active tenant** are signed out: `token_version` bumped, session families revoked (`revoked_reason = tenant_closed`). Members of other tenants keep their session | The per-request gate refuses this tenant (403) |
| Service tokens | Revoked (`revoked_at`) unless `revoke_credentials=false` | Authentication refuses a token of a non-active tenant (401) |
| Provisioning keys | Revoked unless `revoke_credentials=false` | Key exchange refuses a non-active tenant (401) |
| Agent JWTs (sensors, Lariska) | — | Every agent request re-reads the tenant's status with the key (`agents.check_credential`): claim, heartbeat, results upload and inventory submission answer 401 |
| Queued scans | Cancelled | Admission refuses new scans for a non-active tenant |
| Running agent scans | Moved to `cancelling` (#360), so the lease reaper cannot hand them to another agent; the grace reaper closes them (`OCTO_JOB_CANCEL_GRACE_SECONDS`) | — |
| Running local scans | Cannot be stopped (`job_control.cancel_job`), run to their end | — |
| Scan and report schedules | Paused by the status; `enabled` is not touched | Dispatchers select active tenants only |
| SLA escalation, offline-agent alerts, ticket sync, webhook deliveries, notification channels, retro/software matchers | Skip the tenant (`tenants.active_tenant_ids`) | — |

**Why the sensor is not told to stop.** The #360 stop travels on the
heartbeat's answer, and the heartbeat is refused with everything else the
tenant's agents send: accepting any request from a suspended tenant's machine
would mean authenticating a credential of a tenant the platform has decided to
cut off. A scan already running on a sensor therefore finishes locally (or hits
the agent's scan timeout) and its upload is refused. To stop scan traffic at
once, cancel the running jobs *before* suspending (`POST /api/jobs/{id}/cancel`),
or stop the sensor host.

`revoke_credentials=false` keeps keys and tokens for a short suspension — they
are refused by the status on every request either way, and work again after the
resume without re-running installers.

Suspending a suspended tenant changes nothing and records nothing.

## 3. Resume

`POST /api/tenants/{id}/resume` restores what the status paused and **nothing
that was revoked**: a key or token that left the platform's control while the
customer was out is not re-trusted by flipping a status. Mint new provisioning
keys (re-run the installer or update the sensors' key) and new service tokens.

Overdue scan and report schedules move to their **next occurrence after the
resume** instead of all firing at once; missed ticks are not replayed. Held
webhook deliveries go out as queued. Members who were signed out sign in again.

A tenant pending deletion is resumed by cancelling the deletion first (it stays
`suspended`, then resume). A tenant being purged cannot be resumed.

## 4. Deletion: two steps, a grace period, two people

1. **Request** — `POST /api/tenants/{id}/deletion` with
   `{"confirm": "<tenant id, typed exactly>", "reason": "..."}`. The tenant
   becomes `pending_deletion` with suspension's cuts, and its credentials are
   revoked whatever an earlier suspension kept. Nothing is deleted. Refused
   with 409 for a tenant on legal hold, the default tenant, and one with a
   deletion already open.
2. **Grace period** — `OCTO_TENANT_DELETION_GRACE_DAYS` (7). During it,
   `DELETE /api/tenants/{id}/deletion` cancels with nothing lost; the tenant
   stays `suspended`.
3. **Approve** — `POST /api/tenants/{id}/deletion/approve` with the tenant id
   typed again, after the grace period, by a platform admin **other than the
   requester** (`OCTO_TENANT_DELETION_TWO_PERSON`, on by default; 403
   otherwise — #348's rule; turn it off only on an installation with a single
   platform admin). In one transaction: the tenant row is locked
   (`SELECT … FOR UPDATE`, the lock `place_hold` takes), a legal hold refuses
   with 409, and only then the tenant becomes `deleting` and the journal
   `purging`. From here there is no way back.

The purge worker (`api/services/tenant_purge`, every replica,
`OCTO_TENANT_PURGE_ENABLED`) takes it from there.

## 5. The purge, store by store

Steps run in this order; each is idempotent, verifies that nothing of the
tenant is left in its store, and records what it removed:

| Step | Store | What goes |
|---|---|---|
| `quiesce` | Postgres | Waits (state `waiting`) until no job of the tenant is queued, claimed, running or cancelling; a queued one left by a race is cancelled |
| `outbox` | Postgres | `nats_outbox`, `run_publications` — before JetStream, so the relay cannot republish into purged subjects |
| `jetstream` | NATS | Durable consumers `octo-agents-{tenant}[-{group}]` (matched by **filter subject**, never by name — `acme`'s group `eu` and tenant `acme-eu` share a name); subjects `jobs.scan.{t}[.>]`, `ingest.results.{t}`, `ingest.endpoint_inventory.{t}`, `events.asset.{t}.>`, `events.workflow.{t}.>`; the tenant's copies on the deprecated shared `ingest.raw_results` subject, located by message id next to the tenant's own message and deleted by sequence. A copy not located there ages out with the stream (`OCTO_NATS_INGEST_MAX_AGE_SECONDS`) and is counted as `legacy_ingest_unlocated`. `events.audit.{t}` is kept (see §6). Skipped when `OCTO_NATS_URL` is unset |
| `artifacts` | volume or bucket | `runs/_tenants/{segment}/` (#427) with screenshots and staging trees; flat runs of earlier releases whose `tenant.json` names the tenant; `job_inputs/{job_id}/` for every job row; `reports/{tenant}/` and any report `storage_path` outside it; this replica's working copies. A flat run whose `tenant.json` cannot be read **fails** the step — repair or remove it and retry |
| `clickhouse` | ClickHouse | `ALTER TABLE … DELETE WHERE tenant_id = <uuid5>` on the three analytics tables with `mutations_sync = 2` (a mutation, not a lightweight delete: the bytes go, not just a mask), then a count that must be 0. Skipped when `OCTO_CLICKHOUSE_URL` is unset |
| `postgres` | Postgres | Every table that names the tenant, children before parents, in batches of `OCTO_TENANT_PURGE_BATCH_SIZE`; the list is `api/services/tenant_purge/postgres.py` and a test checks it against the live schema |
| `finalize` | Postgres | Counts every planned table (a row a late writer slipped in sends the Postgres steps round again), disables accounts whose **only** membership was this tenant (an account with no membership would otherwise act in `default` with its global role), deletes the memberships and the tenant row, and writes the tombstone — one transaction |

**Legal hold.** Before every batch the worker locks the tenant row, checks the
hold and renews its lease, in one transaction; a Postgres batch runs inside it,
an external one (bucket, ClickHouse, JetStream) right after it. A hold placed
while the purge runs — `PUT …/legal-hold` is never refused for a tenant being
deleted — waits for the current batch and stops the purge at the next one: the
journal says `blocked`, the tenant stays `deleting`, the rest of its data
stays. Releasing the hold does **not** resume the purge: that is a separate
decision, `POST /api/tenants/{id}/deletion/retry`. The `RESTRICT` key from
`tenant_legal_holds` to `tenants` (#332) remains the backstop behind all of it.

**Failure.** A step that raises records its error on its row and on the
journal, is written to the audit trail once (`tenant.delete.fail`), and is due
again after a backoff: the purge interval doubled per attempt of that step,
capped at an hour. `POST …/deletion/retry` makes it due now. The tenant stays
`deleting`; the console shows each step's state, attempts, counts and last
error.

**Crash.** A deletion is claimed with `FOR UPDATE SKIP LOCKED` and held on a
15-minute lease that every batch renews. A replica that dies mid-step leaves the
step `running` and its lease to lapse; the next replica resumes from that step.
Counts are recorded by each batch in its own transaction (Postgres) or right
after it (other stores), so a resumed step does not count twice; a crash
between an external delete and its bookkeeping can undercount by one batch.

## 6. What is kept

- **The audit trail** (`audit_events`, and its `events.audit.{t}` feed) is
  append-only (#329) and is not purged: what was done in a tenant matters most
  after the tenant is gone. The tenant's rows age out with the audit retention
  job on the platform default window (`OCTO_AUDIT_EVENT_RETENTION_DAYS`) — its
  own policy row goes with the tenant, and `audit_events_prune` prunes rows of
  tenants that no longer exist. Every lifecycle decision is a platform-level
  row: `tenant.suspend`, `tenant.resume`, `tenant.delete.request`, `.cancel`,
  `.approve`, `.retry`, `.fail`, `.block`, `.complete`.
- **The deletion journal** (`tenant_deletions`, `tenant_deletion_steps`) is the
  proof. A completed row's `outcome` is the **tombstone**: counts per store and
  per table, what was skipped and why, what was retained — no names, no
  usernames, nothing the tenant wrote. `GET /api/tenants/deletions` lists it.
- **Console accounts** of the tenant's members are disabled, not erased: the
  audit trail names them. Erase them with `POST /api/users/{u}/erase` if the
  DPA requires it ([data-retention.md](data-retention.md)).
- **A deleted tenant's id is never reused** (`POST /api/tenants` refuses it):
  the journal is keyed by it, and a new customer under the old id would inherit
  whatever of the old one a store still held.

## 7. Backups: deleted data comes back with a restore

A backup taken before a purge still holds the tenant: restoring Postgres,
ClickHouse, the bucket or JetStream from it brings the tenant back. After any
restore, re-apply the deletions:

1. Before restoring, save the list: `GET /api/tenants/deletions?state=completed`
   (tenant ids and completion times). The journal itself is in Postgres, so a
   Postgres restore to a point before a deletion also loses its tombstone —
   keep the export with the restore ticket.
2. After the restore, for every tenant on the list whose `completed_at` is
   later than the backup: if the tenant row is back, request its deletion
   again (`POST …/deletion`, grace period and approval as usual —
   `OCTO_TENANT_DELETION_GRACE_DAYS=0` for the duration of the re-application
   is a reasonable, recorded, choice); if only a non-Postgres store was
   restored, the tenant row is gone and the purge has nothing to lock — delete
   its data from that store by hand using the key scheme in §5.
3. Record the re-application in the restore ticket.

The restore runbooks are in [disaster-recovery.md](disaster-recovery.md)
(#333).

## 8. Rollout notes

Migration `0066_tenant_lifecycle` is expand-only. A replica still on the
previous release refuses every non-active tenant, but its `TenantInfo` knows
only `active`/`suspended`, so its `GET /api/tenants` answers a platform admin
500 while a tenant is `pending_deletion` or `deleting`: finish the rollout
before requesting a deletion. It also does not re-read the tenant status on an
agent's JWT, which the default revocation of provisioning keys covers.
