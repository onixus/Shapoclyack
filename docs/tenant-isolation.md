# Tenant isolation in the database

Tenant isolation in Shapoclyack has two lines
([#311](https://github.com/onixus/Shapoclyack/issues/311)).

1. **The route and the query.** Every tenant-scoped route resolves its tenant
   server-side (`require_tenant`, `require_permission`,
   `require_path_tenant_permission`, `require_agent` — see
   [API and RBAC § Tenant memberships](api-and-rbac.md#tenant-memberships)), and
   every query it makes carries `WHERE tenant_id = …`. This is the line that
   decides what a caller sees.
2. **Postgres row-level security.** Every table with a `tenant_id` column has a
   policy that, for a transaction acting for a tenant, drops the other tenants'
   rows from what it reads and refuses any other tenant's row it writes. This is
   the line that catches the query written without its predicate — the
   `select(Asset).where(Asset.asset_id == asset_id)` that trusts an id from the
   URL.

The second line does not replace the first, and nothing in the code relies on
it: a route that returns the right rows only because of the policy is a bug in
the route. What it changes is what such a bug costs — an empty result or a
refused write instead of another customer's data.

A third, cheaper line guards the first: `tests/test_route_tenant_guards.py`
walks every route the application mounts and fails for one that has no tenant
guard and no entry in its reviewed allowlist, which says why the route may
answer across tenants.

## How it works

### In the schema — migration `0067_tenant_rls`

| Object | What it is |
|---|---|
| Role `shapoclyack_tenant` | `NOLOGIN`, no attributes. A tenant-scoped transaction assumes it with `SET LOCAL ROLE`; nobody connects as it. Created by the migration (it needs `CREATEROLE`), cluster-wide |
| Function `shapoclyack_current_tenant()` | `shapoclyack.tenant_id` when set; otherwise it reads a setting that does not exist, which is an **error**. A plain SQL function the planner inlines, so the policy stays an index condition on `tenant_id` |
| Policy `shapoclyack_unscoped` on every tenant table | Permissive, every role, `true`. Keeps every role that is *not* the tenant role exactly where it was — without it, row security would deny a non-owner API role (and its workers) the whole table |
| Policy `shapoclyack_tenant_isolation` on every tenant table | Restrictive, **only** for `shapoclyack_tenant`: `tenant_id = shapoclyack_current_tenant()` for rows read and rows written |
| Grants to `shapoclyack_tenant` | `SELECT, INSERT, UPDATE, DELETE` on every table except `alembic_version`; `SELECT, INSERT` only on `audit_events`; `USAGE, SELECT` on sequences; the same as default privileges of the migrating role |
| Membership | The migrating role is made a member `WITH INHERIT FALSE` (PostgreSQL 16+) so it may switch; a superuser needs none |

Row security is `ENABLE`d, not `FORCE`d: the table owner and a superuser still
bypass it, which is what keeps every worker working unchanged (below).

Tenant tables are every table with a `tenant_id` column, found in the catalog
(54 policies today: 52 such tables, `asset_tags` and `tenant_deletion_steps`).
Three differ:

* `roles` and `role_permissions` keep the built-in rows (`tenant_id = ''`,
  every tenant's) readable; restrictive `FOR UPDATE` and `FOR DELETE` policies
  stop a tenant rewriting, taking over or removing them.
* `asset_tags` and `tenant_deletion_steps` hold tenant data without a
  `tenant_id` column. Their policy is that the parent row is visible —
  `EXISTS (SELECT 1 FROM assets a WHERE a.asset_id = asset_tags.asset_id)`, and
  the same through `tenant_deletions` for a purge step (#325) — and the parent
  table is itself held to the tenant, so the row is visible and writable
  exactly when its parent is (`tenant_scope.PARENT_SCOPED_TABLES`).
* `audit_events` is an ordinary tenant table: its platform-level rows
  (`tenant_id` NULL) are neither read nor written by a tenant-scoped
  transaction. (The ORM's `INSERT … RETURNING` reads the row back, so even a
  laxer write rule could not append one.) Nothing does that today; a tenant
  request that records a platform act has to do it in the system scope.

**Locks.** `ENABLE ROW LEVEL SECURITY` and `CREATE POLICY` take `ACCESS
EXCLUSIVE` on their table — no rewrite, no scan, but every query of that table
queues behind the request while it waits. The migration therefore does each
table in a transaction of its own under `lock_timeout = 5s`: one table locked at
a time, for milliseconds. A table some long transaction holds fails the run in
seconds instead of stalling traffic; the run is idempotent, and the rollout's
retry — or a second `python -m api.db.migrate` — finishes it. Everything before
that step is catalog-only (the `GRANT`s included: measured not to wait behind a
reader) and bounded by the same timeout.

**Tables another role owns** — `audit_events` after the ownership split in
[operations.md § Recommended GRANT layout](operations.md#recommended-grant-layout)
— cannot be altered by the migrating role. The migration leaves them, logs the
exact statements for their owner as a warning (see *Migrations* below), and
completes; `enforce` then refuses to start and names the table until the owner
has run them.

### In the application — `api/db/tenant_scope.py`

A transaction is scoped once, when it begins (SQLAlchemy `after_begin` on the
Postgres session factory), in one of three scopes:

| Scope | Who | What the transaction does |
|---|---|---|
| **tenant** | A console request resolved by `resolve_tenant_principal` for anyone but the platform admin; every request authenticated with a **service token** (pinned at authentication, before any route runs); every **sensor** request (`require_agent`, or `require_agent_heartbeat` for the heartbeat a closed tenant's agent still gets its stop on (#325): the tenant its signed token names; `default` for the legacy shared token) | `SELECT set_config('role', 'shapoclyack_tenant', true), set_config('shapoclyack.tenant_id', <tenant>, true)` |
| **system** | Everything outside a request — every background worker, the startup imports, CLI tools; authentication itself (it is what *finds* the tenant); the **platform admin's** requests (tenant-scoped routes, and `require_role` / `require_platform_permission` routes); routes that declare `tenant_scope.cross_tenant(reason)` | Nothing: the connecting role, exactly as before |
| **undeclared** | A request that has not reached any of the above — including a *non-admin* caller behind `require_role` / `require_platform_permission`: a global gate widens nothing for anyone but the platform admin | The tenant role with **no** tenant: any statement on a tenant table fails with `unrecognized configuration parameter "shapoclyack.tenant_scope_undeclared"` |

Details that matter:

* **Every transaction, not every session.** `SET LOCAL` ends with the commit,
  and handlers commit more than once. The hook runs at the start of each
  transaction of a session, so the third transaction of a handler is scoped
  like the first.
* **Nothing leaks through the pool.** Both settings are transaction-local, so a
  connection goes back to the pool on the connecting role with no tenant — the
  next checkout, whoever it is for, starts clean. `tests/test_tenant_rls.py`
  pins one connection and hands it from a tenant to a worker to check this.
* **A tenant, once declared, is sticky** for the rest of the request: a later
  `declare_system` cannot widen it, and declaring a *different* tenant is a
  `TenantScopeConflict` (a 500 — no caller can provoke it; it is a route that
  combines two guards wrongly). So the order of a route's dependencies does not
  matter.
* **Threads do not inherit it.** A deployment, notification or local-scan
  thread a request starts runs in the system scope, like any worker. Work handed
  to `asyncio.to_thread` (the results ingest) does inherit it.
* **Savepoints are free.** A `SAVEPOINT` inside a scoped transaction keeps its
  settings (they were made before it and survive its rollback), so the hook
  skips nested transactions rather than paying a round trip for each.
* **The explicit escape hatch** is `with tenant_scope.system("reason"):`. Its
  uses, all reviewed: authentication (service-token lookup, tenant resolution,
  agent credential check); the caller's own memberships for `GET /api/tenants`
  and `/tenants/posture`; and the two ownership checks on ids a client chooses —
  `agents.register_agent` (`agent_id`) and `endpoint_inventory.ingest_snapshot`
  (`snapshot_id`) — which must see another tenant's row to refuse it by name
  rather than die on the primary key. Keep it greppable and rare.
* **Its narrowing twin** is `with tenant_scope.tenant(t):`. A non-admin's
  `GET /api/tenants/posture` reads each of the caller's tenants inside one, so a
  grouped read that forgot its membership filter still sees one tenant.

## Why this design

**Why the tenant path takes a role, rather than the system path taking a
bypass flag.** A superuser, a role with `BYPASSRLS` and a table's owner (unless
`FORCE ROW LEVEL SECURITY`) all bypass row security. Every shipped manifest —
`k8s/` base, `scripts/install-server.py`'s compose file — connects the API as
`octo`, the `POSTGRES_USER` of the official image, i.e. a superuser. A policy
keyed on a setting alone would therefore be enforced on no stock installation
until somebody split the database roles, and the second line would exist on
paper. `SET ROLE` to a role that is none of those three is what makes the
policy apply to whoever the API connects as — superuser, owner, or a separate
non-owner role — without changing the manifests.

**Why not a separate database role for the platform admin**, as the issue
suggested. The decision "is this transaction cross-tenant?" is made in the same
application code either way; a second login role would add a second connection
pool per replica (the `max_connections` budget in
[high-availability.md](high-availability.md) doubles), a second credential to
provision and rotate, and routing of every session to one engine or the other —
for no gain against the threat this addresses. The threat is a query that forgot
its predicate. It is **not** SQL injection: a statement an attacker controls can
`RESET ROLE` or name another tenant under either design. Bound parameters and
the SAST gate are the defence against that. The design does the useful half of
the issue's idea in the direction that deploys: the *restricted* authority is
the separate role.

**Why the platform admin is not narrowed.** The platform admin is authorized in
every tenant, and the routes are built on it: fleet-wide lists when no tenant is
named, writes to any tenant's finding (`_write_scope` in
`api/routes/vulnerabilities.py`), a scan started in a tenant named in the body.
Narrowing its requests would break those, and a missing predicate in a request
made by someone entitled to every row is a correctness bug, not a disclosure.

**Why "undeclared" fails instead of returning nothing.** A policy that answers
"no rows" when nobody set the tenant is indistinguishable from "this tenant has
none": a readiness probe would report no backlog, a list would render empty,
and nothing would say why. A request that reads tenant data before anyone
decided whose it is has a bug worth a 500 with a message that names it.

**Why workers need no change.** They run outside any request, so their scope is
`system` and their transactions never switch role; the permissive policy keeps a
non-owner connecting role seeing every row. Retention reapers, SLA escalation,
the ticket poller, the NATS outbox, retro matching, the schedulers and the
publication worker are all this case.

## Rollout: `OCTO_TENANT_RLS`

| Value | Meaning |
|---|---|
| `enforce` (default) | Tenant-scoped transactions assume the role; startup **refuses** if the database cannot deliver it (below) |
| `off` | No transaction ever switches role — exactly the behaviour before `0067`. A `prod` start says so in the log, every time |

`enforce` is the default in every environment. A second line that has to be
switched on is a second line nobody has; the blast radius is bounded by
construction (only tenant-scoped request transactions change), the whole test
suite runs in this mode, and `off` is a restart away. The migration is the same
in both modes and safe to run under either, so switching needs no downgrade.

The setting is per process. Canary it: set `off` on the Deployment, roll one
replica with `enforce` (or the reverse during an incident) — replicas in
different modes share one schema without conflict.

A value other than the two is refused at startup rather than guessed, in every
environment.

### What `enforce` checks at startup

`create_app()` refuses to start, naming each problem and its fix, when:

* the role `shapoclyack_tenant` does not exist (migrations not run);
* it is `SUPERUSER` or `BYPASSRLS` (someone altered it; the policy would never apply);
* the API's role may not `SET ROLE` to it;
* a tenant table lacks row security, its restrictive policy, or its permissive
  one (without which a non-owner API role's workers see nothing) — naming the
  tables another role owns, whose owner has to run the statements;
* the API's role *inherits* the tenant role and does not own every tenant table
  (the restrictive policy would then apply to its own worker statements);
* the tenant role lacks a privilege on a table, or `USAGE` on a sequence (a
  serial column's `INSERT` needs it — `audit_events_id_seq` after the ownership
  split).

## Operations

### Database roles and grants

| Installation | What to do |
|---|---|
| Stock `k8s/` base, `prod`, compose from `install-server.py` (API and migrations as superuser `octo`) | Nothing. The migration creates the role; a superuser may switch to it |
| External Postgres (`prod-ha`), one role for migrations and the API, with `CREATEROLE` (RDS / Cloud SQL / Yandex master users have it) | Nothing. The migration creates the role and grants itself membership `WITH INHERIT FALSE` |
| External Postgres, migration role **without** `CREATEROLE` | Before upgrading, as a superuser: `CREATE ROLE shapoclyack_tenant NOLOGIN; GRANT shapoclyack_tenant TO <migration role> WITH INHERIT FALSE;` — the migration fails with exactly this hint otherwise, before changing anything |
| API connects as a **different** role from the migrations (least-privilege split) | `GRANT shapoclyack_tenant TO <api role> WITH INHERIT FALSE;` The API role needs its usual table privileges as before; the permissive policy keeps its own (system) reads unrestricted |
| `audit_events` moved to its own owner ([operations.md § Recommended GRANT layout](operations.md#recommended-grant-layout)) | Also `GRANT SELECT, INSERT ON audit_events TO shapoclyack_tenant;` — the migration's grant is made by the migrating role and does not reach a table it no longer owns. The startup check names it if missing |
| PostgreSQL 14 or 15 | `GRANT … WITH INHERIT FALSE` does not exist; the migration skips the grant (NOTICE). A superuser API needs nothing. Otherwise `ALTER ROLE <api role> NOINHERIT; GRANT shapoclyack_tenant TO <api role>;` — `NOINHERIT` applies to *all* of that role's memberships, so check it holds no privilege through another role first — or run `off`. The startup check prints the variant for the server it runs against |

`INHERIT FALSE` is not decoration: a member that *inherits* the tenant role has
the restrictive policy applied to its own statements on every table it does not
own, and its workers stop seeing rows there. The startup check refuses that
combination.

### Migrations

`python -m api.db.migrate` as before, as the role that owns the schema. Any
later migration that **creates a table with `tenant_id`** must give it the same
two policies — the test `tests/test_tenant_rls.py::test_every_tenant_table_carries_the_isolation_policy`
and the `enforce` startup check both fail until it does:

```sql
ALTER TABLE new_table ENABLE ROW LEVEL SECURITY;
CREATE POLICY shapoclyack_unscoped ON new_table
  AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY shapoclyack_tenant_isolation ON new_table
  AS RESTRICTIVE FOR ALL TO shapoclyack_tenant
  USING (tenant_id = shapoclyack_current_tenant())
  WITH CHECK (tenant_id = shapoclyack_current_tenant());
```

Grants on the new table come from the default privileges `0067` set, as long as
the same role creates it. Do it in the migration's own short transaction with
`SET LOCAL lock_timeout`, as `0067` does, if the table can already hold traffic.

**A table another role owns.** When the migrating role is neither the owner nor
a superuser, `0067` skips the table and logs a warning that ends with the
statements to run as that owner — for `audit_events` after the ownership split:

```
WARNI [alembic.runtime.migration] 0067_tenant_rls: audit_events is owned by another role; its tenant policies were not created. Run as its owner:
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS shapoclyack_unscoped ON audit_events;
CREATE POLICY shapoclyack_unscoped ON audit_events AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS shapoclyack_tenant_isolation ON audit_events;
DROP POLICY IF EXISTS shapoclyack_tenant_update ON audit_events;
DROP POLICY IF EXISTS shapoclyack_tenant_delete ON audit_events;
CREATE POLICY shapoclyack_tenant_isolation ON audit_events AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant());
GRANT SELECT, INSERT ON audit_events TO shapoclyack_tenant;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO shapoclyack_tenant;
```

Run them as that owner (a superuser can `SET ROLE shapoclyack_audit_owner;`
first). They are idempotent. Until they have run, `enforce` refuses to start and
names the table; `off` starts as before. The downgrade does the same in reverse,
and then leaves `shapoclyack_current_tenant()` in place, because those policies
still call it.

Downgrading `0067` drops the policies and the function, disables row security
and revokes this database's grants — table by table, under the same lock bound.
It leaves the role: it is cluster-wide and may be in use by another database.
Downgrade only with `OCTO_TENANT_RLS=off` already rolled out, or `enforce`
replicas refuse to start.

**Supported PostgreSQL.** 16 is what the shipped manifests run and what this was
built and tested on. 14 and 15 work with a superuser API role, or with the
`NOINHERIT` layout above; the migration and the startup check print the
variant of each statement for the server they run against.

### Verifying

```sql
-- Every tenant table protected (expect no rows):
SELECT c.relname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
 WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind = 'r'
   AND a.attname = 'tenant_id' AND NOT a.attisdropped
   AND NOT (c.relrowsecurity AND EXISTS (
       SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid
          AND p.polname = 'shapoclyack_tenant_isolation'));

-- The API's role may switch, and does not inherit (expect t, f):
SELECT pg_has_role(current_user, 'shapoclyack_tenant', 'SET'),
       pg_has_role(current_user, 'shapoclyack_tenant', 'USAGE');

-- What a tenant sees (read-only, rolled back):
BEGIN;
SELECT set_config('role', 'shapoclyack_tenant', true),
       set_config('shapoclyack.tenant_id', 'acme', true);
SELECT count(*), count(DISTINCT tenant_id) FROM vulnerabilities;  -- n, 1
ROLLBACK;
```

### Diagnosing a denied row

| Symptom | Meaning | Where to look |
|---|---|---|
| `unrecognized configuration parameter "shapoclyack.tenant_scope_undeclared"` | A request touched a tenant table before any guard said whose request it is | The route: give it a tenant guard, or — if it truly spans tenants — `dependencies=[Depends(tenant_scope.cross_tenant("reason"))]` and an entry in the test's allowlist |
| `new row violates row-level security policy "shapoclyack_tenant_isolation" for table "…"` | A tenant-scoped transaction wrote a row of **another** tenant (insert, or an update that moved `tenant_id`) | The tenant id the code wrote: this is the second line catching a first-line bug. The request id (`X-Request-Id`) in the API log names the request |
| A `404`/empty list for a row that exists | Either the row is another tenant's (correct), or the code looks across tenants on purpose inside a tenant request | Reproduce with the `BEGIN; set_config…` block above as that tenant. A deliberate cross-tenant check needs `tenant_scope.system(...)` around exactly that lookup |
| The migration fails with `canceling statement due to lock timeout` | A long transaction held a tenant table while `0067` waited 5 s for it | Nothing is half-done: every table already finished stays protected. Run the migration again (the rollout retries it); find the long transaction in `pg_stat_activity` if it keeps happening |
| `enforce` refuses to start naming `audit_events` (or another table) as owned elsewhere | The migrating role could not alter a table another role owns | Run the statements `0067` logged, as that owner (*Migrations* above) |
| `permission denied for table …` | The tenant role lacks a privilege on a table created by a different role than the one `0067` set default privileges for | `GRANT SELECT, INSERT, UPDATE, DELETE ON … TO shapoclyack_tenant` |
| `permission denied to set role "shapoclyack_tenant"` | The API's role is not a member | Should not reach a request — the startup check refuses first. `GRANT … WITH INHERIT FALSE` |
| Workers see nothing on one table | The API's role inherits the tenant role and does not own that table | `REVOKE shapoclyack_tenant FROM …; GRANT … WITH INHERIT FALSE` |

A request's scope is not logged per statement. `current_user` and
`current_setting('shapoclyack.tenant_id', true)` in the failing transaction
answer the question; so does the `api.db.tenant_scope` startup log line
`Tenant row security is enforced`.

### Backups and other clients

`pg_dump` sets `row_security = off`, and for a role that row security applies
to — anything that is not a superuser, `BYPASSRLS` or the table's owner — that
is a refusal, however permissive the policy: `query would be affected by
row-level security policy for table "…"`. The shipped backup CronJob and
`scripts/restore-postgres.sh` run as the superuser `octo`, which bypasses row
security, so they are unaffected. A backup role of your own either gets
`BYPASSRLS`, or runs `pg_dump --enable-row-security`, which then dumps every row
through the permissive policy (checked against PostgreSQL 16 with a non-owner
role holding only `SELECT`). Any other client (a BI tool, `psql`) sees every
row through that policy unless it switches to `shapoclyack_tenant` itself.

### Cost

One extra statement per transaction of a tenant-scoped request (both settings in
one `SELECT`). The policy is inlined into each query as
`tenant_id = COALESCE(NULLIF(current_setting(…)), …)` and used as an index
condition — measured with `EXPLAIN` on PostgreSQL 16 in the development
container: a 200 000-row table with an index on `tenant_id` answered a scoped
`count(*)` with a Bitmap Index Scan on that index, not a sequential scan.
System-scope transactions pay nothing.

## What it does not cover

* **Platform-admin requests, workers, CLI tools** — system scope by design (above).
* **SQL injection** — see *Why not a separate database role*.
* **Foreign keys.** Postgres checks referential integrity as the table owner,
  past row security. So a tenant-scoped transaction learns whether an id exists
  in *another* tenant from a foreign-key error (an existence oracle), and can
  write its own row pointing at another tenant's parent — a finding of tenant A
  on tenant B's `asset_id` — which B's `ON DELETE CASCADE` then reaches into.
  That is the IDOR class the second line does not close: a route that takes a
  parent id from the request and writes a child row with it must still check the
  parent is the caller's (the first line). Closing it in the
  schema means composite foreign keys `(tenant_id, parent_id) → parent(tenant_id,
  id)` on every parent/child pair, which needs a unique index on each parent and
  a migration per pair; not done here.
* **ClickHouse, NATS subjects, artifact storage** — row security is Postgres
  only. NATS subjects carry the tenant (`ingest.endpoint_inventory.{tenant}`);
  run artifacts are keyed under their tenant since
  [#427](https://github.com/onixus/Shapoclyack/issues/427)
  (`runs/_tenants/<tenant>/<run_id>`, ids minted with a random suffix) with an
  owner-checked read-through for runs from before it — see
  [operations.md § Run directories](operations.md#run-directories).
* **The SQLite fallback** — no roles and no row security; it is refused in
  `prod` (#174).

## Checklist for a change

* A new tenant-scoped route: a tenant guard in its dependencies. Nothing else.
* A new route that spans tenants: an allowlist entry in
  `tests/test_route_tenant_guards.py` with the reason, and — if it reads a
  tenant table — a `tenant_scope.cross_tenant(reason)` dependency. A
  `require_role` gate declares nothing for callers other than the platform
  admin; a route that serves them several tenants says how (see `list_tenants`,
  `list_tenant_posture`). An entry that says "reads no table" is requested by
  that test in the undeclared scope, so it has to stay true.
* A new table with `tenant_id`: the two policies in its migration.
* Code that must see another tenant's row inside a tenant request (an identity
  check that refuses by name): `with tenant_scope.system("reason"):` around that
  lookup only.
