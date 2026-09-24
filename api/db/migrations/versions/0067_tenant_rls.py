"""Row-level security on every tenant table: the second line behind WHERE (#311)

Revision ID: 0067_tenant_rls
Revises: 0064_asset_services_retro_match
Create Date: 2026-09-24

Until this revision tenant isolation in Postgres was the ``tenant_id``
predicate of each query and nothing else: a route that forgot one read or wrote
another tenant's rows, and the database had no opinion. This revision gives it
one, for the transactions the API marks as acting for a tenant. The runtime half
— which transactions those are — is ``api/db/tenant_scope.py``; the design, the
grants and the diagnostics are in ``docs/tenant-isolation.md``.

``shapoclyack_tenant`` (role)
    NOLOGIN, no attributes. A tenant-scoped transaction assumes it with
    ``SET LOCAL ROLE``; nobody connects as it. It is created here, unlike the
    audit roles 0037 leaves to the operator: those are the *installation's*
    roles, named by whoever runs the database, while this one is part of the
    schema — the policies below name it the way a foreign key names a table.
    Cluster-wide, so two databases on one server share it; that is harmless,
    because it holds privileges only where a migration granted them.

    Creating it needs CREATEROLE (the stock ``octo`` is a superuser; managed
    services give their master user CREATEROLE). A role that lacks it fails
    here with the two statements a superuser runs instead — before anything
    else is changed — rather than leaving a schema half-protected.

    The migrating role is made a member ``WITH INHERIT FALSE`` (PostgreSQL 16+)
    so the API, which in every shipped manifest is the same role, may switch to
    it. ``INHERIT FALSE`` matters: a member that inherited it would have the
    restrictive policy applied to its *own* statements on every table it does
    not own — ``audit_events`` after the ownership split 0037 recommends — and
    its workers would stop seeing rows. A superuser needs no membership.

``shapoclyack_current_tenant()``
    ``shapoclyack.tenant_id`` when set, else a read of a setting that does not
    exist — i.e. an error. So a transaction on the tenant role that nobody told
    which tenant it is fails loudly instead of answering "no rows". A plain SQL
    function, which the planner inlines: the policy stays an index condition on
    ``tenant_id`` (measured with ``EXPLAIN``, see the doc).

Every table in the schema with a ``tenant_id`` column
    ``ENABLE ROW LEVEL SECURITY`` (not ``FORCE``) and two policies:
    ``shapoclyack_unscoped`` — permissive, every role, ``true`` — which keeps
    every role that is *not* the tenant role exactly where it was, the table's
    owner and a superuser bypassing row security anyway; and
    ``shapoclyack_tenant_isolation`` — restrictive, only for
    ``shapoclyack_tenant`` — ``tenant_id = shapoclyack_current_tenant()`` for
    rows read and rows written. Discovered from the catalog rather than listed,
    so a table an earlier revision added is covered however the chain is
    ordered; a table added *after* this revision needs the same statements
    in its own migration, and ``tests/test_tenant_rls.py`` fails
    until it has them.

    Four tables differ. ``roles`` and ``role_permissions`` keep the built-in
    rows (``tenant_id = ''``, every tenant's) readable, and a tenant can
    neither update, take over nor delete them (restrictive ``FOR UPDATE`` and
    ``FOR DELETE`` policies on top). ``audit_events`` is an ordinary tenant
    table here: its platform-level rows (``tenant_id`` NULL) are neither read
    nor written by a tenant-scoped transaction — a tenant request that records
    a platform act has to do it in the system scope. ``asset_tags`` holds
    tenant data without a ``tenant_id`` column; its policy is "the tag's asset
    is visible", which the assets table's own policy decides.

Grants
    ``SELECT, INSERT, UPDATE, DELETE`` on every table but ``alembic_version``,
    ``USAGE, SELECT`` on every sequence, and the same as default privileges for
    what this role creates later. ``audit_events`` gets ``SELECT, INSERT`` only,
    the layout 0037's documentation already asks of the API.

Locks. ``ENABLE ROW LEVEL SECURITY`` and ``CREATE POLICY`` take ACCESS
EXCLUSIVE on their table — no rewrite, no scan, but a lock every query of the
table queues behind while it waits. So each table is done in a transaction of
its own with ``lock_timeout = 5s`` (Alembic ``autocommit_block``): at most one
table is locked at a time, for milliseconds, and a table a long transaction is
holding makes the run fail in seconds rather than stall traffic. The run is
idempotent, and the rollout's retry (or a second ``python -m api.db.migrate``)
finishes it. Everything before that step is catalog-only and bounded by the
same timeout.

Tables another role owns — ``audit_events`` after the ownership split
docs/operations.md recommends — are not touched: the migrating role cannot
alter them. The exact statements for their owner are logged as a warning, the
upgrade completes, and ``OCTO_TENANT_RLS=enforce`` refuses to start until they
have been run (docs/tenant-isolation.md).

Rolling deploy: harmless to a replica of the previous release, which never
assumes the role, so every policy it meets is the permissive one.

Rollback drops the policies and the function (per table, with the same lock
bound), disables row security, and takes back this database's grants. It
leaves the role and its memberships: they are cluster-wide, another database
may be using them, and an inert NOLOGIN role is cheaper to keep than a
membership an operator granted by hand is to rediscover.
"""
from __future__ import annotations

from typing import Sequence, Union

import logging

import sqlalchemy as sa
from alembic import op

revision: str = "0067_tenant_rls"
down_revision: Union[str, None] = "0064_asset_services_retro_match"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_log = logging.getLogger("alembic.runtime.migration")


# Every statement below is a fixed string. Identifiers that vary — the table
# names found in the catalog, the migrating role — are quoted by quote_ident()
# inside PL/pgSQL, never formatted in Python: an f-string reaching sa.text() is
# the shape CI's semgrep gate refuses (see 0037), and rightly.

_CREATE_ROLE = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shapoclyack_tenant') THEN
        BEGIN
            CREATE ROLE shapoclyack_tenant
                NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        EXCEPTION
            -- Another database's migration created it between the check and
            -- here: the role is cluster-wide, and theirs is the same role.
            WHEN duplicate_object THEN NULL;
            WHEN insufficient_privilege THEN
                RAISE EXCEPTION USING
                    MESSAGE = 'cannot create role shapoclyack_tenant (#311): '
                        || quote_ident(current_user) || ' lacks CREATEROLE',
                    HINT = 'As a superuser run: CREATE ROLE shapoclyack_tenant NOLOGIN; '
                        -- WITH INHERIT FALSE is 16 syntax; before it the member
                        -- itself has to be NOINHERIT (docs/tenant-isolation.md).
                        || CASE WHEN current_setting('server_version_num')::integer >= 160000
                           THEN 'GRANT shapoclyack_tenant TO ' || quote_ident(current_user)
                                || ' WITH INHERIT FALSE; '
                           ELSE 'ALTER ROLE ' || quote_ident(current_user) || ' NOINHERIT; '
                                || 'GRANT shapoclyack_tenant TO ' || quote_ident(current_user) || '; '
                           END
                        || 'then re-run the migration. See docs/tenant-isolation.md.';
        END;
    END IF;
END
$$;
"""

_GRANT_MEMBERSHIP = """
DO $$
BEGIN
    -- A superuser may SET ROLE to anything; everyone else needs membership.
    IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RETURN;
    END IF;
    IF current_setting('server_version_num')::integer < 160000 THEN
        -- Before 16 a membership always inherits, which would put the
        -- restrictive policy on this role's own statements (see the module
        -- docstring). Left to the operator; the API refuses to enforce
        -- without it and says what to run.
        RAISE NOTICE USING MESSAGE = 'shapoclyack_tenant: not granting membership to '
            || quote_ident(current_user) || ' on PostgreSQL < 16; see docs/tenant-isolation.md';
        RETURN;
    END IF;
    -- SET, not MEMBER: a CREATEROLE role that has just created the role above
    -- is already a member — with ADMIN and without SET, which is exactly the
    -- membership that cannot switch to it.
    IF pg_has_role(current_user, 'shapoclyack_tenant', 'SET') THEN
        RETURN;
    END IF;
    BEGIN
        EXECUTE 'GRANT shapoclyack_tenant TO ' || quote_ident(current_user)
            || ' WITH INHERIT FALSE, SET TRUE';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE EXCEPTION USING
                MESSAGE = 'cannot grant shapoclyack_tenant to ' || quote_ident(current_user)
                    || ' (#311)',
                HINT = 'As a superuser run: GRANT shapoclyack_tenant TO '
                    || quote_ident(current_user) || ' WITH INHERIT FALSE; '
                    || 'then re-run the migration. See docs/tenant-isolation.md.';
    END;
END
$$;
"""

_CURRENT_TENANT_FUNCTION = """
CREATE OR REPLACE FUNCTION shapoclyack_current_tenant() RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        NULLIF(pg_catalog.current_setting('shapoclyack.tenant_id', true), ''),
        pg_catalog.current_setting('shapoclyack.tenant_scope_undeclared')
    )
$$;
"""

_GRANTS = """
DO $$
BEGIN
    EXECUTE 'GRANT USAGE ON SCHEMA ' || quote_ident(current_schema())
        || ' TO shapoclyack_tenant';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA '
        || quote_ident(current_schema()) || ' TO shapoclyack_tenant';
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA '
        || quote_ident(current_schema()) || ' TO shapoclyack_tenant';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA ' || quote_ident(current_schema())
        || ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO shapoclyack_tenant';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA ' || quote_ident(current_schema())
        || ' GRANT USAGE, SELECT ON SEQUENCES TO shapoclyack_tenant';
END
$$;
"""

# One statement per execute: psycopg sends a statement with a parameter set,
# even an empty one, through the extended protocol, which takes one command.
_NARROW_GRANTS = (
    "REVOKE ALL ON TABLE alembic_version FROM shapoclyack_tenant",
    "REVOKE UPDATE, DELETE ON TABLE audit_events FROM shapoclyack_tenant",
)

# Each tenant table is protected by one call of this function, in a transaction
# of its own (see upgrade()). It returns NULL when it protected the table, and
# the statements the table's owner has to run when the migrating role is not
# that owner — the hardened layout of docs/operations.md, where audit_events
# belongs to a role of its own. The statements are built once and either
# executed or handed back, so the hint is exactly what the migration would have
# done. Every one is idempotent (DROP POLICY IF EXISTS first), which is what
# lets an interrupted run be run again.
#
# Temporary (pg_temp): it exists for this session only, so the schema gains no
# helper nobody maintains. A later migration that adds a tenant table spells
# the same statements out (docs/tenant-isolation.md).
_PROTECT_FUNCTION = """
CREATE OR REPLACE FUNCTION pg_temp.shapoclyack_protect(t text) RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    rel regclass := (quote_ident(current_schema()) || '.' || quote_ident(t))::regclass;
    q text := quote_ident(t);
    tenant_match text := 'tenant_id = shapoclyack_current_tenant()';
    parent_match text := 'EXISTS (SELECT 1 FROM assets a WHERE a.asset_id = asset_tags.asset_id)';
    statements text[] := ARRAY[]::text[];
    seq text;
    owner name;
    statement text;
BEGIN
    -- Transaction-local, so it bounds this table's lock and nothing else: a
    -- table some long transaction is reading makes the migration fail in
    -- seconds (and the rollout retry it) instead of queueing every query on
    -- that table behind an ACCESS EXCLUSIVE request that cannot be granted.
    PERFORM set_config('lock_timeout', '5s', true);

    statements := statements
        || ('ALTER TABLE ' || q || ' ENABLE ROW LEVEL SECURITY')
        || ('DROP POLICY IF EXISTS shapoclyack_unscoped ON ' || q)
        || ('CREATE POLICY shapoclyack_unscoped ON ' || q
            || ' AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)')
        || ('DROP POLICY IF EXISTS shapoclyack_tenant_isolation ON ' || q)
        || ('DROP POLICY IF EXISTS shapoclyack_tenant_update ON ' || q)
        || ('DROP POLICY IF EXISTS shapoclyack_tenant_delete ON ' || q);
    IF t IN ('roles', 'role_permissions') THEN
        -- Built-in roles are every tenant's (tenant_id = ''): readable, and
        -- neither rewritten, taken over nor removed by a tenant.
        statements := statements
            || ('CREATE POLICY shapoclyack_tenant_isolation ON ' || q
                || ' AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = '''' OR '
                || tenant_match || ') WITH CHECK (' || tenant_match || ')')
            || ('CREATE POLICY shapoclyack_tenant_update ON ' || q
                || ' AS RESTRICTIVE FOR UPDATE TO shapoclyack_tenant USING ('
                || tenant_match || ')')
            || ('CREATE POLICY shapoclyack_tenant_delete ON ' || q
                || ' AS RESTRICTIVE FOR DELETE TO shapoclyack_tenant USING ('
                || tenant_match || ')');
    ELSIF t = 'asset_tags' THEN
        -- Tenant data without a tenant_id column: a tag is its asset's, and
        -- the assets table is itself held to the tenant, so a tag is visible
        -- and writable exactly when its asset is.
        statements := statements
            || ('CREATE POLICY shapoclyack_tenant_isolation ON ' || q
                || ' AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (' || parent_match
                || ') WITH CHECK (' || parent_match || ')');
    ELSE
        statements := statements
            || ('CREATE POLICY shapoclyack_tenant_isolation ON ' || q
                || ' AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (' || tenant_match
                || ') WITH CHECK (' || tenant_match || ')');
    END IF;
    IF t = 'audit_events' THEN
        statements := statements || ('GRANT SELECT, INSERT ON ' || q || ' TO shapoclyack_tenant');
    ELSE
        statements := statements
            || ('GRANT SELECT, INSERT, UPDATE, DELETE ON ' || q || ' TO shapoclyack_tenant');
    END IF;
    FOR seq IN
        SELECT s.oid::regclass::text
          FROM pg_depend d JOIN pg_class s ON s.oid = d.objid
         WHERE d.refobjid = rel AND d.classid = 'pg_class'::regclass
           AND d.deptype IN ('a', 'i') AND s.relkind = 'S'
    LOOP
        statements := statements
            || ('GRANT USAGE, SELECT ON SEQUENCE ' || seq || ' TO shapoclyack_tenant');
    END LOOP;

    SELECT pg_get_userbyid(relowner) INTO owner FROM pg_class WHERE oid = rel;
    IF owner <> current_user
       AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RETURN array_to_string(statements, ';' || chr(10)) || ';';
    END IF;
    FOREACH statement IN ARRAY statements LOOP
        EXECUTE statement;
    END LOOP;
    RETURN NULL;
END
$$;
"""

_UNPROTECT_FUNCTION = """
CREATE OR REPLACE FUNCTION pg_temp.shapoclyack_unprotect(t text) RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    q text := quote_ident(t);
    statements text[];
    owner name;
    statement text;
BEGIN
    PERFORM set_config('lock_timeout', '5s', true);
    statements := ARRAY[
        'DROP POLICY IF EXISTS shapoclyack_tenant_delete ON ' || q,
        'DROP POLICY IF EXISTS shapoclyack_tenant_update ON ' || q,
        'DROP POLICY IF EXISTS shapoclyack_tenant_isolation ON ' || q,
        'DROP POLICY IF EXISTS shapoclyack_unscoped ON ' || q,
        'ALTER TABLE ' || q || ' DISABLE ROW LEVEL SECURITY'
    ];
    SELECT pg_get_userbyid(relowner) INTO owner FROM pg_class
     WHERE oid = (quote_ident(current_schema()) || '.' || q)::regclass;
    IF owner <> current_user
       AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RETURN array_to_string(statements, ';' || chr(10)) || ';';
    END IF;
    FOREACH statement IN ARRAY statements LOOP
        EXECUTE statement;
    END LOOP;
    RETURN NULL;
END
$$;
"""

# Fixed statements, one per direction: nothing is formatted into the SQL text.
_CALL = {
    "protect": "SELECT pg_temp.shapoclyack_protect(:t)",
    "unprotect": "SELECT pg_temp.shapoclyack_unprotect(:t)",
}

# Every table with a tenant_id column, plus asset_tags (tenant data scoped
# through its asset). From the catalog rather than a list, so a table an
# earlier revision added is covered however the chain is ordered at merge.
_TENANT_TABLES = """
SELECT c.relname
  FROM pg_class c
 WHERE c.relnamespace = current_schema()::regnamespace
   AND c.relkind IN ('r', 'p')
   AND (c.relname = 'asset_tags' OR EXISTS (
        SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped))
 ORDER BY c.relname
"""

_PROTECTED_TABLES = """
SELECT DISTINCT c.relname
  FROM pg_policy p
  JOIN pg_class c ON c.oid = p.polrelid
 WHERE c.relnamespace = current_schema()::regnamespace
   AND p.polname IN (
       'shapoclyack_unscoped',
       'shapoclyack_tenant_isolation',
       'shapoclyack_tenant_update',
       'shapoclyack_tenant_delete'
   )
 ORDER BY c.relname
"""

_REVOKE_GRANTS = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'shapoclyack_tenant') THEN
        RETURN;
    END IF;
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA ' || quote_ident(current_schema())
        || ' REVOKE ALL ON SEQUENCES FROM shapoclyack_tenant';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA ' || quote_ident(current_schema())
        || ' REVOKE ALL ON TABLES FROM shapoclyack_tenant';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA ' || quote_ident(current_schema())
        || ' FROM shapoclyack_tenant';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA ' || quote_ident(current_schema())
        || ' FROM shapoclyack_tenant';
    EXECUTE 'REVOKE USAGE ON SCHEMA ' || quote_ident(current_schema())
        || ' FROM shapoclyack_tenant';
END
$$;
"""


def _per_table(bind: sa.engine.Connection, direction: str, tables: list[str]) -> dict[str, str]:
    """Run the ``direction`` function once per table, each call its own transaction.

    One transaction for all of them held ACCESS EXCLUSIVE on every table it
    had reached until the last one was done, so a single long reader anywhere
    stalled the traffic of every table already locked. One per table holds one
    lock at a time, for milliseconds; a lock that cannot be had within the
    function's ``lock_timeout`` fails the run, and the run can simply be run
    again. Returns ``{table: statements}`` for the tables another role owns.
    """
    left_to_owner: dict[str, str] = {}
    with op.get_context().autocommit_block():
        for table in tables:
            statements = bind.execute(sa.text(_CALL[direction]), {"t": table}).scalar()
            if statements:
                left_to_owner[table] = statements
    return left_to_owner


def _report(left_to_owner: dict[str, str], what: str) -> None:
    for table, statements in left_to_owner.items():
        # A warning and not a failure: refusing would block the upgrade on
        # statements only another role may run. OCTO_TENANT_RLS=enforce then
        # refuses to start and names the table, so the gap cannot go unseen.
        _log.warning(
            "0067_tenant_rls: %s is owned by another role; its tenant policies were not "
            "%s. Run as its owner:\n%s",
            table,
            what,
            statements,
        )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # The SQLite fallback has no roles and no row security; it is refused
        # in prod (#174) and gets its schema from the models, not from here.
        return
    # Catalog changes only up to the per-table step (GRANT included: measured
    # not to wait behind a reader), but bounded all the same.
    op.execute(sa.text("SET LOCAL lock_timeout = '5s'"))
    op.execute(sa.text(_CREATE_ROLE))
    op.execute(sa.text(_GRANT_MEMBERSHIP))
    op.execute(sa.text(_CURRENT_TENANT_FUNCTION))
    op.execute(sa.text(_GRANTS))
    for statement in _NARROW_GRANTS:
        op.execute(sa.text(statement))
    op.execute(sa.text(_PROTECT_FUNCTION))
    tables = [row[0] for row in bind.execute(sa.text(_TENANT_TABLES))]
    _report(_per_table(bind, "protect", tables), "created")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(_UNPROTECT_FUNCTION))
    tables = [row[0] for row in bind.execute(sa.text(_PROTECTED_TABLES))]
    left_to_owner = _per_table(bind, "unprotect", tables)
    _report(left_to_owner, "dropped")
    op.execute(sa.text("SET LOCAL lock_timeout = '5s'"))
    if left_to_owner:
        # Their policies still call it; it goes when their owner drops them.
        _log.warning(
            "0067_tenant_rls: shapoclyack_current_tenant() left in place for the policies "
            "on %s; drop it after their owner has run the statements above.",
            ", ".join(left_to_owner),
        )
    else:
        op.execute(sa.text("DROP FUNCTION IF EXISTS shapoclyack_current_tenant()"))
    op.execute(sa.text(_REVOKE_GRANTS))
