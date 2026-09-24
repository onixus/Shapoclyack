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
    ordered; a table added *after* this revision needs the same three
    statements in its own migration, and ``tests/test_tenant_rls.py`` fails
    until it has them.

    Three tables differ. ``roles`` and ``role_permissions`` keep the built-in
    rows (``tenant_id = ''``, every tenant's) readable, and writable by no
    tenant. ``audit_events.tenant_id`` is NULL for a platform-level act: those
    rows are readable by no tenant, and a tenant-scoped transaction may still
    *append* one, because refusing the record of an action would refuse the
    action.

Grants
    ``SELECT, INSERT, UPDATE, DELETE`` on every table but ``alembic_version``,
    ``USAGE, SELECT`` on every sequence, and the same as default privileges for
    what this role creates later. ``audit_events`` gets ``SELECT, INSERT`` only,
    the layout 0037's documentation already asks of the API.

Rolling deploy: harmless to a replica of the previous release, which never
assumes the role, so every policy it meets is the permissive one. Nothing here
takes more than a brief lock per table (``ALTER TABLE … ENABLE ROW LEVEL
SECURITY`` and ``CREATE POLICY`` are catalog changes; no rewrite, no scan).

Rollback drops the policies and the function, disables row security, and takes
back this database's grants. It leaves the role and its memberships: they are
cluster-wide, another database may be using them, and an inert NOLOGIN role is
cheaper to keep than a membership an operator granted by hand is to rediscover.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0067_tenant_rls"
down_revision: Union[str, None] = "0064_asset_services_retro_match"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


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
                        || 'GRANT shapoclyack_tenant TO ' || quote_ident(current_user)
                        || ' WITH INHERIT FALSE; then re-run the migration. '
                        || 'See docs/tenant-isolation.md.';
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

_POLICIES = """
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT c.relname
          FROM pg_class c
          JOIN pg_attribute a ON a.attrelid = c.oid
         WHERE c.relnamespace = current_schema()::regnamespace
           AND c.relkind IN ('r', 'p')
           AND a.attname = 'tenant_id'
           AND NOT a.attisdropped
         ORDER BY c.relname
    LOOP
        EXECUTE 'ALTER TABLE ' || quote_ident(t) || ' ENABLE ROW LEVEL SECURITY';
        EXECUTE 'CREATE POLICY shapoclyack_unscoped ON ' || quote_ident(t)
            || ' AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)';
        IF t IN ('roles', 'role_permissions') THEN
            -- Built-in roles are every tenant's (tenant_id = ''): readable,
            -- never written or removed by a tenant.
            EXECUTE 'CREATE POLICY shapoclyack_tenant_isolation ON ' || quote_ident(t)
                || ' AS RESTRICTIVE FOR ALL TO shapoclyack_tenant'
                || ' USING (tenant_id = '''' OR tenant_id = shapoclyack_current_tenant())'
                || ' WITH CHECK (tenant_id = shapoclyack_current_tenant())';
            EXECUTE 'CREATE POLICY shapoclyack_tenant_delete ON ' || quote_ident(t)
                || ' AS RESTRICTIVE FOR DELETE TO shapoclyack_tenant'
                || ' USING (tenant_id = shapoclyack_current_tenant())';
        ELSIF t = 'audit_events' THEN
            -- NULL = a platform-level act: no tenant reads it, and a tenant
            -- transaction may still append one.
            EXECUTE 'CREATE POLICY shapoclyack_tenant_isolation ON ' || quote_ident(t)
                || ' AS RESTRICTIVE FOR ALL TO shapoclyack_tenant'
                || ' USING (tenant_id = shapoclyack_current_tenant())'
                || ' WITH CHECK (tenant_id IS NULL OR tenant_id = shapoclyack_current_tenant())';
        ELSE
            EXECUTE 'CREATE POLICY shapoclyack_tenant_isolation ON ' || quote_ident(t)
                || ' AS RESTRICTIVE FOR ALL TO shapoclyack_tenant'
                || ' USING (tenant_id = shapoclyack_current_tenant())'
                || ' WITH CHECK (tenant_id = shapoclyack_current_tenant())';
        END IF;
    END LOOP;
END
$$;
"""

_DROP_POLICIES = """
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT DISTINCT c.relname
          FROM pg_policy p
          JOIN pg_class c ON c.oid = p.polrelid
         WHERE c.relnamespace = current_schema()::regnamespace
           AND p.polname IN (
               'shapoclyack_unscoped',
               'shapoclyack_tenant_isolation',
               'shapoclyack_tenant_delete'
           )
    LOOP
        EXECUTE 'DROP POLICY IF EXISTS shapoclyack_tenant_delete ON ' || quote_ident(t);
        EXECUTE 'DROP POLICY IF EXISTS shapoclyack_tenant_isolation ON ' || quote_ident(t);
        EXECUTE 'DROP POLICY IF EXISTS shapoclyack_unscoped ON ' || quote_ident(t);
        EXECUTE 'ALTER TABLE ' || quote_ident(t) || ' DISABLE ROW LEVEL SECURITY';
    END LOOP;
END
$$;
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


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # The SQLite fallback has no roles and no row security; it is refused
        # in prod (#174) and gets its schema from the models, not from here.
        return
    op.execute(sa.text(_CREATE_ROLE))
    op.execute(sa.text(_GRANT_MEMBERSHIP))
    op.execute(sa.text(_CURRENT_TENANT_FUNCTION))
    op.execute(sa.text(_GRANTS))
    for statement in _NARROW_GRANTS:
        op.execute(sa.text(statement))
    op.execute(sa.text(_POLICIES))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(_DROP_POLICIES))
    op.execute(sa.text("DROP FUNCTION IF EXISTS shapoclyack_current_tenant()"))
    op.execute(sa.text(_REVOKE_GRANTS))
