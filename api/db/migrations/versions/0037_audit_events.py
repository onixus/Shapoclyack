"""Append-only administrative audit trail (#327, #329)

Revision ID: 0037_audit_events
Revises: 0036_oidc_pending_states
Create Date: 2026-09-09

``auth_events`` records who signed in and what was refused. Nothing recorded
what was *changed*: an account created and promoted to admin, a membership
granted, a service token minted, a scan scope replaced, the installation-wide
scanner config edited. This is that table, and it is append-only.

**No expand/contract phase and nothing to backfill.** The table is new, no
reader precedes it, and the events it would want from before this migration
were never written down — inventing them would be the opposite of an audit
trail. The writers are added in the same release, so a rolling deploy has old
replicas that record nothing and new ones that record everything; both keep
serving, and the gap is bounded by the rollout.

**Immutability (#329) is enforced by the database, not by the application.**
``audit_events_immutable`` refuses every UPDATE and every DELETE, so a bug in
the API — or an operator with the API's credentials — cannot rewrite history.
Retention still has to remove aged rows, and it does so through
``audit_events_prune``, a SECURITY DEFINER function: it sets a transaction-local
GUC that the trigger honours, and the trigger *also* requires the effective
user to be the table's owner, which is true inside the definer function and
false for anyone who merely sets the GUC themselves. So the escape hatch is the
function, and EXECUTE on the function is the privilege to guard.

The alternative — ``ALTER TABLE … DISABLE TRIGGER`` around the delete — was
rejected: it needs table ownership anyway, takes an ACCESS EXCLUSIVE lock on
the audit table for the length of the sweep, and leaves a window in which
*every* session can delete, including the one that owns the API.

The INSERT-only database role for the API is documented in
``docs/operations.md`` as the recommended GRANT layout rather than created
here: this migration does not know what the installation's roles are called,
and a migration that invents roles is one that fails on every installation
whose names differ.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0037_audit_events"
down_revision: Union[str, None] = "0036_oidc_pending_states"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# The trigger and the retention function agree on one spelling of the GUC that
# opens the escape hatch: ``shapoclyack.audit_retention``. Written out in the
# SQL below rather than interpolated — an f-string reaching sa.text() is the
# shape CI's semgrep gate refuses, and rightly.
_IMMUTABLE_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- The one hole, and it is deliberately narrow: a DELETE issued from inside
    -- audit_events_prune(), which is SECURITY DEFINER and therefore runs as the
    -- table's owner. A session that merely sets the GUC keeps its own
    -- current_user and is refused here.
    IF TG_OP = 'DELETE'
       AND current_setting('shapoclyack.audit_retention', true) = 'on'
       AND current_user = (
           SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = TG_RELID
       ) THEN
        RETURN OLD;
    END IF;
    -- Built by concatenation rather than a '%' format placeholder: this SQL
    -- reaches the driver through sa.text(), and a lone '%' in a statement that
    -- may carry an (empty) parameter set is a portability trap not worth taking
    -- for one interpolation.
    RAISE EXCEPTION USING
        MESSAGE = 'audit_events is append-only: ' || TG_OP || ' refused (#329)',
        ERRCODE = 'restrict_violation';
END;
$$;
"""

_PRUNE_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_events_prune(cutoff timestamp without time zone)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    removed bigint;
BEGIN
    -- Transaction-local (the third argument): it cannot outlive this call and
    -- leave a pooled connection able to delete.
    PERFORM set_config('shapoclyack.audit_retention', 'on', true);
    DELETE FROM audit_events WHERE occurred_at < cutoff;
    GET DIAGNOSTICS removed = ROW_COUNT;
    PERFORM set_config('shapoclyack.audit_retention', 'off', true);
    RETURN removed;
END;
$$;
"""


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        # Naive UTC, like every other timestamp column in this schema: a
        # timestamptz filled with a naive UTC value is reinterpreted by the
        # session's TimeZone, which nothing in this repo pins.
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        # Nullable, and no foreign key: a platform-level act belongs to no
        # tenant, and deleting a tenant must not delete the record of what was
        # done in it.
        sa.Column("tenant_id", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False, server_default=""),
        sa.Column("actor_type", sa.String(), nullable=False, server_default="user"),
        sa.Column("action", sa.String(), nullable=False, server_default=""),
        sa.Column("resource_type", sa.String(), nullable=False, server_default=""),
        sa.Column("resource_id", sa.String(), nullable=False, server_default=""),
        # Redacted by api/services/audit.py before they get here. NULL where the
        # action has no such side: a creation has no "before".
        sa.Column("before", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("client_ip", sa.String(), nullable=False, server_default=""),
        sa.Column("user_agent", sa.String(), nullable=False, server_default=""),
        sa.Column("request_id", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_audit_events_tenant_time", "audit_events", ["tenant_id", "occurred_at"]
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index(
        "ix_audit_events_resource", "audit_events", ["resource_type", "resource_id"]
    )
    op.create_index("ix_audit_events_time", "audit_events", ["occurred_at"])

    op.execute(sa.text(_IMMUTABLE_FUNCTION))
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION audit_events_immutable()"
        )
    )
    op.execute(sa.text(_PRUNE_FUNCTION))
    # Retention is a privileged job, not something the API may do. PUBLIC keeps
    # EXECUTE on a new function otherwise, which would hand the escape hatch to
    # every role including the API's.
    op.execute(
        sa.text(
            "REVOKE ALL ON FUNCTION audit_events_prune(timestamp without time zone) "
            "FROM PUBLIC"
        )
    )


def downgrade() -> None:
    # Lossy, and unusually so: this drops an audit trail. Kept because a
    # migration without a downgrade cannot be tested by the round-trip in
    # tests/test_db_migrate.py, and because the release that fails to start is
    # the one an operator has to be able to back out of.
    op.execute(
        sa.text("DROP FUNCTION IF EXISTS audit_events_prune(timestamp without time zone)")
    )
    op.execute(sa.text("DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS audit_events_immutable()"))
    op.drop_index("ix_audit_events_time", table_name="audit_events")
    op.drop_index("ix_audit_events_resource", table_name="audit_events")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_tenant_time", table_name="audit_events")
    op.drop_table("audit_events")
