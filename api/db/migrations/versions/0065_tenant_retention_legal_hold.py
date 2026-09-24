"""Per-tenant retention, legal hold, and erasable console accounts (#332)

Revision ID: 0065_tenant_retention_legal_hold
Revises: 0064_asset_services_retro_match
Create Date: 2026-09-24

Every reaper in the platform read one global window from ``Settings``: thirty
days of run artifacts, a year of audit trail, the same for every tenant on the
installation. A customer whose contract says "keep our reports for five years"
and one whose DPA says "no scan evidence past ninety days" could not both be
served, and nothing could stop a sweep from deleting a tenant's data while that
tenant was in litigation. This revision adds the three things that were missing.

``tenant_retention_policies``
    One row per tenant, one nullable column per retention category. NULL is
    "inherit the platform default", so a tenant with no row — every tenant on
    the day this ships — is swept exactly as before. The bounds a value must
    sit within are *not* stored here: they are platform configuration
    (``OCTO_RETENTION_BOUNDS``) compiled over defaults in
    ``api/services/retention_policy.py``, because a floor a tenant row could
    carry is a floor a tenant admin could edit. CASCADE on the tenant.

``tenant_legal_holds``
    One row per tenant on hold: why, who, when. While a row exists no reaper
    deletes that tenant's data. The foreign key is **RESTRICT**, not CASCADE,
    on purpose: a tenant on hold cannot be deleted by any code path, including
    one written later that forgets to ask (#325 builds tenant purge on top of
    this). Releasing a hold deletes the row; its history is the audit trail.

``users.erased_at``
    Set when an account is erased under a data-subject request. The row stays
    as a tombstone holding nothing but the username, which is what makes the
    username a *stable* pseudonym: ``audit_events`` is append-only (#329) and
    names actors by username, so a freed name reissued to somebody else would
    re-attribute a stranger's history to them.

``audit_events_prune``
    Replaced, keeping its signature. It still deletes rows older than the
    cutoff, but no longer rows of a tenant on legal hold or of a tenant with an
    audit window of its own — the second are pruned by the new
    ``audit_events_prune_tenant(tenant_id, cutoff)``, which deletes one
    tenant's rows and nothing while that tenant is on hold. The hold is thereby
    enforced by the database for the one table whose deletions already go
    through a privileged function: a retention job built from an older image,
    or one passing a wrong cutoff, still cannot delete a held tenant's trail.
    Both are SECURITY DEFINER with EXECUTE revoked from PUBLIC, like 0037's.

Three permissions are seeded with the catalogue rows 0049 introduced:
``tenant.retention.read`` (admin, auditor, platform-admin),
``tenant.retention.manage`` (admin, platform-admin) and
``platform.legal_hold.manage`` (platform-admin only).

**Rolling deploy.** Expand-only for the tables and the column: a replica still
running 0064 neither reads nor writes them, and keeps sweeping on the global
window — which for a tenant with a *longer* window of its own means the old
replica can still delete what the new one would keep, until the rollout ends.
The replaced ``audit_events_prune`` is the exception, and it errs the safe way:
an old retention job calling it after this revision keeps held and overridden
tenants' rows instead of deleting them.

**Downgrade** restores 0037's function body, drops the new function, the two
tables, the column and the permission rows. Lossy for the policies and holds
themselves (their history stays in ``audit_events``); an erased account's
tombstone survives as a disabled account with no password, which is still one
nobody can sign in to.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0065_tenant_retention_legal_hold"
down_revision: Union[str, None] = "0064_asset_services_retro_match"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Frozen copies of the catalogue entries, for the reason 0049 and 0053 give: a
# migration that imports application code changes meaning after it has run.
_PERMISSIONS = (
    ("tenant.retention.read", "Read the tenant's data retention policy and legal hold"),
    ("tenant.retention.manage", "Set the tenant's retention windows within the platform bounds"),
    ("platform.legal_hold.manage", "Place and release a legal hold on any tenant"),
)
_GRANTS = (
    ("admin", "tenant.retention.read"),
    ("auditor", "tenant.retention.read"),
    ("platform-admin", "tenant.retention.read"),
    ("admin", "tenant.retention.manage"),
    ("platform-admin", "tenant.retention.manage"),
    ("platform-admin", "platform.legal_hold.manage"),
)

# The retention categories, one column each. Frozen here for the same reason;
# api/services/retention_policy.py:CATEGORIES is the live list and a test
# asserts the two still agree.
_CATEGORY_COLUMNS = (
    "run_days",
    "screenshot_days",
    "report_days",
    "endpoint_snapshot_days",
    "endpoint_change_days",
    "risk_snapshot_days",
    "webhook_delivery_days",
    "workflow_marker_days",
    "audit_event_days",
)

# Written out rather than interpolated, like 0037: an f-string reaching
# sa.text() is the shape CI's semgrep gate refuses. The GUC and the owner check
# are 0037's; only the WHERE clause is new.
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
    PERFORM set_config('shapoclyack.audit_retention', 'on', true);
    -- The default pass (#332). A tenant on legal hold keeps everything; a
    -- tenant with an audit window of its own is pruned by
    -- audit_events_prune_tenant on that window instead of this one. Rows with
    -- no tenant (platform-level acts) and rows of tenants that no longer exist
    -- have neither, and age out here.
    DELETE FROM audit_events AS a
     WHERE a.occurred_at < cutoff
       AND NOT EXISTS (
           SELECT 1 FROM tenant_legal_holds AS h WHERE h.tenant_id = a.tenant_id
       )
       AND NOT EXISTS (
           SELECT 1 FROM tenant_retention_policies AS p
            WHERE p.tenant_id = a.tenant_id AND p.audit_event_days IS NOT NULL
       );
    GET DIAGNOSTICS removed = ROW_COUNT;
    PERFORM set_config('shapoclyack.audit_retention', 'off', true);
    RETURN removed;
END;
$$;
"""

_PRUNE_TENANT_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_events_prune_tenant(
    target_tenant text, cutoff timestamp without time zone
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    removed bigint;
BEGIN
    -- NULL would match nothing in the DELETE below and return 0, which reads
    -- as "nothing was due"; a caller that meant the platform rows has the
    -- default function for them.
    IF target_tenant IS NULL THEN
        RAISE EXCEPTION USING
            MESSAGE = 'audit_events_prune_tenant needs a tenant id (#332)',
            ERRCODE = 'null_value_not_allowed';
    END IF;
    -- Checked here and not only by the caller: the hold is the one thing this
    -- function must never be talked out of.
    IF EXISTS (SELECT 1 FROM tenant_legal_holds WHERE tenant_id = target_tenant) THEN
        RETURN 0;
    END IF;
    PERFORM set_config('shapoclyack.audit_retention', 'on', true);
    DELETE FROM audit_events WHERE tenant_id = target_tenant AND occurred_at < cutoff;
    GET DIAGNOSTICS removed = ROW_COUNT;
    PERFORM set_config('shapoclyack.audit_retention', 'off', true);
    RETURN removed;
END;
$$;
"""

# 0037's body, verbatim, for the downgrade.
_PRUNE_FUNCTION_0037 = """
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
        "tenant_retention_policies",
        sa.Column("tenant_id", sa.String(), nullable=False),
        # NULL = inherit the platform default. A value is days, within the
        # platform bounds the service enforces on write.
        *[sa.Column(name, sa.Integer(), nullable=True) for name in _CATEGORY_COLUMNS],
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_table(
        "tenant_legal_holds",
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("set_by", sa.String(), nullable=False),
        sa.Column("set_at", sa.DateTime(), nullable=False),
        # RESTRICT: see the module docstring. Deleting a held tenant fails in
        # the database, whatever the code that tried.
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.add_column("users", sa.Column("erased_at", sa.DateTime(), nullable=True))

    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
        ),
        [{"permission_key": key, "description": text} for key, text in _PERMISSIONS],
    )
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("permission_key", sa.String()),
        ),
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": key}
            for role_id, key in _GRANTS
        ],
    )

    op.execute(sa.text(_PRUNE_FUNCTION))
    op.execute(sa.text(_PRUNE_TENANT_FUNCTION))
    # As 0037 did for the first function: PUBLIC keeps EXECUTE on a new
    # function otherwise, which would hand the escape hatch to the API's role.
    op.execute(
        sa.text(
            "REVOKE ALL ON FUNCTION "
            "audit_events_prune_tenant(text, timestamp without time zone) FROM PUBLIC"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS "
            "audit_events_prune_tenant(text, timestamp without time zone)"
        )
    )
    # Before the tables it reads are dropped: a function body naming a missing
    # table is only an error when it runs, and the first run would be the
    # retention job's.
    op.execute(sa.text(_PRUNE_FUNCTION_0037))
    op.execute(
        sa.text(
            "DELETE FROM role_permissions WHERE permission_key IN "
            "('tenant.retention.read', 'tenant.retention.manage', "
            "'platform.legal_hold.manage')"
        )
    )
    op.execute(
        sa.text(
            "DELETE FROM permissions WHERE permission_key IN "
            "('tenant.retention.read', 'tenant.retention.manage', "
            "'platform.legal_hold.manage')"
        )
    )
    op.drop_column("users", "erased_at")
    op.drop_table("tenant_legal_holds")
    op.drop_table("tenant_retention_policies")
