"""Tenant lifecycle: who suspended a tenant and why, and the deletion journal (#325)

Revision ID: 0066_tenant_lifecycle
Revises: 0065_tenant_retention_legal_hold
Create Date: 2026-09-24

``suspended`` has been a status every gate refuses since #318, and nothing but
a hand-written ``UPDATE`` could set it. Deleting a tenant had no path at all:
its rows, its run archives, its ClickHouse partitions and its JetStream subjects
outlived the customer by as long as nobody went looking. This revision adds what
the lifecycle needs to be recorded rather than remembered.

``tenants.status_reason`` / ``status_changed_at`` / ``status_changed_by``
    Why the tenant is in the state it is in, since when, and on whose word. The
    platform admin's page shows them; nothing else reads them. NULL on every
    existing row, which is an ``active`` tenant nobody has touched. ``status``
    itself gains two values in the application, ``pending_deletion`` (the grace
    period, with suspension's semantics) and ``deleting`` (the purge is
    running); no CHECK constraint, like the column never had one.

``tenants.closed_at``
    When the tenant last left ``active``; NULL while it is active. Moving
    between the closed states (suspended, pending deletion, deleting) keeps
    it. What it is for: an agent of a closed tenant is still told to stop the
    scan it is running, even with its key revoked — but only when the key was
    revoked *by* the closure (``revoked_at >= closed_at``), not one an operator
    had revoked before it (``api/services/agents.py``, ``check_credential``).
    Set to the upgrade's time on every tenant that is already closed, so a key
    revoked before this revision is never taken for one the closure revoked.

``tenant_deletions``
    The journal: one row per deletion *request*, whatever became of it. No
    foreign key to ``tenants`` — the row has to outlive the tenant, because a
    completed row is the tombstone that proves the deletion (``outcome``: what
    was removed from each store, counts only) and the list an operator re-applies
    after restoring a backup taken before it (``docs/tenant-lifecycle.md``). A
    partial unique index allows one *open* deletion per tenant; cancelled and
    completed rows are history and may repeat.

``tenant_deletion_steps``
    One row per store the purge walks (``api/services/tenant_purge``), each with
    its own state, attempts, last error and counts, so a purge that failed on
    ClickHouse says so and resumes at ClickHouse. CASCADE on the journal row.

One permission is seeded with the catalogue rows 0049 introduced:
``platform.tenant.lifecycle`` (platform-admin only) — suspend, resume, and
request, cancel, approve and retry a deletion.

**Rolling deploy.** Expand-only. A replica still on 0065 refuses every
non-``active`` tenant at every gate, so a tenant this release suspends or marks
for deletion stays refused there too — but that replica's ``TenantInfo`` knows
only ``active`` and ``suspended``, so its ``GET /api/tenants`` answers a platform
admin 500 while a tenant is ``pending_deletion`` or ``deleting``. Finish the
rollout before requesting a deletion. The old replica also does not re-read the
tenant's status on an agent's JWT; suspension revokes the tenant's provisioning
keys by default, which that replica does check.

**Downgrade** drops the journal, the four columns and the permission rows, and
turns ``pending_deletion`` into ``suspended`` — a status 0065 can serialise,
and one every gate still refuses. It refuses to run while a purge is under way
or stopped by a legal hold (a deletion ``purging`` or ``blocked``): its tenant is
``deleting`` with part of its data gone, and as ``suspended`` on 0065 a resume
would put it back into service half-empty. Let the purge finish (lift the hold
and retry it, if that is what stopped it) and downgrade then. The journal —
the tombstones included — is gone with the table, so export
``GET /api/tenants/deletions`` first if you need the list.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0066_tenant_lifecycle"
down_revision: Union[str, None] = "0065_tenant_retention_legal_hold"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Frozen copies of the catalogue entry, for the reason 0049 and 0053 give: a
# migration that imports application code changes meaning after it has run.
_PERMISSION = ("platform.tenant.lifecycle", "Suspend, resume and delete tenants")
_GRANTS = (("platform-admin", "platform.tenant.lifecycle"),)

# The states in which a deletion is still open. Frozen here like the permission;
# api/services/tenant_lifecycle.py:OPEN_STATES is the live list.
_OPEN_STATES = "state IN ('pending', 'purging', 'blocked')"


def upgrade() -> None:
    op.add_column("tenants", sa.Column("status_reason", sa.String(), nullable=True))
    op.add_column("tenants", sa.Column("status_changed_at", sa.DateTime(), nullable=True))
    op.add_column("tenants", sa.Column("status_changed_by", sa.String(), nullable=True))
    op.add_column("tenants", sa.Column("closed_at", sa.DateTime(), nullable=True))
    # Naive UTC like every timestamp column here, whatever the session's zone.
    op.execute(
        sa.text(
            "UPDATE tenants SET closed_at = timezone('utc', now()) WHERE status <> 'active'"
        )
    )

    op.create_table(
        "tenant_deletions",
        sa.Column("deletion_id", sa.String(), nullable=False),
        # Not a foreign key: see the module docstring.
        sa.Column("tenant_id", sa.String(), nullable=False),
        # pending | cancelled | purging | blocked | completed
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        # The end of the grace period: the purge cannot be approved before it.
        sa.Column("purge_after", sa.DateTime(), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("cancelled_by", sa.String(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        # The worker's claim: a replica holds the row while lease_until is in
        # the future, and renews it between batches.
        sa.Column("lease_owner", sa.String(), nullable=True),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        # The tombstone, written when the purge completes: counts per store.
        sa.Column("outcome", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("deletion_id"),
    )
    op.create_index("ix_tenant_deletions_tenant", "tenant_deletions", ["tenant_id"])
    op.create_index(
        "ix_tenant_deletions_due", "tenant_deletions", ["state", "next_attempt_at"]
    )
    # One open deletion per tenant: two would race each other's purge, and a
    # second request while the first is pending is a mistake to refuse, not to
    # queue.
    op.create_index(
        "uq_tenant_deletions_open",
        "tenant_deletions",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text(_OPEN_STATES),
        sqlite_where=sa.text(_OPEN_STATES),
    )

    op.create_table(
        "tenant_deletion_steps",
        sa.Column("deletion_id", sa.String(), nullable=False),
        sa.Column("step", sa.String(), nullable=False),
        # The order the purge walks them in.
        sa.Column("position", sa.Integer(), nullable=False),
        # pending | done | skipped | failed | waiting
        sa.Column("state", sa.String(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("counts", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["deletion_id"], ["tenant_deletions.deletion_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("deletion_id", "step"),
    )

    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
        ),
        [{"permission_key": _PERMISSION[0], "description": _PERMISSION[1]}],
    )
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("permission_key", sa.String()),
        ),
        [{"role_id": role_id, "tenant_id": "", "permission_key": key} for role_id, key in _GRANTS],
    )


def downgrade() -> None:
    half_purged = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT tenant_id, state FROM tenant_deletions "
                "WHERE state IN ('purging', 'blocked') ORDER BY tenant_id"
            )
        )
        .all()
    )
    if half_purged:
        listed = ", ".join(f"{tenant_id} ({state})" for tenant_id, state in half_purged)
        raise RuntimeError(
            f"refusing to downgrade 0066: tenants being purged: {listed}. As "
            "'suspended' on 0065 a resume would put a half-purged tenant back into "
            "service. Let each purge finish (lift a legal hold and retry a blocked "
            "one) and downgrade then."
        )
    op.execute(
        sa.text(
            "DELETE FROM role_permissions WHERE permission_key = 'platform.tenant.lifecycle'"
        )
    )
    op.execute(
        sa.text("DELETE FROM permissions WHERE permission_key = 'platform.tenant.lifecycle'")
    )
    # See the module docstring: 0065's TenantInfo cannot serialise these, and
    # every gate refuses ``suspended`` just the same.
    op.execute(
        sa.text(
            "UPDATE tenants SET status = 'suspended' "
            "WHERE status IN ('pending_deletion', 'deleting')"
        )
    )
    op.drop_table("tenant_deletion_steps")
    op.drop_index("uq_tenant_deletions_open", table_name="tenant_deletions")
    op.drop_index("ix_tenant_deletions_due", table_name="tenant_deletions")
    op.drop_index("ix_tenant_deletions_tenant", table_name="tenant_deletions")
    op.drop_table("tenant_deletions")
    op.drop_column("tenants", "closed_at")
    op.drop_column("tenants", "status_changed_by")
    op.drop_column("tenants", "status_changed_at")
    op.drop_column("tenants", "status_reason")
