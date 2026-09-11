"""Agent groups: which agents a tenant's job may be handed to (#361)

Revision ID: 0052_agent_groups
Revises: 0049_rbac_permissions
Create Date: 2026-09-11

An agent job was claimable by *any* agent of the tenant. A managed service
provider who runs one agent inside a customer's payment segment and another in
their office network had no way to say that the payment segment's scan must be
executed from the payment segment — the queue was flat, and whichever worker
polled first got the job. Two things follow from that and neither is
acceptable in an enterprise: a scan reached its targets from a network nobody
approved it to come from, and an agent sitting in a low-trust segment was
handed the targets of a high-trust one.

``agent_groups`` is the vocabulary. A group is a name inside one tenant
(``ops-eu``, ``pci-segment``), and three places refer to it *by that name*
rather than by ``group_id``:

* ``agents.agent_group`` — where an operator put this agent. Written only
  through the API by somebody holding ``agent.group.manage``; an agent cannot
  put itself into a group, because a self-declared label that widened what a
  worker may claim would be the hole this revision closes.
* ``jobs.agent_group`` — the group this job is addressed to. NULL is the
  pre-#361 meaning, "any agent of the tenant", which is what every existing
  row has and what every scan that names no group keeps.
* ``tenant_scan_scopes.agent_groups`` — on an *allow* entry, the groups
  entitled to scan what that entry approves. ``[]`` is "any", which is what
  every existing entry gets, so an installation that never writes a group
  behaves exactly as it did on 0049.

Names rather than foreign keys on purpose: the name is the vocabulary shared
by the scope document, the API and the console, and ``jobs.assigned_agent_id``
already carries an identifier without a constraint for the same reason. The
integrity a foreign key would give is enforced in
``api/services/agent_groups.py``, which refuses to delete a group that a live
job, an agent or a scope entry still names — the deletion is the only event
that could leave a dangling name, and a deleted group silently widening a
restricted scope entry back to "any agent" is precisely the wrong failure.

**Expand only.** Every added column is nullable or carries a server default,
the new table is empty, and a replica still running 0049 reads and writes jobs
and agents exactly as before — it simply ignores three columns. The permission
row below is additive too: ``agent.group.manage`` lands on ``admin`` and
``platform-admin``, and a role that does not hold it is unchanged.

The downgrade drops the groups and the assignments, which is the feature
rather than a cache of it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0052_agent_groups"
down_revision: Union[str, None] = "0049_rbac_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# A frozen copy of the entry added to api/core/permissions.py, for the same
# reason 0049 froze the rest of the catalogue: a migration that imports
# application code is a migration whose meaning changes after it has run.
_PERMISSION = ("agent.group.manage", "Manage the tenant's agent groups and their members")
_ROLES_WITH_PERMISSION = ("admin", "platform-admin")


def upgrade() -> None:
    op.create_table(
        "agent_groups",
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("group_id"),
        # The name is the identifier every other table refers to, so it has to
        # be unique inside the tenant or the reference would be ambiguous.
        sa.UniqueConstraint("tenant_id", "name", name="uq_agent_groups_tenant_name"),
    )
    op.create_index("ix_agent_groups_tenant_id", "agent_groups", ["tenant_id"], unique=False)

    op.add_column("agents", sa.Column("agent_group", sa.String(), nullable=True))
    op.create_index("ix_agents_group", "agents", ["tenant_id", "agent_group"], unique=False)

    op.add_column("jobs", sa.Column("agent_group", sa.String(), nullable=True))
    # The claim query's predicate gains the group, so it stays an index scan
    # over queued agent jobs instead of filtering the whole tenant's queue.
    op.create_index(
        "ix_jobs_claim_group",
        "jobs",
        ["execution", "status", "tenant_id", "agent_group", "queued_at"],
        unique=False,
    )

    op.add_column(
        "tenant_scan_scopes",
        sa.Column("agent_groups", sa.JSON(), nullable=False, server_default="[]"),
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
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": _PERMISSION[0]}
            for role_id in _ROLES_WITH_PERMISSION
        ],
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM role_permissions WHERE permission_key = :key").bindparams(
            key=_PERMISSION[0]
        )
    )
    op.execute(
        sa.text("DELETE FROM permissions WHERE permission_key = :key").bindparams(
            key=_PERMISSION[0]
        )
    )
    op.drop_column("tenant_scan_scopes", "agent_groups")
    op.drop_index("ix_jobs_claim_group", table_name="jobs")
    op.drop_column("jobs", "agent_group")
    op.drop_index("ix_agents_group", table_name="agents")
    op.drop_column("agents", "agent_group")
    op.drop_index("ix_agent_groups_tenant_id", table_name="agent_groups")
    op.drop_table("agent_groups")
