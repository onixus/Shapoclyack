"""Tenant scan policy: how hard the platform may scan, decided centrally (#362)

Revision ID: 0053_tenant_scan_policy
Revises: 0052_agent_groups
Create Date: 2026-09-11

The API told a remote agent one thing about aggressiveness — ``--mode`` — and
everything the packets actually did was read from the ``scanner/config/
default.yaml`` sitting on the *agent's own host*: 2000 packets per second for
``safe`` discovery, and whatever the person who installed that agent had edited
it to. So the platform operator, who answers for the traffic, could not set the
pace; the customer's local admin could, by accident, and nobody could tell
afterwards which of the two had. The scanner also knew nothing about the
protocols that fall over when probed — modbus, DNP3, BACnet, S7 — so an
"internal" sweep of a plant network was one rate limit away from stopping a
production line.

``tenant_scan_policies`` is one row per tenant and the answer to both. It holds
the ceilings (discovery and port packets per second, host concurrency, per-host
pace), the ports that must never be touched, whether this tenant may run
anything but ``safe``, and a profile: ``standard`` or ``fragile``. The
``fragile`` profile is the OT/ICS one, and what it adds is not stored here — it
is compiled into ``api/services/scan_policy.py`` as a floor the stored row can
only make *stricter*, so an operator cannot raise their way out of it by
editing the row, and a scan request cannot by naming a mode or a port list.

**A tenant with no row behaves exactly as it did before this revision**: no
ceilings are pushed, the agent reads its local config, every mode is allowed.
That is every existing tenant, so the upgrade changes no behaviour until
somebody writes a policy. The table is new and empty, which makes this an
expand-only step: a replica still running 0052 does not read it.

The permission row is additive in the same way: ``scan_policy.manage`` lands on
``admin`` and ``platform-admin``, and a role that does not hold it is
unchanged. Reading a policy is gated on the existing ``scan_scope.read`` —
whoever may see what a tenant is allowed to scan may see how hard.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0053_tenant_scan_policy"
down_revision: Union[str, None] = "0052_agent_groups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# A frozen copy of the entry added to api/core/permissions.py, for the same
# reason 0049 froze the rest of the catalogue: a migration that imports
# application code is a migration whose meaning changes after it has run.
_PERMISSION = ("scan_policy.manage", "Set how hard this tenant may be scanned")
_ROLES_WITH_PERMISSION = ("admin", "platform-admin")


def upgrade() -> None:
    op.create_table(
        "tenant_scan_policies",
        # One row per tenant: a policy is the tenant's ceiling, not a list of
        # rules to be evaluated, so there is nothing to order or to intersect.
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("profile", sa.String(), nullable=False, server_default="standard"),
        sa.Column("safe_only", sa.Boolean(), nullable=False, server_default=sa.false()),
        # NULL is "no ceiling of its own" — the profile floor still applies.
        sa.Column("max_discover_rate", sa.Integer(), nullable=True),
        sa.Column("max_port_rate", sa.Integer(), nullable=True),
        sa.Column("max_host_concurrency", sa.Integer(), nullable=True),
        sa.Column("per_host_rate", sa.Integer(), nullable=True),
        sa.Column("avoid_ports", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id"),
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
    op.drop_table("tenant_scan_policies")
