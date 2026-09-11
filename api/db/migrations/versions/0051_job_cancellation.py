"""Stopping a running scan: the cancellation clock and the right to use it (#360)

Revision ID: 0051_job_cancellation
Revises: 0049_rbac_permissions
Create Date: 2026-09-11

Cancelling used to be legal only from ``queued``, so the one thing an operator
could do about a scan that was hammering production was wait for the agent's
local ``--scan-timeout`` — two hours. The stop now travels to the agent on its
next heartbeat and the job waits in ``cancelling`` until the agent confirms.

Two additions, both expand-only:

``jobs.cancel_requested_at``
    When the stop was asked for. It is the deadline clock for the answer: an
    agent too old to understand the request keeps scanning and keeps
    heartbeating, so without a second timestamp there would be nothing to
    distinguish "stopping" from "stuck", and the job would sit in ``cancelling``
    for as long as the scan ran. Nullable with no backfill — a job nobody asked
    to stop has no such moment, and NULL is exactly that statement.

``scan.cancel``
    The named permission the endpoint is gated on (#318), seeded into the
    catalogue tables and granted to the roles that already ran scans:
    ``operator``, ``scan-operator``, ``admin`` and the platform admin. Nobody
    gains an authority they did not have — before this, cancelling a queued job
    was ``require_tenant(Role.operator)``, which is exactly the set below — and
    an installation that wants to hand "stop a scan" to somebody who is not an
    operator now has a grant to make.

Rolling deploy: a replica still running the old code never writes the column
and never reads it, and it resolves its own authority from
``api/core/permissions.py`` rather than from these tables, so the seeded rows
change nothing for it either.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0051_job_cancellation"
down_revision: Union[str, None] = "0049_rbac_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PERMISSION = "scan.cancel"
_DESCRIPTION = "Stop a queued or running scan"
#: Frozen, like 0049's seed: the roles that hold the new permission at the
#: moment this migration runs, not whatever the role table says later.
_ROLES = ("operator", "scan-operator", "admin", "platform-admin")


def upgrade() -> None:
    op.add_column("jobs", sa.Column("cancel_requested_at", sa.DateTime(), nullable=True))
    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
        ),
        [{"permission_key": _PERMISSION, "description": _DESCRIPTION}],
    )
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("permission_key", sa.String()),
        ),
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": _PERMISSION}
            for role_id in _ROLES
        ],
    )


def downgrade() -> None:
    # The grants go with the permission (``role_permissions`` cascades on the
    # catalogue row), and a job mid-cancellation loses only the clock — the
    # status column is a plain string, so the old code reads such a row as an
    # unknown status rather than failing on it.
    op.execute(
        sa.text("DELETE FROM role_permissions WHERE permission_key = :key").bindparams(
            key=_PERMISSION
        )
    )
    op.execute(
        sa.text("DELETE FROM permissions WHERE permission_key = :key").bindparams(
            key=_PERMISSION
        )
    )
    op.drop_column("jobs", "cancel_requested_at")
