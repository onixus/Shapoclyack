"""Scan queue: job priority, per-tenant concurrency and queue-depth limits (#365)

Revision ID: 0074_scan_queue_admission
Revises: 0072_run_publication_projected
Create Date: 2026-10-05

Until this revision the queue was one FIFO per tenant with no ceiling: a
tenant could queue as many scans as it liked and have every one of them out
with a sensor at once, and an urgent re-scan waited behind the nightly sweep.
Expand-only:

``jobs.priority``
    Higher is handed out first; ties fall back to ``queued_at`` as before.
    ``NOT NULL DEFAULT 0``, so every row that exists when this runs — queued
    or not — reads 0, and a claim over a queue of zeroes orders exactly as the
    old ``ORDER BY queued_at, job_id`` did. An old replica's insert gets the
    default; an old replica's claim ignores the column, which during a rolling
    update means FIFO until it is replaced — never a lost or duplicated job.

``tenants.max_concurrent_scans`` / ``tenants.max_queued_scans``
    NULL is unlimited and is what every tenant gets: an upgrade that started
    holding back customers' scans because nobody had typed a number would be
    an outage. On the tenant row rather than in ``tenant_quotas``: a quota row
    that exists overrides the platform's billing defaults even in its NULL
    columns, so creating one to set a concurrency ceiling would silently
    exempt the tenant from its asset and scan quota.

``scan.priority.raise``
    Seeded into the catalogue and granted to the tenant ``admin`` and the
    platform admin, the roles :mod:`api.core.permissions` gives it to.
    Nobody loses anything: priority is new.

Chained onto 0072 on purpose — 0073 is in flight on another branch and this
revision is re-chained onto it when the two land.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0074_scan_queue_admission"
down_revision: Union[str, None] = "0072_run_publication_projected"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PERMISSION = "scan.priority.raise"
_DESCRIPTION = "Queue a scan ahead of the tenant's other scans"
#: Frozen, like 0049's seed: the roles that hold the permission when this
#: migration runs, not whatever the role table says later.
_ROLES = ("admin", "platform-admin")


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column("tenants", sa.Column("max_concurrent_scans", sa.Integer(), nullable=True))
    op.add_column("tenants", sa.Column("max_queued_scans", sa.Integer(), nullable=True))
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
    # Every grant of the key, tenant-defined roles included: a role naming a
    # permission the catalogue no longer has would fail its foreign key.
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
    op.drop_column("tenants", "max_queued_scans")
    op.drop_column("tenants", "max_concurrent_scans")
    op.drop_column("jobs", "priority")
