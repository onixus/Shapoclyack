"""Approved per-tenant scanning scope, and a subject column for its refusals (#226)

Revision ID: 0025_tenant_scan_scopes
Revises: 0024_agent_deployment_security
Create Date: 2026-08-26

``tenant_scan_scopes`` is the answer to "was this tenant allowed to scan that
network", which the platform could not give before: target validation checked
syntax only.

Two changes belong together here:

* the table itself, one row per allow/deny entry with its own approval
  provenance;
* ``auth_events.detail``, so a refusal can record *what* was refused. The
  access-decision journal already existed (#157) and had nowhere to put a
  subject other than a username and a client address.

**Grandfathering.** Enforcement is fail-closed — a tenant with no rows scans
nothing — so a straight upgrade would stop every existing installation's scans,
scheduled ones included, with no operator present. This revision therefore
inserts an explicit allow-all entry (``0.0.0.0/0``, ``::/0``, ``*``) for every
tenant that exists at upgrade time, stamped ``approved_by = 'migration-0025'``.
That preserves behaviour without inventing an implicit "no scope means
everything" rule in the code: the permission is a visible row an admin reads in
``GET /api/tenants/{id}/scan-scope`` and narrows, and "who allowed this" has an
honest answer ("nobody — the upgrade did"). Tenants created *after* this
revision get nothing and are fail-closed from their first day. See
docs/operations.md for the narrowing procedure.

The downgrade drops the table and the column; the grandfathered rows go with
it, which is the state that preceded the upgrade.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0025_tenant_scan_scopes"
down_revision: Union[str, None] = "0024_agent_deployment_security"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (kind, value) pairs of the grandfathered allow-all scope. Both IP families
# are listed because an allow entry is matched within one family only.
_GRANDFATHER_ENTRIES = (("cidr", "0.0.0.0/0"), ("cidr", "::/0"), ("domain", "*"))
_GRANDFATHER_APPROVER = "migration-0025"
_GRANDFATHER_NOTE = "grandfathered on upgrade to 0025 (#226) — narrow this"


def upgrade() -> None:
    op.create_table(
        "tenant_scan_scopes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("effect", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("approved_by", sa.String(), nullable=False, server_default=""),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "effect", "kind", "value", name="uq_tenant_scan_scopes_entry"
        ),
    )
    op.create_index(
        "ix_tenant_scan_scopes_tenant_id",
        "tenant_scan_scopes",
        ["tenant_id"],
        unique=False,
    )

    op.add_column("auth_events", sa.Column("detail", sa.Text(), nullable=True))

    scopes = sa.table(
        "tenant_scan_scopes",
        sa.column("tenant_id", sa.String),
        sa.column("effect", sa.String),
        sa.column("kind", sa.String),
        sa.column("value", sa.String),
        sa.column("note", sa.String),
        sa.column("approved_by", sa.String),
        sa.column("approved_at", sa.DateTime(timezone=True)),
    )
    bind = op.get_bind()
    tenant_ids = [row[0] for row in bind.execute(sa.text("SELECT tenant_id FROM tenants"))]
    if not tenant_ids:
        return
    approved_at = datetime.now(UTC)
    op.bulk_insert(
        scopes,
        [
            {
                "tenant_id": tenant_id,
                "effect": "allow",
                "kind": kind,
                "value": value,
                "note": _GRANDFATHER_NOTE,
                "approved_by": _GRANDFATHER_APPROVER,
                "approved_at": approved_at,
            }
            for tenant_id in tenant_ids
            for kind, value in _GRANDFATHER_ENTRIES
        ],
    )


def downgrade() -> None:
    op.drop_column("auth_events", "detail")
    op.drop_index("ix_tenant_scan_scopes_tenant_id", table_name="tenant_scan_scopes")
    op.drop_table("tenant_scan_scopes")
