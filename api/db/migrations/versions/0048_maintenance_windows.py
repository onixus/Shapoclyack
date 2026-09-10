"""Maintenance windows, blackout calendars and the per-tenant change freeze (#352)

Revision ID: 0048_maintenance_windows
Revises: 0043_user_mfa
Create Date: 2026-09-10

The platform could say when a scan repeats and nothing at all about when it
must not happen. Every customer has periods during which their estate is not
to be touched — quarter close, a payment window, the night of a migration —
and until now honouring one meant somebody disabling the schedules by hand and
remembering to switch them back on. Both halves of that are people, and the
second half is the one that gets forgotten.

``maintenance_windows`` is the calendar. One row is one recurring period, with
an RFC 5545 ``RRULE`` (the supported subset lives in
``api/services/maintenance.py``), a wall-clock ``dtstart_local`` and the IANA
``timezone`` it is read in — the *tenant's* zone, so "Saturdays at 22:00" is
22:00 for the customer across a DST change rather than drifting with the
server. ``kind`` is the polarity: ``blackout`` forbids scanning while the
window is open, ``allowed`` permits it only then.

The four ``tenants`` columns are the change freeze: a switch the customer
flips when nothing may touch their estate for a while that has no end date
yet. Deliberately not ``status``: a frozen tenant is fully operational, it has
simply stopped consenting to scans, and deactivating the tenant to stop a scan
would take the customer's own data away from them.

**Expand only.** The table is new and empty, and every added column is
nullable or carries a server default — ``change_freeze`` defaults to false, so
the DDL backfills every existing tenant into "not frozen" and a replica still
running the old code inserts tenants exactly as before. An installation that
never writes a window behaves identically to one on 0043: admission with no
windows and no freeze admits everything, which is the state that preceded this
revision.

There is no contract phase. The downgrade drops the calendar and the freeze
flags, which loses the windows an operator wrote — they are the feature, not a
cache of something else.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0048_maintenance_windows"
down_revision: Union[str, None] = "0047_notification_channels"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "maintenance_windows",
        sa.Column("window_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="blackout"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("timezone", sa.String(), nullable=False, server_default="UTC"),
        sa.Column("rrule", sa.String(), nullable=False),
        # Naive: wall clock in ``timezone``, not UTC. A timestamptz here would
        # be reinterpreted by the session's TimeZone (which nothing in this
        # repo pins) and would in any case answer the wrong question — the
        # window is "22:00 where the customer is", and what that is in UTC
        # depends on the date.
        sa.Column("dtstart_local", sa.DateTime(), nullable=False),
        sa.Column("duration_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("scope_kind", sa.String(), nullable=False, server_default="tenant"),
        sa.Column("asset_group", sa.String(), nullable=True),
        sa.Column("scope_targets", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("window_id"),
    )
    op.create_index(
        "ix_maintenance_windows_tenant_id", "maintenance_windows", ["tenant_id"], unique=False
    )
    op.create_index(
        "ix_maintenance_windows_tenant_enabled",
        "maintenance_windows",
        ["tenant_id", "enabled"],
        unique=False,
    )

    op.add_column(
        "tenants",
        sa.Column("change_freeze", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("tenants", sa.Column("change_freeze_note", sa.String(), nullable=True))
    op.add_column(
        "tenants", sa.Column("change_freeze_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("tenants", sa.Column("change_freeze_by", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "change_freeze_by")
    op.drop_column("tenants", "change_freeze_at")
    op.drop_column("tenants", "change_freeze_note")
    op.drop_column("tenants", "change_freeze")
    op.drop_index("ix_maintenance_windows_tenant_enabled", table_name="maintenance_windows")
    op.drop_index("ix_maintenance_windows_tenant_id", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
