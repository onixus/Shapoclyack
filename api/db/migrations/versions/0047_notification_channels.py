"""Per-tenant notification channels for finished runs (#351)

Revision ID: 0047_notification_channels
Revises: 0043_user_mfa
Create Date: 2026-09-10

Run alerts were installation-wide. ``OCTO_SLACK_WEBHOOK``, ``OCTO_TELEGRAM_*``
and ``OCTO_SMTP_TO`` were read by the scanner stage, and ``OCTO_DEFECTDOJO_*``
by the bulk export next to it, so on an MSSP installation every tenant's scan
announced itself in one Slack channel and every tenant's findings were imported
into one DefectDojo product. Nothing in the code knew which tenant a run
belonged to at that point, which is why no amount of care in the scanner could
have fixed it.

``notification_channels`` is the per-tenant destination table, shaped like
``webhook_subscriptions``: tenant-scoped with ``ON DELETE CASCADE``, a ``kind``
that selects the adapter, non-secret adapter knobs in a JSON column, and the
credential encrypted at rest under #310 with ``key_id`` mirroring which KEK
opens it. See the model docstring for which kind keeps its credential where —
for Slack, Teams and Mattermost the incoming-webhook URL *is* the credential
and lives in ``secret``.

**Additive only, and nothing is backfilled.** There is no installation-wide row
to migrate: the old configuration lived in environment variables, which this
migration cannot read and must not guess a tenant for. An upgraded installation
therefore sends nothing until an admin creates a channel — and the global
variables keep working, for a single-tenant installation that sets
``OCTO_SINGLE_TENANT_ALERTS=true``, which is the migration path documented in
docs/configuration.md § Notification channels.

The contract phase is that flag's eventual removal, not a column drop.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0047_notification_channels"
down_revision: Union[str, None] = "0043_user_mfa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("channel_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        # NOT NULL with a default: "this channel has no floor" and "this channel
        # wants everything" are the same thing said two ways, and a reader
        # should not have to defend against both.
        sa.Column("min_severity", sa.String(), nullable=False, server_default="high"),
        sa.Column("endpoint", sa.String(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("secret", sa.String(), nullable=True),
        sa.Column("key_id", sa.String(), nullable=True),
        # Naive, like every other timestamp column in this schema, and the
        # values written into it are UTC. Python-side they are *aware*
        # (``channels._now()`` is ``datetime.now(UTC)``), so a row read back
        # loses the tzinfo the row just written still carried;
        # ``channels._iso`` re-attaches UTC on the way out, which is why a
        # POST response and the following GET agree on the ``Z``. The same
        # mismatch is in ``webhooks.py`` — see its note at the ``created_at``
        # column — and this is the copy that is at least documented.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("last_send_at", sa.DateTime(), nullable=True),
        sa.Column("last_status", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_notification_channels_tenant_id", "notification_channels", ["tenant_id"]
    )
    # The fan-out's only query: this tenant's enabled channels, asked once per
    # finished run.
    op.create_index(
        "ix_notification_channels_tenant_enabled",
        "notification_channels",
        ["tenant_id", "enabled"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_channels_tenant_enabled", table_name="notification_channels")
    op.drop_index("ix_notification_channels_tenant_id", table_name="notification_channels")
    op.drop_table("notification_channels")
