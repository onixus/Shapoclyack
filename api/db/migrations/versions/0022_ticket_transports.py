"""Ticket transports on the webhook queue (ROADMAP P2 / Phase 10.3)

Revision ID: 0022_ticket_transports
Revises: 0021_finding_cwe
Create Date: 2026-08-20

Jira / ServiceNow / DefectDojo ticket *creation* is a further transport
over the existing delivery queue, not a second queue. ``transport``
defaults to ``webhook`` so every current subscription keeps HMAC-POSTing.
``transport_config`` holds non-secret adapter knobs (project key, issue
type, table, DefectDojo test id). Credentials stay in ``secret`` /
``headers``, which are already write-only on read.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022_ticket_transports"
down_revision: Union[str, None] = "0021_finding_cwe"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "webhook_subscriptions",
        sa.Column("transport", sa.String(), nullable=False, server_default="webhook"),
    )
    op.add_column(
        "webhook_subscriptions",
        sa.Column("transport_config", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )


def downgrade() -> None:
    op.drop_column("webhook_subscriptions", "transport_config")
    op.drop_column("webhook_subscriptions", "transport")
