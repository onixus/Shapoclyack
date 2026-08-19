"""Ticket link on a tracked finding (#138)

Revision ID: 0016_vuln_ticket_link
Revises: 0015_vuln_lifecycle
Create Date: 2026-08-19

#138's Kanban needs a place to *show* the ticket a finding is being worked in.
Creating that ticket in Jira/ServiceNow/SMAX/DefectDojo is a transport over
the 10.3 delivery queue and is not this revision — those adapters belong to
one queue, built once (ROADMAP P2). What this adds is the operator-set link
(system + key + url) so the board and the detail card can name the work item
without pretending the platform opened it.

Nullable throughout: a finding with no ticket is the common case, not an
error. Clearing the three columns is how a link is withdrawn.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016_vuln_ticket_link"
down_revision: Union[str, None] = "0015_vuln_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("ticket_system", sa.String(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("ticket_key", sa.String(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("ticket_url", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("vulnerabilities", "ticket_url")
    op.drop_column("vulnerabilities", "ticket_key")
    op.drop_column("vulnerabilities", "ticket_system")
