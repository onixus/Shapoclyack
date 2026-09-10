"""The inbound ticket-sync worker's cursor on a finding (#347)

Revision ID: 0045_vuln_ticket_sync_cursor
Revises: 0043_user_mfa
Create Date: 2026-09-10

"Two-way sync" was one button. ``POST /api/vulnerabilities/{id}/ticket/sync``
read one ticket when an operator clicked it, and nothing read a ticket
otherwise — so a fix an assignee marked Done in Jira stayed OPEN here until
somebody happened to open that finding's page.

The worker that closes that loop needs a durable answer to "which linked
ticket has waited longest", and it has to survive a restart and be the same
answer in every replica. ``ticket_synced_at`` is it: the cursor the worker
orders and filters by, written on every read *attempt* rather than every
success. Writing it only on success would put a ticket that answers 404 at the
head of every batch forever and starve every other finding behind it;
``ticket_sync_error`` carries which of the two the last attempt was, and is
what makes a broken link visible instead of merely quiet.

``ticket_remote_status`` is the third, and it is the one that keeps the poller
from arguing with people. It holds the tracker's own status string as of the
last read, and the worker applies a suggestion only when that string
*changes*. Without it, an operator reopening a finding whose Jira issue is
still ``Done`` — which happens whenever the project's workflow has no reopen
transition for us to drive — would have their decision undone on the next tick,
and on every tick after that.

**Expand only, and nothing is backfilled.** All three columns are nullable and
NULL means "never polled", which is the truth for every existing row. A replica
still running the old code keeps inserting and updating ``vulnerabilities``
exactly as before during a rollout, and the manual button behaves identically.

**The poller is on by default** (``OCTO_TICKET_SYNC_ENABLED``, like the webhook
and report dispatchers), so on the first tick after this upgrade every linked
ticket is due at once — a tenant with thousands of them will notice, and so
will their tracker. ``docs/operations.md`` § Inbound ticket sync says how to
pace or stop it. What a tracker can do to a finding does not change: a closure
from it is ``ticket_resolved`` and never ``machine_verified``, exactly as when
the button was the only caller.

The index is the worker's due read — one tenant's findings on one tracker,
oldest cursor first. Nothing else queries these columns, and a full scan of
the vulnerability table once per tick per tenant is exactly the shape of query
that stops being free on a large estate.

No contract phase to schedule: the columns are the feature.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0045_vuln_ticket_sync_cursor"
down_revision: Union[str, None] = "0044_idempotency_records"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Naive UTC, like every other timestamp column in this schema: a
    # timestamptz filled with a naive UTC value is reinterpreted by the
    # session's TimeZone, which nothing in this repo pins.
    op.add_column("vulnerabilities", sa.Column("ticket_synced_at", sa.DateTime(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("ticket_sync_error", sa.String(), nullable=True))
    op.add_column(
        "vulnerabilities", sa.Column("ticket_remote_status", sa.String(), nullable=True)
    )
    op.create_index(
        "ix_vulnerabilities_ticket_sync",
        "vulnerabilities",
        ["tenant_id", "ticket_system", "ticket_synced_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_ticket_sync", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "ticket_remote_status")
    op.drop_column("vulnerabilities", "ticket_sync_error")
    op.drop_column("vulnerabilities", "ticket_synced_at")
