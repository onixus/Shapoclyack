"""Cursor table for the audit → SIEM forwarder's database source (#328)

Revision ID: 0042_audit_forward_cursors
Revises: 0040_encrypted_secrets
Create Date: 2026-09-10

``api.services.audit_syslog_forwarder`` normally reads ``events.audit.>`` out of
JetStream, where its position is a durable consumer and no table is involved.
An installation with no ``OCTO_NATS_URL`` has no such stream, and it is exactly
the installation most likely to need the SIEM feed, so the forwarder also has a
``db`` source that walks ``audit_events`` by ascending id. This is where that
walk keeps its place.

**Additive only, and nothing to backfill.** A missing row means "start at 0",
which is what a first run should do — the forwarder inserts it on that run. No
expand/contract phase is needed because no existing reader or writer touches
this table: the code that uses it is new in the same change.

Deliberately outside the immutability regime migration 0037 put on
``audit_events``: this is bookkeeping *about* the trail, not part of it, and it
has to be updatable by an ordinary role every poll.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0042_audit_forward_cursors"
down_revision: Union[str, None] = "0040_encrypted_secrets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_forward_cursors",
        # The destination's name ("syslog"). One row per forwarder, so a second
        # destination added later gets its own place instead of fighting over
        # this one.
        sa.Column("forwarder", sa.String(length=64), nullable=False),
        # The id of the last audit_events row written to that destination's
        # socket. Half of the position — it breaks the tie between two rows
        # sharing an `occurred_at`; the column below leads the ordering. Its
        # default is what makes a fresh install start from the beginning of the
        # trail rather than from wherever the forwarder happened to be deployed.
        # Integer, not BigInteger: it holds an `audit_events.id`, and that
        # column is a SERIAL. A wider cursor than the thing it points into
        # would be a type the models and the schema disagree about for no gain.
        sa.Column("last_id", sa.Integer(), nullable=False, server_default="0"),
        # Naive UTC, like every other timestamp column in this schema. The
        # leading half of the position, and incidentally the answer to "how far
        # behind is the feed" without a join back to audit_events. NULL until
        # the forwarder has sent something, which reads as "before every row".
        sa.Column("last_occurred_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("forwarder"),
    )


def downgrade() -> None:
    # Lossy, and safely so: dropping the cursor makes the next `db`-mode run
    # start at the beginning of the trail. The SIEM sees duplicates, which the
    # CEF `cs6`/eventId extension exists to let it collapse — the opposite
    # failure, silently skipping rows, is the one worth avoiding.
    op.drop_table("audit_forward_cursors")
