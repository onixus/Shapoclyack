"""NATS outbox: publications the broker refused, kept until they are on the stream

Revision ID: 0059_nats_outbox
Revises: 0058_agent_results_ingest_bound
Create Date: 2026-09-21

One new table, additive, with no backfill and no contract phase — there is no
reader before it and the publications it would have wanted for the past were
never written down.

The table is what lets NATS leave ``health.BLOCKING_CHECKS`` (P2 of
``docs/architecture-review-2026-09-18.ru.md``). Before it, a broker outage with
readiness relaxed would have meant uploads answered 200 whose ingest message
went nowhere, with nothing to replay and nothing an operator could see;
``results_ingest.publish_raw_results`` already returned ``published=false`` and
its caller already ignored it. A row here is that refusal made durable, and the
reconciler in ``api/services/nats_outbox.py`` drains it when the broker is back.

Rolling upgrade is safe in both directions of the deploy: the migration runs
before any replica starts, and an old replica simply never reads or writes the
table. The readiness probe's ``ingest_backlog`` check is fail-soft
(``nats_outbox.is_backlogged``), so a replica that somehow meets a missing
table reports "not backlogged" rather than unreadying itself.

``(subject, msg_id)`` is unique because that is the key JetStream itself
dedupes on: two replicas recording the same refused message keep one row, and
republishing a message the broker actually accepted is dropped by the stream.

Rollback is a plain drop. An installation that downgrades past this loses the
rows that had not been republished yet — which is the state it was in before
the table existed — so drain the backlog (``status='pending'`` empty) before
downgrading rather than after.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0059_nats_outbox"
down_revision: Union[str, None] = "0058_agent_results_ingest_bound"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "nats_outbox",
        sa.Column("outbox_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("subject", sa.String(), nullable=False),
        sa.Column("msg_id", sa.String(), nullable=False),
        # The body as it was to be published, archive included: re-deriving it
        # later would mean re-tarring a run whose files may be gone by then.
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=True),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        # Naive UTC like every other timestamp in this schema: a timestamptz
        # filled with a naive UTC value is reinterpreted by the session's
        # TimeZone, which nothing in this repo pins.
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("outbox_id"),
        sa.UniqueConstraint("subject", "msg_id", name="uq_nats_outbox_message"),
    )
    op.create_index("ix_nats_outbox_tenant_id", "nats_outbox", ["tenant_id"])
    # The reconciler's predicate, running on every replica on a timer.
    op.create_index("ix_nats_outbox_due", "nats_outbox", ["status", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("ix_nats_outbox_due", table_name="nats_outbox")
    op.drop_index("ix_nats_outbox_tenant_id", table_name="nats_outbox")
    op.drop_table("nats_outbox")
