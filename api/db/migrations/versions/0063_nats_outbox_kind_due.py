"""Index due NATS outbox rows by kind for the reserved ingest claim window.

Revision ID: 0063_nats_outbox_kind_due
Revises: 0062_run_publication_lease
Create Date: 2026-09-23
"""

from alembic import op

revision = "0063_nats_outbox_kind_due"
down_revision = "0062_run_publication_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_nats_outbox_kind_due",
        "nats_outbox",
        ["status", "kind", "next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_nats_outbox_kind_due", table_name="nats_outbox")
