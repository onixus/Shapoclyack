"""Single-use SAML request state shared by API replicas (#317)."""

import sqlalchemy as sa
from alembic import op

revision = "0105_saml_pending_requests"
down_revision = "0104_operator_campaigns_merge"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saml_pending_requests",
        sa.Column("request_id", sa.String(), nullable=False),
        sa.Column("relay_state_hash", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="login"),
        sa.Column("next_url", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("request_id"),
    )
    op.create_index(
        "ix_saml_pending_requests_relay_state_hash",
        "saml_pending_requests",
        ["relay_state_hash"],
        unique=True,
    )
    op.create_index(
        "ix_saml_pending_requests_expires_at",
        "saml_pending_requests",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("saml_pending_requests")
