"""Service-token linked overlap rotation, source networks and expiry notices."""
import sqlalchemy as sa
from alembic import op

revision = "0089_service_token_rotation"
down_revision = "0088_actionable_non_cve"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("service_tokens", sa.Column("allowed_cidrs", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("service_tokens", sa.Column("rotated_from_id", sa.String(), nullable=True))
    op.add_column("service_tokens", sa.Column("rotation_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("service_tokens", sa.Column("expiry_notice_days", sa.Integer(), nullable=False, server_default="7"))


def downgrade():
    # Older code has no overlap/source-policy fields. Preserve the effective
    # deadline and refuse policy-bound secrets rather than broadening access.
    op.execute("UPDATE service_tokens SET expires_at = rotation_expires_at "
               "WHERE rotation_expires_at IS NOT NULL AND rotation_expires_at < expires_at")
    op.execute("UPDATE service_tokens SET revoked_at = CURRENT_TIMESTAMP "
               "WHERE revoked_at IS NULL AND json_array_length(allowed_cidrs) > 0")
    for name in ("expiry_notice_days", "rotation_expires_at", "rotated_from_id", "allowed_cidrs"):
        op.drop_column("service_tokens", name)
