"""Remediation campaigns over a snapshot of tracked findings (#579).

Additive only (expand): three new tenant tables and nothing read or written by
existing code paths. ``vulnerabilities`` is not touched — a campaign never
owns a finding's lifecycle, owner, SLA or exception.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0101_remediation_campaigns"
down_revision = "0100_asset_groups"
branch_labels = None
depends_on = None

_TABLES = (
    "remediation_campaigns",
    "remediation_campaign_members",
    "remediation_campaign_events",
)
_SEQUENCED = ("remediation_campaign_members", "remediation_campaign_events")


def _json():
    return sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade():
    op.create_table(
        "remediation_campaigns",
        sa.Column("campaign_id", sa.String(), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("owner", sa.String(), nullable=True),
        sa.Column("due_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("status_changed_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("reopen_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("composition_hash", sa.String(), nullable=False, server_default=""),
        sa.Column("snapshot_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("selection", _json(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_remediation_campaigns_tenant_id", "remediation_campaigns", ["tenant_id"]
    )
    op.create_index(
        "ix_remediation_campaigns_status",
        "remediation_campaigns",
        ["tenant_id", "status", "due_at"],
    )
    op.create_table(
        "remediation_campaign_members",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column(
            "campaign_id",
            sa.String(),
            sa.ForeignKey("remediation_campaigns.campaign_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vuln_id",
            sa.String(),
            sa.ForeignKey("vulnerabilities.vuln_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(), nullable=False, server_default="included"),
        sa.Column("problem_key", sa.String(), nullable=False),
        sa.Column("reopen_baseline", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("snapshot", _json(), nullable=False),
        sa.Column("added_by", sa.String(), nullable=True),
        sa.Column("added_at", sa.DateTime(), nullable=False),
        sa.Column("add_reason", sa.String(), nullable=True),
        sa.Column("excluded_by", sa.String(), nullable=True),
        sa.Column("excluded_at", sa.DateTime(), nullable=True),
        sa.Column("exclude_reason", sa.String(), nullable=True),
        sa.Column("last_verify_at", sa.DateTime(), nullable=True),
        sa.Column("last_verify_outcome", sa.String(), nullable=True),
        sa.Column("last_verify_detail", sa.Text(), nullable=True),
        sa.UniqueConstraint("campaign_id", "vuln_id", name="uq_campaign_member"),
    )
    op.create_index(
        "ix_remediation_campaign_members_tenant_id",
        "remediation_campaign_members",
        ["tenant_id"],
    )
    op.create_index(
        "ix_remediation_campaign_members_campaign_id",
        "remediation_campaign_members",
        ["campaign_id"],
    )
    op.create_index(
        "ix_campaign_members_vuln", "remediation_campaign_members", ["tenant_id", "vuln_id"]
    )
    op.create_index(
        "ix_campaign_members_problem",
        "remediation_campaign_members",
        ["campaign_id", "problem_key"],
    )
    op.create_table(
        "remediation_campaign_events",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column(
            "campaign_id",
            sa.String(),
            sa.ForeignKey("remediation_campaigns.campaign_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("detail", _json(), nullable=False),
    )
    op.create_index(
        "ix_remediation_campaign_events_tenant_id",
        "remediation_campaign_events",
        ["tenant_id"],
    )
    op.create_index(
        "ix_remediation_campaign_events_campaign_id",
        "remediation_campaign_events",
        ["campaign_id"],
    )
    op.create_index(
        "ix_campaign_events_time",
        "remediation_campaign_events",
        ["campaign_id", "occurred_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        for name in _TABLES:
            op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
            op.execute(
                f"CREATE POLICY shapoclyack_unscoped ON {name} AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
            )
            op.execute(
                f"CREATE POLICY shapoclyack_tenant_isolation ON {name} AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())"
            )
            op.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO shapoclyack_tenant"
            )
            if name in _SEQUENCED:
                op.execute(
                    f"GRANT USAGE, SELECT ON SEQUENCE {name}_id_seq TO shapoclyack_tenant"
                )


def downgrade():
    for name in reversed(_TABLES):
        op.drop_table(name)
