"""Append-only scan-fold risk receipts; no backfill or historical reevaluation (#453)."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0086_run_risk_assessments"
down_revision = "0085_drop_nmap_config_overrides"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("jobs", sa.Column("risk_assessment_contract", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("risk_assessment_execution_id", sa.String(), nullable=True))
    op.add_column("run_publications", sa.Column("risk_assessment_contract", sa.String(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "risk_assessment",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
    )
    op.create_table(
        "run_risk_assessments",
        sa.Column("assessment_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False
        ),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("execution_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=True),
        sa.Column("observation_digest", sa.String(), nullable=False),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
        sa.Column("publication_id", sa.String(), nullable=True),
        sa.Column(
            "scores",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "run_id",
            "execution_id",
            "observation_digest",
            name="uq_run_risk_assessment_observation",
        ),
    )
    op.create_index(
        "ix_run_risk_assessments_tenant_id", "run_risk_assessments", ["tenant_id"]
    )
    op.create_index(
        "ix_run_risk_assessment_lookup",
        "run_risk_assessments",
        ["tenant_id", "run_id", "execution_id", "observation_digest", "captured_at"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE run_risk_assessments ENABLE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY shapoclyack_unscoped ON run_risk_assessments AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
        )
        op.execute(
            "CREATE POLICY shapoclyack_tenant_isolation ON run_risk_assessments AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())"
        )
        # Tenant clients can append/read receipts or purge their tenant, never rewrite.
        op.execute(
            "GRANT SELECT, INSERT, DELETE ON run_risk_assessments TO shapoclyack_tenant"
        )
        op.execute("REVOKE UPDATE ON run_risk_assessments FROM shapoclyack_tenant")


def downgrade():
    op.drop_column("jobs", "risk_assessment_execution_id")
    op.drop_column("jobs", "risk_assessment_contract")
    op.drop_column("run_publications", "risk_assessment_contract")
    op.drop_table("run_risk_assessments")
    op.drop_column("vulnerabilities", "risk_assessment")
