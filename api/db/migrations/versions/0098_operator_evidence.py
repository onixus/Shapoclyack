"""Tenant-owned bounded operator exact/fulltext evidence index (#587)."""
from alembic import op
import sqlalchemy as sa

revision = "0098_operator_evidence"
down_revision = "0097_operator_state"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("operator_evidence_snapshots",
        sa.Column("snapshot_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("publication_snapshot", sa.String(), nullable=False),
        sa.Column("summary_hash", sa.String(), nullable=False),
        sa.Column("findings_hash", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("indexed_at", sa.DateTime(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("tenant_id", "run_id", name="uq_operator_evidence_run"))
    op.create_table("operator_evidence_documents",
        sa.Column("source_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("snapshot_id", sa.String(), sa.ForeignKey("operator_evidence_snapshots.snapshot_id", ondelete="CASCADE"), nullable=False),
        *[sa.Column(name, sa.String(), nullable=False) for name in ("source_hash", "document_hash", "artifact", "cve", "package")],
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False))
    for table in ("operator_evidence_snapshots", "operator_evidence_documents"):
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
        if op.get_bind().dialect.name == "postgresql":
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY shapoclyack_unscoped ON {table} AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)")
            op.execute(f"CREATE POLICY shapoclyack_tenant_isolation ON {table} AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())")
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO shapoclyack_tenant")
    op.create_index("ix_operator_evidence_document_snapshot", "operator_evidence_documents", ["tenant_id", "snapshot_id"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE INDEX ix_operator_evidence_fulltext ON operator_evidence_documents USING gin (to_tsvector('simple'::regconfig, content))")


def downgrade():
    op.drop_table("operator_evidence_documents")
    op.drop_table("operator_evidence_snapshots")
