"""Pinned tenant/source/model-keyed local CPU embedding indexes (#587)."""
from alembic import op
import sqlalchemy as sa

revision = "0102_operator_semantic"
down_revision = "0101_operator_actions"
branch_labels = None
depends_on = None


def upgrade():
    for table, columns, name in (
        ("operator_evidence_snapshots", ["tenant_id", "snapshot_id"], "uq_operator_evidence_snapshot_tenant"),
        ("operator_evidence_documents", ["tenant_id", "source_id"], "uq_operator_evidence_document_tenant"),
    ):
        with op.batch_alter_table(table) as batch:
            batch.create_unique_constraint(name, columns)
    op.create_table("operator_embedding_indexes",
        sa.Column("index_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_snapshot_id", sa.String(), nullable=True),
        sa.Column("inventory_snapshot_id", sa.String(), nullable=True),
        *[sa.Column(name, sa.String(), nullable=False) for name in (
            "scope_kind", "scope_id", "source_snapshot", "model_fingerprint", "model_revision", "model_sha256", "corpus_hash")],
        sa.Column("dimensions", sa.Integer(), nullable=False),
        sa.Column("document_count", sa.Integer(), nullable=False),
        sa.Column("indexed_at", sa.DateTime(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_snapshot_id"], ["operator_evidence_snapshots.tenant_id", "operator_evidence_snapshots.snapshot_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "inventory_snapshot_id"], ["endpoint_inventory_snapshots.tenant_id", "endpoint_inventory_snapshots.snapshot_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "index_id", name="uq_operator_embedding_index_tenant"),
        sa.UniqueConstraint("tenant_id", "scope_kind", "scope_id", "source_snapshot", "model_fingerprint", name="uq_operator_embedding_corpus"),
        sa.CheckConstraint("scope_kind IN ('run','device_remediation')", name="ck_operator_embedding_scope"),
        sa.CheckConstraint("(scope_kind = 'run' AND evidence_snapshot_id IS NOT NULL AND inventory_snapshot_id IS NULL) OR (scope_kind = 'device_remediation' AND evidence_snapshot_id IS NULL AND inventory_snapshot_id IS NOT NULL)", name="ck_operator_embedding_source"),
        sa.CheckConstraint("dimensions >= 1 AND dimensions <= 4096", name="ck_operator_embedding_dimensions"),
        sa.CheckConstraint("document_count >= 0 AND document_count <= 1001", name="ck_operator_embedding_document_count"))
    op.create_table("operator_evidence_embeddings",
        sa.Column("index_id", sa.String(), primary_key=True),
        sa.Column("source_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False),
        sa.Column("evidence_source_id", sa.String(), nullable=True),
        sa.Column("document_hash", sa.String(), nullable=False),
        sa.Column("text_hash", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("vector", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "index_id"], ["operator_embedding_indexes.tenant_id", "operator_embedding_indexes.index_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_source_id"], ["operator_evidence_documents.tenant_id", "operator_evidence_documents.source_id"], ondelete="CASCADE"))
    op.create_index("ix_operator_embedding_indexes_tenant_id", "operator_embedding_indexes", ["tenant_id"])
    op.create_index("ix_operator_embedding_scope", "operator_embedding_indexes", ["tenant_id", "scope_kind", "scope_id"])
    op.create_index("ix_operator_evidence_embedding_tenant", "operator_evidence_embeddings", ["tenant_id", "index_id"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE INDEX ix_operator_embedding_fulltext ON operator_evidence_embeddings USING gin (to_tsvector('simple'::regconfig, content))")
    for table in ("operator_embedding_indexes", "operator_evidence_embeddings"):
        if op.get_bind().dialect.name == "postgresql":
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"CREATE POLICY shapoclyack_unscoped ON {table} AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)")
            op.execute(f"CREATE POLICY shapoclyack_tenant_isolation ON {table} AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())")
            op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO shapoclyack_tenant")


def downgrade():
    op.drop_table("operator_evidence_embeddings")
    op.drop_table("operator_embedding_indexes")
    for table, name in (("operator_evidence_documents", "uq_operator_evidence_document_tenant"),
                        ("operator_evidence_snapshots", "uq_operator_evidence_snapshot_tenant")):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(name, type_="unique")
