"""Permit the bounded finding-analysis task alongside count summaries."""
from alembic import op

revision = "0099_operator_analysis_task"
down_revision = "0098_operator_evidence"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("operator_tasks") as batch:
        batch.drop_constraint("ck_operator_task_kind", type_="check")
        batch.create_check_constraint("ck_operator_task_kind", "kind IN ('summarize_run','analyze_run')")


def downgrade():
    # Existing analyze_run records must be archived/removed explicitly before
    # downgrading. Refuse incompatible history instead of silently erasing it.
    with op.batch_alter_table("operator_tasks") as batch:
        batch.drop_constraint("ck_operator_task_kind", type_="check")
        batch.create_check_constraint("ck_operator_task_kind", "kind = 'summarize_run'")
