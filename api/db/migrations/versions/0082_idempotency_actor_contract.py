"""Finish the caller-owned idempotency contract (#517).

Revision ID: 0082_idempotency_actor_contract
Revises: 0081_endpoint_release_variants

An idle installation may still hold pre-0055 rows: the TTL sweep runs only
on writes. Remove expired unowned rows, but refuse to discard a live retry
window or invent its owner. PostgreSQL's table lock keeps old writers out
between the check and NOT NULL. Releases 0.45/0.46 already supply actor.
"""

from datetime import UTC, datetime, timedelta
from importlib import import_module

import sqlalchemy as sa
from alembic import op

revision = "0082_idempotency_actor_contract"
down_revision = "0081_endpoint_release_variants"
branch_labels = None
depends_on = None

# Frozen migration policy, independent of future runtime settings.
_RETENTION_SECONDS = 24 * 3600


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("LOCK TABLE idempotency_records IN ACCESS EXCLUSIVE MODE"))
        now = bind.execute(
            sa.text("SELECT clock_timestamp() AT TIME ZONE 'UTC'")
        ).scalar_one()
    else:
        now = datetime.now(UTC).replace(tzinfo=None)
    cutoff = now - timedelta(seconds=_RETENTION_SECONDS)
    live = bind.execute(
        sa.text(
            "SELECT 1 FROM idempotency_records "
            "WHERE actor IS NULL AND created_at >= :cutoff LIMIT 1"
        ),
        {"cutoff": cutoff},
    ).first()
    if live:
        raise RuntimeError(
            "0082: unexpired idempotency records without actor remain; stop all "
            "pre-0055 writers, wait 24 hours after their last reservation, then "
            "retry the migration. Do not assign an owner or truncate live records."
        )
    bind.execute(
        sa.text(
            "DELETE FROM idempotency_records "
            "WHERE actor IS NULL AND created_at < :cutoff"
        ),
        {"cutoff": cutoff},
    )
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "DROP TRIGGER idempotency_records_cross_generation ON idempotency_records"
            )
        )
        op.execute(sa.text("DROP FUNCTION idempotency_cross_generation()"))
    op.drop_index(
        "uq_idempotency_legacy_tenant_endpoint_key", table_name="idempotency_records"
    )
    with op.batch_alter_table("idempotency_records") as batch:
        batch.alter_column("actor", existing_type=sa.String(), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("idempotency_records") as batch:
        batch.alter_column("actor", existing_type=sa.String(), nullable=True)
    op.create_index(
        "uq_idempotency_legacy_tenant_endpoint_key",
        "idempotency_records",
        ["tenant_id", "endpoint", "key"],
        unique=True,
        postgresql_where=sa.text("actor IS NULL"),
        sqlite_where=sa.text("actor IS NULL"),
    )
    if op.get_bind().dialect.name == "postgresql":
        # Restore the immutable expand migration's exact guard on rollback.
        expand = import_module("api.db.migrations.versions.0055_idempotency_actor")
        op.execute(sa.text(expand._CROSS_GENERATION_FUNCTION))  # noqa: SLF001
        op.execute(
            sa.text(
                "CREATE TRIGGER idempotency_records_cross_generation "
                "BEFORE INSERT ON idempotency_records "
                "FOR EACH ROW EXECUTE FUNCTION idempotency_cross_generation()"
            )
        )
