"""Token buckets for the general request rate limiter (#320).

Revision ID: 0069_rate_limit_buckets
Revises: 0068_compliance_frameworks
Create Date: 2026-10-04

One row per principal or tenant that made a request recently
(``api/services/rate_limit.py``). Expand only: a new table nothing existing
reads, so a replica still running the previous release during the rollout
simply does not limit, which is what it did before.

``UNLOGGED`` on Postgres. The rows are counters, rewritten on every
authenticated request; losing them in a crash hands every principal a full
bucket, which is the state an idle principal is in anyway, and in exchange the
hot write costs no WAL. A standby does not get the table either, and does not
need it — the API never writes to a standby.

No index on ``refilled_at``. Every charge rewrites that column, and an index
on it would make every one of those updates non-HOT — a new heap tuple and an
index entry per authenticated request. The prune that reads it runs every few
minutes over one row per active principal, and a sequential scan does.

No row security and no ``shapoclyack_tenant`` grant: there is no ``tenant_id``
column (``tenant_scope.tenant_tables`` keys on it), and the limiter reads the
rows from authentication, under ``tenant_scope.system``, before any request
has declared a tenant.
"""

from alembic import op
import sqlalchemy as sa

revision = "0069_rate_limit_buckets"
down_revision = "0068_compliance_frameworks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    prefixes = ["UNLOGGED"] if op.get_bind().dialect.name == "postgresql" else []
    op.create_table(
        "rate_limit_buckets",
        sa.Column("bucket_key", sa.String(), nullable=False),
        sa.Column("tokens", sa.Float(), nullable=False),
        # Epoch seconds from the database clock, so replicas with skewed
        # clocks still agree on how much time has passed.
        sa.Column("refilled_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("bucket_key"),
        prefixes=prefixes,
    )


def downgrade() -> None:
    op.drop_table("rate_limit_buckets")
