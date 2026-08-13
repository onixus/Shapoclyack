"""Console users in Postgres, with a real FK from user_tenants (#156)

Revision ID: 0013_users
Revises: 0012_wordlists
Create Date: 2026-08-14

Before this, console accounts lived in the ``OCTO_API_USERS`` environment
variable: a password could not be rotated without a pod restart, nothing
recorded who changed an account, and disabling one user meant rewriting the
whole JSON. ``user_tenants`` (migration 0007) already referenced ``username``
as a plain string precisely because there was no table to point at.

Two things here are worth reading before running this:

**Orphan memberships.** ``user_tenants`` may hold rows whose username was
never in ``OCTO_API_USERS`` (a membership granted for a user later removed from
the env var). Adding the FK with those rows present fails, and deleting them
would silently revoke tenant access that an operator deliberately granted. So
every distinct username in ``user_tenants`` is backfilled as a **disabled**
account with an empty password hash: inert — an empty hash matches no password
— but visible in ``GET /api/users``, where an admin can enable it with a real
password or delete it. A disabled row is a decision waiting to be made; an
orphan FK is a migration that will not run.

**No accounts are seeded.** In particular the built-in ``admin``/``operator``/
``viewer`` demo users are *not* inserted. Their passwords are published in this
repository, so seeding them would re-open, through the table, exactly the hole
#155 closed at the environment level. The first real account comes from a
one-time import of ``OCTO_API_USERS`` at startup (api/services/users.py), and a
prod install with neither that variable nor any row refuses to start.

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013_users"
down_revision: Union[str, None] = "0012_wordlists"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("username", sa.String(), primary_key=True),
        sa.Column("password_hash", sa.String(), nullable=False, server_default=""),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(), nullable=True),
    )

    # Backfill disabled placeholders for existing memberships, so the FK below
    # can be added without either failing on orphans or deleting grants. The
    # empty password_hash is what makes them inert; bcrypt verification of ""
    # never succeeds, and the service refuses to authenticate an empty hash
    # outright rather than relying on that.
    op.execute(
        sa.text(
            """
            INSERT INTO users (
                username, password_hash, role,
                created_at, updated_at, disabled_at, created_by
            )
            SELECT DISTINCT
                ut.username, '', 'viewer',
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                'migration:0013_users'
            FROM user_tenants ut
            WHERE NOT EXISTS (
                SELECT 1 FROM users u WHERE u.username = ut.username
            )
            """
        )
    )

    # SQLite (the dev/test fallback URL) cannot ALTER a table to add a
    # constraint; batch_alter_table rebuilds the table there and emits a plain
    # ALTER on Postgres.
    with op.batch_alter_table("user_tenants") as batch:
        batch.create_foreign_key(
            "fk_user_tenants_username",
            "users",
            ["username"],
            ["username"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("user_tenants") as batch:
        batch.drop_constraint("fk_user_tenants_username", type_="foreignkey")
    op.drop_table("users")
