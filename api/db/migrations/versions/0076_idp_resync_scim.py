"""IdP-authoritative resync and SCIM 2.0 provisioning (#316)

Revision ID: 0076_idp_resync_scim
Revises: 0074_scan_queue_admission
Create Date: 2026-10-05

Before this, the identity provider decided a console account's role and tenant
once — at just-in-time provisioning — and never again: removing somebody from
a group at the IdP changed nothing here. What the resync and SCIM need from the
schema, and nothing else:

``user_tenants.source``
    ``local`` or ``idp``. The resync adds, changes and removes ``idp`` rows
    only, so turning ``OCTO_IDP_AUTHORITATIVE`` on cannot take away what an
    administrator granted by hand. **Every existing row is ``local``** —
    including the ones JIT provisioning wrote before this revision, because
    nothing recorded where they came from and guessing from ``created_by``
    would let the first resync after the upgrade remove grants somebody may
    have re-granted by hand since. The server default makes an old replica's
    insert ``local`` too, which is the direction a rolling deploy must fail in.
``users.disabled_source``
    NULL (a console administrator), ``idp`` (the resync found the account in
    no mapped group) or ``scim`` (the provisioning client set ``active:
    false``). The IdP re-enables only what it disabled. A replica still on the
    previous release does not clear it when an administrator toggles the
    account; the only consequence is that an account the IdP disabled, which
    an administrator then re-enabled and disabled again *on an old replica*,
    can be re-enabled by the IdP afterwards — a window that closes with the
    rollout.
``users.scim_external_id``
    The ``externalId`` a SCIM client sent for an account it created — the
    directory's key for the person, which carries the IdP subject. The first
    SSO login whose ``sub`` equals it links the account; a login's username
    claim never does (it can be an address nobody verified). Unique where set,
    so one subject never matches two accounts.
``scim_tokens``, ``scim_groups``, ``scim_group_members``
    The provisioning credential (its own type — see the model), and the
    groups a SCIM client pushes with their members. No ``tenant_id`` column on
    any of them, so none is a row-security table: SCIM is installation-wide
    and runs in the system scope, holding a token to its tenants in the
    service (``api/services/scim.py``).

Expand-only; the previous release reads and writes none of it. Rollback is a
plain drop, which forgets which memberships the IdP owns (they become local
again) and every SCIM token and group — re-issue and let the client push
again.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0076_idp_resync_scim"
down_revision: Union[str, None] = "0074_scan_queue_admission"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "user_tenants",
        sa.Column("source", sa.String(), nullable=False, server_default="local"),
    )
    op.create_check_constraint(
        "ck_user_tenants_source", "user_tenants", "source IN ('local', 'idp')"
    )
    op.add_column("users", sa.Column("disabled_source", sa.String(), nullable=True))
    op.create_check_constraint(
        "ck_users_disabled_source",
        "users",
        "disabled_source IS NULL OR disabled_source IN ('idp', 'scim')",
    )
    op.add_column("users", sa.Column("scim_external_id", sa.String(), nullable=True))
    op.create_index(
        "uq_users_scim_external_id",
        "users",
        ["scim_external_id"],
        unique=True,
        postgresql_where=sa.text("scim_external_id IS NOT NULL"),
    )

    op.create_table(
        "scim_tokens",
        sa.Column("token_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("token_prefix", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("tenant_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("all_tenants", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("grant_platform_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("token_id"),
        # The platform-admin grant is meaningless on a token held to some
        # tenants, and the service refuses it; the constraint keeps a
        # hand-written row from carrying it either.
        sa.CheckConstraint(
            "NOT grant_platform_admin OR all_tenants", name="ck_scim_tokens_admin_scope"
        ),
    )
    op.create_index("ix_scim_tokens_token_prefix", "scim_tokens", ["token_prefix"], unique=True)

    op.create_table(
        "scim_groups",
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("external_id", sa.String(), nullable=True),
        sa.Column("scim_token_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("group_id"),
        sa.UniqueConstraint("display_name", name="uq_scim_groups_display_name"),
    )
    op.create_table(
        "scim_group_members",
        sa.Column("group_id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["scim_groups.group_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["username"], ["users.username"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("group_id", "username"),
    )
    op.create_index("ix_scim_group_members_username", "scim_group_members", ["username"])


def downgrade() -> None:
    op.drop_index("ix_scim_group_members_username", table_name="scim_group_members")
    op.drop_table("scim_group_members")
    op.drop_table("scim_groups")
    op.drop_index("ix_scim_tokens_token_prefix", table_name="scim_tokens")
    op.drop_table("scim_tokens")
    op.drop_index("uq_users_scim_external_id", table_name="users")
    op.drop_column("users", "scim_external_id")
    op.drop_constraint("ck_users_disabled_source", "users", type_="check")
    op.drop_column("users", "disabled_source")
    op.drop_constraint("ck_user_tenants_source", "user_tenants", type_="check")
    op.drop_column("user_tenants", "source")
