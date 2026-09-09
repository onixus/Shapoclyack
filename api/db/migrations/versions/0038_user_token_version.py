"""Session revocation: a token generation per account and a logout denylist (#314)

Revision ID: 0038_user_token_version
Revises: 0036_oidc_pending_states
Create Date: 2026-09-09

A console JWT used to be believed on its own for its whole eight-hour life: the
decoder read the role out of the claims and asked the database nothing, so
disabling, deleting or demoting an account changed nothing for the token
already in that person's browser. Two pieces of schema answer that.

``users.token_version`` is the generation an account's sessions belong to.
Every issued token carries the value it was minted at, and the decoder refuses
one that no longer matches, so bumping the column *is* "end every session of
this account". ``revoked_tokens`` is the narrow case: one ``jti`` refused
before its own ``exp``, which is what ``POST /api/auth/logout`` writes.

**Expand only, nothing to contract.** The column arrives with a server default
of 0, so the DDL backfills the existing rows itself and both the old and the
new code run against this schema during a rollout: the old decoder ignores the
column, and the new one reads a token minted without a ``ver`` claim as
version 0 -- exactly what every backfilled row holds. That is deliberate. An
upgrade that invalidated every live session would sign the whole console out
mid-rollout; an operator who wants precisely that runs
``POST /api/auth/sessions/revoke-all`` (or the per-user admin route) after it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0038_user_token_version"
down_revision: Union[str, None] = "0036_oidc_pending_states"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        # server_default rather than a follow-up UPDATE: the column is NOT NULL
        # from the first moment, so a replica still running the old code cannot
        # insert a user row without it.
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=False),
        # Naive UTC, like oidc_pending_states.expires_at and for the same
        # reason: a timestamptz filled with a naive UTC value is reinterpreted
        # by the session's TimeZone, which nothing in this repo pins.
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("jti"),
        sa.ForeignKeyConstraint(["username"], ["users.username"], ondelete="CASCADE"),
    )
    op.create_index("ix_revoked_tokens_username", "revoked_tokens", ["username"])
    # The sweep's whole predicate: rows whose token has since expired on its
    # own and no longer needs refusing.
    op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"])


def downgrade() -> None:
    # Lossy on purpose in both directions: dropping the column returns every
    # live token to being believed on its own, and the denylist rows describe
    # tokens the old decoder never consulted anything about.
    op.drop_index("ix_revoked_tokens_expires_at", table_name="revoked_tokens")
    op.drop_index("ix_revoked_tokens_username", table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
    op.drop_column("users", "token_version")
