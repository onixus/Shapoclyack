"""Refresh tokens: a session family per sign-in, rotated on every refresh (#314)

Revision ID: 0060_refresh_tokens
Revises: 0059_nats_outbox
Create Date: 2026-09-23

A console access token used to live for ``OCTO_JWT_EXPIRE_MINUTES`` (8 hours)
with nothing behind it to renew it, so the choice was a long-lived bearer
token in local storage or a re-login every few minutes. Two tables change that
into a short access token plus a refresh token that the browser holds in an
httpOnly cookie and the server holds as a digest.

``session_families`` is one row per sign-in. It carries the absolute end of
the session, the last time it was refreshed (the idle timeout reads it), the
account generation it was opened at, and why it ended. ``refresh_tokens`` is
one row per refresh token ever issued to a family, kept after use: a token
presented a second time is the signal that somebody else holds a copy, and the
family is revoked as a whole.

**Expand only, nothing to contract.** Both tables are new and nothing reads
them before this change, so the old and the new code run against this schema
during a rollout: an old replica issues its 8-hour tokens without a ``sid`` and
never touches the tables, and the new decoder accepts a token with no ``sid``
exactly as it did before. Such a token simply cannot be refreshed, which is
the behaviour it was issued under.

Rollback is a plain drop. It ends every refresh-token session at once — the
cookie names a row that no longer exists — while the access tokens already
issued keep working until their own short ``exp``, after which the console
signs in again.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0060_refresh_tokens"
down_revision: Union[str, None] = "0059_nats_outbox"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "session_families",
        sa.Column("family_id", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        # Naive UTC, like revoked_tokens.expires_at and for the same reason: a
        # timestamptz filled with a naive UTC value is reinterpreted by the
        # session's TimeZone, which nothing in this repo pins.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=False),
        sa.Column("mfa_verified_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_reason", sa.String(length=32), nullable=True),
        sa.PrimaryKeyConstraint("family_id"),
        # CASCADE for the reason revoked_tokens has it: a deleted account's
        # sessions are already refused for the missing user row.
        sa.ForeignKeyConstraint(["username"], ["users.username"], ondelete="CASCADE"),
    )
    op.create_index("ix_session_families_username", "session_families", ["username"])
    # The sweep's whole predicate: families past their absolute end.
    op.create_index("ix_session_families_expires_at", "session_families", ["expires_at"])
    op.create_table(
        "refresh_tokens",
        # sha256 hex of the cookie value; the plaintext is never stored.
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("token_hash"),
        sa.ForeignKeyConstraint(
            ["family_id"], ["session_families.family_id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index("ix_session_families_expires_at", table_name="session_families")
    op.drop_index("ix_session_families_username", table_name="session_families")
    op.drop_table("session_families")
