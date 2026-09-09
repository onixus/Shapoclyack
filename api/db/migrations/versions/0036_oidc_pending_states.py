"""OIDC pending authorization requests, shared by every replica (#321)

Revision ID: 0036_oidc_pending_states
Revises: 0035_asset_scan_coverage
Create Date: 2026-09-09

The nonce and the PKCE verifier of an in-flight SSO login lived in a dict in
the API process. That made the flow correct only where one replica served both
the redirect and the callback — the documented workaround was session affinity
on ``/api/auth/oidc/*``, which a rollout defeats anyway. This is the same
record as a row, so the callback can land anywhere.

**No expand/contract phase and nothing to backfill.** The rows this replaces
never outlive ``OCTO_OIDC_STATE_TTL_SECONDS`` (10 minutes by default) and exist
only between one browser redirect and its callback. During a rolling deploy the
old and the new code disagree about where a pending login is kept, so a login
begun on one and finished on the other is refused — and a refused SSO login is
one the user retries. Copying anything forward would mean reading a dict out of
a process that is being replaced.

``state_hash`` is ``sha256`` of the state's ``jti``, not the ``jti``: with the
platform's JWT secret the ``jti`` is enough to mint a valid state, so storing
it plain would make a dump of this table a way to complete somebody else's
login.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0036_oidc_pending_states"
down_revision: Union[str, None] = "0035_asset_scan_coverage"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oidc_pending_states",
        # 64 hex characters of sha256. The primary key is what makes the flow
        # single-use: `DELETE … RETURNING` on it either returns the row or
        # returns nothing, so two replicas answering the same callback cannot
        # both go on to exchange the code.
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("code_verifier", sa.String(length=128), nullable=False),
        sa.Column("redirect_uri", sa.String(length=1024), nullable=False),
        sa.Column("next_url", sa.String(length=512), nullable=False, server_default=""),
        # Naive UTC, like every other timestamp column in this schema and like
        # `api/services/oidc.py::_now`, which writes them. A `timestamptz`
        # filled with a naive UTC value is reinterpreted by the session's
        # TimeZone, which nothing in this repo pins, so on an installation not
        # running UTC every pending login would be expired or immortal.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("state_hash"),
    )
    # The sweep's whole predicate: rows past their TTL. It is the only query
    # against this table that is not a primary-key lookup.
    op.create_index(
        "ix_oidc_pending_states_expires_at", "oidc_pending_states", ["expires_at"]
    )


def downgrade() -> None:
    # Lossy by design: the rows are pending logins, and a login whose record is
    # gone fails closed and is retried.
    op.drop_index("ix_oidc_pending_states_expires_at", table_name="oidc_pending_states")
    op.drop_table("oidc_pending_states")
