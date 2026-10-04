"""Run publications: which derived updates a publication has already fed

Revision ID: 0072_run_publication_projected
Revises: 0068_compliance_frameworks
Create Date: 2026-10-04

#454 feeds a published run to its derived state *before* the row is closed,
so a replica killed in between replays the feed. The vulnerability fold told a
replay apart by ``last_seen_run_id``, and that is the wrong key: a tenant picks
``run_id`` and reuses it across jobs (a nightly ``run_id="nightly"``), so the
next job's observations were swallowed as a replay — a closed finding that
came back stayed closed — while a replay that arrived after another run
counted again and wound the finding back to the older run. One column,
expand-only:

``projected``
    The steps of ``run_completion.POST_PUBLICATION`` this publication has
    already fed, as a JSON list (``["assets", "findings"]``). Written by each
    step in its own transaction under the row's lock
    (``publication_marks.first_pass``), so the mark and the update commit
    together. Lives and dies with the row: a closed row is deleted, and a
    closed row is never fed again.

Rolling deploy: an old replica neither reads nor writes it, and its inserts
get the server default. An old replica never replays a feed — it feeds after
closing the row — but a row a new replica fed and could not close, adopted by
an old one, is fed a second time without the mark: what every release before
this one did on every retry. No backfill: a pending row written before this
revision has not been fed, which is what ``[]`` says.

Rollback is a plain drop.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0072_run_publication_projected"
down_revision: Union[str, None] = "0068_compliance_frameworks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "run_publications",
        sa.Column("projected", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("run_publications", "projected")
