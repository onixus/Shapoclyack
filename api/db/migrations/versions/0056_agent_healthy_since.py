"""An agent's unbroken run of heartbeats, so "offline" can be closed (#349)

Revision ID: 0056_agent_healthy_since
Revises: 0053_tenant_scan_policy
Create Date: 2026-09-11

``agent_offline`` was claimed in ``workflow_event_markers`` under the agent's
``last_seen_at``. That reads as "announce one silence once", and it is —
provided the silence is total. An agent whose link degrades keeps beating and
keeps failing: with ``OCTO_AGENT_STALE_SECONDS=120`` and a 60s heartbeat, one
beat in two arrives, so every tick found a *different* ``last_seen_at`` that
was still past the cutoff, took a fresh marker and announced the same degraded
agent again. Ninety-six events a day for one agent, nineteen thousand for a
fleet of two hundred, and no way for the receiver to tell them apart.

The fix claims the *episode* rather than the timestamp: one marker per agent,
taken when it goes quiet and given back when it comes back. "Comes back" is
what this column is for. ``last_seen_at`` alone cannot say it — a flapping
agent's last beat is fresh half the time — so the row now also carries the
moment its current unbroken run of heartbeats began. Every write of
``last_seen_at`` keeps it, and only a gap longer than the stale window
restarts it (``api/services/agents.py``). An agent that is genuinely back has
a run that keeps growing; one that blinks has a run no longer than its gap,
and the worker refuses to call that recovered.

**Expand only.** The column is nullable and backfilled from ``last_seen_at``,
which is the most this revision can honestly say about agents that were
already registered: nothing recorded when their current run started, and their
last beat is the only evidence there is. A replica still running 0053 writes
``last_seen_at`` without touching this column, which the worker reads as a run
starting at the last beat — conservative, since that postpones a recovery
rather than inventing one.

The revision also folds the markers themselves. Every ``agent_offline`` claim
standing under the old per-timestamp key becomes the one ``offline`` claim the
new code takes — the storm's debris (one row per tick per degraded agent)
collapses into one row per agent, and, more to the point, the first tick after
the upgrade finds the claim already taken. Without that fold it would take a
fresh one for every agent that was *already* quiet and announce the lot again:
``webhook_deliveries`` would de-duplicate it by ``event_id``, which does not
change, but the copy on the bus would not be — JetStream's content window is
minutes wide and these agents have been silent for hours.

The downgrade drops the column and leaves the folded markers, so an agent
announced offline before the downgrade is announced once more under the old,
per-timestamp key the next time the old code looks at it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0056_agent_healthy_since"
down_revision: Union[str, None] = "0053_tenant_scan_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("healthy_since", sa.DateTime(), nullable=True))
    op.execute("UPDATE agents SET healthy_since = last_seen_at WHERE healthy_since IS NULL")
    # One standing claim per agent, dated from the last time the agent was
    # announced: the worker releases a claim only for a run of heartbeats that
    # began *after* it was taken, so the newest of the old rows is the honest
    # date and the conservative one.
    op.execute(
        """
        INSERT INTO workflow_event_markers
            (marker_id, tenant_id, kind, subject_id, marker, created_at)
        SELECT
            'wem_' || substr(md5(random()::text || clock_timestamp()::text || subject_id), 1, 16),
            tenant_id,
            'agent_offline',
            subject_id,
            'offline',
            max(created_at)
        FROM workflow_event_markers
        WHERE kind = 'agent_offline' AND marker <> 'offline'
        GROUP BY tenant_id, subject_id
        ON CONFLICT ON CONSTRAINT uq_workflow_event_marker DO NOTHING
        """
    )
    op.execute(
        "DELETE FROM workflow_event_markers "
        "WHERE kind = 'agent_offline' AND marker <> 'offline'"
    )


def downgrade() -> None:
    op.drop_column("agents", "healthy_since")
