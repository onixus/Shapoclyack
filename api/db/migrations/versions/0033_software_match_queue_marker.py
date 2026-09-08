"""Durable queue marker for the software→CVE matcher (ROADMAP Track E, M3)

Revision ID: 0033_software_match_queue_marker
Revises: 0032_endpoint_software_findings
Create Date: 2026-09-08


``0032`` shipped the software match worker with a queue that needed no column:
a device is due when its ``endpoint_devices.latest_snapshot_id`` differs from
the ``snapshot_id`` on its ``software_cve_matches`` rows. That is durable and
replica-independent, and it is wrong for the one case nobody pictured — a host
the matcher has nothing to say about. Every package matchable, no advisory
hits, no ``unknown`` placeholders: zero rows written, so the comparison finds
no snapshot and reports the device due again on the very next tick. Forever.
With ``LIMIT batch_size`` and no ``ORDER BY``, a few hundred such hosts are
enough to permanently starve the devices that actually changed.

``last_matched_snapshot_id`` is the marker the derived queue could not be:
"the fold ran over this snapshot", written whatever the fold concluded,
including "nothing to record" and "this device has no asset to hang findings
on". Backfilled from the device's own match rows so an installation upgrading
in place does not re-fold its whole estate on the first tick after deploy; a
device with no rows is left NULL, which is exactly "never matched" and is what
it should have been saying all along.

``match_failure_count`` and ``match_retry_after`` are the other half. The
worker folded a whole batch in one session and caught exceptions at tenant
level, so one device that raised failed its batch and was re-read at the head
of the same batch on the next tick — the tenant never progressed. The fold now
takes each device in a SAVEPOINT and a device that raises is held off with a
capped backoff instead of blocking the queue behind it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0033_software_match_queue_marker"
down_revision: Union[str, None] = "0032_endpoint_software_findings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "endpoint_devices",
        sa.Column("last_matched_snapshot_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "endpoint_devices",
        sa.Column(
            "match_failure_count", sa.Integer(), nullable=False, server_default="0"
        ),
    )
    op.add_column(
        "endpoint_devices",
        sa.Column("match_retry_after", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_endpoint_devices_match_queue",
        "endpoint_devices",
        ["tenant_id", "last_matched_snapshot_id"],
    )
    # Expand/contract's "fill it" step (docs/operations.md): the marker is read
    # by the worker from the moment this lands, and an empty column would mean
    # every device in the estate is due at once on the first tick after deploy.
    op.execute(
        """
        UPDATE endpoint_devices AS d
           SET last_matched_snapshot_id = m.snapshot_id
          FROM (
                SELECT DISTINCT ON (device_id) device_id, snapshot_id
                  FROM software_cve_matches
                 ORDER BY device_id, matched_at DESC
               ) AS m
         WHERE m.device_id = d.device_id
        """
    )


def downgrade() -> None:
    op.drop_index("ix_endpoint_devices_match_queue", table_name="endpoint_devices")
    op.drop_column("endpoint_devices", "match_retry_after")
    op.drop_column("endpoint_devices", "match_failure_count")
    op.drop_column("endpoint_devices", "last_matched_snapshot_id")
