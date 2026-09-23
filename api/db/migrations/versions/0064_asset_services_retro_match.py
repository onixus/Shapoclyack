"""Stored service fingerprints and retro CVE matching

Revision ID: 0064_asset_services_retro_match
Revises: 0063_nats_outbox_kind_due
Create Date: 2026-09-23

Retro matching (docs/retro-cve-matching.md) re-asks an updated NVD range
dataset about services a scan fingerprinted earlier, which needs the
fingerprints to outlive the run directory they came from. Expand-only:

``asset_services``
    One row per ``(tenant, asset, port, protocol)`` a scan found open, with the
    product/version/banner/CPE it disclosed. Filled by the post-run projection
    of every succeeded run and, once, by ``scripts/backfill-asset-services.py``
    from runs still on disk. ``matched_dataset_version`` is the retro worker's
    durable queue. CASCADE on both tenant and asset, like the findings.

``asset_os``
    The newest scan's OS guess per asset (nmap ``osmatch`` / Pulse
    ``os.json``). Read by the matcher for listeners whose own banner names no
    distribution. CASCADE on tenant and asset.

``retro_match_state``
    Per-tenant bookkeeping for ``GET /api/retro-match/status``: last sweep,
    dataset marker, totals. Not a queue.

``vulnerabilities.match_confidence`` / ``match_evidence`` / ``match_announced_at``
    Why a ``source = 'retro_match'`` finding exists, how sure it is, and when
    it was announced as a ``new_cve`` event (NULL = committed, not yet
    announced). NULL on every existing row, which is correct: no existing row
    came from a match. A partial index covers the announcer's read.

Rolling deploy: an old replica neither reads nor writes any of this. It keeps
projecting runs without recording fingerprints — those listeners are picked up
by the next scan or by re-running the backfill — and it never sees a
``retro_match`` finding as anything but a finding with an unfamiliar
``source``, which every read path already renders as text.

Follows ``0063_nats_outbox_kind_due`` (#438) only for ordering; nothing here
depends on it.

Rollback drops everything added; the fingerprints are re-derivable from any
run still on disk.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0064_asset_services_retro_match"
down_revision: Union[str, None] = "0063_nats_outbox_kind_due"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_services",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host", sa.String(), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(), nullable=False, server_default="tcp"),
        sa.Column("service", sa.String(), nullable=False, server_default=""),
        sa.Column("product", sa.String(), nullable=False, server_default=""),
        sa.Column("version", sa.String(), nullable=False, server_default=""),
        sa.Column("banner", sa.String(), nullable=False, server_default=""),
        sa.Column("cpe", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("source", sa.String(), nullable=False, server_default=""),
        # Naive UTC like every other timestamp in this schema.
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_run_id", sa.String(), nullable=True),
        sa.Column("fingerprint_changed_at", sa.DateTime(), nullable=False),
        sa.Column("matched_dataset_version", sa.String(), nullable=True),
        sa.Column("matched_at", sa.DateTime(), nullable=True),
        sa.Column("match_summary", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("match_failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("match_retry_after", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", "asset_id", "port", "protocol", name="uq_asset_service_listener"
        ),
    )
    op.create_index("ix_asset_services_tenant_id", "asset_services", ["tenant_id"])
    op.create_index("ix_asset_services_asset_id", "asset_services", ["asset_id"])
    op.create_index(
        "ix_asset_services_match_due",
        "asset_services",
        ["tenant_id", "matched_dataset_version"],
    )

    op.create_table(
        "asset_os",
        sa.Column(
            "asset_id",
            sa.String(),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("os_name", sa.String(), nullable=False, server_default=""),
        sa.Column("accuracy", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(), nullable=False, server_default=""),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_run_id", sa.String(), nullable=True),
    )
    op.create_index("ix_asset_os_tenant_id", "asset_os", ["tenant_id"])

    op.create_table(
        "retro_match_state",
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("dataset_version", sa.String(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_published", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_suppressed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_marker", sa.String(), nullable=True),
        sa.Column(
            "events_marker_individual", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("last_stats", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("refresh_requested_at", sa.DateTime(), nullable=True),
        sa.Column("refresh_requested_by", sa.String(), nullable=True),
    )

    op.add_column("vulnerabilities", sa.Column("match_confidence", sa.String(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("match_evidence", sa.JSON(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("match_announced_at", sa.DateTime(), nullable=True))
    # Partial: every existing row and every non-retro row stays out of it, so
    # the index costs nothing until retro findings exist, and the announcer's
    # "what is still unannounced" is a scan of exactly those.
    op.create_index(
        "ix_vulnerabilities_retro_unannounced",
        "vulnerabilities",
        ["tenant_id"],
        postgresql_where=sa.text("source = 'retro_match' AND match_announced_at IS NULL"),
        sqlite_where=sa.text("source = 'retro_match' AND match_announced_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_retro_unannounced", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "match_announced_at")
    op.drop_column("vulnerabilities", "match_evidence")
    op.drop_column("vulnerabilities", "match_confidence")
    op.drop_table("retro_match_state")
    op.drop_index("ix_asset_os_tenant_id", table_name="asset_os")
    op.drop_table("asset_os")
    op.drop_index("ix_asset_services_match_due", table_name="asset_services")
    op.drop_index("ix_asset_services_asset_id", table_name="asset_services")
    op.drop_index("ix_asset_services_tenant_id", table_name="asset_services")
    op.drop_table("asset_services")
