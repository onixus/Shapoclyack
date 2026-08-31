"""Software→CVE matches over the endpoint inventory (ROADMAP Track E, M1)

Revision ID: 0027_software_cve_matches
Revises: 0026_service_tokens
Create Date: 2026-08-30


``software_cve_matches`` is where the answer to "is this endpoint's installed
software affected by anything" is kept. It is a *derived* table: every row is
recomputed from the device's latest accepted inventory snapshot and the vendor
advisory dataset on disk, and a run replaces a device's rows wholesale. Nothing
is lost by dropping it — ``downgrade`` does exactly that — and nothing here is
authored by a person, so there is no data to preserve on the way down.

Two shapes of row share the table. A CVE match carries a ``cve_id`` and the
advisory that produced it. An ``unknown`` row carries the empty string and an
``unknown_reason``, because an endpoint whose distribution could not be
resolved must not read as clean, and one row per unassessable package would be
thousands of rows saying one thing. ``match_key`` — a sha256 over
``(cve_id, source_package, unknown_reason)`` — is what the uniqueness
constraint uses, since a constraint over the nullable ``unknown_reason`` would
not constrain the unknown rows at all.

The index is ``(tenant_id, device_id, cve_id)``: every read is tenant-scoped,
the endpoint panel asks for one device, and the cross-tenant list filters by
CVE.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0027_software_cve_matches"
down_revision: Union[str, None] = "0026_service_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "software_cve_matches",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("snapshot_id", sa.String(), nullable=True),
        sa.Column("match_key", sa.String(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("severity", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("source_package", sa.String(), nullable=False, server_default=""),
        sa.Column("installed_package", sa.String(), nullable=False, server_default=""),
        sa.Column("installed_version", sa.String(), nullable=True),
        sa.Column("fixed_version", sa.String(), nullable=True),
        sa.Column("advisory_id", sa.String(), nullable=True),
        sa.Column("advisory_url", sa.String(), nullable=True),
        sa.Column("provider", sa.String(), nullable=False, server_default=""),
        sa.Column("distro", sa.String(), nullable=True),
        sa.Column("distro_release", sa.String(), nullable=True),
        sa.Column("purl", sa.String(), nullable=True),
        sa.Column("cpe23", sa.String(), nullable=True),
        sa.Column("unknown_reason", sa.String(), nullable=True),
        sa.Column("feed_date", sa.String(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["device_id"], ["endpoint_devices.device_id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "device_id", "match_key", name="uq_software_cve_match_row"
        ),
    )
    op.create_index(
        "ix_software_cve_matches_tenant_id", "software_cve_matches", ["tenant_id"]
    )
    op.create_index(
        "ix_software_cve_matches_device_id", "software_cve_matches", ["device_id"]
    )
    op.create_index(
        "ix_software_cve_matches_tenant_device_cve",
        "software_cve_matches",
        ["tenant_id", "device_id", "cve_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_software_cve_matches_tenant_device_cve", table_name="software_cve_matches"
    )
    op.drop_index("ix_software_cve_matches_device_id", table_name="software_cve_matches")
    op.drop_index("ix_software_cve_matches_tenant_id", table_name="software_cve_matches")
    op.drop_table("software_cve_matches")
