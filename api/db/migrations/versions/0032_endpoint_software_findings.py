"""Endpoint software matches become tracked findings (ROADMAP Track E, M3)

Revision ID: 0032_endpoint_software_findings
Revises: 0031_tenant_promoted_domains
Create Date: 2026-09-08


``software_cve_matches`` (migration ``0027``) is keyed on ``device_id`` and is
replaced wholesale on every matcher run, so an authenticated finding had no
``finding_key``, no deadline, no owner, no ticket, no NIST risk and no line in
``vulnerability_events`` — and disappeared at the next run. This revision makes
``vulnerabilities`` able to hold the second kind of finding rather than adding
a second lifecycle beside the first.

``source`` says which observer produced the row: ``scan`` for everything the
network scanner registers, ``endpoint_software`` for a match folded in from the
endpoint inventory. The server default is ``scan`` and **nothing is
backfilled**: every row that exists at this revision came from a run, so the
default is already the right answer for all of them.

``device_id`` is ``SET NULL``, matching ``endpoint_devices.asset_id`` and for
the same reason: deleting a device must not delete the remediation history of
what was found on it. The finding stays attached to its asset, which is what
the SLA and the ownership were ever about.

``closure_reason`` gains ``patched`` — a software finding is closed when the
next accepted inventory snapshot no longer matches it, which is neither a
verification re-scan (``verified_remediated``) nor a person's assertion
(``manual``). The column carries no CHECK constraint (see ``0028``), so the
allowed set is enforced in ``api/services/vulnerabilities.py``'s
``CLOSURE_REASONS`` and there is no DDL for it here; it is named in this
docstring so the vocabulary change is visible in the migration history rather
than only in a diff.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0032_endpoint_software_findings"
down_revision: Union[str, None] = "0031_tenant_promoted_domains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "source", sa.String(length=32), nullable=False, server_default="scan"
        ),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("device_id", sa.String(length=64), nullable=True),
    )
    op.create_foreign_key(
        "fk_vulnerabilities_device",
        "vulnerabilities",
        "endpoint_devices",
        ["device_id"],
        ["device_id"],
        ondelete="SET NULL",
    )
    # The Vulnerability Center's source filter and the software worker's own
    # "what is still open on this device" read, which is a tenant-scoped scan
    # of one source in one lifecycle state.
    op.create_index(
        "ix_vulnerabilities_source",
        "vulnerabilities",
        ["tenant_id", "source", "state"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_source", table_name="vulnerabilities")
    op.drop_constraint("fk_vulnerabilities_device", "vulnerabilities", type_="foreignkey")
    op.drop_column("vulnerabilities", "device_id")
    op.drop_column("vulnerabilities", "source")
