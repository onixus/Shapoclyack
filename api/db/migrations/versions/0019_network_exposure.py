"""Network exposure on tracked findings (#171)

Revision ID: 0019_network_exposure
Revises: 0018_vuln_exploit_signals
Create Date: 2026-08-19

#171 feeds *this host's* reachability into likelihood. CVSS ``AV:N`` is a
property of the vulnerability, not of the machine. These columns record
the resolved signal (``external`` / ``internal`` / ``unknown``) and its
source (``address-space``, ``operator-set``, ``finding``) from the latest
observation, the same way ``risk_level`` is copied.

A public IP is not written as ``external``. That would launder a routing
fact as a scan observation. RFC1918 is ``internal`` (``address-space``).
Operator ``exposure_level=internet`` is ``external`` (``operator-set``).
Everything else stays ``unknown``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019_network_exposure"
down_revision: Union[str, None] = "0018_vuln_exploit_signals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("network_exposure", sa.String(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("network_exposure_source", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("vulnerabilities", "network_exposure_source")
    op.drop_column("vulnerabilities", "network_exposure")
