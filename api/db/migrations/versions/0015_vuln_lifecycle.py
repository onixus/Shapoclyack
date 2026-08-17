"""Vulnerability lifecycle, ownership and SLA (#145, Track C)

Revision ID: 0015_vuln_lifecycle
Revises: 0014_auth_events
Create Date: 2026-08-17

Before this revision the platform had no vulnerability *entity*. Findings
existed per run in ``vulnerabilities.json`` (rewritten by the next scan) and in
ClickHouse's ``shapoclyack_vulnerabilities``, a ``ReplacingMergeTree`` whose
purpose is to keep only the latest observation. Neither can hold what a person
decided: an owner, a lifecycle state, a deadline — a merge would drop them.

So the three tables here are the operator-produced half, in Postgres alongside
assets and jobs:

``vulnerabilities``
    One row per finding per asset, identified by ``sha256(asset_id|cve or
    script_id|port)`` — the same triple the report pipeline de-duplicates on —
    unique within a tenant, so a later scan updates the row rather than
    inserting a second one.
``vulnerability_events``
    Every observation, transition, assignment and exception, written in the
    same transaction as the change. #145's acceptance criterion is that all
    transitions are auditable.
``sla_policies``
    ``(asset_criticality, severity) → remediation_days``, with
    ``asset_criticality = NULL`` as the tenant fallback. Empty is a valid state:
    the built-in defaults in ``api/services/vulnerabilities.py`` apply, so
    deadlines exist before anyone configures anything.

No backfill. Existing runs' findings enter the tracker the next time they are
observed, which is the only moment their asset correlation and their current
score are both known. A backfill from the last run on disk would date the SLA
clock from whenever that scan happened to run and would invent deadlines that
are already breached.

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015_vuln_lifecycle"
down_revision: Union[str, None] = "0014_auth_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sla_policies",
        sa.Column("policy_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("asset_criticality", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("remediation_days", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "tenant_id", "asset_criticality", "severity", name="uq_sla_policy_scope"
        ),
    )
    op.create_index("ix_sla_policies_tenant_id", "sla_policies", ["tenant_id"])

    op.create_table(
        "vulnerabilities",
        sa.Column("vuln_id", sa.String(), primary_key=True),
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
        sa.Column("finding_key", sa.String(), nullable=False),
        sa.Column("cve", sa.String(), nullable=True),
        sa.Column("script_id", sa.String(), nullable=True),
        sa.Column("port", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("risk_level", sa.String(), nullable=True),
        sa.Column("contextual_score", sa.Float(), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("state", sa.String(), nullable=False, server_default="OPEN"),
        sa.Column("state_changed_at", sa.DateTime(), nullable=False),
        sa.Column("state_changed_by", sa.String(), nullable=True),
        sa.Column("assignee", sa.String(), nullable=True),
        sa.Column("owner_team", sa.String(), nullable=True),
        sa.Column("due_at", sa.DateTime(), nullable=True),
        sa.Column("sla_days", sa.Integer(), nullable=True),
        sa.Column("sla_source", sa.String(), nullable=True),
        sa.Column("exception_until", sa.DateTime(), nullable=True),
        sa.Column("exception_reason", sa.String(), nullable=True),
        sa.Column("exception_by", sa.String(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("sla_started_at", sa.DateTime(), nullable=False),
        sa.Column("first_seen_run_id", sa.String(), nullable=True),
        sa.Column("last_seen_run_id", sa.String(), nullable=True),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("reopen_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("tenant_id", "finding_key", name="uq_vulnerability_finding"),
    )
    op.create_index("ix_vulnerabilities_tenant_id", "vulnerabilities", ["tenant_id"])
    op.create_index("ix_vulnerabilities_asset_id", "vulnerabilities", ["asset_id"])
    op.create_index(
        "ix_vulnerabilities_due", "vulnerabilities", ["tenant_id", "state", "due_at"]
    )
    op.create_index(
        "ix_vulnerabilities_risk",
        "vulnerabilities",
        ["tenant_id", "state", "contextual_score"],
    )
    op.create_index("ix_vulnerabilities_asset", "vulnerabilities", ["tenant_id", "asset_id"])
    op.create_index(
        "ix_vulnerabilities_assignee", "vulnerabilities", ["tenant_id", "assignee"]
    )

    op.create_table(
        "vulnerability_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "vuln_id",
            sa.String(),
            sa.ForeignKey("vulnerabilities.vuln_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("from_state", sa.String(), nullable=True),
        sa.Column("to_state", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("note", sa.String(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
    )
    op.create_index("ix_vulnerability_events_vuln_id", "vulnerability_events", ["vuln_id"])
    op.create_index("ix_vulnerability_events_tenant_id", "vulnerability_events", ["tenant_id"])
    op.create_index(
        "ix_vulnerability_events_vuln_time",
        "vulnerability_events",
        ["vuln_id", "occurred_at"],
    )
    op.create_index(
        "ix_vulnerability_events_tenant_time",
        "vulnerability_events",
        ["tenant_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerability_events_tenant_time", table_name="vulnerability_events")
    op.drop_index("ix_vulnerability_events_vuln_time", table_name="vulnerability_events")
    op.drop_index("ix_vulnerability_events_tenant_id", table_name="vulnerability_events")
    op.drop_index("ix_vulnerability_events_vuln_id", table_name="vulnerability_events")
    op.drop_table("vulnerability_events")
    op.drop_index("ix_vulnerabilities_assignee", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_asset", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_risk", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_due", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_asset_id", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_tenant_id", table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index("ix_sla_policies_tenant_id", table_name="sla_policies")
    op.drop_table("sla_policies")
