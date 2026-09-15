"""Endpoint agents are a different kind, and can be managed remotely (#358)

Revision ID: 0057_endpoint_agent_management
Revises: 0056_agent_healthy_since
Create Date: 2026-09-15

Three things, all consequences of the same discovery: the Lariska endpoint
agent registers through ``POST /api/agent/register``, the scanning agents'
door, and the platform had no way to tell the two apart.

**``agents.agent_kind``.** An endpoint agent showed up in the scan fleet with
``is_outdated: true`` and an offer to upgrade it to the *API's* version
(0.44-0907 against its own 0.2.0), because the fleet view compares every row
against the scanner's version — the two are different programs with different
version lines. It was also a candidate for the ``agent_offline`` escalation,
which on a laptop that sleeps means a false alarm every night, while its real
liveness is already tracked as endpoint-device staleness. The column separates
them; existing rows are scanners, which is what they all are today.

**``endpoint_agent_releases``.** Remote upgrade needs the platform to hold the
binary an agent is told to move to, together with the digest it must check
before running it. The bytes live in the row rather than on a volume: the API
already cannot scale past one replica because artifacts sit on an RWO PVC
(#336), and adding a second such dependency to a path an *endpoint* polls
would make that worse. A release is identified by (version, platform), where
platform is the Rust target triple the agent reports, e.g.
``x86_64-pc-windows-msvc``.

**``endpoint_agent_policies``.** What an operator wants an agent to be doing:
collection intervals, log level, and the version it should be running. One row
per tenant (``agent_id IS NULL``) is the default, and a row naming an agent
overrides it. ``revision`` increments on every write and is what the agent
compares against what it already applied, so a heartbeat carries a decision
only when there is a new one to carry.

Nothing here is required for an agent to work: an installation that sets no
policy and uploads no release behaves exactly as before, and an agent that
never asks is never told.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0057_endpoint_agent_management"
down_revision: Union[str, None] = "0056_agent_healthy_since"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column(
            "agent_kind",
            sa.String(),
            nullable=False,
            server_default="scanner",
        ),
    )
    # Every row that exists predates endpoint agents having a kind of their
    # own, and every one of them is a scanner: the endpoint agent had no way
    # to say otherwise. The server_default carries that for rows a replica
    # still running 0056 inserts during a rolling deploy.
    op.execute("UPDATE agents SET agent_kind = 'scanner' WHERE agent_kind IS NULL")

    op.create_table(
        "endpoint_agent_releases",
        sa.Column("version", sa.String(), primary_key=True),
        sa.Column("platform", sa.String(), primary_key=True),
        sa.Column("sha256", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("notes", sa.String(), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("uploaded_by", sa.String(), nullable=True),
    )

    op.create_table(
        "endpoint_agent_policies",
        sa.Column("policy_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        # NULL is the tenant-wide default. A named agent overrides it.
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("settings", sa.JSON(), nullable=False),
        sa.Column("desired_version", sa.String(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=True),
    )
    # One default and one override per agent. A partial unique index rather
    # than a plain one: NULLs do not collide in a UNIQUE constraint, so
    # without the first index a tenant could accumulate any number of
    # "defaults" and which one won would be whichever the query happened to
    # order first.
    op.create_index(
        "uq_endpoint_agent_policy_default",
        "endpoint_agent_policies",
        ["tenant_id"],
        unique=True,
        postgresql_where=sa.text("agent_id IS NULL"),
    )
    op.create_index(
        "uq_endpoint_agent_policy_agent",
        "endpoint_agent_policies",
        ["tenant_id", "agent_id"],
        unique=True,
        postgresql_where=sa.text("agent_id IS NOT NULL"),
    )

    # The catalogue tables 0049 seeded are what the API publishes and what a
    # custom role inherits from; enforcement resolves built-in roles from
    # api/core/permissions.py instead. Both have to learn the new permission or
    # tests/test_api_rbac_permissions.py fails on the drift -- which is the
    # point of that test. Spelled out rather than imported, for the reason 0049
    # gives: a migration that imports application code is one whose meaning
    # changes after it has run.
    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
        ),
        [
            {
                "permission_key": "endpoint_agent.manage",
                "description": "Manage the tenant's endpoint agents and their builds",
            }
        ],
    )
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("permission_key", sa.String()),
        ),
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": "endpoint_agent.manage"}
            # The two roles api/core/permissions.py gives it to: the tenant's
            # own admin, and the platform admin, who holds every permission in
            # the catalogue by construction.
            for role_id in ("admin", "platform-admin")
        ],
    )


def downgrade() -> None:
    op.execute(
        "DELETE FROM role_permissions WHERE permission_key = 'endpoint_agent.manage'"
    )
    op.execute("DELETE FROM permissions WHERE permission_key = 'endpoint_agent.manage'")
    op.drop_index("uq_endpoint_agent_policy_agent", table_name="endpoint_agent_policies")
    op.drop_index("uq_endpoint_agent_policy_default", table_name="endpoint_agent_policies")
    op.drop_table("endpoint_agent_policies")
    op.drop_table("endpoint_agent_releases")
    op.drop_column("agents", "agent_kind")
