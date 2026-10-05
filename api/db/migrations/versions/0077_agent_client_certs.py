"""Sensor and endpoint-agent client certificates (#309)

Revision ID: 0077_agent_client_certs
Revises: 0072_run_publication_projected
Create Date: 2026-10-05

One new table, ``agent_client_certs``: the certificates a sensor or a Lariska
endpoint agent may authenticate with next to its bearer token, and their
revocations. Read on every agent request that presents a certificate (when
``OCTO_AGENT_MTLS_MODE`` is not ``off``), written when the API signs a CSR,
when an operator pins or revokes one, and the first time a cert-manager
certificate naming its sensor is seen.

Unique on ``(tenant_id, fingerprint_sha256)`` rather than on the fingerprint:
every lookup is in the token's tenant, so one tenant cannot pin or revoke a
certificate into another tenant's sensor's way (see the model).

Tenant RLS as 0067 and 0068 lay it down for a table added after them: the
permissive ``shapoclyack_unscoped`` for every role that is not the tenant role,
the restrictive ``shapoclyack_tenant_isolation`` for it, and its grants.

**Expand only.** Nothing existing changes meaning, and with the mode left at
``off`` — the default — nothing reads the table. A replica still on the
previous release neither reads nor writes it, and ignores the mode; during a
rolling deploy to ``required`` the old replicas therefore still accept a token
alone, so switch the mode only once the rollout is complete
(docs/operations.md § Sensor client certificates).

Rollback is a plain drop: it forgets every issued and revoked certificate, and
a revoked certificate becomes good again on the next upgrade only if a SPIFFE
URI binds it — revoke the provisioning key as well if that matters.

The revision number leaves room for the parallel branches of the same wave;
``down_revision`` is re-chained when they merge.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0077_agent_client_certs"
down_revision: Union[str, None] = "0072_run_publication_projected"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_client_certs",
        sa.Column("cert_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("fingerprint_sha256", sa.String(), nullable=False),
        sa.Column("serial_hex", sa.String(), nullable=False, server_default=""),
        sa.Column("subject", sa.String(), nullable=False, server_default=""),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("not_before", sa.DateTime(), nullable=True),
        sa.Column("not_after", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("revoked_reason", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("cert_id"),
        sa.UniqueConstraint(
            "tenant_id", "fingerprint_sha256", name="uq_agent_client_certs_tenant_fingerprint"
        ),
        sa.CheckConstraint(
            "source IN ('csr', 'pinned', 'observed', 'tombstone')",
            name="ck_agent_client_certs_source",
        ),
    )
    op.create_index(
        "ix_agent_client_certs_tenant_agent",
        "agent_client_certs",
        ["tenant_id", "agent_id"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("ALTER TABLE agent_client_certs ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            "CREATE POLICY shapoclyack_unscoped ON agent_client_certs "
            "AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
        ))
        op.execute(sa.text(
            "CREATE POLICY shapoclyack_tenant_isolation ON agent_client_certs "
            "AS RESTRICTIVE FOR ALL TO shapoclyack_tenant "
            "USING (tenant_id = shapoclyack_current_tenant()) "
            "WITH CHECK (tenant_id = shapoclyack_current_tenant())"
        ))
        op.execute(sa.text(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON agent_client_certs TO shapoclyack_tenant"
        ))


def downgrade() -> None:
    op.drop_index("ix_agent_client_certs_tenant_agent", table_name="agent_client_certs")
    op.drop_table("agent_client_certs")
