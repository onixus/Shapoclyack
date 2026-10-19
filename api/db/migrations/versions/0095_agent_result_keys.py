"""Pin each sensor's result-signing public key (#366).

Two nullable columns on ``agents``: the ed25519 public key (base64 of the raw
32 bytes) the sensor registered for signing its run archives, and when it was
pinned. The API verifies an upload's signature against this key.

**Expand only.** Nothing existing changes meaning: a sensor that never
registers a key keeps a NULL here and its uploads are accepted as unsigned
while ``OCTO_REQUIRE_SIGNED_RESULTS`` is off (the default). A replica still on
the previous release ignores the columns and the new form fields.

Rollback drops the columns and with them every pinned key; the next upgrade
pins whatever key each sensor registers first (trust on first use again).
"""
import sqlalchemy as sa
from alembic import op

revision = "0095_agent_result_keys"
down_revision = "0091_asset_connector_run_lease"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("agents", sa.Column("result_signing_key", sa.String(), nullable=True))
    op.add_column("agents", sa.Column("result_key_pinned_at", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("agents", "result_key_pinned_at")
    op.drop_column("agents", "result_signing_key")
