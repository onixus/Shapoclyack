"""False-positive verdicts as an expiring attribute of a finding (Track E)

Revision ID: 0034_vuln_false_positive
Revises: 0033_software_match_queue_marker
Create Date: 2026-09-08

The verdict is six columns on ``vulnerabilities`` rather than a seventh state
or a table of its own. A state would need a rule for where a finding lands when
the suppression runs out — the rule risk acceptance deliberately avoided — and
a side table would have to be keyed on something that survives re-observation,
which is exactly what ``finding_key`` already is.

**Downgrade destroys data.** The verdict, who made it, when it expires and how
many times the finding was seen under it all live only in these columns; there
is nowhere else in the schema to reconstruct them from. Dropping them leaves
the affected rows ``CLOSED`` with ``closure_reason='false_positive'`` — a
string the code before this revision does not know — so a downgrade should
first rewrite those rows to ``'manual'``. Recorded in the table in
docs/operations.md.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0034_vuln_false_positive"
down_revision: Union[str, None] = "0033_software_match_queue_marker"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("fp_reason", sa.String(length=2000), nullable=True))
    op.add_column("vulnerabilities", sa.Column("fp_marked_by", sa.String(length=320), nullable=True))
    # Naive UTC, like every other lifecycle column on this table
    # (`0015_vuln_lifecycle`) and like `api/services/vulnerabilities.py::_now`,
    # which writes them. A `timestamptz` here would be filled with a naive UTC
    # value that Postgres reinterprets by the session's TimeZone, so on any
    # installation not running UTC this column would drift against
    # `first_seen_at` beside it — and adoption's "median hours to a verdict",
    # which subtracts one from the other, would go negative on a fast verdict.
    op.add_column("vulnerabilities", sa.Column("fp_marked_at", sa.DateTime(), nullable=True))
    # Why the finding is not real: the run it was judged on, the port, an
    # excerpt of the output. A verdict nobody can re-check is an assertion.
    op.add_column(
        "vulnerabilities",
        sa.Column("fp_evidence", sa.JSON(), nullable=False, server_default="{}"),
    )
    # Mandatory when the verdict is set, for the same reason `exception_until`
    # is: an indefinite suppression is a decision nobody revisits. Nullable in
    # the schema because every pre-existing row has no verdict at all.
    op.add_column("vulnerabilities", sa.Column("fp_suppress_until", sa.DateTime(), nullable=True))
    op.add_column(
        "vulnerabilities",
        sa.Column("fp_observations", sa.Integer(), nullable=False, server_default="0"),
    )
    # "How much of what we closed was noise" — one tenant's closures by reason,
    # over a window.
    op.create_index(
        "ix_vulnerabilities_fp",
        "vulnerabilities",
        ["tenant_id", "closure_reason", "closed_at"],
    )
    # Adoption's window over closures, which until now was a full scan of the
    # tenant's findings.
    op.create_index(
        "ix_vulnerabilities_closed",
        "vulnerabilities",
        ["tenant_id", "state", "closed_at"],
    )


def downgrade() -> None:
    # Leave no closure_reason the older code cannot read. This is lossy on
    # purpose and is the destructive half of the revision.
    op.execute(
        "UPDATE vulnerabilities SET closure_reason = 'manual' "
        "WHERE closure_reason = 'false_positive'"
    )
    op.drop_index("ix_vulnerabilities_closed", table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_fp", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "fp_observations")
    op.drop_column("vulnerabilities", "fp_suppress_until")
    op.drop_column("vulnerabilities", "fp_evidence")
    op.drop_column("vulnerabilities", "fp_marked_at")
    op.drop_column("vulnerabilities", "fp_marked_by")
    op.drop_column("vulnerabilities", "fp_reason")
