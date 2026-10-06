"""Which detectors observed a finding, for the verification closure (#451)

Revision ID: 0079_vuln_detectors
Revises: 0077_agent_client_certs
Create Date: 2026-10-06

A verification re-scan closed a finding as ``machine_verified`` whenever its
run did not report it, without asking whether the run could have: a nuclei
finding of medium severity was re-checked by ``intent=vuln``, which loads
critical and high templates only; a run whose nuclei binary was missing
succeeded all the same; an NSE finding was re-checked on the Pulse backend,
which runs no NSE. The closure now needs every detector of the finding to
have demonstrably looked again (``api/services/verification_coverage.py``),
and that needs to know which detectors there were. Expand-only:

``vulnerabilities.detectors``
    A JSON list, newest first and capped at 16: ``{detector, ref, host, port,
    last_run_id, last_seen_at}`` per detector that observed the finding --
    ``pulse`` / ``nuclei`` / ``nmap-nse``, the pulse origin, template id or NSE
    script, and the host as the scanner addressed it. Merged on every
    observation by ``register_findings_from_run``; ``script_id`` keeps meaning
    "the first observer's".

Backfill, scan findings only, from what ``script_id`` already says: a
``nuclei:<template>`` id is nuclei, ``pulse:<origin>`` is Pulse, any other
non-empty id is an NSE script (the only other writer of ``script_id``,
``scanner/pipeline/report.py``). ``host`` is NULL -- the observed spelling was
never stored -- so a backfilled detector is re-checked against the asset's
own addresses, the weaker rule docs/vulnerability-lifecycle.md describes. A row
with no ``script_id`` (a run imported or written by hand; every scanner stage
sets one) stays ``[]``, which the closure reads as "unknown" and holds to the
legacy rule: Pulse with CVE matching on the finding's port. Endpoint-software
and retro rows carry no scan detector and stay ``[]``; neither is verifiable
by a re-scan in the first place.

One ``UPDATE`` over the scan findings that have a ``script_id``: a row lock
per row it rewrites, no table lock, and the column add before it is
catalog-only (a constant default). Its duration is that of rewriting those
rows once -- not measured on a large installation; the ingest's writes to
the same rows wait behind it.

Rolling deploy: an old replica neither reads nor writes the column, and its
inserts get ``[]``. A finding an old replica observes keeps the detectors it
had; one it closes by verification is closed the old way, which is the defect
this revision exists to fix -- finish the rollout before verifying.

Rollback is a plain drop; the backfill is re-derivable from ``script_id``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0079_vuln_detectors"
down_revision: Union[str, None] = "0077_agent_client_certs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# A fixed statement: nothing in it is formatted from Python.
_BACKFILL = """
UPDATE vulnerabilities
SET detectors = json_build_array(
    json_build_object(
        'detector',
        CASE
            WHEN script_id LIKE 'nuclei:%' THEN 'nuclei'
            WHEN script_id LIKE 'pulse:%' THEN 'pulse'
            ELSE 'nmap-nse'
        END,
        'ref',
        CASE
            WHEN script_id LIKE 'nuclei:%' THEN substr(script_id, 8)
            WHEN script_id LIKE 'pulse:%' THEN substr(script_id, 7)
            ELSE script_id
        END,
        'host', NULL,
        'port', port,
        'last_run_id', last_seen_run_id,
        'last_seen_at', to_char(last_seen_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
    )
)
WHERE source = 'scan'
  AND script_id IS NOT NULL
  AND btrim(script_id) <> ''
"""


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("detectors", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    if op.get_bind().dialect.name != "postgresql":
        # The SQLite fallback gets its schema from the models and holds no
        # history worth deriving anything from.
        return
    op.execute(sa.text(_BACKFILL))


def downgrade() -> None:
    op.drop_column("vulnerabilities", "detectors")
