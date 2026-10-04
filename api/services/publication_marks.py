"""Which derived updates a publication has already fed (#454).

A published run is fed to its derived state *before* its ``run_publications``
row is closed (``run_publisher._project``), so a replica killed in between —
or two attempts on one row whose lease lapsed — feeds it again. The asset
upsert and the vulnerability fold are not naturally idempotent against that:
an observation counted twice, an older run's assessment written over a newer
one's, a decommissioned asset revived by a run it had already been retired
after.

"Has this been fed already" cannot be asked of the run: ``run_id`` is chosen
by the tenant (``POST /api/scans``) and a nightly integration reuses it, so a
second job under the same id is a new observation, not a replay. It is asked
of the publication instead — one accepted outcome of one job — and answered
in the step's own transaction, under the row's lock, so the mark and the
update it stands for commit together or not at all.
"""

from __future__ import annotations

from api.db import models

#: The steps that mark. The rest converge on a second pass by themselves
#: (``run_completion.on_run_published``).
ASSETS = "assets"
FINDINGS = "findings"


def first_pass(session, publication_id: str | None, step: str) -> bool:
    """Whether this transaction feeds ``step`` from ``publication_id``.

    Takes the row's lock first, so a second attempt running the same step
    waits here for the first one's transaction and then reads its mark rather
    than both reading "not yet". Call it before the step reads anything it is
    going to write.

    ``None`` means the caller is not feeding a publication (a backfill, a
    test, a replica's direct call) and always passes. A row that is gone was
    closed out, and a row is closed only after it was fed — or discarded by an
    operator, who gave it up — so neither is fed again.
    """
    if publication_id is None:
        return True
    row = session.get(models.RunPublication, publication_id, with_for_update=True)
    if row is None:
        return False
    done = list(row.projected or [])
    if step in done:
        return False
    # A new list, not an append: the JSON column does not track in-place edits.
    row.projected = [*done, step]
    return True
