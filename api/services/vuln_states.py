"""The vulnerability lifecycle, as data (#145, Track C).

The job lifecycle got this treatment in P1.3 (``api/services/job_states.py``)
for a reason that applies again here: a status that is "whatever the last
writer assigned" cannot be audited, and every route would re-invent its own
idea of what may follow what. The difference is *who* writes. A job's state is
written by the control plane; a vulnerability's state is written by people —
an operator acknowledging, a team planning a fix, someone verifying it — and by
one machine path, the scanner re-observing (or no longer observing) the finding.

The states are the ones #145 names::

    OPEN → ACKNOWLEDGED → PLANNED → FIXING → VERIFYING → CLOSED

That arrow chain is the happy path, not the transition table. Three kinds of
move are legal beyond it, and each is a real thing operators do:

**Skipping forward.** ``OPEN → FIXING`` (someone just fixes it), ``OPEN →
CLOSED`` (a false positive, or a finding on a host being decommissioned). A
lifecycle that forced a false positive through four ceremonial states would be
worked around by closing nothing at all, and an un-triaged backlog is exactly
what #145 exists to prevent.

**Falling back.** ``PLANNED → ACKNOWLEDGED`` (the work left the sprint),
``FIXING → PLANNED`` (it stalled), ``VERIFYING → FIXING`` (verification found
it still there). Remediation is not monotonic and pretending otherwise would
make ``FIXING`` mean "was once being fixed".

**Reopening.** ``CLOSED → OPEN``, and it is the only move into ``OPEN``.
``CLOSED`` is therefore *not* terminal, unlike a job's ``succeeded`` — a job
that finished is finished, while a vulnerability that was closed and then
observed again is the single most important event this model can report. It
arrives from two places: the observer (``register_findings_from_run`` sees the
finding in a later run) and an operator who closed it by mistake. Both are
recorded as a reopen in the audit trail, and the SLA clock restarts from the
re-observation rather than from the original discovery — the deadline for
fixing something that came back is not measured from before it was fixed.

Deliberately **not** legal:

- Same-state moves (``FIXING → FIXING``). As with jobs, rejecting them is what
  makes a retried or double-clicked request safe, and a no-op audit entry that
  claims a transition is worse than a 409.
- ``CLOSED → ACKNOWLEDGED`` and friends. Something that is back is ``OPEN``;
  re-triaging it is then a second, separately auditable decision by whoever
  looks at it, not an inference this module makes on their behalf.
- Anything into ``OPEN`` other than from ``CLOSED``. ``OPEN`` means "nobody has
  looked at this yet", so moving a triaged finding back to it would erase the
  fact that someone did.

Risk acceptance is **not** a state here. It is an expiring attribute of the row
(``exception_until``), because an accepted exception does not change where the
finding sits in the remediation workflow — it suspends the SLA clock and
nothing else, and it has to expire back into whatever state the work was
actually in. Modelling it as a seventh state would mean inventing a rule for
where a finding lands when the acceptance runs out, and losing the answer the
row already had. See ``api/services/vulnerabilities.py``.
"""

from __future__ import annotations

OPEN = "OPEN"
ACKNOWLEDGED = "ACKNOWLEDGED"
PLANNED = "PLANNED"
FIXING = "FIXING"
VERIFYING = "VERIFYING"
CLOSED = "CLOSED"

#: Declaration order — the happy path, used for stable ordering in summaries.
ORDER = (OPEN, ACKNOWLEDGED, PLANNED, FIXING, VERIFYING, CLOSED)

#: States whose findings are still someone's problem, i.e. the ones an SLA is
#: counted over. ``CLOSED`` is excluded; every other state is included, an
#: accepted exception included — the exception suspends the clock, and that is
#: expressed by the due date, not by dropping the row out of the population.
ACTIVE = frozenset({OPEN, ACKNOWLEDGED, PLANNED, FIXING, VERIFYING})

#: Un-triaged: nobody has made a decision about this finding yet.
UNTRIAGED = frozenset({OPEN})

TRANSITIONS: dict[str, frozenset[str]] = {
    OPEN: frozenset({ACKNOWLEDGED, PLANNED, FIXING, CLOSED}),
    ACKNOWLEDGED: frozenset({PLANNED, FIXING, CLOSED}),
    PLANNED: frozenset({ACKNOWLEDGED, FIXING, CLOSED}),
    FIXING: frozenset({PLANNED, VERIFYING, CLOSED}),
    VERIFYING: frozenset({FIXING, CLOSED}),
    # The reopen, and the only edge into OPEN. See the module docstring.
    CLOSED: frozenset({OPEN}),
}

ALL = frozenset(TRANSITIONS)


class InvalidVulnTransition(ValueError):
    """An illegal lifecycle move was attempted.

    Subclasses ``ValueError`` so route handlers that already map ``ValueError``
    to 422 keep working; the transition route catches it specifically and
    answers 409, as ``POST /jobs/{id}/cancel`` does for its own refusals.
    """


def can_transition(current: str, new: str) -> bool:
    return new in TRANSITIONS.get(current, frozenset())


def check_transition(vuln_id: str, current: str, new: str) -> None:
    """Raise unless ``current → new`` is a legal move for ``vuln_id``."""
    if new not in ALL:
        raise InvalidVulnTransition(f"Vulnerability {vuln_id}: unknown state {new!r}")
    if not can_transition(current, new):
        raise InvalidVulnTransition(
            f"Vulnerability {vuln_id} cannot move from {current} to {new}"
            + (" (already in that state)" if current == new else "")
        )
