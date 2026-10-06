"""Vulnerability lifecycle, ownership, SLA and its audit trail (#145, Track C).

The state machine itself is ``api/services/vuln_states.py``; this module is
everything around it: turning a finished run's findings into tracked rows,
computing deadlines from policy, applying operator decisions, and writing the
audit trail those decisions are only worth anything with.

**Two writers, one table.** The observer (``register_findings_from_run``, called
best-effort from ``api/services/jobs.py`` once a run's artifacts are on disk and
its assets are upserted) may create a row, update the finding's latest
assessment, and reopen a closed row. It never otherwise touches lifecycle state:
a scan seeing a finding again says nothing about whether the fix is planned.
Operators own every other move. Keeping that split explicit is what stops the
next scan from undoing a triage decision.

**A finding that stopped being observed is not closed** by this module. It is
tempting — the scanner no longer sees it, so surely it is fixed — but the same
absence is produced by a host that was down, a port that was firewalled during
the scan window, a credential that expired, or a scan profile someone narrowed.
Auto-closing on absence would mean the platform silently forgives findings
whenever scanning breaks, which is the failure mode a vulnerability manager most
needs it not to have. Absence is visible instead: ``last_seen_at`` stops moving,
and ``GET /vulnerabilities?stale_days=N`` lists what has not been re-observed,
so closing it stays a decision with a name attached.

**SLA.** ``due_at = sla_started_at + remediation_days``, where the days come
from the tenant's ``sla_policies`` row for (asset criticality, severity), or
that severity's tenant fallback, or ``DEFAULT_SLA_DAYS``. Breach is derived on
read (``sla_state``), never stored — see the model docstring. An accepted
exception pushes ``due_at`` to the acceptance expiry: the clock is suspended,
not deleted, so the finding reappears in the breach report the day the
acceptance runs out rather than never.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session, insert_or_skip
from api.services import bdu_fstec
from api.services import audit as audit_service
from api.services import exploit_evidence
from api.services import metrics
from api.services import nist_risk
from api.services import pagination
from api.services import publication_marks
from api.services import runs as runs_service
from api.services import scan_surface
from api.services import verification_coverage
from api.services import vuln_states
from api.services import workflow_events
from scanner.pipeline.config_schema import MAX_NUCLEI_TEMPLATE_IDS, NUCLEI_TEMPLATE_ID_RE
from scanner.pipeline.cvss4 import normalize_cwes
from api.services.risk_scoring import (
    FOOTHOLD,
    LOCAL,
    NETWORK_EXPOSURES,
    UNKNOWN_EXPOSURE,
    get_scorer,
    index_cdn_waf,
    path_role,
)
from api.settings import Settings
from scanner.pipeline.asset_identity import identity_candidates_for_host
from scanner.pipeline.report import SEVERITY_ORDER

LOG = logging.getLogger("shapoclyack.vulnerabilities")


class VerificationDispatchError(RuntimeError):
    """A verification scan could not be started, so the finding stays put."""

#: Fallback remediation windows, in days, when the tenant has no matching
#: ``sla_policies`` row. Roughly the shape most published remediation standards
#: settle on (CISA BOD 22-01's 15 days for KEV criticals being the strictest
#: widely cited figure), deliberately *not* stricter than an installation can
#: act on: a default nobody can meet makes every finding a breach and the
#: breach count useless. Overridden per tenant through the SLA policy API.
DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180,
    "unknown": 90,
}

#: How much sooner than ``due_at`` a finding is reported as ``due_soon``. A
#: purely binary on_track/breached signal gives an operator no window in which
#: to act, which is the difference between an SLA and a scoreboard.
DUE_SOON_DAYS = 7

VULN_EVENT_KINDS = (
    "observed",
    "state_change",
    "reopened",
    "assigned",
    "exception_set",
    "exception_cleared",
    # The approval workflow around an acceptance (#348). ``exception_set``
    # above stays what it always was — the moment the clock was suspended —
    # and is now written by the approval rather than by the request, so a
    # finding's history reads request → decision → (expiry) in four rows.
    "exception_requested",
    # The requester taking their own ask back, which is not the same row as
    # ``exception_cleared``: that one says a signed acceptance stopped holding.
    "exception_request_withdrawn",
    "exception_approved",
    "exception_rejected",
    "exception_expired",
    "comment",
    "ticket_set",
    "ticket_cleared",
    # Closed-loop remediation (#183).
    "verification_started",
    "verification_passed",
    "verification_failed",
    # The verification run did not show that every detector of the finding
    # re-checked it (api/services/verification_coverage.py), or did not
    # finish at all. Neither fixed nor still there: back to FIXING, never
    # machine-verified, with what was not covered in ``detail.gaps`` (#451).
    "verification_inconclusive",
    # The verification run's connect probe was refused on the finding's port
    # (closure_reason endpoint_unreachable): not reachable from where the run
    # looked. Never machine-verified — a firewall REJECT in front of a
    # listening port answers the same way (#451).
    "verification_unreachable",
    "ticket_synced",
    # SLA escalation (#349): the worker reassigned the finding or raised its
    # severity because its deadline passed. Recorded as an event of its own
    # rather than as an ``assigned`` one, because the actor is the platform
    # acting on a policy — "who moved this to the platform team" has to have a
    # different answer from "somebody did".
    "escalated",
    # False-positive verdicts (Track E).
    "false_positive_set",
    "false_positive_cleared",
    "fp_reobserved",
    "fp_overridden",
)

#: Why a finding is closed. ``false_positive`` is the only one an operator
#: chooses; the other three are what the platform observed happening — a
#: verification run stopped seeing it, someone closed it by hand, or the ticket
#: it was linked to was resolved.
#:
#: A false positive is *not* a fourth flavour of "fixed". It is a statement
#: about the evidence — the finding was never real — so it is carried by the
#: expiring ``fp_*`` attributes next to it rather than by this string alone,
#: and it is excluded from every metric that measures remediation work
#: (see api/services/adoption.py). Marking noise honestly must not be able to
#: move the numbers a team is judged on, in either direction.
CLOSURE_REASONS = ("verified_remediated", "manual", "ticket_resolved", "false_positive")

FALSE_POSITIVE = "false_positive"

#: Bounds on how long a false-positive verdict suppresses re-opening. Both ends
#: are deliberate: no indefinite suppression, and no verdict so short it is
#: pure ceremony.
MIN_FP_SUPPRESS_DAYS = 1
MAX_FP_SUPPRESS_DAYS = 365
DEFAULT_FP_SUPPRESS_DAYS = 90

TICKET_SYSTEMS = ("jira", "servicenow", "smax", "defectdojo", "other")

#: Which observer produced a finding. ``scan`` is this module's own path;
#: ``endpoint_software`` is ``api/services/software_findings.py``;
#: ``retro_match`` is ``api/services/retro_findings.py`` — a stored service
#: fingerprint re-matched against the NVD range dataset.
SOURCES = ("scan", "endpoint_software", "retro_match")

#: Why a finding is closed. Never taken from a request body — the value of
#: ``machine_verified`` is that it cannot be self-attested. ``patched`` is the
#: software path's: a later accepted inventory snapshot no longer matches it.
CLOSURE_REASONS = (
    "verified_remediated",
    "patched",
    "manual",
    "ticket_resolved",
    # A verification's connect probe was refused on the finding's port, from
    # the vantage that observed it (#451). Not a verified fix.
    "endpoint_unreachable",
)

ENDPOINT_UNREACHABLE = "endpoint_unreachable"

#: The shortest window, in days from an ``endpoint_unreachable`` closure,
#: within which a finding seen again continues its old SLA clock. The window
#: is the finding's own ``sla_days`` when longer. Never shorter than this:
#: the most urgent findings have the shortest SLA (a 1-day FSTEC deadline),
#: and a window that short let a REJECT rule and one quiet day erase an
#: overdue deadline (#451 review, round 3).
ENDPOINT_UNREACHABLE_SLA_WINDOW_MIN_DAYS = 30

#: Derived SLA readings. ``none`` is a finding with no deadline at all, which
#: happens only for a CLOSED row.
SLA_STATES = ("on_track", "due_soon", "breached", "accepted", "none")


@dataclass(frozen=True)
class RegisterStats:
    findings_seen: int
    created: int
    reobserved: int
    reopened: int
    skipped_unknown_asset: int
    # Findings this run was dispatched to re-check, and how it went. Zero for
    # any run that was not a verification run.
    verification_passed: int = 0
    verification_failed: int = 0
    # Not observed, but not demonstrably looked for either: sent back to
    # FIXING rather than closed (verification_coverage.py).
    verification_inconclusive: int = 0
    # Closed as endpoint_unreachable: refused from the observing vantage,
    # not machine-verified.
    verification_unreachable: int = 0
    # Findings seen again while a false-positive verdict suppressed them, and
    # verdicts this run broke early because the assessment got worse.
    fp_suppressed: int = 0
    fp_overridden: int = 0


def _now() -> datetime:
    """Naive UTC, matching ``api/services/jobs.py`` and the ``DateTime`` columns.

    Every timestamp in this module — including the operator-supplied exception
    expiry, which arrives from Pydantic with a timezone — is normalised through
    here or ``_naive``. Mixing the two kinds inside one comparison is a
    ``TypeError`` at best and a breach report that is right on one driver and
    wrong on another at worst.
    """
    return datetime.now(UTC).replace(tzinfo=None)


def _naive(dt: datetime | None) -> datetime | None:
    """One timestamp as naive UTC, whichever kind it arrived as."""
    if dt is None:
        return None
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def _iso(dt: datetime | None) -> str | None:
    naive = _naive(dt)
    return naive.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if naive else None


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def finding_key(*, asset_id: str, cve: str | None, script_id: str | None, port: str | None) -> str:
    """Stable identity for one finding on one asset.

    ``(asset, cve-or-script, port)`` is the same triple
    ``scanner.pipeline.report._dedupe_vulnerabilities`` already collapses
    duplicates on, so "the same finding" means the same thing in the tracker as
    in the report. Hashed rather than concatenated because the parts are
    scanner-supplied strings of no fixed shape, and a delimiter one of them
    contains would make two different findings share a key.
    """
    what = (cve or "").strip().upper() or f"script:{(script_id or '').strip()}"
    material = "|".join([asset_id, what, (port or "").strip()])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


#: How many detector entries a finding keeps (``Vulnerability.detectors``),
#: newest first. A bound because the list is merged on every observation of a
#: row nobody may ever close; sixteen is far more detectors and addresses than
#: one CVE on one port plausibly has.
MAX_DETECTORS = 16

#: How many vantages one detector entry remembers (``vantages``, newest
#: first). Only "one, and it is the verifying one" ever lets a refusal close
#: a finding, so a bound that keeps at least two loses no decision.
MAX_VANTAGES = 8

#: The vantage of an observation nobody recorded: a run no job owns, or an
#: entry from before vantages were kept (backfilled by 0079). The two are
#: not the same: the backfill predates recording and gives way to the first
#: known vantage (:func:`merge_detectors`), while a run no job owns did look,
#: from a place nobody knows, and stays beside any known one.
UNKNOWN_VANTAGE = "unknown"


def _detector_of(source: Any, script_id: Any) -> tuple[str, str] | None:
    """``(detector, ref)`` for one vulnerabilities.json row, or ``None``.

    ``source`` is what the scanner stages write (``pulse``, ``nuclei``,
    ``nmap-nse``; scanner/pipeline/report.py); ``script_id`` carries the ref —
    ``nuclei:<template id>``, ``pulse:<origin>`` or the NSE script id. A row
    without a ``source`` (a run from before the stages wrote one, or written
    by hand) is classified from the ``script_id`` prefix, as migration 0079
    backfills, and a row with neither has no detector anyone can name.
    """
    name = str(source or "").strip().lower()[:32]
    script = str(script_id or "").strip()
    derived: tuple[str, str] | None = None
    if script.startswith("nuclei:"):
        derived = (verification_coverage.NUCLEI, script[len("nuclei:") :])
    elif script.startswith("pulse:"):
        derived = (verification_coverage.PULSE, script[len("pulse:") :])
    elif script:
        derived = (verification_coverage.NMAP_NSE, script)
    if not name:
        return derived
    return name, (derived[1] if derived and derived[0] == name else script)


def _observed_detectors(
    entry: dict[str, Any],
    *,
    port: str | None,
    run_id: str,
    now: datetime,
    vantage: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """The detector entries one vulnerabilities.json row stands for.

    The row's own, plus ``also_detected_by``: the report collapses one CVE
    seen by several stages on one endpoint into one row and lists the others
    there, because a verification has to re-check every one of them.
    """
    host = str(entry.get("host") or "").strip()[:255] or None
    rows = [entry, *(other for other in entry.get("also_detected_by") or [] if isinstance(other, dict))]
    out: list[dict[str, Any]] = []
    for row in rows:
        detector = _detector_of(row.get("source"), row.get("script_id"))
        if detector is None:
            continue
        name, ref = detector
        candidate = {
            "detector": name,
            "ref": ref[:200] or None,
            "host": host,
            "port": port,
            "last_run_id": run_id,
            "last_seen_at": _iso(now),
        }
        if vantage:
            # ``vantages`` is written by merge_detectors, from this one and
            # every earlier one; without a vantage it reads as unknown.
            candidate.update(vantage)
        protocol = str(row.get("protocol") or "").strip().lower()
        if protocol in ("tcp", "udp"):
            # Recorded so a UDP finding is never judged by a TCP re-check.
            candidate["protocol"] = protocol
        ruleset = str(row.get("ruleset_version") or "").strip()[:64]
        if name == verification_coverage.PULSE and ruleset:
            # The offline ruleset this match was made with: a verification
            # matching with an older one has not re-checked it.
            candidate["ruleset"] = ruleset
        if not any(_detector_key(candidate) == _detector_key(seen) for seen in out):
            out.append(candidate)
    return out


def _detector_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    host = entry.get("host")
    return (
        entry.get("detector"),
        entry.get("ref") or None,
        verification_coverage.normalize_host(host) if host else None,
        str(entry.get("port") or ""),
    )


def _vantages_of(entry: dict[str, Any]) -> list[str]:
    """Every vantage ``entry`` was observed from, newest first.

    An entry written before the list was kept names one (``vantage``) or
    none, and none is :data:`UNKNOWN_VANTAGE`, not "anywhere".
    """
    listed = entry.get("vantages")
    if isinstance(listed, list) and listed:
        return [str(value) for value in listed]
    return [str(entry.get("vantage") or UNKNOWN_VANTAGE)]


def _union_vantages(*lists: list[str]) -> list[str]:
    """The vantages of ``lists``, newest first, once each, capped."""
    out: list[str] = []
    for values in lists:
        out.extend(value for value in values if value not in out)
    return out[:MAX_VANTAGES]


def _handed_on(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """The vantages ``old`` hands to ``new``, the entry replacing it.

    All of them for the same endpoint. For a host-less entry a located one
    replaces, its known vantages only: an ``unknown`` there is 0079's
    backfill, which predates recording rather than naming a place, and kept
    it would leave a finding from before the upgrade unable to be shown
    unreachable from anywhere.
    """
    if _detector_key(old) == _detector_key(new):
        return _vantages_of(old)
    return [value for value in _vantages_of(old) if value != UNKNOWN_VANTAGE]


def _loose_detector_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (entry.get("detector"), entry.get("ref") or None, str(entry.get("port") or ""))


def merge_detectors(
    existing: list[dict[str, Any]] | None, observed: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """``existing`` with ``observed`` folded in: newest first, capped.

    An entry seen again moves to the front with its new run and time; one not
    seen this time keeps its place behind, because a detector that did not
    report the finding in one run did observe it once and a verification
    still owes it a look. A host-less entry (backfilled by 0079) is replaced
    by the same detector and ref observed with a host — the observation now
    says where it looked.

    Vantages are only ever added to: an entry seen again from another sensor
    group keeps the one it was seen from before (``vantages``), and an entry
    the cap drops hands its vantages to the newest one. A refusal from one
    vantage says nothing about what another observed, so a later observer
    must not erase an earlier one (#451). That includes ``unknown`` from a
    run no job owns; only a replaced host-less entry's ``unknown`` — 0079's
    backfill — is not handed on (:func:`_handed_on`).
    """
    previous = [entry for entry in (existing or []) if isinstance(entry, dict)]
    fresh = {_detector_key(entry) for entry in observed}
    located = {_loose_detector_key(entry) for entry in observed if entry.get("host")}

    def replaced_by(old: dict[str, Any], new: dict[str, Any]) -> bool:
        if _detector_key(old) == _detector_key(new):
            return True
        return not old.get("host") and bool(new.get("host")) and _loose_detector_key(old) == _loose_detector_key(new)

    renewed = [
        {
            **entry,
            "vantages": _union_vantages(
                _vantages_of(entry), *(_handed_on(old, entry) for old in previous if replaced_by(old, entry))
            ),
        }
        for entry in observed
    ]
    kept = [
        entry
        for entry in previous
        if _detector_key(entry) not in fresh
        and not (not entry.get("host") and _loose_detector_key(entry) in located)
    ]
    merged = [*renewed, *kept]
    if len(merged) <= MAX_DETECTORS:
        return merged
    # Over the cap, an entry repeating a detector and ref a newer entry
    # already holds (the same template seen on another address) goes first,
    # oldest of those first; only then the oldest entries outright. Dropping
    # the one entry of a detector would let a verification close the finding
    # without that detector ever looking again.
    held: set[tuple[Any, Any]] = set()
    repeats: list[int] = []
    for index, entry in enumerate(merged):
        key = (entry.get("detector"), entry.get("ref") or None)
        if key in held:
            repeats.append(index)
        held.add(key)
    excess = len(merged) - MAX_DETECTORS
    dropped = set(repeats[::-1][:excess])
    survivors = [index for index in range(len(merged)) if index not in dropped][:MAX_DETECTORS]
    capped = [merged[index] for index in survivors]
    lost = [
        vantage
        for index, entry in enumerate(merged)
        if index not in survivors
        for vantage in _vantages_of(entry)
    ]
    capped[0] = {**capped[0], "vantages": _union_vantages(_vantages_of(capped[0]), lost)}
    return capped


def _severity_of(entry: dict[str, Any]) -> str:
    severity = str(entry.get("severity") or "").strip().lower()
    return severity if severity in SEVERITY_ORDER else "unknown"


def _maturity_rank(value: str | None) -> int:
    """Rank an exploit maturity level, with ``unknown`` and junk at the floor.

    ``unknown`` is an admission that nothing was asked, not a level, so it can
    never *out*rank a real one — see api/services/exploit_evidence.py.
    """
    try:
        return exploit_evidence.MATURITY_ORDER.index(str(value or "").strip().lower())
    except ValueError:
        return -1


def _fp_suppressed(row: models.Vulnerability, now: datetime) -> bool:
    """Is a false-positive verdict still holding this finding closed?

    All three conditions are required. A row that was reopened by hand keeps
    none of them, and one whose ``fp_suppress_until`` has passed is back under
    the ordinary re-open rule — which is the entire point of making the expiry
    mandatory.
    """
    return (
        row.state == vuln_states.CLOSED
        and row.closure_reason == FALSE_POSITIVE
        and row.fp_suppress_until is not None
        # Both sides through _naive: callers pass either kind of ``now``, and a
        # mixed comparison is a TypeError on one driver and silently wrong on
        # the other (see the _now docstring).
        and _naive(row.fp_suppress_until) > _naive(now)
    )


def _clear_fp(row: models.Vulnerability) -> None:
    """Drop the verdict from a row. Not the audit trail — that is in the events."""
    row.fp_reason = None
    row.fp_marked_by = None
    row.fp_marked_at = None
    row.fp_evidence = {}
    row.fp_suppress_until = None
    row.fp_observations = 0


def _fp_escalations(row: models.Vulnerability, latest: dict[str, Any]) -> list[str]:
    """Which parts of a suppressed finding's assessment got materially worse.

    A false-positive verdict is a statement about the evidence *as it stood*.
    New intelligence is new evidence, so a suppression that outlived it is not
    a decision anyone made — it is one nobody revisited. Only these four moves
    count: they are the ones that change whether the finding would be worth
    looking at again, as opposed to a score drifting inside the same band.
    """
    changed: list[str] = []
    if SEVERITY_ORDER.get(str(latest.get("severity")), 0) > SEVERITY_ORDER.get(str(row.severity), 0):
        changed.append("severity")
    if bool(latest.get("in_kev")) and not bool(row.in_kev):
        changed.append("in_kev")
    if latest.get("network_exposure") == "external" and row.network_exposure != "external":
        changed.append("network_exposure")
    if _maturity_rank(latest.get("exploit_maturity")) > _maturity_rank(row.exploit_maturity):
        changed.append("exploit_maturity")
    return changed


#: What weighing a re-observation against a false-positive verdict decided.
#: ``FP_HELD`` is the only one that forbids the caller to re-open the finding.
FP_NONE = "none"
FP_HELD = "held"
FP_OVERRIDDEN = "overridden"


def weigh_fp_verdict(
    session: Any,
    row: models.Vulnerability,
    latest: dict[str, Any],
    *,
    tenant_id: str,
    now: datetime,
    detail: dict[str, Any],
) -> str:
    """Weigh one re-observation against a false-positive verdict, for any observer.

    A verdict is a statement about a *finding*, not about the path that found
    it, so every observer that can re-open a finding has to reach the same
    answer here: this module's run path, and the endpoint-software fold in
    ``api/services/software_findings.py``. It is one shared entry rather than a
    rule each of them re-implements, because a private copy is exactly how the
    software path came to re-open suppressed findings on the next inventory
    snapshot while the console still showed the verdict on them.

    Call it **before** ``latest`` is written onto the row: an escalation is a
    difference between what the verdict was made on and what this observation
    says, and once the row carries the new assessment that difference is gone.

    ``detail`` is the observer's own description of the observation — the run
    id, or the device and snapshot — and is merged into whichever event this
    writes, so the trail says which observer the verdict survived.
    """
    if not _fp_suppressed(row, now):
        return FP_NONE
    escalations = _fp_escalations(row, latest)
    if escalations:
        # New intelligence breaks the suppression early. The verdict is cleared
        # by the caller's re-open (``drop_fp_verdict_on_reopen``) rather than
        # kept alongside an open finding: leaving it on the row would make a
        # later reader think the finding is still considered noise.
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=tenant_id,
            kind="fp_overridden",
            occurred_at=now,
            from_state=row.state,
            note="False-positive suppression overridden by a worse assessment",
            detail={
                **detail,
                "changed": escalations,
                "fp_observations": row.fp_observations,
                "fp_suppress_until": _iso(row.fp_suppress_until),
                "fp_marked_by": row.fp_marked_by,
            },
        )
        return FP_OVERRIDDEN

    # The verdict stands: the finding is still not real, so seeing it again is
    # not a regression. It stays CLOSED, the SLA clock stays stopped and
    # ``reopen_count`` stays put — otherwise marking noise honestly would be
    # punished by every metric.
    assessment_changed = any(getattr(row, field) != value for field, value in latest.items())
    row.fp_observations += 1
    # One event per verdict, not one per observation: ``observed`` rows are
    # already the high-volume kind and have no retention sweep behind them (see
    # the VulnerabilityEvent docstring). The first sighting under the verdict,
    # and any later change in the assessment, are the two worth a row.
    if row.fp_observations == 1 or assessment_changed:
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=tenant_id,
            kind="fp_reobserved",
            occurred_at=now,
            to_state=row.state,
            note="Still observed while suppressed as a false positive",
            detail={
                **detail,
                "fp_observations": row.fp_observations,
                "fp_suppress_until": _iso(row.fp_suppress_until),
            },
        )
    return FP_HELD


def drop_fp_verdict_on_reopen(row: models.Vulnerability) -> bool:
    """Drop a false-positive verdict from a finding that is being re-opened.

    Every re-open goes through here, whichever observer or operator caused it:
    a run, an inventory snapshot, an operator transition or a resolved ticket
    coming back. A verdict left on an open row is read by the console — and by
    the next human — as a current judgement that this finding is not real, and
    ``closure_reason`` being cleared without it was how an *open* finding came
    to render "Suppressed until 2027" with a button that withdrew nothing.

    Returns whether there was a verdict to drop, so the caller can say so in
    the event it is already writing.
    """
    if row.closure_reason != FALSE_POSITIVE:
        return False
    _clear_fp(row)
    return True


# --------------------------------------------------------------------------
# SLA policy
# --------------------------------------------------------------------------


def _policy_to_dict(row: models.SlaPolicy) -> dict[str, Any]:
    return {
        "policy_id": row.policy_id,
        "tenant_id": row.tenant_id,
        "asset_criticality": row.asset_criticality,
        "severity": row.severity,
        "remediation_days": row.remediation_days,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
    }


def _validate_severity(value: str) -> str:
    severity = str(value or "").strip().lower()
    if severity not in SEVERITY_ORDER:
        raise ValueError(
            f"unknown severity {value!r}; expected one of {', '.join(SEVERITY_ORDER)}"
        )
    return severity


def _validate_criticality(value: int | None) -> int | None:
    if value is None:
        return None
    criticality = int(value)
    if not 0 <= criticality <= 4:
        raise ValueError("asset_criticality must be between 0 and 4, or null for the fallback")
    return criticality


def upsert_sla_policy(
    settings: Settings,
    *,
    tenant_id: str,
    severity: str,
    remediation_days: int,
    asset_criticality: int | None = None,
    created_by: str | None = None,
) -> dict[str, Any]:
    """Set the deadline for one (criticality, severity) scope.

    Upsert rather than create: the scope *is* the identity, so a second POST for
    the same pair is an edit of the policy that exists, not a second policy the
    resolver would then have to choose between.
    """
    severity = _validate_severity(severity)
    criticality = _validate_criticality(asset_criticality)
    days = int(remediation_days)
    if days < 1:
        raise ValueError("remediation_days must be at least 1")

    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.SlaPolicy).where(
                models.SlaPolicy.tenant_id == tenant_id,
                models.SlaPolicy.severity == severity,
                models.SlaPolicy.asset_criticality.is_(criticality)
                if criticality is None
                else models.SlaPolicy.asset_criticality == criticality,
            )
        ).scalar_one_or_none()
        if row is None:
            row = models.SlaPolicy(
                policy_id=f"sla_{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                asset_criticality=criticality,
                severity=severity,
                remediation_days=days,
                created_at=now,
                created_by=created_by,
            )
            session.add(row)
        else:
            row.remediation_days = days
            row.updated_at = now
        session.flush()
        return _policy_to_dict(row)


def list_sla_policies(settings: Settings, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.SlaPolicy.tenant_id == tenant_id)
        rows = session.execute(
            select(models.SlaPolicy)
            .where(*filters)
            .order_by(
                models.SlaPolicy.tenant_id,
                models.SlaPolicy.asset_criticality,
                models.SlaPolicy.severity,
            )
        ).scalars().all()
    return [_policy_to_dict(row) for row in rows]


def delete_sla_policy(settings: Settings, *, tenant_id: str, policy_id: str) -> bool:
    """Delete one scope. Findings keep the ``due_at`` the policy produced until
    they are next re-observed — recomputing every deadline on a policy edit
    would move thousands of dates on one operator's click, and the row records
    which ``sla_days`` it was judged against."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.SlaPolicy, policy_id)
        if row is None or row.tenant_id != tenant_id:
            return False
        session.delete(row)
        return True


#: What a tenant with no ``sla_escalation_policies`` row gets (#349). Every
#: action is off: the breach *events* need no policy, and rewriting somebody's
#: assignments or mailing their asset owners is not a default to inherit from a
#: version bump. ``configured`` tells a caller which of the two it is looking
#: at, so the console can say "not set up" rather than "disabled".
ESCALATION_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "escalate_after_days": 0,
    "escalate_to": None,
    "escalate_owner_team": None,
    "bump_severity": False,
    "digest_enabled": False,
}

#: Cap on the grace period past ``due_at``. A year of grace is a deadline
#: nobody has, and the column is read into a ``timedelta``.
MAX_ESCALATE_AFTER_DAYS = 365


def _escalation_to_dict(row: models.SlaEscalationPolicy | None, tenant_id: str) -> dict[str, Any]:
    if row is None:
        return {
            "tenant_id": tenant_id,
            **ESCALATION_DEFAULTS,
            "configured": False,
            "updated_at": None,
            "updated_by": "",
        }
    return {
        "tenant_id": row.tenant_id,
        "enabled": bool(row.enabled),
        "escalate_after_days": int(row.escalate_after_days or 0),
        "escalate_to": row.escalate_to,
        "escalate_owner_team": row.escalate_owner_team,
        "bump_severity": bool(row.bump_severity),
        "digest_enabled": bool(row.digest_enabled),
        "configured": True,
        "updated_at": _iso(row.updated_at),
        "updated_by": row.updated_by or "",
    }


def get_escalation_policy(settings: Settings, *, tenant_id: str) -> dict[str, Any]:
    """The tenant's escalation policy, or the all-off defaults if it has none."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.SlaEscalationPolicy, tenant_id)
        return _escalation_to_dict(row, tenant_id)


def upsert_escalation_policy(
    settings: Settings,
    *,
    tenant_id: str,
    enabled: bool,
    escalate_after_days: int = 0,
    escalate_to: str | None = None,
    escalate_owner_team: str | None = None,
    bump_severity: bool = False,
    digest_enabled: bool = False,
    updated_by: str | None = None,
) -> dict[str, Any]:
    """Replace the tenant's escalation policy. One row per tenant, so ``PUT``.

    Refuses ``enabled`` with nothing to do: a policy that reassigns to nobody,
    bumps nothing and mails nobody is a switch an operator would reasonably
    read as "escalation is on", and it would do precisely nothing.
    """
    days = int(escalate_after_days or 0)
    if days < 0 or days > MAX_ESCALATE_AFTER_DAYS:
        raise ValueError(
            f"escalate_after_days must be between 0 and {MAX_ESCALATE_AFTER_DAYS}"
        )
    assignee = (escalate_to or "").strip() or None
    team = (escalate_owner_team or "").strip() or None
    if enabled and not (assignee or team or bump_severity or digest_enabled):
        raise ValueError(
            "escalation is enabled but has no action: set escalate_to, "
            "escalate_owner_team, bump_severity or digest_enabled"
        )
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.SlaEscalationPolicy, tenant_id)
        if row is None:
            row = models.SlaEscalationPolicy(tenant_id=tenant_id, updated_at=now)
            session.add(row)
        row.enabled = bool(enabled)
        row.escalate_after_days = days
        row.escalate_to = assignee
        row.escalate_owner_team = team
        row.bump_severity = bool(bump_severity)
        row.digest_enabled = bool(digest_enabled)
        row.updated_at = now
        row.updated_by = updated_by or ""
        session.flush()
        return _escalation_to_dict(row, tenant_id)


def escalate(
    settings: Settings,
    *,
    tenant_id: str,
    vuln_id: str,
    assignee: str | None = None,
    owner_team: str | None = None,
    bump_severity: bool = False,
) -> dict[str, Any] | None:
    """Apply a tenant's escalation to one breached finding (#349).

    Called only by ``api/services/sla_escalation.py``, and deliberately narrow:
    it writes ownership and severity, records an ``escalated`` event, and does
    not touch the lifecycle state. A finding whose deadline passed is not in a
    different state — it is the same work, late, and moving it would erase
    whatever its owner had recorded about it.

    Returns the finding with a ``escalation`` key naming what changed, or
    ``None`` if there was nothing left to do (already assigned there, already
    critical). ``None`` is not a failure: the worker uses it to decide whether
    the event it is about to send should claim an escalation happened.
    """
    now = _now()
    changed: dict[str, Any] = {}
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        target_assignee = (assignee or "").strip() or None
        if target_assignee and row.assignee != target_assignee:
            changed["assignee_from"] = row.assignee
            row.assignee = target_assignee
            changed["assignee_to"] = target_assignee
        target_team = (owner_team or "").strip() or None
        if target_team and row.owner_team != target_team:
            changed["owner_team_from"] = row.owner_team
            row.owner_team = target_team
            changed["owner_team_to"] = target_team
        if bump_severity:
            raised = _raise_severity(row.severity)
            if raised != row.severity:
                changed["severity_from"] = row.severity
                row.severity = raised
                changed["severity_to"] = raised
        if not changed:
            return None
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="escalated",
            occurred_at=now,
            to_state=row.state,
            # No actor: the platform did this because the tenant's policy said
            # so, and naming a user would put somebody's name on a decision
            # they did not make today.
            actor=None,
            note="SLA breach escalation",
            detail=changed,
        )
        session.flush()
        result = _to_dict(row, now=now)
    if "severity_to" in changed:
        metrics.SLA_ESCALATIONS_TOTAL.labels(action="severity_bumped").inc()
    if "assignee_to" in changed or "owner_team_to" in changed:
        metrics.SLA_ESCALATIONS_TOTAL.labels(action="reassigned").inc()
    result["escalation"] = changed
    return result


def _raise_severity(current: str | None) -> str:
    """One step up the severity ladder, capped at ``critical``.

    ``unknown`` becomes ``medium`` rather than ``low``: the point of the bump
    is to make a missed deadline more visible, and an unrated finding that
    nobody fixed in time is not evidence that it is mild.
    """
    ladder = ("low", "medium", "high", "critical")
    value = (current or "unknown").strip().lower()
    if value == "unknown":
        return "medium"
    if value not in ladder:
        return value
    return ladder[min(ladder.index(value) + 1, len(ladder) - 1)]


def _resolve_sla_days(
    session: Any, *, tenant_id: str, severity: str, criticality: int | None
) -> tuple[int, str]:
    """Days for this finding, and where they came from ("policy" | "default").

    Most specific first: the exact (criticality, severity) pair, then the
    severity's tenant fallback, then the built-in table. Criticality narrows the
    scope, so an asset-specific policy has to win over the tenant-wide one — the
    opposite order would make setting criticality on an asset have no effect on
    its deadlines, which is the whole point of having the axis.
    """
    if criticality is not None:
        specific = session.execute(
            select(models.SlaPolicy.remediation_days).where(
                models.SlaPolicy.tenant_id == tenant_id,
                models.SlaPolicy.severity == severity,
                models.SlaPolicy.asset_criticality == criticality,
            )
        ).scalar_one_or_none()
        if specific is not None:
            return int(specific), "policy"
    fallback = session.execute(
        select(models.SlaPolicy.remediation_days).where(
            models.SlaPolicy.tenant_id == tenant_id,
            models.SlaPolicy.severity == severity,
            models.SlaPolicy.asset_criticality.is_(None),
        )
    ).scalar_one_or_none()
    if fallback is not None:
        return int(fallback), "policy"
    return DEFAULT_SLA_DAYS.get(severity, DEFAULT_SLA_DAYS["unknown"]), "default"


def sla_state(row: models.Vulnerability | dict[str, Any], *, now: datetime | None = None) -> str:
    """Derived SLA reading for one finding. Never stored — see the model."""
    now = now or _now()
    if isinstance(row, dict):
        state = str(row.get("state") or "")
        due_at = row.get("due_at")
        exception_until = row.get("exception_until")
        if isinstance(due_at, str):
            due_at = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
        if isinstance(exception_until, str):
            exception_until = datetime.fromisoformat(exception_until.replace("Z", "+00:00"))
        due_at = _naive(due_at)
        exception_until = _naive(exception_until)
    else:
        state = row.state
        due_at = row.due_at
        exception_until = row.exception_until

    if state == vuln_states.CLOSED:
        return "none"
    due = _naive(due_at)
    if due is None:
        return "none"
    accepted_until = _naive(exception_until)
    if accepted_until is not None and accepted_until > now:
        # Reported as accepted rather than on_track: an operator scanning the
        # list has to be able to see that this deadline is a suspension and not
        # a remediation estimate.
        return "accepted"
    if due <= now:
        return "breached"
    if due - now <= timedelta(days=DUE_SOON_DAYS):
        return "due_soon"
    return "on_track"


# --------------------------------------------------------------------------
# Audit trail
# --------------------------------------------------------------------------


def _record_event(
    session: Any,
    *,
    vuln_id: str,
    tenant_id: str,
    kind: str,
    occurred_at: datetime,
    from_state: str | None = None,
    to_state: str | None = None,
    actor: str | None = None,
    note: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append one audit row **inside the caller's transaction**.

    Never its own session: the trail and the change it describes have to commit
    or fail together, or a crash between them produces a state nobody is
    recorded as having caused.
    """
    if kind not in VULN_EVENT_KINDS:  # pragma: no cover - programming error
        raise ValueError(f"unknown vulnerability event kind {kind!r}")
    session.add(
        models.VulnerabilityEvent(
            vuln_id=vuln_id,
            tenant_id=tenant_id,
            occurred_at=occurred_at,
            kind=kind,
            from_state=from_state,
            to_state=to_state,
            actor=actor,
            note=str(note)[:2000] if note else None,
            detail=detail or {},
        )
    )


# --------------------------------------------------------------------------
# Observation: a finished run becomes tracked findings
# --------------------------------------------------------------------------


def _run_findings(settings: Settings, run_id: str, *, tenant_id: str) -> list[dict[str, Any]]:
    run_dir = runs_service.get_written_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return []
    raw = runs_service._load_json(run_dir / "vulnerabilities.json")  # noqa: SLF001
    return [entry for entry in raw if isinstance(entry, dict)] if isinstance(raw, list) else []


def _asset_for_finding(session: Any, *, tenant_id: str, host: str) -> models.Asset | None:
    """Resolve a finding's host string to a registered asset.

    A finding's ``host`` is whatever the scanner addressed — an IP or an FQDN —
    so both identifier kinds are tried, through the same candidate builder the
    asset upsert uses. Assets are upserted from the same run immediately before
    this runs, so a miss means the host never became an asset (a bare hostname
    with no A record, typically), and the finding is skipped rather than given a
    synthetic asset the rest of the platform would not know about.
    """
    host = (host or "").strip()
    if not host:
        return None
    candidates = identity_candidates_for_host(tenant_id, host_ip=host, hostnames=[host])
    for candidate in candidates:
        asset_id = session.execute(
            select(models.AssetIdentifier.asset_id).where(
                models.AssetIdentifier.tenant_id == tenant_id,
                models.AssetIdentifier.identifier_type == candidate.identifier_type,
                models.AssetIdentifier.identifier_value == candidate.identifier_value,
            )
        ).scalar_one_or_none()
        if asset_id is not None:
            asset = session.get(models.Asset, asset_id)
            if asset is not None:
                return asset
    return None


def _run_verifies_anything(settings: Settings, *, run_id: str, tenant_id: str) -> bool:
    """Is any finding waiting on the job that produced this run?

    Asked only when a run carried no findings at all, which for a verification
    run is the outcome that closes the loop.
    """
    with get_session(settings.postgres_url) as session:
        return (
            session.scalar(
                select(func.count())
                .select_from(models.Vulnerability)
                .join(models.Job, models.Job.job_id == models.Vulnerability.verification_job_id)
                .where(
                    models.Vulnerability.tenant_id == tenant_id,
                    models.Vulnerability.state == vuln_states.VERIFYING,
                    models.Job.run_id == run_id,
                )
            )
            or 0
        ) > 0


def _run_vantage(session: Any, *, tenant_id: str, run_id: str) -> dict[str, Any] | None:
    """Where the job that produced ``run_id`` scanned from, or ``None``.

    ``{"vantage": "local"}`` for the API's own executor; for a sensor its id,
    its group (the job's when the sensor has none on record) and the key a
    closure compares — ``group:<name>`` for a grouped sensor, ``agent:<id>``
    for an ungrouped one, since two ungrouped sensors may sit in different
    networks. ``None`` for a run no job owns (imported, hand-placed).
    """
    job = session.scalars(
        select(models.Job)
        .where(models.Job.tenant_id == tenant_id, models.Job.run_id == run_id)
        .order_by(models.Job.queued_at.desc())
        .limit(1)
    ).first()
    if job is None:
        return None
    if job.execution == "local":
        return {"vantage": "local"}
    if not job.assigned_agent_id:
        return None
    agent = session.get(models.Agent, job.assigned_agent_id)
    group = (agent.agent_group if agent is not None else None) or job.agent_group
    return {
        "agent_id": job.assigned_agent_id,
        "agent_group": group,
        "vantage": f"group:{group}" if group else f"agent:{job.assigned_agent_id}",
    }


def _observed_vantages(row: models.Vulnerability) -> set[str]:
    """Every vantage any detector of ``row`` ever observed it from."""
    return {
        vantage
        for entry in (row.detectors or [])
        if isinstance(entry, dict)
        for vantage in _vantages_of(entry)
    }


def _same_vantage(row: models.Vulnerability, verifying: dict[str, Any] | None) -> bool:
    """Whether ``row`` was only ever observed from where the run looked.

    One observing vantage, and it is the verifying one. A finding two sensor
    groups saw is not shown unreachable by a refusal from either: each one's
    path is its own. False whenever either side is unknown — an observation
    nobody recorded the sensor of, a row with no detector, a run no job owns.
    An ungrouped sensor is its own vantage (``agent:<id>``), so a refusal
    another ungrouped sensor got does not count either.
    """
    key = (verifying or {}).get("vantage")
    return bool(key) and _observed_vantages(row) == {key}


def _asset_hosts(session: Any, row: models.Vulnerability) -> set[str]:
    """Every address the finding's asset is known by.

    What a detector that never recorded where it looked (backfilled by 0079,
    or a row with no detector at all) is re-checked against: any of them
    answering counts. The weaker rule — an asset with two addresses can be
    "verified" on the one the finding was not on — and the reason a detector
    records its host from 0079 on.
    """
    return {
        str(value).strip()
        for value in session.scalars(
            select(models.AssetIdentifier.identifier_value).where(
                models.AssetIdentifier.tenant_id == row.tenant_id,
                models.AssetIdentifier.asset_id == row.asset_id,
                # Addresses only: a certificate fingerprint is an identity,
                # not something a scan can be pointed at.
                models.AssetIdentifier.identifier_type.in_(("ip", "fqdn")),
            )
        )
        if value and str(value).strip()
    }


def _finding_hosts(row: models.Vulnerability, addresses: set[str]) -> set[str]:
    """Where the finding's port has to be closed for it to be unreachable.

    Each detector's own host, and for one that never recorded it (or a row
    with none) every IP of the asset — the same set its coverage is held to.
    """
    normalized = {verification_coverage.normalize_host(a) for a in addresses}
    asset_ips = {a for a in normalized if _is_ip(a)}
    detectors = [entry for entry in (row.detectors or []) if isinstance(entry, dict)]
    hosts = {
        verification_coverage.normalize_host(entry["host"])
        for entry in detectors
        if entry.get("host")
    }
    if not detectors or any(not entry.get("host") for entry in detectors):
        hosts |= asset_ips
    return hosts


def _send_back_inconclusive(
    session: Any,
    row: models.Vulnerability,
    *,
    now: datetime,
    note: str,
    detail: dict[str, Any],
) -> None:
    """``VERIFYING → FIXING`` for a verification that proved nothing either way.

    Not left in ``VERIFYING``: nothing is looking at it any more, and a finding
    parked there is the state that used to end in a false closure. Not
    ``verification_failed`` either, which says the finding is still there —
    the run did not say that. ``machine_verified`` is not touched: it is false
    on every row in ``VERIFYING``, and stays so.
    """
    row.state = vuln_states.FIXING
    row.state_changed_at = now
    row.state_changed_by = "system:verification"
    row.last_verified_at = now
    row.updated_at = now
    _record_event(
        session,
        vuln_id=row.vuln_id,
        tenant_id=row.tenant_id,
        kind="verification_inconclusive",
        occurred_at=now,
        from_state=vuln_states.VERIFYING,
        to_state=vuln_states.FIXING,
        actor="system:verification",
        note=note,
        detail=detail,
    )


def _declared_surface_for_run(session: Any, *, tenant_id: str, run_id: str) -> str | None:
    """The surface the operator declared on the job that produced this run.

    ``None`` when no job owns the run (an imported or hand-placed run
    directory), or when the surface on it was derived rather than declared —
    see ``scan_surface.declared_surface_for_job``. Newest job first, because a
    retried scan reuses the run id and the last request is the current
    declaration.
    """
    options = session.scalars(
        select(models.Job.scan_options)
        .where(models.Job.tenant_id == tenant_id, models.Job.run_id == run_id)
        .order_by(models.Job.queued_at.desc())
        .limit(1)
    ).first()
    return scan_surface.declared_surface_for_job(options)


def register_findings_from_run(
    settings: Settings, *, tenant_id: str, run_id: str, publication_id: str | None = None
) -> RegisterStats:
    """Fold one run's findings into the tracker. Idempotent per publication.

    Identity is the finding, not the observation: every entry of the run finds
    or creates its row, and each one is an observation — two entries of one
    pass that land on one key are two, as they always were.

    A published run's derived updates run at least once
    (``run_completion.on_run_published``, #454): a replica killed after the
    fold and before the publication was closed folds the run again. Given the
    ``publication_id`` it is fed from, a second fold of that publication does
    nothing at all — no ``observation_count`` bump, no second ``observed``
    event, no SLA restart, no older assessment written over a newer run's —
    and the mark that says so commits with the fold (``publication_marks``).
    Not ``run_id``: a tenant reuses one across jobs, and the next job under
    the same id is a new sighting that must reopen what was closed.
    """
    entries = _run_findings(settings, run_id, tenant_id=tenant_id)
    if not entries and not _run_verifies_anything(settings, run_id=run_id, tenant_id=tenant_id):
        return RegisterStats(0, 0, 0, 0, 0)

    # A verification run that finds nothing is the *success* case — it is the
    # scan reporting the finding is gone — so an empty run still has to reach
    # the verification block below.

    scorer = get_scorer()
    run_dir = runs_service.get_written_run_dir(settings, run_id, tenant_id=tenant_id)
    cdn_waf = index_cdn_waf(
        runs_service._load_json(run_dir / "fingerprint.json") if run_dir is not None else None  # noqa: SLF001
    )
    now = _now()
    created = reobserved = reopened = skipped = 0
    verification_passed = verification_failed = verification_inconclusive = 0
    verification_unreachable = 0
    fp_suppressed_observations = fp_overridden = 0
    # Read only if a finding is waiting on this run, and then once.
    coverage = verification_coverage.RunCoverage(run_dir)

    with get_session(settings.postgres_url) as session:
        if not publication_marks.first_pass(
            session, publication_id, publication_marks.FINDINGS
        ):
            LOG.info(
                "Findings of run %s were already folded from publication %s",
                run_id,
                publication_id,
            )
            return RegisterStats(0, 0, 0, 0, 0)
        declared_surface = _declared_surface_for_run(
            session, tenant_id=tenant_id, run_id=run_id
        )
        # Where this run looked from (#451): recorded on every detector it
        # observes, compared with the verification run's at closure.
        vantage = _run_vantage(session, tenant_id=tenant_id, run_id=run_id)
        resolved: list[tuple[dict[str, Any], Any]] = []
        for entry in entries:
            host = str(entry.get("host") or "")
            asset = _asset_for_finding(session, tenant_id=tenant_id, host=host)
            if asset is None:
                skipped += 1
                continue
            cve = str(entry.get("cve") or "").strip() or None
            script_id = str(entry.get("script_id") or "").strip() or None
            if not cve and not script_id:
                skipped += 1
                continue
            resolved.append((entry, asset))

        footholds = {
            asset.asset_id for entry, asset in resolved if path_role(entry) == FOOTHOLD
        }

        for entry, asset in resolved:
            port = str(entry.get("port")) if entry.get("port") is not None else None
            cve = str(entry.get("cve") or "").strip() or None
            script_id = str(entry.get("script_id") or "").strip() or None
            scored = scorer.score_vulnerability(
                entry,
                asset_criticality_override=asset.asset_criticality,
                operator_exposure=asset.exposure_level,
                declared_surface=declared_surface,
                cdn_waf_index=cdn_waf,
                same_asset_foothold=(
                    path_role(entry) == LOCAL and asset.asset_id in footholds
                ),
            )
            severity = _severity_of(entry)
            key = finding_key(asset_id=asset.asset_id, cve=cve, script_id=script_id, port=port)
            # Who saw it and where, merged into the row whatever else this
            # observation does — a held false positive included: provenance is
            # what a later verification is judged against, not a verdict.
            observed = _observed_detectors(
                entry, port=port, run_id=run_id, now=now, vantage=vantage
            )

            row = session.execute(
                select(models.Vulnerability).where(
                    models.Vulnerability.tenant_id == tenant_id,
                    models.Vulnerability.finding_key == key,
                )
            ).scalar_one_or_none()

            latest = {
                "severity": severity,
                "risk_level": scored.get("risk_level"),
                "contextual_score": scored.get("contextual_score"),
                "cvss": entry.get("cvss"),
                "in_kev": bool(scored.get("exploit_active")),
                "exploit_maturity": scored.get("exploit_maturity"),
                "network_exposure": scored.get("network_exposure"),
                "network_exposure_source": scored.get("network_exposure_source"),
                "cwe": normalize_cwes(entry.get("cwe")),
                "title": (cve or script_id or "")[:500],
            }

            if row is None:
                days, source = _resolve_sla_days(
                    session,
                    tenant_id=tenant_id,
                    severity=severity,
                    criticality=asset.asset_criticality,
                )
                candidate = models.Vulnerability(
                    vuln_id=f"vln_{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    asset_id=asset.asset_id,
                    finding_key=key,
                    cve=cve,
                    script_id=script_id,
                    port=port,
                    detectors=merge_detectors([], observed),
                    state=vuln_states.OPEN,
                    state_changed_at=now,
                    # Remediation ownership starts at whoever owns the asset, so
                    # a new finding is never unassigned when the platform knows
                    # who to ask. It is then edited independently (see model).
                    assignee=asset.owner_email,
                    owner_team=asset.business_unit,
                    due_at=now + timedelta(days=days),
                    sla_days=days,
                    sla_source=source,
                    first_seen_at=now,
                    last_seen_at=now,
                    sla_started_at=now,
                    first_seen_run_id=run_id,
                    last_seen_run_id=run_id,
                    observation_count=1,
                    created_at=now,
                    updated_at=now,
                    **latest,
                )
                # ON CONFLICT DO NOTHING: another writer can commit this very
                # key between the read above and this insert — the retro
                # matcher (retro_findings.py) shares the key by design. A bare
                # flush would abort the whole run's transaction on the unique
                # constraint and every finding of the run with it; losing the
                # race instead means the row exists, and this observation
                # updates it like any re-observation. Not a SAVEPOINT: this
                # loop inserts every new finding of the run in one
                # transaction, and a subtransaction per row overflows
                # Postgres's subxid cache past 64 (engine.insert_or_skip).
                if insert_or_skip(session, candidate, conflict=["tenant_id", "finding_key"]):
                    row = candidate
                    created += 1
                    _record_event(
                        session,
                        vuln_id=row.vuln_id,
                        tenant_id=tenant_id,
                        kind="observed",
                        occurred_at=now,
                        to_state=vuln_states.OPEN,
                        detail={
                            "run_id": run_id,
                            "first_seen": True,
                            "severity": severity,
                            "due_at": _iso(row.due_at),
                            "sla_days": days,
                            "sla_source": source,
                        },
                    )
                    continue
                row = session.execute(
                    select(models.Vulnerability).where(
                        models.Vulnerability.tenant_id == tenant_id,
                        models.Vulnerability.finding_key == key,
                    )
                ).scalar_one()

            # Weighed before ``latest`` is written over the row: an escalation
            # is a difference between what the verdict was made on and what
            # this run says. Shared with the endpoint-software observer.
            outcome = weigh_fp_verdict(
                session,
                row,
                latest,
                tenant_id=tenant_id,
                now=now,
                detail={"run_id": run_id, "severity": severity},
            )

            for field, value in latest.items():
                setattr(row, field, value)
            row.last_seen_at = now
            row.last_seen_run_id = run_id
            # A new list, not an in-place edit: the JSON column is not a
            # mutable type, so only an assignment is written back.
            row.detectors = merge_detectors(row.detectors, observed)
            row.observation_count += 1
            row.updated_at = now
            reobserved += 1
            if row.source == "retro_match":
                # A scan has now observed what the retro matcher inferred from
                # a stored banner. Same key, same row (retro_findings.py): it
                # becomes a scan finding, verifiable and closable the scan way,
                # and stops claiming a confidence it no longer needs. The
                # evidence stays as the record of how it was first found.
                row.source = "scan"
                row.match_confidence = None

            if outcome == FP_HELD:
                fp_suppressed_observations += 1
                continue
            if outcome == FP_OVERRIDDEN:
                fp_overridden += 1

            if row.state == vuln_states.CLOSED:
                # A regression: it was closed and it is back. The SLA clock
                # restarts from this observation, because the deadline for
                # fixing something that returned is not measured from before it
                # was fixed the first time.
                #
                # Except after an endpoint_unreachable closure: nothing was
                # fixed, the port was out of one sensor's reach for one run.
                # Restarting the clock there would let a verify/reopen cycle
                # reset an overdue finding's deadline as often as anyone
                # pressed Verify (#451), so it continues from where it was —
                # within max(sla_days, 30) days of that closure. Seen again
                # later than that, it is a new exposure (a redeploy months
                # on), and its clock starts now like any other regression's.
                previous = row.state
                days, source = _resolve_sla_days(
                    session,
                    tenant_id=tenant_id,
                    severity=severity,
                    criticality=asset.asset_criticality,
                )
                continue_clock = (
                    row.closure_reason == ENDPOINT_UNREACHABLE
                    and row.closed_at is not None
                    and now - row.closed_at
                    <= timedelta(days=max(row.sla_days or days, ENDPOINT_UNREACHABLE_SLA_WINDOW_MIN_DAYS))
                )
                row.state = vuln_states.OPEN
                row.state_changed_at = now
                row.state_changed_by = None
                row.closed_at = None
                # Same reset the operator reopen in ``transition`` does. Without
                # it a finding that came back kept asserting it had been
                # machine-verified as fixed, which is the one claim this column
                # exists to make un-fakeable.
                row.machine_verified = False
                if not continue_clock:
                    row.sla_started_at = now
                    row.due_at = now + timedelta(days=days)
                    row.sla_days = days
                    row.sla_source = source
                row.reopen_count += 1
                reopened += 1
                detail: dict[str, Any] = {"run_id": run_id, "reopen_count": row.reopen_count}
                if continue_clock:
                    detail["sla_continued"] = True
                    detail["after"] = ENDPOINT_UNREACHABLE
                # Either the suppression ran out or an escalation broke it.
                # Both mean the verdict no longer holds.
                if drop_fp_verdict_on_reopen(row):
                    detail["after_fp_suppression"] = True
                    if outcome == FP_OVERRIDDEN:
                        detail["fp_overridden"] = True
                row.closure_reason = None
                _record_event(
                    session,
                    vuln_id=row.vuln_id,
                    tenant_id=tenant_id,
                    kind="reopened",
                    occurred_at=now,
                    from_state=previous,
                    to_state=vuln_states.OPEN,
                    note="Re-observed after being closed",
                    detail=detail,
                )
            else:
                _record_event(
                    session,
                    vuln_id=row.vuln_id,
                    tenant_id=tenant_id,
                    kind="observed",
                    occurred_at=now,
                    to_state=row.state,
                    detail={"run_id": run_id, "severity": severity},
                )

        # Close the loop, but only for the findings this run was dispatched to
        # re-check. Gating on ``verification_job_id`` rather than on "some scan
        # touched the asset" is the whole safety property: a routine recon run
        # that never probed the affected port must not be allowed to assert
        # that the finding is gone.
        verification_jobs = {
            job_id
            for (job_id,) in session.execute(
                select(models.Job.job_id).where(models.Job.run_id == run_id)
            )
        }
        if verification_jobs:
            awaiting = session.scalars(
                select(models.Vulnerability).where(
                    models.Vulnerability.tenant_id == tenant_id,
                    models.Vulnerability.state == vuln_states.VERIFYING,
                    models.Vulnerability.verification_job_id.in_(verification_jobs),
                )
            ).all()

            for v_row in awaiting:
                if v_row.last_seen_run_id == run_id:
                    # Still there: the fix did not take. Back to FIXING, and the
                    # bounce is on the record.
                    v_row.state = vuln_states.FIXING
                    v_row.state_changed_at = now
                    v_row.state_changed_by = "system:verification"
                    v_row.last_verified_at = now
                    v_row.updated_at = now
                    _record_event(
                        session,
                        vuln_id=v_row.vuln_id,
                        tenant_id=tenant_id,
                        kind="verification_failed",
                        occurred_at=now,
                        from_state=vuln_states.VERIFYING,
                        to_state=vuln_states.FIXING,
                        actor="system:verification",
                        note=f"Still observed by verification run {run_id}",
                        detail={"run_id": run_id, "job_id": v_row.verification_job_id},
                    )
                    verification_failed += 1
                    continue
                # The run that was sent to look for it did not find it. That
                # is evidence of a fix only if it demonstrably looked: every
                # detector of the finding re-checked its endpoint in this run
                # (#451). A skipped nuclei, a template the run never loaded,
                # a Pulse that did not match CVEs, a backend without NSE, a
                # port that did not answer — each used to close the finding as
                # verified-fixed here.
                addresses = _asset_hosts(session, v_row)
                gaps, waived = coverage.assess(
                    list(v_row.detectors or []),
                    port=v_row.port,
                    asset_hosts=addresses,
                )
                unreachable = (
                    coverage.endpoint_unreachable(
                        _finding_hosts(v_row, addresses),
                        verification_coverage.port_of(v_row.port),
                        protocol=verification_coverage.finding_protocol(list(v_row.detectors or [])),
                    )
                    if gaps
                    else None
                )
                if unreachable is not None and not _same_vantage(v_row, vantage):
                    # A refusal is about the path from where the run looked.
                    # One from a DMZ sensor says nothing about what an internal
                    # one saw, and a finding seen from two places is not shown
                    # unreachable from either: it closes nothing.
                    gaps = [
                        *gaps,
                        {
                            "detector": "vantage",
                            "ref": None,
                            "host": None,
                            "port": v_row.port,
                            "reason": "vantage_differs",
                            "observed_from": sorted(_observed_vantages(v_row)) or [UNKNOWN_VANTAGE],
                            "verified_from": (vantage or {}).get("vantage") or UNKNOWN_VANTAGE,
                        },
                    ]
                    unreachable = None
                if unreachable is not None:
                    # No detector re-checked it because nothing got through:
                    # the port was asked about in a batch that finished, nothing
                    # saw it open, and every connect was refused, from the one
                    # vantage that ever observed the finding. That is "not
                    # reachable from there", not a fix: an iptables or
                    # kube-proxy REJECT, a tcp-reset rule or a fail2ban ban in
                    # front of a listening port is refused the same way. So it
                    # closes, and is never machine-verified, exposure or CVE.
                    verified_from = (vantage or {}).get("vantage") or UNKNOWN_VANTAGE
                    v_row.state = vuln_states.CLOSED
                    v_row.state_changed_at = now
                    v_row.state_changed_by = "system:verification"
                    v_row.closed_at = now
                    v_row.last_verified_at = now
                    v_row.machine_verified = False
                    v_row.closure_reason = ENDPOINT_UNREACHABLE
                    dropped_exception = _drop_exception(v_row)
                    v_row.updated_at = now
                    _record_event(
                        session,
                        vuln_id=v_row.vuln_id,
                        tenant_id=tenant_id,
                        kind="verification_unreachable",
                        occurred_at=now,
                        from_state=vuln_states.VERIFYING,
                        to_state=vuln_states.CLOSED,
                        actor="system:verification",
                        note=(
                            f"Verification run {run_id}: port {v_row.port} not reachable "
                            f"from {verified_from} (connect refused on every attempt); "
                            "closed, not machine-verified"
                        ),
                        detail={
                            "run_id": run_id,
                            "job_id": v_row.verification_job_id,
                            "machine_verified": False,
                            "closure_reason": ENDPOINT_UNREACHABLE,
                            "evidence": unreachable,
                            "verified_from": vantage,
                            "gaps": gaps,
                            **dropped_exception,
                        },
                    )
                    verification_unreachable += 1
                    continue
                if gaps:
                    _send_back_inconclusive(
                        session,
                        v_row,
                        now=now,
                        note=(
                            f"Not observed by verification run {run_id}, but the run does not "
                            "show that it looked: "
                            f"{verification_coverage.describe(gaps)}"
                        ),
                        detail={
                            "run_id": run_id,
                            "job_id": v_row.verification_job_id,
                            "gaps": gaps,
                            "verified_from": vantage,
                        },
                    )
                    verification_inconclusive += 1
                    continue
                v_row.state = vuln_states.CLOSED
                v_row.state_changed_at = now
                v_row.state_changed_by = "system:verification"
                v_row.closed_at = now
                v_row.last_verified_at = now
                v_row.machine_verified = True
                v_row.closure_reason = "verified_remediated"
                # The same erasure the operator's close does: a fixed
                # finding carries no risk to accept, and an acceptance left
                # on it stayed in the risk register and was still swept
                # into an "it lapsed" audit row weeks later.
                dropped_exception = _drop_exception(v_row)
                v_row.updated_at = now
                _record_event(
                    session,
                    vuln_id=v_row.vuln_id,
                    tenant_id=tenant_id,
                    kind="verification_passed",
                    occurred_at=now,
                    from_state=vuln_states.VERIFYING,
                    to_state=vuln_states.CLOSED,
                    actor="system:verification",
                    note=f"Not observed by verification run {run_id}",
                    detail={
                        "run_id": run_id,
                        "job_id": v_row.verification_job_id,
                        "machine_verified": True,
                        "closure_reason": "verified_remediated",
                        # Which rule the closure passed: every recorded
                        # detector, or the legacy Pulse rule for a row that
                        # has none (verification_coverage.py).
                        "coverage_rule": "detectors" if v_row.detectors else "legacy",
                        "verified_from": vantage,
                        # NSE detectors another detector of the finding stood
                        # in for (verification_coverage.assess).
                        **({"waived": waived} if waived else {}),
                        **dropped_exception,
                    },
                )
                verification_passed += 1

    stats = RegisterStats(
        findings_seen=len(entries),
        created=created,
        reobserved=reobserved,
        reopened=reopened,
        skipped_unknown_asset=skipped,
        verification_passed=verification_passed,
        verification_failed=verification_failed,
        verification_inconclusive=verification_inconclusive,
        verification_unreachable=verification_unreachable,
        fp_suppressed=fp_suppressed_observations,
        fp_overridden=fp_overridden,
    )
    LOG.info(
        "Vulnerability tracker: run=%s tenant=%s seen=%s created=%s reobserved=%s "
        "reopened=%s skipped=%s verification passed=%s failed=%s inconclusive=%s "
        "unreachable=%s",
        run_id,
        tenant_id,
        stats.findings_seen,
        stats.created,
        stats.reobserved,
        stats.reopened,
        stats.skipped_unknown_asset,
        stats.verification_passed,
        stats.verification_failed,
        stats.verification_inconclusive,
        stats.verification_unreachable,
    )

    try:
        from api.services import risk_snapshots

        risk_snapshots.take_snapshot(settings, tenant_id=tenant_id, source="run", now=now)
    except Exception:  # noqa: BLE001
        LOG.warning(
            "Failed to record risk snapshot for run %s tenant %s",
            run_id,
            tenant_id,
            exc_info=True,
        )

    return stats


def release_unfinished_verification(
    settings: Settings, *, tenant_id: str, job_id: str, run_id: str | None, status: str
) -> int:
    """Send the findings a failed or cancelled verification job held back to FIXING.

    Only a succeeded run reaches :func:`register_findings_from_run`
    (``run_completion.POST_PUBLICATION``), so a verification whose scan failed
    or was cancelled left its finding in ``VERIFYING`` with nothing looking at
    it — until somebody noticed and moved it by hand. It is the same outcome
    as a run that did not cover the finding: ``verification_inconclusive``,
    back to ``FIXING``, never machine-verified. Keyed on the job, not the run
    id, which a tenant may reuse. Idempotent: a second pass finds nothing in
    ``VERIFYING`` behind this job. Returns how many findings it moved.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(
            select(models.Vulnerability).where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.state == vuln_states.VERIFYING,
                models.Vulnerability.verification_job_id == job_id,
            )
        ).all()
        for row in rows:
            _send_back_inconclusive(
                session,
                row,
                now=now,
                note=(
                    f"Verification job {job_id} ended {status} before its run could show "
                    "anything; the finding is neither verified fixed nor seen again"
                ),
                detail={
                    "run_id": run_id,
                    "job_id": job_id,
                    "job_status": status,
                    "gaps": [],
                },
            )
    if rows:
        LOG.info(
            "Verification job %s (tenant %s) ended %s: %d finding(s) back to FIXING",
            job_id,
            tenant_id,
            status,
            len(rows),
        )
    return len(rows)


# --------------------------------------------------------------------------
# Operator decisions
# --------------------------------------------------------------------------


def _to_dict(row: models.Vulnerability, *, now: datetime | None = None) -> dict[str, Any]:
    now = now or _now()
    bdu = bdu_fstec.lookup(row.cve)
    return {
        "vuln_id": row.vuln_id,
        "tenant_id": row.tenant_id,
        "asset_id": row.asset_id,
        "finding_key": row.finding_key,
        "source": row.source,
        "device_id": row.device_id,
        "cve": row.cve,
        "bdu_ids": list(bdu["bdu_ids"]),
        "bdu_source": bdu["source"],
        "bdu_updated": bdu["updated"],
        "bdu_source_sha256": bdu["source_sha256"],
        "cwe": list(row.cwe or []),
        "script_id": row.script_id,
        "port": row.port,
        "detectors": [
            dict(entry)
            for entry in (row.detectors or [])
            if isinstance(entry, dict) and entry.get("detector")
        ],
        "title": row.title,
        "severity": row.severity,
        "risk_level": row.risk_level,
        "contextual_score": row.contextual_score,
        "cvss": row.cvss,
        "in_kev": bool(row.in_kev),
        "exploit_maturity": row.exploit_maturity,
        "network_exposure": row.network_exposure,
        "network_exposure_source": row.network_exposure_source,
        "state": row.state,
        "state_changed_at": _iso(row.state_changed_at),
        "state_changed_by": row.state_changed_by,
        "assignee": row.assignee,
        "owner_team": row.owner_team,
        "due_at": _iso(row.due_at),
        "sla_days": row.sla_days,
        "sla_source": row.sla_source,
        "sla_state": sla_state(row, now=now),
        "exception_until": _iso(row.exception_until),
        "exception_reason": row.exception_reason,
        "exception_by": row.exception_by,
        "exception_state": row.exception_state or vuln_states.EXCEPTION_NONE,
        "exception_requested_by": row.exception_requested_by,
        "exception_requested_at": _iso(row.exception_requested_at),
        "exception_requested_until": _iso(row.exception_requested_until),
        "exception_decided_by": row.exception_decided_by,
        "exception_decided_at": _iso(row.exception_decided_at),
        "exception_decision_note": row.exception_decision_note,
        "exception_requested_reason": row.exception_requested_reason,
        "exception_approved_at": _iso(row.exception_approved_at),
        "exception_approved_requested_by": row.exception_approved_requested_by,
        "exception_expired_at": _iso(row.exception_expired_at),
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "sla_started_at": _iso(row.sla_started_at),
        "first_seen_run_id": row.first_seen_run_id,
        "last_seen_run_id": row.last_seen_run_id,
        "observation_count": row.observation_count,
        "reopen_count": row.reopen_count,
        "closed_at": _iso(row.closed_at),
        "ticket_system": row.ticket_system,
        "ticket_key": row.ticket_key,
        "ticket_url": row.ticket_url,
        "ticket_synced_at": _iso(row.ticket_synced_at),
        "ticket_sync_error": row.ticket_sync_error,
        "ticket_remote_status": row.ticket_remote_status,
        "machine_verified": bool(row.machine_verified),
        "verification_job_id": row.verification_job_id,
        "last_verified_at": _iso(row.last_verified_at),
        "closure_reason": row.closure_reason,
        "fp_reason": row.fp_reason,
        "fp_marked_by": row.fp_marked_by,
        "fp_marked_at": _iso(row.fp_marked_at),
        "fp_evidence": dict(row.fp_evidence or {}),
        "fp_suppress_until": _iso(row.fp_suppress_until),
        "fp_observations": row.fp_observations,
        "fp_suppressed": _fp_suppressed(row, now),
        "match_confidence": row.match_confidence,
        "match_evidence": dict(row.match_evidence) if row.match_evidence else None,
    }


#: What a workflow event (#349) carries about a finding. A deliberate subset of
#: :func:`_to_dict`: a webhook payload crosses the trust boundary and is stored
#: in ``webhook_deliveries``, so it names the finding, says how bad it is and
#: who owns it, and leaves the false-positive evidence and the observation
#: bookkeeping where they are.
WORKFLOW_EVENT_FIELDS = (
    "vuln_id",
    "asset_id",
    "cve",
    "script_id",
    "port",
    "title",
    "severity",
    "risk_level",
    "cvss",
    "in_kev",
    "state",
    "assignee",
    "owner_team",
    "due_at",
    "sla_days",
    "sla_state",
    "ticket_system",
    "ticket_key",
)


def workflow_event_data(row: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """The finding fields one workflow event carries, plus its own extras.

    Shared by the write paths here and by ``api/services/sla_escalation.py`` so
    that ``sla_breached`` and ``vuln_state_changed`` describe a finding the same
    way — a receiver should not need two parsers for two events about one row.
    """
    data = {key: row.get(key) for key in WORKFLOW_EVENT_FIELDS}
    data.update(extra)
    return data


def _event_to_dict(row: models.VulnerabilityEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "vuln_id": row.vuln_id,
        "tenant_id": row.tenant_id,
        "occurred_at": _iso(row.occurred_at),
        "kind": row.kind,
        "from_state": row.from_state,
        "to_state": row.to_state,
        "actor": row.actor,
        "note": row.note,
        "detail": dict(row.detail or {}),
    }


def _load(session: Any, *, tenant_id: str | None, vuln_id: str) -> models.Vulnerability | None:
    row = session.get(models.Vulnerability, vuln_id)
    if row is None or (tenant_id is not None and row.tenant_id != tenant_id):
        return None
    return row


def get_vulnerability(
    settings: Settings, *, tenant_id: str | None, vuln_id: str
) -> dict[str, Any] | None:
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        return _to_dict(row) if row else None


def transition(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    to_state: str,
    actor: str | None = None,
    note: str | None = None,
) -> dict[str, Any] | None:
    """Move one finding through the lifecycle. Raises on an illegal move.

    Closing clears any accepted exception: the acceptance was a statement about
    an open risk, and leaving it on a closed row would suspend the SLA clock of
    a finding that came back later.
    """
    to_state = str(to_state or "").strip().upper()
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        previous = row.state
        vuln_states.check_transition(vuln_id, previous, to_state)

        row.state = to_state
        row.state_changed_at = now
        row.state_changed_by = actor
        row.updated_at = now
        kind = "state_change"
        detail: dict[str, Any] = {}

        if to_state == vuln_states.CLOSED:
            row.closed_at = now
            # ``machine_verified`` is never taken from the caller. A closure
            # made by hand is a manual closure however it is described, and a
            # metric an operator can assert about their own work measures
            # nothing.
            row.machine_verified = False
            row.closure_reason = "manual"
            detail["closure_reason"] = row.closure_reason
            detail.update(_drop_exception(row))
        elif previous == vuln_states.CLOSED:
            # The operator reopen. Same clock reset as the observer's regression
            # path, and recorded as the same kind of event so "how often does
            # this come back" is one query.
            kind = "reopened"
            row.closed_at = None
            row.machine_verified = False
            if drop_fp_verdict_on_reopen(row):
                detail["after_fp_suppression"] = True
            row.closure_reason = None
            row.sla_started_at = now
            days = row.sla_days or DEFAULT_SLA_DAYS.get(row.severity, DEFAULT_SLA_DAYS["unknown"])
            row.due_at = now + timedelta(days=days)
            row.reopen_count += 1
            detail["reopen_count"] = row.reopen_count

        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind=kind,
            occurred_at=now,
            from_state=previous,
            to_state=to_state,
            actor=actor,
            note=note,
            detail=detail,
        )
        session.flush()
        result = _to_dict(row, now=now)
        ticket = (row.ticket_system, row.ticket_key)

    # Outbound reflection runs *after* the transaction closes: the tracker is a
    # foreign service with a ten-second budget, and holding a row lock open for
    # that long is how one slow Jira stalls the vulnerability table.
    if ticket[0] and ticket[1]:
        push_ticket_state(
            settings,
            tenant_id=tenant_id,
            ticket_system=ticket[0],
            ticket_key=ticket[1],
            to_state=to_state,
        )
    # Also after the commit, and for the stronger version of the same reason:
    # the fan-out writes rows of its own, and an event announcing a transition
    # that then rolled back would be a notification about something that did
    # not happen. One kind for the move and the reopen alike — ``reopened`` is
    # a move whose ``from_state`` says so, and a receiver filtering on the kind
    # should not have to know both spellings (#349).
    workflow_events.emit(
        settings,
        "vuln_state_changed",
        tenant_id=result["tenant_id"],
        subject_id=vuln_id,
        # The change's own timestamp: two moves of one finding are two events,
        # a retried publish of one move is not.
        marker=str(result["state_changed_at"] or ""),
        data=workflow_event_data(
            result,
            from_state=previous,
            to_state=to_state,
            reopened=kind == "reopened",
            actor=actor,
            note=note,
        ),
        occurred_at=now,
    )
    return result


def _ticket_endpoint(
    session: Any, *, tenant_id: str, ticket_system: str
) -> tuple[str, str | None, dict[str, str], dict[str, Any]] | None:
    """``(base_url, secret, headers, config)`` for the tenant's tracker, or ``None``.

    ``config`` is the subscription's ``transport_config`` — non-secret adapter
    knobs, of which ``auth_mode`` is the one both directions of the sync need
    (#347): a Jira Cloud token presented as ``Bearer`` is a 401.

    The tracker is addressed through the subscription that configured it, not
    by string-splitting the stored ``ticket_url``: that is where the credential
    lives, and a URL we did not configure is a URL we should not be calling.

    Imported here rather than at module scope because ``webhooks`` imports this
    module — the credential lives in its table, so it owns decrypting it (#310).
    """
    from api.services.integrations import webhooks as webhooks_service

    row = session.scalar(
        select(models.WebhookSubscription)
        .where(
            models.WebhookSubscription.tenant_id == tenant_id,
            models.WebhookSubscription.transport == ticket_system,
            models.WebhookSubscription.enabled.is_(True),
        )
        .order_by(models.WebhookSubscription.created_at.desc())
    )
    if row is None:
        return None
    secret, headers = webhooks_service.endpoint_credentials(row)
    return str(row.url), secret, headers, dict(row.transport_config or {})


#: The overlay version a verification job asks of its sensor, whatever its
#: overlay carries: v2 is the build that loads pinned nuclei templates and
#: writes the coverage evidence (nuclei.json ``coverage``, ``adapter.cve`` and
#: ``adapter.ruleset`` in pulse/raw.json, the port-scan record) the closure is
#: judged on. A v1 sensor's run of a pulse-only verification would carry none
#: of it and end inconclusive every time.
VERIFICATION_OVERLAY_VERSION = 2
VERIFICATION_CAPABILITY = f"config_overlay.v{VERIFICATION_OVERLAY_VERSION}"


def _verification_sensors(settings: Settings, tenant_id: str, group: str | None) -> list[frozenset[str]]:
    """The capabilities of each live sensor that would be offered the job.

    ``group`` is the one the job will carry (the observing group, held to the
    approved scope): only that group's sensors claim it. With none, any
    scanner sensor of the tenant does — a grouped one takes ungrouped jobs too.
    A tenant-wide answer here once refused nothing while the job went to a
    group of v1 sensors and sat in VERIFYING behind 426s (#451 review).
    """
    from api.services import agent_groups as agent_groups_service

    if group:
        return agent_groups_service.live_groups(settings, {tenant_id}).get((tenant_id, group), [])
    return agent_groups_service.live_sensors(settings, {tenant_id}).get(tenant_id, [])


GROUP_DELETED = "group_deleted"
NO_LIVE_SENSOR_FOR = "no_live_sensor_for_"


def _duration(seconds: float) -> str:
    """``45m``, ``3h``, ``2d``: rounded down, for a reason code and a note."""
    seconds = max(0, int(seconds))
    if seconds >= 86400:
        return f"{seconds // 86400}d"
    if seconds >= 3600:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


def _regroup_wording(reason: str) -> str:
    """How a verification's event and refusal say why it left its group."""
    if reason == GROUP_DELETED:
        return "was deleted"
    return f"has had no live sensor for {reason.removeprefix(NO_LIVE_SENSOR_FOR)}"


def _observing_group_gone(
    settings: Settings, tenant_id: str, group: str | None, *, now: datetime
) -> str | None:
    """Why the finding's observing group cannot take its verification, or None.

    ``group_deleted`` when the tenant no longer has the group;
    ``no_live_sensor_for_<duration>`` when nothing in it could claim a job
    for longer than ``verification_regroup_grace_seconds`` (sensors moved
    out, decommissioned, refused at claim). Either way pinning the job there
    would be refused or sit queued forever, so the verification goes out
    tenant-wide instead — and since that is another vantage, a refusal from
    it closes nothing (``vantage_differs``); coverage closes as before.

    Inside the grace period the answer is a refusal, not a reroute: a sensor
    that missed two heartbeats while restarting is not a group gone, and the
    tenant-wide fallback looks from another network path (#451 review, round
    3). Raises :class:`VerificationDispatchError` then.
    """
    from api.services import agent_groups as agent_groups_service

    if not group:
        return None
    if agent_groups_service.live_groups(settings, {tenant_id}).get((tenant_id, group)):
        return None
    heard = agent_groups_service.last_heard_from(settings, tenant_id=tenant_id, name=group)
    if heard is None:
        return GROUP_DELETED
    silent = (now - heard).total_seconds()
    if silent > settings.verification_regroup_grace_seconds:
        return f"{NO_LIVE_SENSOR_FOR}{_duration(silent)}"
    raise VerificationDispatchError(
        f"The observing sensor group '{group}' has no live sensor right now (none for "
        f"{_duration(silent)}): retry once one reports in. After "
        f"{_duration(settings.verification_regroup_grace_seconds)} without one the "
        "verification goes to any sensor of the tenant instead."
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class VerificationPlan:
    """What one verification re-scan is sent to do, from the finding's detectors.

    ``ips``/``names`` are the hosts the detectors observed it on, spelled as
    they saw them — a finding a template matched on a virtual host is re-checked
    on that name, not on the address behind it. ``template_ids`` pins nuclei to
    the templates that found it, whatever their severity; ``nse`` turns the
    service probe to ``hybrid`` so the NSE script that found it runs at all.
    """

    ips: tuple[str, ...]
    names: tuple[str, ...]
    template_ids: tuple[str, ...]
    nse: bool
    from_detectors: bool
    # The sensor group the newest detector that recorded one observed it
    # from: the re-scan goes out from there, so "not observed" is about the
    # same network path (#451). None when no detector recorded a group.
    agent_group: str | None = None

    def config_extra(self) -> dict[str, Any]:
        # The connect probe of the finding's port, always: it is the only
        # evidence that tells a refused port from a dropped one, and a
        # closure as endpoint_unreachable rests on it (reachability.py).
        extra: dict[str, Any] = {"reachability": {"enabled": True}}
        if self.template_ids:
            extra["nuclei"] = {"enabled": True, "template_ids": list(self.template_ids)}
        if self.nse:
            extra["service_probe"] = {"backend": "hybrid"}
        return extra

    def as_detail(self) -> dict[str, Any]:
        return {
            "targets": [*self.ips, *self.names],
            "targets_from": "detectors" if self.from_detectors else "asset",
            "template_ids": list(self.template_ids),
            "nse": self.nse,
            "agent_group": self.agent_group,
        }


def _verification_plan(session: Any, row: models.Vulnerability) -> VerificationPlan:
    """Build the re-scan from ``row.detectors``; refuse what it cannot re-check.

    A detector without a host (backfilled by 0079) or a row with none at
    all adds every address of the asset to the targets, because its closure
    then needs coverage on each of them (verification_coverage.assess).
    """
    detectors = [entry for entry in (row.detectors or []) if isinstance(entry, dict)]
    hosts = {str(entry["host"]).strip() for entry in detectors if entry.get("host")}
    if not detectors or any(not entry.get("host") for entry in detectors):
        # A detector that never recorded where it looked is held to every
        # address of the asset (verification_coverage.assess), so every one of
        # them is scanned: the IPs, or the names of an asset known by none.
        addresses = _asset_hosts(session, row)
        asset_ips = {host for host in addresses if _is_ip(host)}
        hosts |= asset_ips or addresses
    if not hosts:
        raise VerificationDispatchError(
            f"Vulnerability '{row.vuln_id}' has no scannable address on record"
        )
    ips = tuple(sorted(host for host in hosts if _is_ip(host)))
    names = tuple(sorted(host for host in hosts if not _is_ip(host)))
    refs = sorted(
        {
            str(entry.get("ref") or "").strip()
            for entry in detectors
            if entry.get("detector") == verification_coverage.NUCLEI
        }
        - {""}
    )
    refused = [ref for ref in refs if NUCLEI_TEMPLATE_ID_RE.fullmatch(ref) is None]
    if refused or len(refs) > MAX_NUCLEI_TEMPLATE_IDS:
        # Pinned or not at all: a sweep that may or may not load the template
        # would be judged by a closure that requires it, and end inconclusive
        # every time. Refused here so the operator hears it now.
        raise VerificationDispatchError(
            f"Vulnerability '{row.vuln_id}' was found by nuclei templates a sensor "
            f"cannot be asked to load by id: {', '.join(refused) or len(refs)}"
        )
    return VerificationPlan(
        ips=ips,
        names=names,
        template_ids=tuple(refs),
        nse=any(entry.get("detector") == verification_coverage.NMAP_NSE for entry in detectors),
        from_detectors=bool(detectors) and all(entry.get("host") for entry in detectors),
        agent_group=next((str(e["agent_group"]) for e in detectors if e.get("agent_group")), None),
    )


def push_ticket_state(
    settings: Settings,
    *,
    tenant_id: str | None,
    ticket_system: str,
    ticket_key: str,
    to_state: str,
) -> bool:
    """Reflect a lifecycle change onto the linked ticket. Never raises."""
    if tenant_id is None:
        return False
    try:
        from api.services.integrations import ticket_sync

        with get_session(settings.postgres_url) as session:
            endpoint = _ticket_endpoint(
                session, tenant_id=tenant_id, ticket_system=ticket_system
            )
        if endpoint is None:
            LOG.info(
                "No enabled %s subscription for tenant %s; ticket %s not updated",
                ticket_system,
                tenant_id,
                ticket_key,
            )
            return False
        base_url, secret, headers, config = endpoint
        return ticket_sync.push_status_update(
            transport=ticket_system,
            base_url=base_url,
            ticket_key=ticket_key,
            to_state=to_state,
            secret=secret,
            extra_headers=headers,
            auth_mode=config.get("auth_mode"),
        )
    except Exception:  # noqa: BLE001 - a foreign tracker must not fail the move
        LOG.warning(
            "Outbound ticket sync failed for %s/%s", ticket_system, ticket_key, exc_info=True
        )
        return False


def trigger_verification(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
) -> dict[str, Any] | None:
    """Dispatch a targeted re-scan and park the finding in ``VERIFYING``.

    The move is refused if the scan could not be dispatched. A finding sitting
    in ``VERIFYING`` with nothing actually looking at it is the state that
    produces a false "machine verified" closure later, so it is never created.

    It is refused outright for a ``endpoint_software`` finding. The asset does
    have a scannable address, so a target would happily be found and a scan
    would happily run — and it would prove nothing, because an
    installed package is not something a port scan observes. The finding would
    then be closed as machine-verified on the strength of a scan that never
    looked at it, which is the exact thing this whole path exists to prevent.
    Its verification is the next inventory snapshot.

    The scan is built from the finding's detectors (``VerificationPlan``,
    #451): the hosts they observed it on, the nuclei templates that found it
    pinned by id whatever their severity, NSE turned on for an NSE finding.
    A name the approved scope no longer covers is refused, not swapped for the
    address behind it. What the run then has to show before the finding may
    close is ``verification_coverage``'s.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if row.source == "endpoint_software":
            raise VerificationDispatchError(
                f"Vulnerability '{vuln_id}' came from the endpoint software inventory, "
                "which a network re-scan cannot verify: a scan does not observe an "
                "installed package, so a 'machine verified' closure from one would be "
                "false. It is verified by the next accepted inventory snapshot from "
                "its device."
            )
        if row.source == "retro_match":
            # The same trap from the other side: the retro finding came from a
            # stored banner and a range statement, and the re-scan's CVE
            # checks may simply not know this CVE. Its silence would close the
            # finding as machine-verified. A rescan that *does* see it turns it
            # into a scan finding, which is verifiable (register_findings_from_run).
            raise VerificationDispatchError(
                f"Vulnerability '{vuln_id}' was inferred by retro matching from a stored "
                "service fingerprint, which a verification scan cannot disprove: the "
                "scan's own CVE checks may not cover it, and their silence would read as "
                "a fix. Re-scan the asset — if the scan observes it, it becomes a scan "
                "finding and can be verified — or close it with a reason."
            )
        previous = row.state
        # Goes through the same state machine as an operator's move: a closed
        # finding is not re-verified, it is reopened first.
        vuln_states.check_transition(vuln_id, previous, vuln_states.VERIFYING)

        plan = _verification_plan(session, row)

        owning_tenant = row.tenant_id
        port = str(row.port).strip() if row.port is not None else None

    if not settings.allow_scan_start:
        raise VerificationDispatchError(
            "Scan dispatch is disabled on this server (OCTO_ALLOW_SCAN_START), "
            "so this finding cannot be machine-verified"
        )
    # The group the re-scan goes out from: the observing one, unless that
    # one can no longer take it (deleted, or emptied by a regroup).
    requested_group = plan.agent_group
    regrouped: dict[str, Any] | None = None
    if settings.job_execution_mode == "agent":
        from api.services import agent_groups as agent_groups_service
        from api.services import scan_scopes as scopes

        gone = _observing_group_gone(settings, owning_tenant, plan.agent_group, now=now)
        if gone:
            regrouped = {"from": plan.agent_group, "reason": gone}
            requested_group = None
        ranges_text = "\n".join(plan.ips) or None
        domains_text = "\n".join(plan.names) or None
        try:
            # The group the job will carry, decided now as start_scan will:
            # the observing group, held to what the approved scope allows.
            group = agent_groups_service.resolve_for_scan(
                settings,
                tenant_id=owning_tenant,
                requested=requested_group,
                required=scopes.required_agent_groups(
                    settings,
                    tenant_id=owning_tenant,
                    ranges_text=ranges_text,
                    domains_text=domains_text,
                ),
            )
        except (ValueError, PermissionError) as exc:
            raise VerificationDispatchError(f"Could not dispatch a verification scan: {exc}") from exc
        live = _verification_sensors(settings, owning_tenant, group)
        if not any(VERIFICATION_CAPABILITY in capabilities for capabilities in live):
            # Refused rather than queued: the job would wait for a sensor
            # that may never come, with the finding parked in VERIFYING
            # meanwhile — the state this function exists never to create. A
            # local-execution installation runs the scan itself.
            where = f"sensor group '{group}'" if group else "this tenant"
            if regrouped and not group:
                where += f" (its observing group '{plan.agent_group}' {_regroup_wording(regrouped['reason'])})"
            if live:
                raise VerificationDispatchError(
                    f"No live sensor of {where} can run a verification re-scan: it needs "
                    f"capability {VERIFICATION_CAPABILITY} (a sensor from this release, which "
                    "loads pinned nuclei templates and records the coverage evidence the "
                    "closure is judged on). Upgrade a sensor there and verify again."
                )
            # Nothing there to upgrade: no active scanner sensor with a recent
            # heartbeat at or above the version floor.
            raise VerificationDispatchError(
                f"No live sensor of {where} can run a verification re-scan: none is "
                "active and reporting in, of scanner kind and at or above the version "
                f"floor. Bring one online (with capability {VERIFICATION_CAPABILITY}) "
                "and verify again."
            )

    from api.schemas import StartScanRequest
    from api.services import jobs as jobs_service
    from api.services import scan_scopes

    scan_request = StartScanRequest(
        tenant_id=owning_tenant,
        mode="safe",
        # The narrowest intent that still runs the vulnerability checks: the
        # verification has to be able to re-detect what it is confirming gone.
        intent="vuln",
        ranges="\n".join(plan.ips) or None,
        domains="\n".join(plan.names) or None,
        # Re-check the port the finding is on. Verifying a finding on 8443 with
        # a default port sweep is how "not observed" stops meaning "fixed".
        ports=port or None,
        skip_nse=False,
        agent_group=requested_group,
    )
    try:
        job = jobs_service.start_scan(
            settings,
            scan_request,
            username=actor or "system:verification",
            # The platform closing its own loop, not the customer spending an
            # entitlement: a quota-refused verification would strand the
            # finding in VERIFYING with nothing looking at it, which is the
            # exact state this function exists to never create.
            quota_exempt=True,
            # Aimed at one finding: widening it with the tenant's promoted
            # related domains is how "not observed" would stop meaning "fixed".
            widen_with_promoted=False,
            # The detectors' own settings, on the same path as the intent's.
            config_extra=plan.config_extra(),
            # Explicitly, not through some setting the overlay happens to
            # carry: a verification is only handed to a build that writes the
            # coverage evidence it will be judged on.
            min_overlay_version=VERIFICATION_OVERLAY_VERSION,
            verification_of=vuln_id,
        )
    except scan_scopes.ScanScopeDenied as exc:
        LOG.warning("Verification dispatch refused by scope for %s: %s", vuln_id, exc)
        denied = {str(target).lower() for target in exc.targets}
        names = [name for name in plan.names if name.lower() in denied] or (
            list(plan.names) if not denied else []
        )
        if names:
            raise VerificationDispatchError(
                f"Vulnerability '{vuln_id}' was observed on {', '.join(names)}, which "
                "the tenant's approved scan scope does not cover now. It is not re-checked "
                "on the address behind the name instead: a finding a check matched on a "
                "name (a virtual host) says nothing about the bare address, and a re-scan "
                "there would close it without having looked. Approve the name in the scan "
                "scope, or close the finding with a reason."
            ) from exc
        raise VerificationDispatchError(
            f"Could not dispatch a verification scan: {exc}"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as 409
        LOG.warning("Verification dispatch failed for %s: %s", vuln_id, exc, exc_info=True)
        raise VerificationDispatchError(
            f"Could not dispatch a verification scan: {exc}"
        ) from exc

    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        previous = row.state
        row.state = vuln_states.VERIFYING
        row.state_changed_at = now
        row.state_changed_by = actor or "system:verification"
        row.verification_job_id = job.job_id
        row.last_verified_at = now
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="verification_started",
            occurred_at=now,
            from_state=previous,
            to_state=vuln_states.VERIFYING,
            actor=actor or "system:verification",
            note=f"Targeted verification scan dispatched (job {job.job_id})"
            + (
                f"; observing sensor group '{regrouped['from']}' "
                f"{_regroup_wording(regrouped['reason'])}, so it went to any sensor of the "
                "tenant: a refused port cannot close it from there (vantage differs)"
                if regrouped
                else ""
            ),
            detail={
                "job_id": job.job_id,
                "asset_id": row.asset_id,
                "target": ", ".join([*plan.ips, *plan.names]),
                "port": port,
                "cve": row.cve,
                "script_id": row.script_id,
                "plan": plan.as_detail(),
                **({"regrouped": {**regrouped, "dispatched_group": job.agent_group}} if regrouped else {}),
            },
        )
        session.flush()
        return _to_dict(row, now=now)


def sync_ticket_status(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
) -> dict[str, Any] | None:
    """Poll the linked ticket and reconcile the finding's state, now.

    The operator's button. The same reconciliation runs on a cadence in
    ``api/services/integrations/ticket_sync_worker.py`` (#347); both end in
    :func:`apply_ticket_status`, so there is one place where a tracker's answer
    turns into a lifecycle move.

    A tracker can say the work is done or that it is under way. It cannot say
    the finding is *verified* gone — only a scan says that — so a closure from
    here is recorded as ``ticket_resolved`` and never as machine-verified.
    """
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if not row.ticket_system or not row.ticket_key:
            raise ValueError(f"Vulnerability '{vuln_id}' has no linked ticket")
        endpoint = _ticket_endpoint(
            session, tenant_id=row.tenant_id, ticket_system=row.ticket_system
        )
        if endpoint is None:
            raise ValueError(
                f"No enabled '{row.ticket_system}' subscription is configured for this tenant"
            )
        ticket_system, ticket_key = row.ticket_system, row.ticket_key

    from api.services.integrations import ticket_sync

    base_url, secret, headers, config = endpoint
    suggested_state, raw_status, payload = ticket_sync.fetch_ticket_status(
        transport=ticket_system,
        base_url=base_url,
        ticket_key=ticket_key,
        secret=secret,
        extra_headers=headers,
        auth_mode=config.get("auth_mode"),
    )
    return apply_ticket_status(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        suggested_state=suggested_state,
        raw_status=raw_status,
        error=payload.get("error") if isinstance(payload, dict) else None,
        actor=actor,
    )


def apply_ticket_status(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    suggested_state: str | None,
    raw_status: str | None,
    error: str | None = None,
    actor: str | None = None,
    record_unchanged: bool = True,
    only_on_remote_change: bool = False,
) -> dict[str, Any] | None:
    """Reconcile one finding against what its tracker just said.

    Split out of :func:`sync_ticket_status` for #347: the worker reads the
    subscription once and then polls many findings through it, so the part that
    needs a subscription and the part that needs a row had to stop being one
    function. No HTTP happens here.

    Two flags separate the two callers, and both exist because a poller may do
    things a button may not.

    ``record_unchanged``: the button always writes a ``ticket_synced`` event —
    an operator clicked, and "I checked and the tracker still says To Do" is
    exactly what the audit trail is for. The worker passes ``False``, because at
    one poll per linked finding per interval it would otherwise write a row per
    finding per tick into ``vulnerability_events``, which has no retention
    sweep, to record that nothing happened. It still writes the event whenever
    something *did* — a move, or the link starting or stopping to fail.

    ``only_on_remote_change``: the worker applies a suggestion only when the
    tracker's own status string differs from the one recorded at the last read
    (``ticket_remote_status``). Without it the poller re-imposes its own last
    verdict on any operator who disagreed with it: reopen a finding whose Jira
    issue is still ``Done`` — which is the normal case, since the outbound
    reflection cannot reopen an issue whose workflow has no reopen step — and
    the next tick closes it again, and the one after that, indefinitely. The
    button passes ``False``: a person clicking Sync is asking for the tracker's
    current word whatever it is.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if not row.ticket_system or not row.ticket_key:
            # Unlinked between the poller's due read and this write. Returning
            # here rather than recording is what keeps ``clear_ticket``'s reset
            # of the sync bookkeeping from being undone by a read that was
            # already in flight.
            return _to_dict(row, now=now)
        ticket_system = row.ticket_system
        ticket_key = row.ticket_key
        previous = row.state
        applied = False
        # A ticket coming back is a re-open like any other, so the verdict on
        # the row has to go with it — see ``drop_fp_verdict_on_reopen``.
        dropped_fp = False
        dropped_exception: dict[str, Any] = {}
        # Whether the tracker has said something new since the last read. A
        # never-polled finding counts as changed: the first read is the first
        # thing the tracker has ever told us.
        remote_changed = row.ticket_synced_at is None or raw_status != row.ticket_remote_status
        # Only a legal move is applied. An unreachable tracker returns no
        # suggestion at all, and that is recorded as a sync that changed
        # nothing rather than as progress.
        if (
            suggested_state
            and suggested_state != previous
            and (remote_changed or not only_on_remote_change)
            and vuln_states.can_transition(previous, suggested_state)
        ):
            row.state = suggested_state
            row.state_changed_at = now
            row.state_changed_by = actor or f"ticket_sync:{ticket_system}"
            row.updated_at = now
            applied = True
            if suggested_state == vuln_states.CLOSED:
                row.closed_at = now
                row.machine_verified = False
                row.closure_reason = "ticket_resolved"
                # As in every other closing path — see ``_drop_exception``.
                dropped_exception = _drop_exception(row)
            elif previous == vuln_states.CLOSED:
                # Same reopen bookkeeping the operator path does, so a
                # ticket-driven regression is not an SLA-free finding.
                row.closed_at = None
                row.machine_verified = False
                dropped_fp = drop_fp_verdict_on_reopen(row)
                row.closure_reason = None
                row.sla_started_at = now
                days = row.sla_days or DEFAULT_SLA_DAYS.get(
                    row.severity, DEFAULT_SLA_DAYS["unknown"]
                )
                row.due_at = now + timedelta(days=days)
                row.reopen_count += 1

        # The cursor moves on every attempt, including a failed one — see the
        # column's comment in api/db/models.py for why the alternative starves
        # the queue.
        was_failing = row.ticket_sync_error is not None
        row.ticket_synced_at = now
        row.ticket_sync_error = error or None
        if error is None:
            # Only a read that actually reached the tracker moves this. A
            # failed read must not record "the tracker now says nothing",
            # or recovering from an outage would look like a status change and
            # re-apply a verdict the operator had already overruled.
            row.ticket_remote_status = raw_status
        if record_unchanged or applied or was_failing != (error is not None):
            _record_event(
                session,
                vuln_id=row.vuln_id,
                tenant_id=row.tenant_id,
                kind="ticket_synced",
                occurred_at=now,
                from_state=previous,
                to_state=row.state,
                actor=actor or f"ticket_sync:{ticket_system}",
                note=(
                    f"Ticket {ticket_key} could not be read: {error}"
                    if error
                    else f"Ticket {ticket_key} reports '{raw_status or 'unknown'}'"
                ),
                detail={
                    "ticket_system": ticket_system,
                    "ticket_key": ticket_key,
                    "remote_status": raw_status,
                    "suggested_state": suggested_state,
                    "applied": applied,
                    **dropped_exception,
                    **({"error": error} if error else {}),
                    **({"after_fp_suppression": True} if dropped_fp else {}),
                },
            )
        session.flush()
        return _to_dict(row, now=now)


def assign(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    assignee: str | None = None,
    owner_team: str | None = None,
    actor: str | None = None,
    note: str | None = None,
    fields: set[str] | None = None,
) -> dict[str, Any] | None:
    """Set remediation ownership. ``fields`` names which keys were sent, so an
    explicit ``null`` unassigns instead of being read as "leave it alone"."""
    touched = fields if fields is not None else {"assignee", "owner_team"}
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        detail: dict[str, Any] = {}
        if "assignee" in touched:
            detail["assignee_from"] = row.assignee
            row.assignee = (assignee or "").strip() or None
            detail["assignee_to"] = row.assignee
        if "owner_team" in touched:
            detail["owner_team_from"] = row.owner_team
            row.owner_team = (owner_team or "").strip() or None
            detail["owner_team_to"] = row.owner_team
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="assigned",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail=detail,
        )
        session.flush()
        result = _to_dict(row, now=now)

    workflow_events.emit(
        settings,
        "vuln_assigned",
        tenant_id=result["tenant_id"],
        subject_id=vuln_id,
        # ``updated_at`` rather than the new assignee: unassigning is an
        # assignment event too, and two people handed the same finding in turn
        # are two events even if the second hands it back.
        marker=now.isoformat(),
        data=workflow_event_data(result, **detail, actor=actor, note=note),
        occurred_at=now,
    )
    return result


def _same_person(one: str | None, other: str | None) -> bool:
    """Whether two usernames name the same account, for the self-approval bar.

    Case- and whitespace-insensitive: usernames are compared elsewhere in this
    platform as stored, but a separation-of-duties check that ``Alice`` walks
    past because the request said ``alice`` is not a check.
    """
    return (one or "").strip().casefold() == (other or "").strip().casefold() != ""


#: What an exception audit row carries about the finding. The whole
#: :func:`_to_dict` would put a finding's entire assessment in ``before``/
#: ``after`` on every request, where the change is six fields — and the
#: 16 KiB document cap in ``audit.record`` is not somewhere to spend a payload
#: that nobody reads.
_EXCEPTION_AUDIT_FIELDS = (
    "vuln_id",
    "title",
    "severity",
    "state",
    "due_at",
    "exception_state",
    "exception_until",
    "exception_reason",
    "exception_by",
    "exception_requested_by",
    "exception_requested_until",
    "exception_requested_reason",
    "exception_decided_by",
    "exception_decision_note",
    "exception_approved_at",
    "exception_approved_requested_by",
    "exception_expired_at",
)


def _exception_document(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in _EXCEPTION_AUDIT_FIELDS}


def _drop_exception(row: models.Vulnerability) -> dict[str, Any]:
    """Erase an acceptance, in force or merely asked for, and say what went.

    Called from every closing path — the operator's transition, the false
    positive verdict, and the two the machine takes on its own (a verification
    run that no longer sees the finding, a ticket the tracker resolved). A
    closed finding has no risk to accept
    and no request worth answering, so the acceptance *and* the workflow state
    around it go together — leaving ``exception_state`` on a closed row would
    hand the approver a queue item for a finding nobody can act on, and would
    put it back in the register the next time it was reopened.
    """
    detail: dict[str, Any] = {}
    if row.exception_until is not None:
        detail["cleared_exception_until"] = _iso(row.exception_until)
    if (row.exception_state or vuln_states.EXCEPTION_NONE) != vuln_states.EXCEPTION_NONE:
        detail["cleared_exception_state"] = row.exception_state
    if not detail:
        return detail
    row.exception_until = None
    row.exception_reason = None
    row.exception_by = None
    row.exception_state = vuln_states.EXCEPTION_NONE
    row.exception_requested_by = None
    row.exception_requested_at = None
    row.exception_requested_until = None
    row.exception_decided_by = None
    row.exception_decided_at = None
    row.exception_decision_note = None
    row.exception_requested_reason = None
    row.exception_approved_at = None
    row.exception_approved_requested_by = None
    row.exception_expired_at = None
    return detail


def request_exception(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    until: datetime,
    reason: str,
    actor: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Ask for the risk to be accepted until ``until``. **Nothing is suspended.**

    Before #348 this call *was* the acceptance: one tenant admin wrote
    ``exception_until`` and the SLA clock stopped, with the requester and the
    approver being the same person. Now it opens a request that somebody
    holding ``vulnerability.exception.approve`` has to answer, and the clock
    keeps running while it waits — an SLA a request could pause would be an SLA
    anybody could pause by asking.

    An expiry and a reason are both still mandatory, for the reasons they
    always were: an acceptance with no end date is a decision nobody revisits,
    and one with no justification cannot be reviewed by whoever inherits it.
    Asking again while an acceptance is already in force is legal and is how an
    extension is requested — the acceptance in force stays in force until the
    new window is approved, because a pending request must not be able to
    shorten one that was granted.
    """
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("an exception needs a reason")
    until = _naive(until)
    now = _now()
    if until <= now:
        raise ValueError("exception_until must be in the future")

    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if row.state == vuln_states.CLOSED:
            raise ValueError("a closed finding has no risk to accept")
        before = _to_dict(row, now=now)
        vuln_states.check_exception_transition(
            vuln_id, row.exception_state, vuln_states.EXCEPTION_REQUESTED
        )
        if (
            row.exception_state == vuln_states.EXCEPTION_REQUESTED
            and not _same_person(row.exception_requested_by, actor)
        ):
            # Re-filing over your own pending ask is how a wrong date is fixed
            # (#348 debt); overwriting somebody else's is how their request
            # disappears without anybody deciding it. Whoever may answer it
            # rejects it instead.
            raise vuln_states.InvalidExceptionTransition(
                f"Vulnerability {vuln_id}: a request by "
                f"{row.exception_requested_by!r} is waiting for a decision"
            )
        row.exception_state = vuln_states.EXCEPTION_REQUESTED
        row.exception_requested_by = actor
        row.exception_requested_at = now
        row.exception_requested_until = until
        # The ask goes to its own column. Writing it to ``exception_reason``
        # let an unapproved justification replace the one somebody signed for,
        # which is the text the risk register prints as the reason the risk is
        # being carried.
        row.exception_requested_reason = reason[:2000]
        # The previous decision belongs to the previous request. The acceptance
        # in force is untouched: ``exception_until``, ``exception_reason``,
        # ``exception_by`` and the ``exception_approved_*`` pair keep saying
        # what is granted until this request is answered.
        row.exception_decided_by = None
        row.exception_decided_at = None
        row.exception_decision_note = None
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_requested",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=reason,
            detail={"requested_until": _iso(until)},
        )
        result = _to_dict(row, now=now)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_VULN_EXCEPTION_REQUEST,
            resource_type="vulnerability",
            resource_id=row.vuln_id,
            tenant_id=row.tenant_id,
            before=_exception_document(before),
            after=_exception_document(result),
        )
        session.flush()
        return result


def approve_exception(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str,
    note: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Grant a pending request, suspending the SLA clock until its expiry.

    Two people, enforced twice over: the route demands
    ``vulnerability.exception.approve`` (which the tenant ``admin`` who filed
    the request does not carry), and this refuses the requester by name even
    when they do hold it — a platform admin holds every permission, and
    "whoever asked cannot be whoever signed" has to hold for them too.

    ``due_at`` moves to the approved expiry, so the finding returns to the
    breach report the day the acceptance lapses rather than never.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        before = _to_dict(row, now=now)
        vuln_states.check_exception_transition(
            vuln_id, row.exception_state, vuln_states.EXCEPTION_APPROVED
        )
        if _same_person(row.exception_requested_by, actor):
            raise PermissionError(
                "the person who requested an exception cannot approve it; "
                "this decision needs a second pair of eyes"
            )
        until = _naive(row.exception_requested_until)
        if until is None or until <= now:
            # A request that sat in the queue past its own window. Approving it
            # would write an acceptance that is already lapsed, which reads in
            # every report as a granted exception nobody honoured.
            raise ValueError(
                "the requested window has already passed; ask for a new one"
            )
        row.exception_state = vuln_states.EXCEPTION_APPROVED
        row.exception_decided_by = actor
        row.exception_decided_at = now
        row.exception_decision_note = (note or "").strip()[:2000] or None
        row.exception_until = until
        row.exception_by = actor
        row.exception_reason = row.exception_requested_reason or row.exception_reason
        row.exception_approved_at = now
        row.exception_approved_requested_by = row.exception_requested_by
        # A new window has not lapsed, whatever happened to the previous one.
        row.exception_expired_at = None
        row.due_at = until
        row.sla_source = "exception"
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_approved",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail={
                "exception_until": _iso(until),
                "requested_by": row.exception_requested_by,
            },
        )
        result = _to_dict(row, now=now)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_VULN_EXCEPTION_APPROVE,
            resource_type="vulnerability",
            resource_id=row.vuln_id,
            tenant_id=row.tenant_id,
            before=_exception_document(before),
            after=_exception_document(result),
        )
        session.flush()
        return result


def reject_exception(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str,
    note: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Refuse a pending request. The finding keeps the deadline it had.

    Nothing about the SLA changes here, including when the request was an
    extension of an acceptance that is still in force: refusing to extend is
    not withdrawing what was already granted, and conflating the two would let
    a rejection shorten a window somebody had approved.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        before = _to_dict(row, now=now)
        vuln_states.check_exception_transition(
            vuln_id, row.exception_state, vuln_states.EXCEPTION_REJECTED
        )
        if _same_person(row.exception_requested_by, actor):
            raise PermissionError(
                "the person who requested an exception cannot decide it; "
                "this decision needs a second pair of eyes"
            )
        row.exception_state = vuln_states.EXCEPTION_REJECTED
        row.exception_decided_by = actor
        row.exception_decided_at = now
        row.exception_decision_note = (note or "").strip()[:2000] or None
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_rejected",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail={
                "requested_until": _iso(row.exception_requested_until),
                "requested_by": row.exception_requested_by,
            },
        )
        result = _to_dict(row, now=now)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_VULN_EXCEPTION_REJECT,
            resource_type="vulnerability",
            resource_id=row.vuln_id,
            tenant_id=row.tenant_id,
            before=_exception_document(before),
            after=_exception_document(result),
        )
        session.flush()
        return result


def withdraw_exception_request(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
    note: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Take back a pending request, leaving any granted acceptance alone.

    The half of :func:`clear_exception` that the console used to reach by
    accident. With an acceptance in force and an extension waiting on a
    decision, the only button on the card was "Withdraw", and it withdrew the
    *acceptance*: the second person's signature went with the typo the
    requester was trying to fix, and the finding was breached the moment the
    page reloaded. These are two acts with two authorities — the requester
    takes back their own ask; revoking what somebody signed is
    :func:`clear_exception`, gated on the permission that could have granted
    it — so they are two functions.

    Nothing about the SLA moves here: a request never suspended the clock, so
    withdrawing one cannot restart it. ``exception_state`` returns to whatever
    the row was in before the request: the granted window if one is still
    there (lapsed or not), and ``none`` otherwise.

    Refuses somebody else's request by name. Whoever holds
    ``vulnerability.exception.approve`` closes a request they did not file by
    *rejecting* it, which is an answer and leaves one — a withdrawal would
    erase the ask with no record of who made it go away.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        state = row.exception_state or vuln_states.EXCEPTION_NONE
        if state != vuln_states.EXCEPTION_REQUESTED:
            raise vuln_states.InvalidExceptionTransition(
                f"Vulnerability {vuln_id}: no exception request is waiting for a decision"
            )
        if not _same_person(row.exception_requested_by, actor):
            raise PermissionError(
                "only the person who filed an exception request may withdraw it; "
                "somebody holding vulnerability.exception.approve can reject it instead"
            )
        before = _to_dict(row, now=now)
        requested_until = row.exception_requested_until
        row.exception_state = _state_behind_a_request(row, now=now)
        row.exception_requested_by = None
        row.exception_requested_at = None
        row.exception_requested_until = None
        row.exception_requested_reason = None
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_request_withdrawn",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail={
                "requested_until": _iso(requested_until),
                "exception_state": row.exception_state,
            },
        )
        result = _to_dict(row, now=now)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_VULN_EXCEPTION_REQUEST_WITHDRAW,
            resource_type="vulnerability",
            resource_id=row.vuln_id,
            tenant_id=row.tenant_id,
            before=_exception_document(before),
            after=_exception_document(result),
        )
        session.flush()
        return result


def _state_behind_a_request(row: Any, *, now: datetime) -> str:
    """What the acceptance state was before a request was filed over it.

    ``exception_until`` is the granted window and is never touched by a
    request, so it is the whole answer: a window still ahead is an acceptance
    in force, one behind is an acceptance that lapsed — and the register reads
    those two rows differently — and no window at all is ``none``.
    """
    granted = _naive(row.exception_until)
    if granted is None:
        return vuln_states.EXCEPTION_NONE
    return (
        vuln_states.EXCEPTION_APPROVED
        if granted > now
        else vuln_states.EXCEPTION_EXPIRED
    )


def clear_exception(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
    note: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Revoke a granted acceptance and put the finding back under its deadline.

    The deadline is recomputed from ``sla_started_at``, not from now: the risk
    was accepted, not restarted, so a finding whose window had already elapsed
    is immediately breached again rather than being granted a fresh one.

    **A pending request is not part of this.** An extension waiting for a
    decision survives — it is a separate ask, and answering it is
    :func:`approve_exception` or :func:`reject_exception` — and a requester
    taking their own ask back is :func:`withdraw_exception_request`. Before
    those were separate the console offered one "Withdraw" button for both, so
    somebody fixing a typo in their own extension request destroyed the
    acceptance a second person had signed.

    **There is no case where a request goes with it.** With nothing granted
    this raises instead, because the alternative was the same erasure by
    another door: the approver who may revoke an acceptance would clear a
    request nobody had answered, leaving ``exception_decided_by`` empty and the
    register reporting ``exception_cleared`` — "Acceptance revoked" in the
    console — for a finding that never had one. Whoever may revoke may also
    *reject*, which costs one more click and records who made the ask go away.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        state = row.exception_state or vuln_states.EXCEPTION_NONE
        was_until = row.exception_until
        if was_until is None:
            # ``exception_until`` is the granted window and the only thing this
            # route revokes, so with none there is nothing here to take away.
            # Answering 200 spent the acceptance the row did not have: on a row
            # carrying a request it erased the ask, on an empty one it wrote a
            # revocation nobody performed.
            raise vuln_states.InvalidExceptionTransition(
                f"Vulnerability {vuln_id}: no accepted risk to revoke"
                + (
                    "; a request waiting for a decision is closed by rejecting it"
                    if state == vuln_states.EXCEPTION_REQUESTED
                    else ""
                )
            )
        before = _to_dict(row, now=now)
        # A request waiting on a decision keeps its columns and its state: it is
        # a separate ask over the window being revoked, and it stays waiting.
        keeps_request = state == vuln_states.EXCEPTION_REQUESTED
        row.exception_state = (
            vuln_states.EXCEPTION_REQUESTED if keeps_request else vuln_states.EXCEPTION_NONE
        )
        if not keeps_request:
            row.exception_requested_by = None
            row.exception_requested_at = None
            row.exception_requested_until = None
            row.exception_requested_reason = None
        row.exception_decided_by = None
        row.exception_decided_at = None
        row.exception_decision_note = None
        row.exception_reason = None
        row.exception_by = None
        row.exception_approved_at = None
        row.exception_approved_requested_by = None
        row.exception_expired_at = None
        row.updated_at = now
        # The granted window is what moved the deadline, so revoking it is what
        # restores the deadline — recomputed from the policy, not remembered.
        asset = session.get(models.Asset, row.asset_id)
        days, source = _resolve_sla_days(
            session,
            tenant_id=row.tenant_id,
            severity=row.severity,
            criticality=asset.asset_criticality if asset else None,
        )
        row.exception_until = None
        row.sla_days = days
        row.sla_source = source
        row.due_at = (_naive(row.sla_started_at) or now) + timedelta(days=days)
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_cleared",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail={
                "was_until": _iso(was_until),
                "was_exception_state": state,
                "due_at": _iso(row.due_at),
            },
        )
        result = _to_dict(row, now=now)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_VULN_EXCEPTION_WITHDRAW,
            resource_type="vulnerability",
            resource_id=row.vuln_id,
            tenant_id=row.tenant_id,
            before=_exception_document(before),
            after=_exception_document(result),
        )
        session.flush()
        return result


def expire_exceptions(
    settings: Settings,
    *,
    tenant_id: str | None = None,
    now: datetime | None = None,
    limit: int = 500,
) -> int:
    """Record every acceptance whose window has run out. Returns how many.

    The lapse is already *visible* without this — ``sla_state`` derives
    ``accepted`` from ``exception_until`` being in the future, so the finding
    goes back to breached on its own the moment it is not. What the derivation
    cannot do is leave a row saying it happened, and "the acceptance for this
    finding ran out on the 3rd and nobody did anything" is precisely the
    question the register exists to answer. So the expiry is a fourth recorded
    act alongside request, approval and rejection, with the platform as actor.

    Called from the SLA escalation worker's tick (#349), which is already
    leader-locked and already walks the tenants; the reminders it sends at
    30/14/7 days are the warning, this is the obituary. ``exception_until`` is
    deliberately *not* cleared: the register's expired half is read off it.

    What is swept is "an approved window that has run out", not "a row whose
    workflow state is ``exception_approved``". Asking to extend an acceptance
    moves that state to ``exception_requested`` and a refusal leaves it at
    ``exception_rejected`` — while the granted window is still there, still
    suspending the clock and still due to lapse. Keyed on the state, the
    obituary for exactly those findings was never written. ``exception_expired_at``
    is the once-only marker instead, and the state is only advanced when it is
    still the acceptance's own; a pending request is not overwritten by the
    lapse of the window it wants to replace.

    Closed findings are skipped. Their acceptance is dropped when they close,
    and a lapse recorded against one would be an audit row about a risk nobody
    is carrying any more.
    """
    now = _naive(now) or _now()
    expired = 0
    with get_session(settings.postgres_url) as session:
        query = select(models.Vulnerability).where(
            models.Vulnerability.state != vuln_states.CLOSED,
            models.Vulnerability.exception_until.is_not(None),
            models.Vulnerability.exception_by.is_not(None),
            models.Vulnerability.exception_until <= now,
            models.Vulnerability.exception_expired_at.is_(None),
        )
        if tenant_id is not None:
            query = query.where(models.Vulnerability.tenant_id == tenant_id)
        rows = session.scalars(
            query.order_by(models.Vulnerability.exception_until.asc()).limit(limit)
        ).all()
        for row in rows:
            row.exception_expired_at = now
            if (row.exception_state or vuln_states.EXCEPTION_NONE) == (
                vuln_states.EXCEPTION_APPROVED
            ):
                row.exception_state = vuln_states.EXCEPTION_EXPIRED
            row.updated_at = now
            _record_event(
                session,
                vuln_id=row.vuln_id,
                tenant_id=row.tenant_id,
                kind="exception_expired",
                occurred_at=now,
                to_state=row.state,
                # No actor: nobody did this, which is the point of recording it.
                actor=None,
                detail={
                    "exception_until": _iso(row.exception_until),
                    "approved_by": row.exception_by,
                    "requested_by": (
                        row.exception_approved_requested_by or row.exception_requested_by
                    ),
                },
            )
            audit_service.record(
                session,
                audit_service.system_context("system:sla-escalation"),
                action=audit_service.ACTION_VULN_EXCEPTION_EXPIRE,
                resource_type="vulnerability",
                resource_id=row.vuln_id,
                tenant_id=row.tenant_id,
                after=_exception_document(_to_dict(row, now=now)),
            )
            expired += 1
        session.flush()
    return expired


#: How far back the risk register looks for acceptances that have lapsed. A
#: register of only what is in force answers "what are we living with today"
#: and not "what did we accept and then forget", which is the question an
#: auditor asks; a year is the period the answer is usually wanted over.
RISK_REGISTER_DAYS = 365

#: Rows one register read returns. The report renders far fewer; the ceiling is
#: for the CSV export, which is the one somebody hands to an auditor.
RISK_REGISTER_LIMIT = 5000


def _approved_request(row: models.Vulnerability, value: Any) -> Any:
    """``value`` if the request columns still describe the acceptance in force.

    Two of the register's fields have no column of their own — when the ask was
    made, and what the approver wrote — so they are read from the request and
    decision columns, which the *next* request overwrites. Blank is the honest
    answer for a row whose extension is pending or was refused; the alternative
    is printing an unanswered request's timestamp as if the acceptance had been
    asked for then.
    """
    if (row.exception_state or vuln_states.EXCEPTION_NONE) in (
        vuln_states.EXCEPTION_APPROVED,
        vuln_states.EXCEPTION_EXPIRED,
    ):
        return value
    return None


def risk_acceptance_register(
    settings: Settings,
    *,
    tenant_id: str,
    since: datetime | None = None,
    now: datetime | None = None,
    limit: int = RISK_REGISTER_LIMIT,
) -> list[dict[str, Any]]:
    """The register of accepted risk: what is in force, and what has lapsed.

    One row per finding with an approval decision on it — the justification,
    who asked, who approved, until when, and who owns the thing — ordered by
    expiry so the next acceptance to run out is at the top.

    ``status`` is derived from ``exception_until`` against ``now`` rather than
    read off ``exception_state``, because the sweep that writes
    ``exception_expired`` runs on a worker's tick: a register that waited for
    it would show an acceptance that lapsed an hour ago as still in force, and
    this document is the one somebody signs off on.

    A row is here because it *has an approved window* — ``exception_until``
    with an ``exception_by`` against it — and not because its workflow state
    reads ``exception_approved``. Asking for an extension moves that state to
    ``exception_requested``, and a refusal parks it at ``exception_rejected``,
    neither of which takes away the window already signed for: keyed on the
    state, the register lost exactly the acceptances somebody had just been
    refused more time on, which is the case an auditor opens it for.

    Closed findings are absent for the same reason the reminders skip them: the
    acceptance goes when the finding closes, and a register entry for one would
    invite a review of a risk that is no longer carried.

    Pending requests are deliberately absent too. This is the register of risk
    the organisation *accepted*, and something nobody has approved yet is not
    that; ``GET /api/vulnerabilities?exception_state=exception_requested`` is
    the queue of what is waiting.
    """
    now = _naive(now) or _now()
    since = _naive(since) or (now - timedelta(days=RISK_REGISTER_DAYS))
    with get_session(settings.postgres_url) as session:
        query = (
            select(models.Vulnerability, models.Asset)
            .join(models.Asset, models.Asset.asset_id == models.Vulnerability.asset_id)
            .where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.state != vuln_states.CLOSED,
                models.Vulnerability.exception_until.is_not(None),
                models.Vulnerability.exception_by.is_not(None),
                # In force, or lapsed inside the window asked for. An
                # acceptance that ran out three years ago is history, not a
                # register entry.
                or_(
                    models.Vulnerability.exception_until > now,
                    models.Vulnerability.exception_until >= since,
                ),
            )
            .order_by(models.Vulnerability.exception_until.asc())
            .limit(limit)
        )
        entries: list[dict[str, Any]] = []
        for row, asset in session.execute(query).all():
            until = _naive(row.exception_until)
            active = until is not None and until > now
            entries.append(
                {
                    "vuln_id": row.vuln_id,
                    "tenant_id": row.tenant_id,
                    "asset_id": row.asset_id,
                    "title": row.title,
                    "cve": row.cve,
                    "severity": row.severity,
                    "state": row.state,
                    "status": "active" if active else "expired",
                    "exception_state": row.exception_state,
                    "reason": row.exception_reason,
                    # The acceptance in force, read off its own columns. The
                    # request and decision columns describe whatever was asked
                    # last, which may be an extension nobody has answered — or
                    # one that was refused, in which case reading the approver
                    # off ``exception_decided_by`` named the person who said no.
                    "requested_by": (
                        row.exception_approved_requested_by or row.exception_requested_by
                    ),
                    "requested_at": _iso(_approved_request(row, row.exception_requested_at)),
                    "approved_by": row.exception_by,
                    "approved_at": _iso(row.exception_approved_at),
                    "decision_note": _approved_request(row, row.exception_decision_note),
                    "until": _iso(until),
                    "days_remaining": (until - now).days if active else None,
                    # Two owners, because they answer different questions: the
                    # assignee owns the remediation this acceptance postponed,
                    # the asset's owner owns the thing carrying the risk.
                    "assignee": row.assignee,
                    "owner_team": row.owner_team,
                    "asset_owner": asset.owner_email if asset else None,
                    "business_service": asset.business_service if asset else None,
                    # Pre-#348 acceptances, and any the platform admin both
                    # asked for and signed. Named rather than filtered out: an
                    # auditor reading this register has to be able to see which
                    # entries never had a second person on them.
                    "self_approved": _same_person(
                        row.exception_approved_requested_by or row.exception_requested_by,
                        row.exception_by,
                    ),
                }
            )
    return entries


def mark_false_positive(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    reason: str,
    suppress_days: int = DEFAULT_FP_SUPPRESS_DAYS,
    evidence: dict[str, Any] | None = None,
    actor: str | None = None,
) -> dict[str, Any] | None:
    """Close a finding as never having been real, and stop it re-opening.

    A reason and an expiry are both mandatory, as they are for accepted risk
    and for the same reason: an indefinite suppression with no justification is
    a finding that leaves the estate's picture and never comes back into it.
    The two decisions are opposites — an exception says the risk is real and
    accepted, this says there is no risk — but they carry the same obligation.

    The move goes through ``vuln_states.check_transition``, so marking an
    already-closed finding is the same 409 as any other illegal move rather
    than a silent second verdict. ``machine_verified`` is forced false: nothing
    was remediated, so nothing was verified, and letting this path set it would
    make the one un-self-attestable metric self-attestable.

    While the verdict holds, ``register_findings_from_run`` keeps the row closed
    instead of re-opening it — except when the assessment materially worsens,
    which breaks the suppression early (see ``_fp_escalations``).
    """
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a false-positive verdict needs a reason")
    suppress_days = int(suppress_days)
    if not MIN_FP_SUPPRESS_DAYS <= suppress_days <= MAX_FP_SUPPRESS_DAYS:
        raise ValueError(
            f"suppress_days must be between {MIN_FP_SUPPRESS_DAYS} and {MAX_FP_SUPPRESS_DAYS}"
        )
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        previous = row.state
        vuln_states.check_transition(vuln_id, previous, vuln_states.CLOSED)

        row.state = vuln_states.CLOSED
        row.state_changed_at = now
        row.state_changed_by = actor
        row.closed_at = now
        row.machine_verified = False
        row.closure_reason = FALSE_POSITIVE
        row.fp_reason = reason[:2000]
        row.fp_marked_by = actor
        row.fp_marked_at = now
        row.fp_evidence = dict(evidence or {})
        row.fp_suppress_until = now + timedelta(days=suppress_days)
        row.fp_observations = 0
        row.updated_at = now
        detail: dict[str, Any] = {
            "closure_reason": FALSE_POSITIVE,
            "fp_suppress_until": _iso(row.fp_suppress_until),
            "suppress_days": suppress_days,
        }
        # As with any other closure: an acceptance of a risk that turns out not
        # to exist has nothing left to accept.
        detail.update(_drop_exception(row))
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="false_positive_set",
            occurred_at=now,
            from_state=previous,
            to_state=vuln_states.CLOSED,
            actor=actor,
            note=reason,
            detail=detail,
        )
        session.flush()
        return _to_dict(row, now=now)


def clear_false_positive(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
    note: str | None = None,
) -> dict[str, Any] | None:
    """Withdraw a false-positive verdict and re-open the finding.

    Cheaper than setting one on purpose (``operator``, not ``admin``): undoing
    a suppression can only put work back on the queue, and a control that is
    harder to release than to apply is one people stop applying.

    The finding comes back as ``OPEN`` with a fresh SLA clock, exactly as a
    re-observation after a lapsed suppression would leave it — there is one
    rule for "this is a real finding again", not two. ``reopen_count`` is
    deliberately *not* touched: that counter answers "how often does this come
    back", and a verdict someone withdrew is a correction to the record, not a
    regression in the estate.

    Raises ``ValueError`` when the finding carries no verdict to withdraw. It is
    a refusal rather than a quiet success on purpose: the caller is asking to
    undo a decision that is not there, and answering "done" to that is how a
    button comes to lie about what it did.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if row.state != vuln_states.CLOSED or row.closure_reason != FALSE_POSITIVE:
            # Nothing to withdraw, and saying so is the point. Returning the row
            # unchanged made the console's "Withdraw verdict" button report
            # success for a call that did nothing at all — a silent no-op that
            # looks like a write is worse than a refusal, because the operator
            # walks away believing the finding is back on the queue.
            raise ValueError(f"{vuln_id} is not closed as a false positive")
        previous = row.state
        was_until = row.fp_suppress_until
        observations = row.fp_observations
        asset = session.get(models.Asset, row.asset_id)
        days, source = _resolve_sla_days(
            session,
            tenant_id=row.tenant_id,
            severity=row.severity,
            criticality=asset.asset_criticality if asset else None,
        )
        row.state = vuln_states.OPEN
        row.state_changed_at = now
        row.state_changed_by = actor
        row.closed_at = None
        row.closure_reason = None
        row.machine_verified = False
        row.sla_started_at = now
        row.sla_days = days
        row.sla_source = source
        row.due_at = now + timedelta(days=days)
        _clear_fp(row)
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="false_positive_cleared",
            occurred_at=now,
            from_state=previous,
            to_state=vuln_states.OPEN,
            actor=actor,
            note=note,
            detail={
                "was_suppressed_until": _iso(was_until),
                "fp_observations": observations,
                "due_at": _iso(row.due_at),
            },
        )
        session.flush()
        return _to_dict(row, now=now)


def add_comment(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    note: str,
    actor: str | None = None,
) -> dict[str, Any] | None:
    """Write a comment on the trail. The finding itself does not change."""
    text = (note or "").strip()
    if not text:
        raise ValueError("comment cannot be empty")
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="comment",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=text,
        )
        session.flush()
        return _to_dict(row, now=now)


def _validate_ticket_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("ticket_url must be an http(s) URL")
    return url


def set_ticket(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    system: str,
    key: str | None,
    url: str | None,
    actor: str | None = None,
    note: str | None = None,
) -> dict[str, Any] | None:
    """Attach an external ticket.

    Operators call this to *link* a ticket they opened by hand. The P2
    ticket transport also calls it after a successful Jira/ServiceNow/
    DefectDojo create — that path is the one that actually opens the ticket.
    """
    system = (system or "").strip().lower()
    if system not in TICKET_SYSTEMS:
        raise ValueError(f"unknown ticket system {system!r}; expected one of {', '.join(TICKET_SYSTEMS)}")
    key = (key or "").strip() or None
    url = (url or "").strip() or None
    if url:
        url = _validate_ticket_url(url)
    if not key and not url:
        raise ValueError("ticket_key or ticket_url is required")
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        previous = {
            "system": row.ticket_system,
            "key": row.ticket_key,
            "url": row.ticket_url,
        }
        row.ticket_system = system
        row.ticket_key = key
        row.ticket_url = url
        # A new link has never been read, so the sync bookkeeping from the old
        # one is not about it (#347). Leaving it would show "Last read failed:
        # HTTP 404" on a freshly corrected link until the next poll, which is
        # exactly the state re-linking is the documented fix for.
        row.ticket_synced_at = None
        row.ticket_sync_error = None
        row.ticket_remote_status = None
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="ticket_set",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail={"from": previous, "to": {"system": system, "key": key, "url": url}},
        )
        session.flush()
        return _to_dict(row, now=now)


def clear_ticket(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
) -> dict[str, Any] | None:
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if row.ticket_system is None and row.ticket_key is None and row.ticket_url is None:
            return _to_dict(row, now=now)
        previous = {
            "system": row.ticket_system,
            "key": row.ticket_key,
            "url": row.ticket_url,
        }
        row.ticket_system = None
        row.ticket_key = None
        row.ticket_url = None
        # Same reason as in ``set_ticket``: with no link there is nothing for a
        # stale sync error to be about, and the console would keep rendering it.
        row.ticket_synced_at = None
        row.ticket_sync_error = None
        row.ticket_remote_status = None
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="ticket_cleared",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            detail=previous,
        )
        session.flush()
        return _to_dict(row, now=now)


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------


SORT_COLUMNS = {
    "contextual_score": models.Vulnerability.contextual_score,
    "due_at": models.Vulnerability.due_at,
    "first_seen_at": models.Vulnerability.first_seen_at,
    "last_seen_at": models.Vulnerability.last_seen_at,
    "closed_at": models.Vulnerability.closed_at,
    "severity": models.Vulnerability.severity,
    "state": models.Vulnerability.state,
    "cve": models.Vulnerability.cve,
}


def list_vulnerabilities(
    settings: Settings,
    *,
    tenant_id: str | None = None,
    state: str | None = None,
    states: list[str] | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    source: str | None = None,
    network_exposure: str | None = None,
    assignee: str | None = None,
    unassigned: bool = False,
    sla: str | None = None,
    exception_state: str | None = None,
    stale_days: int | None = None,
    in_kev: bool | None = None,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    sort: str | None = None,
    order: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Paginated findings.

    ``sla`` filters on the derived reading, which is a predicate over ``due_at``
    and ``exception_until`` rather than a column — the same expression
    ``sla_state`` computes, pushed into SQL so a breach report does not have to
    page through every open finding to find the overdue ones.

    ``exception_state`` filters on the acceptance workflow (#348), and
    ``exception_requested`` is the approver's queue: nothing notifies whoever
    holds ``vulnerability.exception.approve`` that a request is waiting, so
    without this the only way to find one is to read every finding in the
    tenant.
    """
    if state and state.upper() not in vuln_states.ALL:
        raise ValueError(f"unknown state {state!r}; expected one of {', '.join(vuln_states.ORDER)}")
    if exception_state and exception_state not in vuln_states.EXCEPTION_STATES:
        raise ValueError(
            f"unknown exception_state {exception_state!r}; "
            f"expected one of {', '.join(vuln_states.EXCEPTION_STATES)}"
        )
    if sla and sla not in SLA_STATES:
        raise ValueError(f"unknown sla filter {sla!r}; expected one of {', '.join(SLA_STATES)}")
    if unassigned and assignee:
        raise ValueError("unassigned and assignee cannot be combined")
    if source and source not in SOURCES:
        raise ValueError(f"unknown source {source!r}; expected one of {', '.join(SOURCES)}")
    if network_exposure and network_exposure not in NETWORK_EXPOSURES:
        raise ValueError(
            f"unknown network_exposure {network_exposure!r}; "
            f"expected one of {', '.join(NETWORK_EXPOSURES)}"
        )
    if severity:
        severity = _validate_severity(severity)

    now = _now()
    sort_column = SORT_COLUMNS.get(sort or "", models.Vulnerability.contextual_score)
    direction = sort_column.asc() if (order or "").lower() == "asc" else sort_column.desc()

    filters: list[Any] = []
    if tenant_id:
        filters.append(models.Vulnerability.tenant_id == tenant_id)
    if state:
        filters.append(models.Vulnerability.state == state.upper())
    if states:
        filters.append(models.Vulnerability.state.in_([s.upper() for s in states]))
    if severity:
        filters.append(models.Vulnerability.severity == severity)
    if asset_id:
        filters.append(models.Vulnerability.asset_id == asset_id)
    if source:
        filters.append(models.Vulnerability.source == source)
    if network_exposure == UNKNOWN_EXPOSURE:
        # Findings scored before the exposure signal existed carry NULL, which
        # says the same thing as "unknown" — excluding them would hide most of
        # what the filter is asked for.
        filters.append(
            or_(
                models.Vulnerability.network_exposure.is_(None),
                models.Vulnerability.network_exposure == UNKNOWN_EXPOSURE,
            )
        )
    elif network_exposure:
        filters.append(models.Vulnerability.network_exposure == network_exposure)
    if unassigned:
        filters.append(models.Vulnerability.assignee.is_(None))
    elif assignee:
        filters.append(models.Vulnerability.assignee == assignee)
    if exception_state:
        filters.append(models.Vulnerability.exception_state == exception_state)
    if stale_days is not None:
        filters.append(models.Vulnerability.last_seen_at < now - timedelta(days=stale_days))
    if in_kev is True:
        filters.append(models.Vulnerability.in_kev.is_(True))
    if q and q.strip():
        needle = f"%{q.strip().lower()}%"
        filters.append(
            or_(
                func.lower(models.Vulnerability.cve).like(needle),
                func.lower(models.Vulnerability.script_id).like(needle),
                func.lower(models.Vulnerability.asset_id).like(needle),
                func.lower(models.Vulnerability.assignee).like(needle),
            )
        )
    filters.extend(_sla_filters(sla, now))

    with get_session(settings.postgres_url) as session:
        total = session.execute(
            select(func.count()).select_from(models.Vulnerability).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.Vulnerability)
            .where(*filters)
            .order_by(direction, models.Vulnerability.vuln_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()
        items = [_to_dict(row, now=now) for row in rows]
    return items, total


def _sla_filters(sla: str | None, now: datetime) -> list[Any]:
    """The SQL half of ``sla_state``. Kept beside it so the two cannot drift."""
    if not sla:
        return []
    accepted = models.Vulnerability.exception_until > now
    not_accepted = or_(
        models.Vulnerability.exception_until.is_(None),
        models.Vulnerability.exception_until <= now,
    )
    open_states = models.Vulnerability.state.in_(sorted(vuln_states.ACTIVE))
    has_due = models.Vulnerability.due_at.is_not(None)
    if sla == "accepted":
        return [open_states, has_due, accepted]
    if sla == "breached":
        return [open_states, has_due, not_accepted, models.Vulnerability.due_at <= now]
    if sla == "due_soon":
        return [
            open_states,
            has_due,
            not_accepted,
            models.Vulnerability.due_at > now,
            models.Vulnerability.due_at <= now + timedelta(days=DUE_SOON_DAYS),
        ]
    if sla == "on_track":
        return [
            open_states,
            has_due,
            not_accepted,
            models.Vulnerability.due_at > now + timedelta(days=DUE_SOON_DAYS),
        ]
    # "none": closed, or open with no deadline at all.
    return [
        or_(
            models.Vulnerability.state == vuln_states.CLOSED,
            models.Vulnerability.due_at.is_(None),
        )
    ]


def list_events(
    settings: Settings,
    *,
    tenant_id: str | None = None,
    vuln_id: str | None = None,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
) -> tuple[list[dict[str, Any]], int]:
    filters: list[Any] = []
    if tenant_id:
        filters.append(models.VulnerabilityEvent.tenant_id == tenant_id)
    if vuln_id:
        filters.append(models.VulnerabilityEvent.vuln_id == vuln_id)
    with get_session(settings.postgres_url) as session:
        total = session.execute(
            select(func.count()).select_from(models.VulnerabilityEvent).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.VulnerabilityEvent)
            .where(*filters)
            .order_by(
                models.VulnerabilityEvent.occurred_at.desc(),
                models.VulnerabilityEvent.id.desc(),
            )
            .offset(offset)
            .limit(limit)
        ).scalars().all()
    return [_event_to_dict(row) for row in rows], total


def summary(
    settings: Settings, *, tenant_id: str | None = None, asset_id: str | None = None
) -> dict[str, Any]:
    """Counts by lifecycle state, severity, NIST risk and SLA (#135/#137).

    One pass over the tenant's findings rather than one query per bucket: the
    numbers have to agree with each other, and independent aggregates over a
    table that is being written to do not.

    ``estate_risk`` is the worst open ``risk_level`` (NIST Table I-2), not an
    average. Averaging would let a hundred Lows cancel a Very High, which is
    the opposite of "what creates the biggest security risk right now".
    """
    now = _now()
    filters: list[Any] = []
    if tenant_id:
        filters.append(models.Vulnerability.tenant_id == tenant_id)
    if asset_id:
        filters.append(models.Vulnerability.asset_id == asset_id)

    by_state = {state: 0 for state in vuln_states.ORDER}
    by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    by_risk = {level: 0 for level in nist_risk.LEVELS}
    by_sla = {reading: 0 for reading in SLA_STATES}
    by_exposure = {exposure: 0 for exposure in NETWORK_EXPOSURES}
    total = 0
    open_total = 0
    unassigned = 0
    overdue_worst: str | None = None
    estate_risk: str | None = None

    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(
                models.Vulnerability.state,
                models.Vulnerability.severity,
                models.Vulnerability.risk_level,
                models.Vulnerability.assignee,
                models.Vulnerability.due_at,
                models.Vulnerability.exception_until,
                models.Vulnerability.machine_verified,
                models.Vulnerability.network_exposure,
            ).where(*filters)
        ).all()
    machine_verified_closed = 0
    for (
        state,
        severity,
        risk_level,
        assignee,
        due_at,
        exception_until,
        machine_verified,
        network_exposure,
    ) in rows:
        total += 1
        by_state[str(state)] = by_state.get(str(state), 0) + 1
        if state == vuln_states.CLOSED and machine_verified:
            machine_verified_closed += 1
        reading = sla_state(
            {"state": state, "due_at": due_at, "exception_until": exception_until}, now=now
        )
        by_sla[reading] = by_sla.get(reading, 0) + 1
        if state in vuln_states.ACTIVE:
            open_total += 1
            by_severity[str(severity)] = by_severity.get(str(severity), 0) + 1
            # NULL is what a finding scored before the signal existed carries;
            # it is unknown exposure, not a fourth bucket.
            exposure = (
                network_exposure if network_exposure in NETWORK_EXPOSURES else UNKNOWN_EXPOSURE
            )
            by_exposure[exposure] += 1
            if not assignee:
                unassigned += 1
            level = str(risk_level) if risk_level in nist_risk.LEVEL_RANK else None
            if level:
                by_risk[level] = by_risk.get(level, 0) + 1
                if nist_risk.LEVEL_RANK[level] > nist_risk.LEVEL_RANK.get(estate_risk or "", -1):
                    estate_risk = level
            if reading == "breached" and SEVERITY_ORDER.get(str(severity), 0) > SEVERITY_ORDER.get(
                overdue_worst or "unknown", 0
            ):
                overdue_worst = str(severity)

    closed_total = by_state.get(vuln_states.CLOSED, 0)
    return {
        "total": total,
        "open_total": open_total,
        "untriaged": by_state.get(vuln_states.OPEN, 0),
        "unassigned": unassigned,
        "estate_risk": estate_risk,
        "by_state": by_state,
        # Severity / risk counts cover open findings only: a dashboard tile
        # reading "42 critical" must not be counting ones that were fixed last
        # year.
        "by_severity_open": by_severity,
        "by_network_exposure_open": by_exposure,
        "by_risk_level_open": by_risk,
        "by_sla": by_sla,
        "breached": by_sla.get("breached", 0),
        "worst_breached_severity": overdue_worst,
        # Closed-loop remediation (#183). The rate answers "how much of what we
        # call fixed did a scan actually confirm", so its denominator is every
        # closure, not only the ones that went through verification.
        "closed_total": closed_total,
        "machine_verified_closed": machine_verified_closed,
        "manual_closed": max(0, closed_total - machine_verified_closed),
        "machine_verification_rate": (
            round(machine_verified_closed / closed_total * 100.0, 1) if closed_total else 0.0
        ),
        "generated_at": _iso(now),
    }
