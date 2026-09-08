"""Adoption metrics: is the product producing outcomes, or only data?

ROADMAP Track E ends with a list of what would have to be measured before any
of its new functionality can be called a success, and with the observation
that none of it is measurable — the product is self-hosted and has no
telemetry. This module is the in-product half of the answer: every number here
is computed from tables that already exist (``vulnerabilities``, ``assets``,
``endpoint_devices``, ``jobs``, ``tenants``) for one tenant, on request, and
nothing leaves the installation.

The shape of each number matters more than its value:

* Shares are ``None`` when the denominator is zero, never ``0.0`` or
  ``100.0``. An estate with no closed findings has no verification rate, and a
  dashboard that prints 0% there is lying in the direction that makes the
  product look worst, which is as misleading as the other direction.
* Durations are medians, not means. One finding that sat for a year while the
  owner argued with procurement should not move the number the security lead
  is judged on; it is still visible as a breach.
* "Closed" is read from the finding's own ``closed_at`` and ``machine_verified``
  columns, not reconstructed from the event journal, so this page and the
  Vulnerability Center's summary cannot disagree about how many were fixed.

The control question ROADMAP asks once a quarter — did closed-and-verified
findings per analyst go up — is the ``analysts`` list, over the window.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import coverage as coverage_service
from api.services import job_states, system_status, vuln_states
from api.services.vulnerabilities import FALSE_POSITIVE
from api.settings import Settings
from scanner.pipeline.report import SEVERITY_ORDER

# "Scanned recently" for coverage: ROADMAP names 30 days.
COVERAGE_DAYS = 30
DEFAULT_WINDOW_DAYS = 90
MIN_WINDOW_DAYS = 7
MAX_WINDOW_DAYS = 365
ANALYSTS_LIMIT = 10
UNASSIGNED = "unassigned"
#: Findings with a CVE but no ``script_id`` come from advisory matching rather
#: than from a named check. Their own bucket, never folded into a detector's.
UNKNOWN_SOURCE = "unknown"
SOURCES_LIMIT = 10
#: Below this many closures a per-detector false-positive *rate* is noise about
#: noise: one verdict out of one closure is not a 100% error rate. The raw
#: counts are still reported; only the share is withheld.
MIN_SOURCE_OBSERVATIONS = 20


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    """Columns here are naive UTC; compare them as aware so a mix cannot raise."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    value = _aware(value)
    return value.isoformat() if value else None


def _share(part: int, whole: int) -> float | None:
    """Percentage of ``whole`` that ``part`` is, or ``None`` when there is no whole."""
    if whole <= 0:
        return None
    return round(part / whole * 100.0, 1)


def _hours(later: datetime, earlier: datetime) -> float:
    return round((later - earlier).total_seconds() / 3600.0, 1)


def _median_or_none(values: list[float]) -> float | None:
    return round(float(median(values)), 1) if values else None


def _fp_source(script_id: str | None) -> str:
    """Which detector produced a finding, for a per-detector noise rate.

    A finding with a CVE and no ``script_id`` came from version-to-advisory
    matching rather than from a named check, and there is nothing finer to
    attribute it to. It goes to ``unknown`` — its own bucket, never merged into
    a named detector's rate, because attributing matcher noise to a script would
    make that script look worse than it is and hide that the matcher is the
    thing to tune.
    """
    script_id = (script_id or "").strip()
    if script_id:
        return script_id
    return UNKNOWN_SOURCE


def _noise_rows(counts: dict[str, dict[str, int]], *, only_with_noise: bool) -> list[dict[str, Any]]:
    """``{name: {closed, false_positive}}`` as sorted rows with an earned share.

    The share is withheld below ``MIN_SOURCE_OBSERVATIONS`` closures in both
    tables for the same reason: one verdict out of one closure is a data point,
    not a 100% error rate. The raw counts are returned either way, so a reader
    can see the sample rather than a number computed from it.
    """
    return sorted(
        (
            {
                "source": name,
                "closed": bucket["closed"],
                "false_positive": bucket["false_positive"],
                "false_positive_share": (
                    _share(bucket["false_positive"], bucket["closed"])
                    if bucket["closed"] >= MIN_SOURCE_OBSERVATIONS
                    else None
                ),
            }
            for name, bucket in counts.items()
            if bucket["false_positive"] or not only_with_noise
        ),
        key=lambda item: (-item["false_positive"], item["source"]),
    )


def _closure_rows(session: Any, *, tenant_id: str, since: datetime) -> list[Any]:
    """One tenant's closures inside the window, worst case one row per closure.

    Bounded by the window and served by ``ix_vulnerabilities_closed``, unlike
    the full-table read this replaced. The medians below need the individual
    values, so this is the one place rows are still pulled into Python — the
    point-in-time counts are all aggregates.
    """
    vuln = models.Vulnerability
    return session.execute(
        select(
            vuln.severity,
            vuln.assignee,
            vuln.sla_started_at,
            vuln.first_seen_at,
            vuln.closed_at,
            vuln.due_at,
            vuln.machine_verified,
            vuln.closure_reason,
            vuln.script_id,
            vuln.source,
            vuln.fp_marked_at,
        ).where(
            vuln.tenant_id == tenant_id,
            vuln.state == vuln_states.CLOSED,
            vuln.closed_at >= since,
        )
    ).all()


def metrics(settings: Settings, *, tenant_id: str, window_days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
    """The adoption picture for one tenant over the last ``window_days``.

    Window-scoped: closures, MTTR, SLA adherence and the per-analyst table.
    Point-in-time: open findings, asset coverage and context, enrichment age.

    **False-positive closures are excluded from every remediation metric** —
    verification rate, MTTR and SLA adherence — and counted separately instead.
    A finding that was never real has no time-to-fix, and folding it in would
    mean honest triage of noise dragged down the verification rate while mass
    false-positive marking pumped up the closure count. The quarterly control
    question ROADMAP asks ("did closed-and-verified per analyst go up") has to
    be one that cannot be answered by relabelling.
    """
    window_days = max(MIN_WINDOW_DAYS, min(MAX_WINDOW_DAYS, int(window_days)))
    now = _now()
    since = now - timedelta(days=window_days)
    naive_since = since.replace(tzinfo=None)
    naive_now = now.replace(tzinfo=None)
    coverage_since = (now - timedelta(days=COVERAGE_DAYS)).replace(tzinfo=None)

    vuln = models.Vulnerability
    asset = models.Asset
    device = models.EndpointDevice
    job = models.Job

    with get_session(settings.postgres_url) as session:
        # Point-in-time finding counts, as aggregates. This used to read every
        # finding the tenant had ever had into Python to count four things.
        tracked_total, open_total, accepted_open, reopened = session.execute(
            select(
                func.count(),
                func.count(1).filter(vuln.state.in_(sorted(vuln_states.ACTIVE))),
                func.count(1).filter(
                    vuln.state.in_(sorted(vuln_states.ACTIVE)),
                    vuln.exception_until > naive_now,
                ),
                func.count(1).filter(vuln.reopen_count > 0),
            ).where(vuln.tenant_id == tenant_id)
        ).one()
        closures = _closure_rows(session, tenant_id=tenant_id, since=naive_since)

        suppressions_active, suppressions_lapsed = session.execute(
            select(
                func.count(1).filter(vuln.fp_suppress_until > naive_now),
                func.count(1).filter(vuln.fp_suppress_until <= naive_now),
            ).where(
                vuln.tenant_id == tenant_id,
                vuln.state == vuln_states.CLOSED,
                vuln.closure_reason == FALSE_POSITIVE,
            )
        ).one()
        # From the trail, not from the row: an override clears the verdict, so
        # by the time this is asked the columns no longer say it happened.
        fp_overridden = session.execute(
            select(func.count()).where(
                models.VulnerabilityEvent.tenant_id == tenant_id,
                models.VulnerabilityEvent.kind == "fp_overridden",
                models.VulnerabilityEvent.occurred_at >= naive_since,
            )
        ).scalar_one()

        active, with_owner, with_context, dual_source = session.execute(
            select(
                func.count(),
                func.count(1).filter(func.trim(func.coalesce(asset.owner_email, "")) != ""),
                func.count(1).filter(
                    or_(
                        func.trim(func.coalesce(asset.business_service, "")) != "",
                        func.trim(func.coalesce(asset.environment, "")) != "",
                        func.trim(func.coalesce(asset.data_classification, "")) != "",
                    )
                ),
                func.count(1).filter(
                    asset.asset_id.in_(
                        select(device.asset_id).where(
                            device.tenant_id == tenant_id,
                            device.asset_id.is_not(None),
                            device.reconciliation_status == "linked",
                        )
                    )
                ),
            ).where(asset.tenant_id == tenant_id, asset.status == "active")
        ).one()

        scan_coverage = coverage_service.scan_coverage(
            session, tenant_id=tenant_id, since=coverage_since
        )
        scope_coverage = coverage_service.scope_coverage(
            session,
            tenant_id=tenant_id,
            since=coverage_since,
            history_reason=scan_coverage["history_reason"],
        )

        tenant_created = session.execute(
            select(models.Tenant.created_at).where(models.Tenant.tenant_id == tenant_id)
        ).scalar_one_or_none()
        first_job_done = session.execute(
            select(func.min(job.finished_at)).where(
                job.tenant_id == tenant_id, job.status == job_states.SUCCEEDED
            )
        ).scalar_one()
        first_finding = session.execute(
            select(func.min(vuln.first_seen_at)).where(vuln.tenant_id == tenant_id)
        ).scalar_one()

    # --- closures in the window -------------------------------------------
    closed_in_window = 0
    false_positive_in_window = 0
    closed_verified = 0
    closed_with_deadline = 0
    closed_within_sla = 0
    mttr_by_severity: dict[str, list[float]] = {severity: [] for severity in SEVERITY_ORDER}
    mttr_all: list[float] = []
    triage_hours: list[float] = []
    fp_by_severity: dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
    by_analyst: dict[str, dict[str, int]] = {}
    by_source: dict[str, dict[str, int]] = {}
    by_origin: dict[str, dict[str, int]] = {}

    for row in closures:
        closed = _aware(row.closed_at)
        if closed is None:
            continue
        severity = str(row.severity)
        source = _fp_source(row.script_id)
        bucket = by_source.setdefault(source, {"closed": 0, "false_positive": 0})
        bucket["closed"] += 1
        # Which observer produced the finding, which is a different question
        # from which detector did — see the `by_origin` note in the return.
        origin = by_origin.setdefault(str(row.source), {"closed": 0, "false_positive": 0})
        origin["closed"] += 1

        if row.closure_reason == FALSE_POSITIVE:
            # Counted, and counted apart. Not remediation work, so it is kept
            # out of MTTR, SLA adherence, the verification rate and the
            # per-analyst table below.
            false_positive_in_window += 1
            fp_by_severity[severity] = fp_by_severity.get(severity, 0) + 1
            bucket["false_positive"] += 1
            origin["false_positive"] += 1
            marked = _aware(row.fp_marked_at)
            first_seen = _aware(row.first_seen_at)
            if marked is not None and first_seen is not None:
                # Speed of triage, not speed of fixing: how long noise sat in
                # the queue before someone ruled on it.
                triage_hours.append(_hours(marked, first_seen))
            continue

        closed_in_window += 1
        if row.machine_verified:
            closed_verified += 1
        started = _aware(row.sla_started_at)
        if started is not None:
            hours = _hours(closed, started)
            mttr_all.append(hours)
            mttr_by_severity.setdefault(severity, []).append(hours)
        deadline = _aware(row.due_at)
        if deadline is not None:
            closed_with_deadline += 1
            if closed <= deadline:
                closed_within_sla += 1
        who = (row.assignee or "").strip() or UNASSIGNED
        analyst = by_analyst.setdefault(who, {"closed": 0, "machine_verified": 0})
        analyst["closed"] += 1
        if row.machine_verified:
            analyst["machine_verified"] += 1

    analysts = sorted(
        (
            {"analyst": name, "closed": counts["closed"], "machine_verified": counts["machine_verified"]}
            for name, counts in by_analyst.items()
        ),
        key=lambda item: (-item["machine_verified"], -item["closed"], item["analyst"]),
    )[:ANALYSTS_LIMIT]

    # Detectors are an open-ended vocabulary, so only the noisy ones are worth
    # listing and the list is capped. Origins are two values, and the quiet one
    # is the comparison that makes the noisy one mean anything, so both stay.
    sources = _noise_rows(by_source, only_with_noise=True)[:SOURCES_LIMIT]
    origins = _noise_rows(by_origin, only_with_noise=False)

    created = _aware(tenant_created)
    first_scan = _aware(first_job_done)
    first_seen = _aware(first_finding)

    enrichment = [
        {
            "name": row["name"],
            "present": bool(row["present"]),
            "age_days": row["age_days"],
            "stale": bool(row["stale"]),
        }
        for row in system_status.enrichment_status(system_status._load_config(settings))
    ]

    return {
        "tenant_id": tenant_id,
        "window_days": window_days,
        "generated_at": now.isoformat(),
        "findings": {
            "open": open_total,
            "accepted_open": accepted_open,
            # Remediation only. False-positive closures are the sibling key.
            "closed_in_window": closed_in_window,
            "false_positive_in_window": false_positive_in_window,
            "machine_verified_closed": closed_verified,
            "machine_verified_share": _share(closed_verified, closed_in_window),
            "closed_within_sla_share": _share(closed_within_sla, closed_with_deadline),
            "mttr_hours": _median_or_none(mttr_all),
            "mttr_hours_by_severity": {
                severity: _median_or_none(values) for severity, values in mttr_by_severity.items()
            },
            "reopened_share": _share(reopened, tracked_total),
            "open_per_asset": round(open_total / active, 2) if active else None,
        },
        "false_positives": {
            "in_window": false_positive_in_window,
            # Of everything closed in the window, how much was noise rather
            # than work. Both halves are in the denominator.
            "share_of_closures": _share(
                false_positive_in_window, closed_in_window + false_positive_in_window
            ),
            "by_severity": fp_by_severity,
            "by_source": sources,
            # Which *observer* was wrong, as opposed to which detector.
            # ``vulnerabilities.source`` only exists as of M3
            # (``0032_endpoint_software_findings``); before it, network and
            # endpoint findings were indistinguishable and this split could not
            # be computed at all. It is the coarser cut and the actionable one:
            # a high rate on ``endpoint_software`` says to tune version
            # matching, a high rate on ``scan`` says to tune the scripts, and
            # the two have nothing in common to fix.
            "by_origin": origins,
            "source_threshold": MIN_SOURCE_OBSERVATIONS,
            "suppressions_active": suppressions_active,
            # Verdicts whose expiry has passed and which nothing has re-observed
            # since: the review queue the mandatory expiry exists to create.
            "suppressions_lapsed": suppressions_lapsed,
            # Suppressions the scanner broke early because the assessment got
            # worse. On the page because it is the number that says whether a
            # verdict was hiding something.
            "overridden_in_window": fp_overridden,
            "median_hours_to_verdict": _median_or_none(triage_hours),
        },
        "assets": {
            "active": active,
            "with_owner_share": _share(with_owner, active),
            "with_context_share": _share(with_context, active),
            # Reads assets.last_scanned_at, which only the scan-ingest path
            # writes — see api/services/coverage.py. `None` until the column has
            # data, because migration 0035 has no backfill.
            "scanned_recently_share": scan_coverage["scanned_share"],
            "dual_source_share": _share(dual_source, active),
            "coverage_days": COVERAGE_DAYS,
            "unowned": max(0, active - with_owner),
        },
        "coverage": {
            "coverage_days": COVERAGE_DAYS,
            "assets_with_scan_history": scan_coverage["with_scan_history"],
            "scan_history_share": scan_coverage["scan_history_share"],
            # Why the two shares below are ``None``, when they are: the columns
            # have no backfill, so they fill one run at a time after an upgrade
            # and a share taken too early is a statement about the rollout.
            "scan_history_reason": scan_coverage["history_reason"],
            "scanned_share": scan_coverage["scanned_share"],
            "vuln_scanned_share": scan_coverage["vuln_scanned_share"],
            # Approvals, not addresses — see api/services/coverage.py for why a
            # share of an address space could not be read.
            "approved_entries": scope_coverage["approved_entries"],
            "denied_entries": scope_coverage["denied_entries"],
            "measurable_entries": scope_coverage["measurable_entries"],
            "unmeasurable_entries": scope_coverage["unmeasurable_entries"],
            "scope_covered_entries": scope_coverage["covered_entries"],
            "scope_covered_share": scope_coverage["covered_share"],
            # The actionable half: approved ranges no scan has reached.
            "scope_uncovered_entries": scope_coverage["uncovered_entries"],
            "scope_unbounded_reason": scope_coverage["unbounded_reason"],
        },
        "analysts": analysts,
        "onboarding": {
            "tenant_created_at": _iso(created),
            "first_successful_scan_at": _iso(first_scan),
            "first_tracked_finding_at": _iso(first_seen),
            "hours_to_first_scan": _hours(first_scan, created) if created and first_scan else None,
            "hours_to_first_finding": _hours(first_seen, created) if created and first_seen else None,
        },
        "enrichment": enrichment,
    }
