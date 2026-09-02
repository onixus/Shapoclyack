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

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import job_states, system_status, vuln_states
from api.settings import Settings
from scanner.pipeline.report import SEVERITY_ORDER

# "Scanned recently" for coverage: ROADMAP names 30 days.
COVERAGE_DAYS = 30
DEFAULT_WINDOW_DAYS = 90
MIN_WINDOW_DAYS = 7
MAX_WINDOW_DAYS = 365
ANALYSTS_LIMIT = 10
UNASSIGNED = "unassigned"


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


def _has_context(business_service: str | None, environment: str | None, classification: str | None) -> bool:
    return any(bool((value or "").strip()) for value in (business_service, environment, classification))


def metrics(settings: Settings, *, tenant_id: str, window_days: int = DEFAULT_WINDOW_DAYS) -> dict[str, Any]:
    """The adoption picture for one tenant over the last ``window_days``.

    Window-scoped: closures, MTTR, SLA adherence and the per-analyst table.
    Point-in-time: open findings, asset coverage and context, enrichment age.
    """
    window_days = max(MIN_WINDOW_DAYS, min(MAX_WINDOW_DAYS, int(window_days)))
    now = _now()
    since = now - timedelta(days=window_days)
    coverage_since = now - timedelta(days=COVERAGE_DAYS)

    vuln = models.Vulnerability
    asset = models.Asset
    device = models.EndpointDevice
    job = models.Job

    with get_session(settings.postgres_url) as session:
        findings = session.execute(
            select(
                vuln.severity,
                vuln.state,
                vuln.assignee,
                vuln.sla_started_at,
                vuln.closed_at,
                vuln.due_at,
                vuln.machine_verified,
                vuln.reopen_count,
                vuln.exception_until,
            ).where(vuln.tenant_id == tenant_id)
        ).all()
        assets = session.execute(
            select(
                asset.asset_id,
                asset.status,
                asset.owner_email,
                asset.business_service,
                asset.environment,
                asset.data_classification,
                asset.last_seen,
            ).where(asset.tenant_id == tenant_id)
        ).all()
        linked_assets = set(
            session.execute(
                select(device.asset_id).where(
                    device.tenant_id == tenant_id,
                    device.asset_id.is_not(None),
                    device.reconciliation_status == "linked",
                )
            ).scalars()
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

    # --- findings ---------------------------------------------------------
    open_total = 0
    accepted_open = 0
    reopened = 0
    closed_in_window = 0
    closed_verified = 0
    closed_with_deadline = 0
    closed_within_sla = 0
    mttr_by_severity: dict[str, list[float]] = {severity: [] for severity in SEVERITY_ORDER}
    mttr_all: list[float] = []
    by_analyst: dict[str, dict[str, int]] = {}

    for (
        severity,
        state,
        assignee,
        sla_started_at,
        closed_at,
        due_at,
        machine_verified,
        reopen_count,
        exception_until,
    ) in findings:
        if (reopen_count or 0) > 0:
            reopened += 1
        if state in vuln_states.ACTIVE:
            open_total += 1
            if _aware(exception_until) and _aware(exception_until) > now:
                accepted_open += 1
            continue
        if state != vuln_states.CLOSED:
            continue
        closed = _aware(closed_at)
        if closed is None or closed < since:
            continue
        closed_in_window += 1
        if machine_verified:
            closed_verified += 1
        started = _aware(sla_started_at)
        if started is not None:
            hours = _hours(closed, started)
            mttr_all.append(hours)
            mttr_by_severity.setdefault(str(severity), []).append(hours)
        deadline = _aware(due_at)
        if deadline is not None:
            closed_with_deadline += 1
            if closed <= deadline:
                closed_within_sla += 1
        who = (assignee or "").strip() or UNASSIGNED
        bucket = by_analyst.setdefault(who, {"closed": 0, "machine_verified": 0})
        bucket["closed"] += 1
        if machine_verified:
            bucket["machine_verified"] += 1

    # --- assets -----------------------------------------------------------
    active = 0
    with_owner = 0
    with_context = 0
    scanned_recently = 0
    dual_source = 0
    for asset_id, status, owner_email, business_service, environment, classification, last_seen in assets:
        if status != "active":
            continue
        active += 1
        if (owner_email or "").strip():
            with_owner += 1
        if _has_context(business_service, environment, classification):
            with_context += 1
        seen = _aware(last_seen)
        if seen is not None and seen >= coverage_since:
            scanned_recently += 1
        if asset_id in linked_assets:
            dual_source += 1

    analysts = sorted(
        (
            {"analyst": name, "closed": counts["closed"], "machine_verified": counts["machine_verified"]}
            for name, counts in by_analyst.items()
        ),
        key=lambda item: (-item["machine_verified"], -item["closed"], item["analyst"]),
    )[:ANALYSTS_LIMIT]

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
            "closed_in_window": closed_in_window,
            "machine_verified_closed": closed_verified,
            "machine_verified_share": _share(closed_verified, closed_in_window),
            "closed_within_sla_share": _share(closed_within_sla, closed_with_deadline),
            "mttr_hours": _median_or_none(mttr_all),
            "mttr_hours_by_severity": {
                severity: _median_or_none(values) for severity, values in mttr_by_severity.items()
            },
            "reopened_share": _share(reopened, len(findings)),
            "open_per_asset": round(open_total / active, 2) if active else None,
        },
        "assets": {
            "active": active,
            "with_owner_share": _share(with_owner, active),
            "with_context_share": _share(with_context, active),
            "scanned_recently_share": _share(scanned_recently, active),
            "dual_source_share": _share(dual_source, active),
            "coverage_days": COVERAGE_DAYS,
            "unowned": max(0, active - with_owner),
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
