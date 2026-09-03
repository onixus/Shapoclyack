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
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import nist_risk
from api.services import pagination
from api.services import runs as runs_service
from api.services import vuln_states
from scanner.pipeline.cvss4 import normalize_cwes
from api.services.risk_scoring import FOOTHOLD, LOCAL, get_scorer, index_cdn_waf, path_role
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
    "comment",
    "ticket_set",
    "ticket_cleared",
    # Closed-loop remediation (#183).
    "verification_started",
    "verification_passed",
    "verification_failed",
    "ticket_synced",
)

TICKET_SYSTEMS = ("jira", "servicenow", "smax", "defectdojo", "other")

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


def _severity_of(entry: dict[str, Any]) -> str:
    severity = str(entry.get("severity") or "").strip().lower()
    return severity if severity in SEVERITY_ORDER else "unknown"


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


def _run_findings(settings: Settings, run_id: str) -> list[dict[str, Any]]:
    run_dir = runs_service.get_run_dir(settings, run_id)
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


def register_findings_from_run(
    settings: Settings, *, tenant_id: str, run_id: str
) -> RegisterStats:
    """Fold one run's findings into the tracker. Idempotent per run.

    Re-running it for the same run is a no-op beyond refreshing the latest
    assessment: identity is the finding, not the observation, so the second pass
    finds every row and updates it. That matters because both job completion
    paths (local scan, agent upload) can be retried.
    """
    entries = _run_findings(settings, run_id)
    if not entries and not _run_verifies_anything(settings, run_id=run_id, tenant_id=tenant_id):
        return RegisterStats(0, 0, 0, 0, 0)

    # A verification run that finds nothing is the *success* case — it is the
    # scan reporting the finding is gone — so an empty run still has to reach
    # the verification block below.

    scorer = get_scorer()
    run_dir = runs_service.get_run_dir(settings, run_id)
    cdn_waf = index_cdn_waf(
        runs_service._load_json(run_dir / "fingerprint.json") if run_dir is not None else None  # noqa: SLF001
    )
    now = _now()
    created = reobserved = reopened = skipped = 0
    verification_passed = verification_failed = 0

    with get_session(settings.postgres_url) as session:
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
                operator_exposure=asset.exposure_level,
                cdn_waf_index=cdn_waf,
                same_asset_foothold=(
                    path_role(entry) == LOCAL and asset.asset_id in footholds
                ),
            )
            severity = _severity_of(entry)
            key = finding_key(asset_id=asset.asset_id, cve=cve, script_id=script_id, port=port)

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
                row = models.Vulnerability(
                    vuln_id=f"vln_{uuid.uuid4().hex[:16]}",
                    tenant_id=tenant_id,
                    asset_id=asset.asset_id,
                    finding_key=key,
                    cve=cve,
                    script_id=script_id,
                    port=port,
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
                session.add(row)
                session.flush()
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

            for field, value in latest.items():
                setattr(row, field, value)
            row.last_seen_at = now
            row.last_seen_run_id = run_id
            row.observation_count += 1
            row.updated_at = now
            reobserved += 1

            if row.state == vuln_states.CLOSED:
                # A regression: it was closed and it is back. The SLA clock
                # restarts from this observation, because the deadline for
                # fixing something that returned is not measured from before it
                # was fixed the first time.
                previous = row.state
                days, source = _resolve_sla_days(
                    session,
                    tenant_id=tenant_id,
                    severity=severity,
                    criticality=asset.asset_criticality,
                )
                row.state = vuln_states.OPEN
                row.state_changed_at = now
                row.state_changed_by = None
                row.closed_at = None
                row.sla_started_at = now
                row.due_at = now + timedelta(days=days)
                row.sla_days = days
                row.sla_source = source
                row.reopen_count += 1
                reopened += 1
                _record_event(
                    session,
                    vuln_id=row.vuln_id,
                    tenant_id=tenant_id,
                    kind="reopened",
                    occurred_at=now,
                    from_state=previous,
                    to_state=vuln_states.OPEN,
                    note="Re-observed after being closed",
                    detail={"run_id": run_id, "reopen_count": row.reopen_count},
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
                else:
                    # The run that was sent to look for it did not find it.
                    v_row.state = vuln_states.CLOSED
                    v_row.state_changed_at = now
                    v_row.state_changed_by = "system:verification"
                    v_row.closed_at = now
                    v_row.last_verified_at = now
                    v_row.machine_verified = True
                    v_row.closure_reason = "verified_remediated"
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
    )
    LOG.info(
        "Vulnerability tracker: run=%s tenant=%s seen=%s created=%s reobserved=%s "
        "reopened=%s skipped=%s",
        run_id,
        tenant_id,
        stats.findings_seen,
        stats.created,
        stats.reobserved,
        stats.reopened,
        stats.skipped_unknown_asset,
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


# --------------------------------------------------------------------------
# Operator decisions
# --------------------------------------------------------------------------


def _to_dict(row: models.Vulnerability, *, now: datetime | None = None) -> dict[str, Any]:
    now = now or _now()
    return {
        "vuln_id": row.vuln_id,
        "tenant_id": row.tenant_id,
        "asset_id": row.asset_id,
        "finding_key": row.finding_key,
        "cve": row.cve,
        "cwe": list(row.cwe or []),
        "script_id": row.script_id,
        "port": row.port,
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
        "machine_verified": bool(row.machine_verified),
        "verification_job_id": row.verification_job_id,
        "last_verified_at": _iso(row.last_verified_at),
        "closure_reason": row.closure_reason,
    }


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
            if row.exception_until is not None:
                detail["cleared_exception_until"] = _iso(row.exception_until)
                row.exception_until = None
                row.exception_reason = None
                row.exception_by = None
        elif previous == vuln_states.CLOSED:
            # The operator reopen. Same clock reset as the observer's regression
            # path, and recorded as the same kind of event so "how often does
            # this come back" is one query.
            kind = "reopened"
            row.closed_at = None
            row.machine_verified = False
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
    return result


def _ticket_endpoint(
    session: Any, *, tenant_id: str, ticket_system: str
) -> tuple[str, str | None, dict[str, str]] | None:
    """``(base_url, secret, headers)`` for the tenant's tracker, or ``None``.

    The tracker is addressed through the subscription that configured it, not
    by string-splitting the stored ``ticket_url``: that is where the credential
    lives, and a URL we did not configure is a URL we should not be calling.
    """
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
    return str(row.url), row.secret, {str(k): str(v) for k, v in (row.headers or {}).items()}


def _verification_target(session: Any, row: models.Vulnerability) -> tuple[str | None, bool]:
    """The address to re-scan for one finding, and whether it is an IP.

    Assets carry no address column of their own — the addresses are the
    ``asset_identifiers`` rows the ingest resolved the finding's host through —
    so the target is read back from there. An IP is preferred over an FQDN
    because it is what the original observation was made against.
    """
    identifiers = session.scalars(
        select(models.AssetIdentifier).where(
            models.AssetIdentifier.tenant_id == row.tenant_id,
            models.AssetIdentifier.asset_id == row.asset_id,
        )
    ).all()
    for wanted in ("ip", "fqdn"):
        for identifier in identifiers:
            value = str(identifier.identifier_value or "").strip()
            if identifier.identifier_type == wanted and value:
                return value, wanted == "ip"
    return None, False


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
        base_url, secret, headers = endpoint
        return ticket_sync.push_status_update(
            transport=ticket_system,
            base_url=base_url,
            ticket_key=ticket_key,
            to_state=to_state,
            secret=secret,
            extra_headers=headers,
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
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        previous = row.state
        # Goes through the same state machine as an operator's move: a closed
        # finding is not re-verified, it is reopened first.
        vuln_states.check_transition(vuln_id, previous, vuln_states.VERIFYING)

        target, is_ip = _verification_target(session, row)
        if not target:
            raise VerificationDispatchError(
                f"Vulnerability '{vuln_id}' has no scannable address on record"
            )

        owning_tenant = row.tenant_id
        port = str(row.port).strip() if row.port is not None else None

    if not settings.allow_scan_start:
        raise VerificationDispatchError(
            "Scan dispatch is disabled on this server (OCTO_ALLOW_SCAN_START), "
            "so this finding cannot be machine-verified"
        )

    from api.schemas import StartScanRequest
    from api.services import jobs as jobs_service

    scan_request = StartScanRequest(
        tenant_id=owning_tenant,
        mode="safe",
        # The narrowest intent that still runs the vulnerability checks: the
        # verification has to be able to re-detect what it is confirming gone.
        intent="vuln",
        ranges=target if is_ip else None,
        domains=target if not is_ip else None,
        # Re-check the port the finding is on. Verifying a finding on 8443 with
        # a default port sweep is how "not observed" stops meaning "fixed".
        ports=port or None,
        skip_nse=False,
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
        )
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
            note=f"Targeted verification scan dispatched (job {job.job_id})",
            detail={
                "job_id": job.job_id,
                "asset_id": row.asset_id,
                "target": target,
                "port": port,
                "cve": row.cve,
                "script_id": row.script_id,
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
    """Poll the linked ticket and reconcile the finding's state.

    A tracker can say the work is done or that it is under way. It cannot say
    the finding is *verified* gone — only a scan says that — so a closure from
    here is recorded as ``ticket_resolved`` and never as machine-verified.
    """
    now = _now()
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

    base_url, secret, headers = endpoint
    suggested_state, raw_status, _ = ticket_sync.fetch_ticket_status(
        transport=ticket_system,
        base_url=base_url,
        ticket_key=ticket_key,
        secret=secret,
        extra_headers=headers,
    )

    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        previous = row.state
        applied = False
        # Only a legal move is applied. An unreachable tracker returns no
        # suggestion at all, and that is recorded as a sync that changed
        # nothing rather than as progress.
        if suggested_state and suggested_state != previous and vuln_states.can_transition(
            previous, suggested_state
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
            elif previous == vuln_states.CLOSED:
                # Same reopen bookkeeping the operator path does, so a
                # ticket-driven regression is not an SLA-free finding.
                row.closed_at = None
                row.machine_verified = False
                row.closure_reason = None
                row.sla_started_at = now
                days = row.sla_days or DEFAULT_SLA_DAYS.get(
                    row.severity, DEFAULT_SLA_DAYS["unknown"]
                )
                row.due_at = now + timedelta(days=days)
                row.reopen_count += 1

        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="ticket_synced",
            occurred_at=now,
            from_state=previous,
            to_state=row.state,
            actor=actor or f"ticket_sync:{ticket_system}",
            note=f"Ticket {ticket_key} reports '{raw_status or 'unknown'}'",
            detail={
                "ticket_system": ticket_system,
                "ticket_key": ticket_key,
                "remote_status": raw_status,
                "suggested_state": suggested_state,
                "applied": applied,
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
        return _to_dict(row, now=now)


def set_exception(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    until: datetime,
    reason: str,
    actor: str | None = None,
) -> dict[str, Any] | None:
    """Accept the risk until ``until``, suspending the SLA clock.

    An expiry and a reason are both mandatory. A risk acceptance with no end
    date is a decision nobody will revisit, and one with no reason cannot be
    reviewed by the person who inherits it — which is exactly what an exception
    workflow is for. ``due_at`` moves to the expiry so the finding returns to
    the breach report the day the acceptance lapses.
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
        row.exception_until = until
        row.exception_reason = reason[:2000]
        row.exception_by = actor
        row.due_at = until
        row.sla_source = "exception"
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_set",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=reason,
            detail={"exception_until": _iso(until)},
        )
        session.flush()
        return _to_dict(row, now=now)


def clear_exception(
    settings: Settings,
    *,
    tenant_id: str | None,
    vuln_id: str,
    actor: str | None = None,
    note: str | None = None,
) -> dict[str, Any] | None:
    """Withdraw an acceptance and put the finding back under its policy deadline.

    The deadline is recomputed from ``sla_started_at``, not from now: the risk
    was accepted, not restarted, so a finding whose window had already elapsed
    is immediately breached again rather than being granted a fresh one.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _load(session, tenant_id=tenant_id, vuln_id=vuln_id)
        if row is None:
            return None
        if row.exception_until is None:
            return _to_dict(row, now=now)
        was_until = row.exception_until
        asset = session.get(models.Asset, row.asset_id)
        days, source = _resolve_sla_days(
            session,
            tenant_id=row.tenant_id,
            severity=row.severity,
            criticality=asset.asset_criticality if asset else None,
        )
        row.exception_until = None
        row.exception_reason = None
        row.exception_by = None
        row.sla_days = days
        row.sla_source = source
        row.due_at = (_naive(row.sla_started_at) or now) + timedelta(days=days)
        row.updated_at = now
        _record_event(
            session,
            vuln_id=row.vuln_id,
            tenant_id=row.tenant_id,
            kind="exception_cleared",
            occurred_at=now,
            to_state=row.state,
            actor=actor,
            note=note,
            detail={"was_until": _iso(was_until), "due_at": _iso(row.due_at)},
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
    assignee: str | None = None,
    unassigned: bool = False,
    sla: str | None = None,
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
    """
    if state and state.upper() not in vuln_states.ALL:
        raise ValueError(f"unknown state {state!r}; expected one of {', '.join(vuln_states.ORDER)}")
    if sla and sla not in SLA_STATES:
        raise ValueError(f"unknown sla filter {sla!r}; expected one of {', '.join(SLA_STATES)}")
    if unassigned and assignee:
        raise ValueError("unassigned and assignee cannot be combined")
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
    if unassigned:
        filters.append(models.Vulnerability.assignee.is_(None))
    elif assignee:
        filters.append(models.Vulnerability.assignee == assignee)
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
