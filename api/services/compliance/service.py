"""Compliance posture: control status computed from the tenant's own evidence.

One pass over the tenant's open findings and its asset registry, classified
into signals (``signals.py``) and folded onto the control catalogues
(``frameworks.py``). The pass is shared across all three frameworks in a
single-framework request too, because the expensive part is the query, not the
fold, and because two frameworks disagreeing about the same estate would be a
bug that only appears under load.

**Only open findings count.** A closed finding is evidence that the control
worked, not that it is failing, and a control that stayed red after the fix was
verified would train operators to ignore the page. Accepted risk
(``exception_until`` in the future) is likewise not a failure — it is a
documented decision the framework's own risk-acceptance process covers — but it
is reported separately per control so an auditor can see what was accepted
rather than fixed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services.compliance import frameworks as catalog
from api.services.compliance import signals as sig
from api.settings import Settings
from scanner.pipeline.report import SEVERITY_ORDER

PASSED = "passed"
FAILED = "failed"
NOT_ASSESSED = "not_assessed"

# How many example findings a control carries in the summary. The full list is
# behind the per-control endpoint; a summary that inlined 4,000 findings would
# be the reason nobody opens the page.
_EVIDENCE_SAMPLE = 5


def _now() -> datetime:
    return datetime.now(UTC)


def _meets_floor(severity: str | None, floor: str) -> bool:
    return SEVERITY_ORDER.get(str(severity or "unknown"), 0) >= SEVERITY_ORDER.get(floor, 0)


class _Evidence:
    """A finding or asset that raised signals, kept in the shape the API returns."""

    __slots__ = ("kind", "ref_id", "label", "severity", "detail", "signals", "accepted")

    def __init__(
        self,
        *,
        kind: str,
        ref_id: str,
        label: str,
        severity: str,
        detail: str,
        signals: set[str],
        accepted: bool = False,
    ) -> None:
        self.kind = kind
        self.ref_id = ref_id
        self.label = label
        self.severity = severity
        self.detail = detail
        self.signals = signals
        self.accepted = accepted

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "ref_id": self.ref_id,
            "label": self.label,
            "severity": self.severity,
            "detail": self.detail,
            "signals": sorted(self.signals),
            "accepted": self.accepted,
        }


def _collect_evidence(settings: Settings, tenant_id: str | None) -> dict[str, Any]:
    """Every fact the catalogues can be folded over, gathered once."""

    now = _now()
    # ``sla_state`` compares against the naive-UTC clock the vulnerability
    # module normalises everything to; handing it an aware datetime is a
    # TypeError on the first finding with a deadline.
    sla_now = now.replace(tzinfo=None)
    vuln_filters: list[Any] = []
    asset_filters: list[Any] = []
    if tenant_id:
        vuln_filters.append(models.Vulnerability.tenant_id == tenant_id)
        asset_filters.append(models.Asset.tenant_id == tenant_id)

    evidence: list[_Evidence] = []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(
                models.Vulnerability.vuln_id,
                models.Vulnerability.title,
                models.Vulnerability.cve,
                models.Vulnerability.script_id,
                models.Vulnerability.port,
                models.Vulnerability.severity,
                models.Vulnerability.state,
                models.Vulnerability.in_kev,
                models.Vulnerability.network_exposure,
                models.Vulnerability.due_at,
                models.Vulnerability.exception_until,
                models.Vulnerability.asset_id,
            ).where(*vuln_filters)
        ).all()

        assets = session.execute(
            select(
                models.Asset.asset_id,
                models.Asset.status,
                models.Asset.owner_email,
                models.Asset.environment,
                models.Asset.data_classification,
            ).where(*asset_filters)
        ).all()

        endpoint_filters = (
            [models.SoftwareCveMatch.tenant_id == tenant_id] if tenant_id else []
        )
        endpoint_rows = session.execute(
            select(models.SoftwareCveMatch.status, func.count())
            .where(*endpoint_filters)
            .group_by(models.SoftwareCveMatch.status)
        ).all()

    open_findings = 0
    for row in rows:
        (
            vuln_id,
            title,
            cve,
            script_id,
            port,
            severity,
            state,
            in_kev,
            exposure,
            due_at,
            exception_until,
            asset_id,
        ) = row
        if state not in vuln_states.ACTIVE:
            continue
        open_findings += 1
        finding = {
            "title": title,
            "cve": cve,
            "script_id": script_id,
            "port": port,
            "in_kev": in_kev,
            "network_exposure": exposure,
        }
        reading = vulns_service.sla_state(
            {"state": state, "due_at": due_at, "exception_until": exception_until},
            now=sla_now,
        )
        raised = sig.classify_finding(finding, sla_reading=reading)
        if not raised:
            continue
        evidence.append(
            _Evidence(
                kind="finding",
                ref_id=str(vuln_id),
                label=str(title or cve or script_id or vuln_id),
                severity=str(severity or "unknown"),
                detail=f"asset {asset_id}" + (f", port {port}" if port else ""),
                signals=raised,
                accepted=reading == "accepted",
            )
        )

    for asset_id, status, owner_email, environment, data_classification in assets:
        raised = sig.classify_asset(
            {
                "status": status,
                "owner_email": owner_email,
                "environment": environment,
                "data_classification": data_classification,
            }
        )
        if not raised:
            continue
        evidence.append(
            _Evidence(
                kind="asset",
                ref_id=str(asset_id),
                label=str(asset_id),
                # An asset-context gap has no severity of its own. "medium"
                # rather than "unknown" so a control with a severity floor
                # still sees it, and never "critical" so it cannot outrank a
                # real finding in a sorted evidence list.
                severity="medium",
                detail=f"status {status}",
                signals=raised,
            )
        )

    endpoint_counts = {str(status): int(count) for status, count in endpoint_rows}
    unassessable = endpoint_counts.get("unknown", 0)
    if unassessable:
        evidence.append(
            _Evidence(
                kind="software",
                ref_id="endpoint-inventory",
                label=f"{unassessable} installed packages could not be assessed",
                severity="medium",
                detail="software→CVE matcher reported status=unknown",
                signals={sig.UNASSESSABLE_SOFTWARE},
            )
        )

    available = {catalog.SOURCE_FINDINGS} if rows else set()
    if assets:
        available.add(catalog.SOURCE_ASSETS)
    if endpoint_counts:
        available.add(catalog.SOURCE_ENDPOINT_INVENTORY)

    return {
        "evidence": evidence,
        "available_sources": available,
        "asset_count": len(assets),
        "open_findings": open_findings,
        "generated_at": now,
    }


def _assess_control(control: catalog.Control, collected: dict[str, Any]) -> dict[str, Any]:
    if not set(control.requires) <= collected["available_sources"]:
        return {
            "control_id": control.control_id,
            "title": control.title,
            "status": NOT_ASSESSED,
            "rationale": control.rationale,
            "signals": list(control.signals),
            "severity_floor": control.severity_floor,
            "failing_count": 0,
            "accepted_count": 0,
            "evidence": [],
            "not_assessed_reason": (
                "no "
                + ", ".join(sorted(set(control.requires) - collected["available_sources"]))
                + " data in this tenant"
            ),
        }

    wanted = set(control.signals)
    failing: list[_Evidence] = []
    accepted = 0
    for item in collected["evidence"]:
        if not (item.signals & wanted):
            continue
        if not _meets_floor(item.severity, control.severity_floor):
            continue
        if item.accepted:
            accepted += 1
            continue
        failing.append(item)

    failing.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, 0), reverse=True)
    return {
        "control_id": control.control_id,
        "title": control.title,
        "status": FAILED if failing else PASSED,
        "rationale": control.rationale,
        "signals": list(control.signals),
        "severity_floor": control.severity_floor,
        "failing_count": len(failing),
        "accepted_count": accepted,
        "evidence": [item.as_dict() for item in failing[:_EVIDENCE_SAMPLE]],
        "not_assessed_reason": None,
    }


def assess(
    settings: Settings, *, framework_id: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    """Posture for one framework, or ``None`` if the framework is unknown."""

    framework = catalog.get_framework(framework_id)
    if framework is None:
        return None
    collected = _collect_evidence(settings, tenant_id)
    return _fold(framework, collected)


def assess_all(settings: Settings, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
    """Posture for every framework off one evidence pass (used by the report factory)."""

    collected = _collect_evidence(settings, tenant_id)
    return [_fold(framework, collected) for framework in catalog.FRAMEWORKS.values()]


def _fold(framework: catalog.Framework, collected: dict[str, Any]) -> dict[str, Any]:
    controls = [_assess_control(control, collected) for control in framework.controls]
    assessed = [entry for entry in controls if entry["status"] != NOT_ASSESSED]
    passed = [entry for entry in assessed if entry["status"] == PASSED]
    return {
        "framework_id": framework.framework_id,
        "name": framework.name,
        "version": framework.version,
        "scope_note": framework.scope_note,
        "generated_at": collected["generated_at"].isoformat(),
        "asset_count": collected["asset_count"],
        "open_findings": collected["open_findings"],
        "controls_total": len(controls),
        "controls_assessed": len(assessed),
        "controls_passed": len(passed),
        "controls_failed": len(assessed) - len(passed),
        "controls_not_assessed": len(controls) - len(assessed),
        # Share of the *assessed* controls that pass. Deliberately not a
        # percentage of the framework: the catalogue is a subset of it, and a
        # number presented as "PCI DSS compliance" would be a false claim.
        "coverage_score": round(100.0 * len(passed) / len(assessed), 1) if assessed else None,
        "controls": controls,
    }


def control_evidence(
    settings: Settings,
    *,
    framework_id: str,
    control_id: str,
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Every piece of evidence behind one control, not just the sample."""

    framework = catalog.get_framework(framework_id)
    if framework is None:
        return None
    control = framework.control(control_id)
    if control is None:
        return None
    collected = _collect_evidence(settings, tenant_id)
    assessed = _assess_control(control, collected)
    wanted = set(control.signals)
    items = [
        item
        for item in collected["evidence"]
        if (item.signals & wanted) and _meets_floor(item.severity, control.severity_floor)
    ]
    items.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, 0), reverse=True)
    assessed["evidence"] = [item.as_dict() for item in items]
    assessed["framework_id"] = framework.framework_id
    return assessed
