"""What goes in a report, decided once and rendered three ways (Sprint 4).

The builder produces a plain dict — no PDF objects, no HTML — and the renderers
turn that dict into PDF, HTML or JSON. That split is what makes the JSON export
*the same report* as the PDF rather than a second implementation of it: an MSSP
that pipes the JSON into its own portal and a customer reading the PDF must not
be able to reach different conclusions about the same month.

Every number here is sourced from the tracked-finding tables and the compliance
engine, never from a run directory. A report about a quarter has to be
renderable after that quarter's runs were pruned by retention.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import risk_snapshots
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services.compliance import service as compliance_service
from api.services.reports import branding as branding_service
from api.settings import Settings

# Section keys a template may switch off. Unknown keys in a stored template are
# ignored rather than rejected, so a template written against an older release
# keeps working after a section is renamed.
SECTIONS = (
    "kpis",
    "trend",
    "severity",
    "sla",
    "top_findings",
    "assets",
    "compliance",
)

KINDS = ("executive", "technical", "compliance")

# Sections each kind renders when the template does not say otherwise. An
# executive report that listed 200 findings would be a technical report with a
# misleading name.
_DEFAULT_SECTIONS: dict[str, tuple[str, ...]] = {
    "executive": ("kpis", "trend", "severity", "sla", "compliance"),
    "technical": ("kpis", "severity", "top_findings", "assets"),
    "compliance": ("kpis", "compliance"),
}

_TOP_FINDINGS = {"executive": 10, "technical": 50, "compliance": 10}
_TREND_DAYS = 90
# Snapshots are taken per run, not per day, so a limit equal to ``_TREND_DAYS``
# would silently shorten the window to the last 90 *snapshots* — a few days on a
# busy tenant, while the report still says "90 days".
_TREND_MAX_POINTS = 1000


def _now() -> datetime:
    return datetime.now(UTC)


def enabled_sections(kind: str, sections: dict[str, Any] | None) -> list[str]:
    """The kind's defaults, with the template's switches applied *in both
    directions*.

    An override that could only turn a section off would accept
    ``{"top_findings": true}`` on an executive template and then silently not
    render it — a setting the console offers, the API stores, and the report
    ignores."""

    defaults = _DEFAULT_SECTIONS.get(kind, _DEFAULT_SECTIONS["executive"])
    overrides = sections or {}
    return [key for key in SECTIONS if bool(overrides.get(key, key in defaults))]


def _asset_context(settings: Settings, tenant_id: str) -> dict[str, Any]:
    """Coverage of the fields the SLA and ownership workflow depends on.

    Counted in SQL rather than by paging the registry: at 50,000 assets the
    "unowned assets" number is the one an executive report is read for, and it
    must not cost a full table load into Python to produce."""

    with get_session(settings.postgres_url) as session:
        total = (
            session.execute(
                select(func.count()).select_from(models.Asset).where(
                    models.Asset.tenant_id == tenant_id
                )
            ).scalar()
            or 0
        )
        owned = (
            session.execute(
                select(func.count())
                .select_from(models.Asset)
                .where(
                    models.Asset.tenant_id == tenant_id,
                    models.Asset.owner_email.is_not(None),
                    models.Asset.owner_email != "",
                )
            ).scalar()
            or 0
        )
        with_service = (
            session.execute(
                select(func.count())
                .select_from(models.Asset)
                .where(
                    models.Asset.tenant_id == tenant_id,
                    models.Asset.business_service.is_not(None),
                    models.Asset.business_service != "",
                )
            ).scalar()
            or 0
        )
        active = (
            session.execute(
                select(func.count())
                .select_from(models.Asset)
                .where(models.Asset.tenant_id == tenant_id, models.Asset.status == "active")
            ).scalar()
            or 0
        )
    return {
        "total": total,
        "active": active,
        "with_owner": owned,
        "without_owner": total - owned,
        "with_business_service": with_service,
        "owner_coverage_pct": round(100.0 * owned / total, 1) if total else None,
    }


def _trend(settings: Settings, tenant_id: str, now: datetime) -> list[dict[str, Any]]:
    snapshots = risk_snapshots.list_snapshots(
        settings,
        tenant_id=tenant_id,
        since=now - timedelta(days=_TREND_DAYS),
        limit=_TREND_MAX_POINTS,
    )
    return [
        {
            "recorded_at": entry.get("recorded_at"),
            "open_total": entry.get("open_total", 0),
            "breached": entry.get("breached", 0),
            "estate_risk": entry.get("estate_risk"),
        }
        for entry in snapshots
    ]


def build(
    settings: Settings,
    *,
    tenant_id: str,
    kind: str = "executive",
    framework_id: str | None = None,
    sections: dict[str, Any] | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    """Assemble the report body for one tenant.

    ``tenant_id`` is required and not optional-for-platform-admin, unlike the
    read APIs: a report is a document about one organisation, and a
    cross-tenant one would put one customer's findings in another's PDF.
    """

    if kind not in KINDS:
        raise ValueError(f"unknown report kind {kind!r}; expected one of {', '.join(KINDS)}")
    if not tenant_id:
        raise ValueError("tenant_id is required — a report is about one organisation")

    now = _now()
    active = enabled_sections(kind, sections)
    brand = branding_service.get_branding(settings, tenant_id=tenant_id)
    summary = vulns_service.summary(settings, tenant_id=tenant_id)

    body: dict[str, Any] = {
        "kind": kind,
        "tenant_id": tenant_id,
        "title": title or _default_title(kind, brand, framework_id),
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "period_days": _TREND_DAYS,
        "branding": brand,
        "sections": active,
    }

    if "kpis" in active:
        body["kpis"] = {
            "open_total": summary.get("open_total", 0),
            "total": summary.get("total", 0),
            "untriaged": summary.get("untriaged", 0),
            "unassigned": summary.get("unassigned", 0),
            "estate_risk": summary.get("estate_risk"),
            "breached": summary.get("breached", 0),
            "closed_total": summary.get("closed_total", 0),
            "machine_verified_closed": summary.get("machine_verified_closed", 0),
            "machine_verification_rate": summary.get("machine_verification_rate", 0.0),
        }
    if "severity" in active:
        body["severity"] = dict(summary.get("by_severity_open") or {})
        body["risk_levels"] = dict(summary.get("by_risk_level_open") or {})
    if "sla" in active:
        body["sla"] = dict(summary.get("by_sla") or {})
        body["worst_breached_severity"] = summary.get("worst_breached_severity")
    if "trend" in active:
        body["trend"] = _trend(settings, tenant_id, now)
    if "top_findings" in active:
        rows, _total = vulns_service.list_vulnerabilities(
            settings,
            tenant_id=tenant_id,
            # The lifecycle's own definition of open. A hand-written list drifts
            # from it — the first one here contained "TRIAGED", which is not a
            # state, and dropped ACKNOWLEDGED and PLANNED findings from the
            # table while the KPI block above still counted them.
            states=sorted(vuln_states.ACTIVE),
            limit=_TOP_FINDINGS.get(kind, 10),
            sort="contextual_score",
            order="desc",
        )
        body["top_findings"] = [
            {
                "vuln_id": row.get("vuln_id"),
                "title": row.get("title"),
                "cve": row.get("cve"),
                "asset_id": row.get("asset_id"),
                "port": row.get("port"),
                "severity": row.get("severity"),
                "risk_level": row.get("risk_level"),
                "contextual_score": row.get("contextual_score"),
                "state": row.get("state"),
                "sla": row.get("sla"),
                "in_kev": row.get("in_kev", False),
                "due_at": row.get("due_at"),
            }
            for row in rows
        ]
    if "assets" in active:
        body["assets"] = _asset_context(settings, tenant_id)
    if "compliance" in active:
        if framework_id:
            posture = compliance_service.assess(
                settings, framework_id=framework_id, tenant_id=tenant_id
            )
            if posture is None:
                raise ValueError(f"unknown compliance framework {framework_id!r}")
            postures = [posture]
        else:
            postures = compliance_service.assess_all(settings, tenant_id=tenant_id)
        # An executive report carries the scores; only a compliance report
        # carries every control, because a 30-page control table appended to a
        # two-page summary is how a report stops being read.
        detail = kind == "compliance"
        body["compliance"] = [
            {
                key: value
                for key, value in entry.items()
                if detail or key != "controls"
            }
            for entry in postures
        ]
    return body


def _default_title(kind: str, brand: dict[str, Any], framework_id: str | None) -> str:
    org = brand.get("org_name") or "Security"
    if kind == "compliance":
        return f"{org} — Compliance posture" + (f" ({framework_id})" if framework_id else "")
    if kind == "technical":
        return f"{org} — Technical vulnerability report"
    return f"{org} — Executive security report"
