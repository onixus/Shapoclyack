"""Security controls matrix for the org_profile module (M3, EPIC #182).

Evaluates the organization across 6 core security controls by reading and
normalizing findings from pipeline artifacts:

1. DNS structure (dns_hygiene.json + domain_monitor.json) — impact: medium
2. TLS certificates (tls_posture.json) — impact: medium
3. Mail protection (mail_posture.json) — impact: high
4. Web technologies (fingerprint.json) — impact: medium
5. Open services (vulnerabilities.json / services.json) — impact: high
6. Credential leaks (credential_leaks.json) — impact: critical

Status evaluation invariant: absence of data NEVER yields 'ok'.
- fail: >= 1 critical or high finding
- weak: only medium or low findings
- ok: checked and 0 findings
- not_checked: stage disabled, no credentials, or no data
- error: stage execution failed

Overall risk is calculated via NIST SP 800-30 Rev. 1 Table I-2:
qualitative likelihood x fixed impact -> risk verdict.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config_schema import ControlsConfig
from .utils import load_json, save_json

LOG = logging.getLogger("shapoclyack.controls")

STAGE = "controls"

# Fixed impact ratings per control definition in docs/org-profile-module.ru.md
CONTROL_DEFINITIONS = (
    {
        "id": "dns_structure",
        "title": "DNS структура",
        "impact": "medium",
        "evidence_files": ("dns_hygiene.json", "domain_monitor.json"),
    },
    {
        "id": "tls_certificates",
        "title": "TLS сертификаты",
        "impact": "medium",
        "evidence_files": ("tls_posture.json",),
    },
    {
        "id": "mail_protection",
        "title": "Почтовая защита",
        "impact": "high",
        "evidence_files": ("mail_posture.json",),
    },
    {
        "id": "web_technologies",
        "title": "Технологии сайта",
        "impact": "medium",
        "evidence_files": ("fingerprint.json",),
    },
    {
        "id": "open_services",
        "title": "Открытые сервисы",
        "impact": "high",
        "evidence_files": ("vulnerabilities.json", "services.json"),
    },
    {
        "id": "credential_leaks",
        "title": "Утечки учетных данных",
        "impact": "critical",
        "evidence_files": ("credential_leaks.json",),
    },
)

# NIST SP 800-30 Rev. 1 levels and Table I-2 risk matrix
VERY_LOW = "very_low"
LOW = "low"
MODERATE = "moderate"
HIGH = "high"
VERY_HIGH = "very_high"

LEVELS = (VERY_LOW, LOW, MODERATE, HIGH, VERY_HIGH)
LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}

_IMPACT_MAP = {
    "critical": VERY_HIGH,
    "high": HIGH,
    "medium": MODERATE,
    "moderate": MODERATE,
    "low": LOW,
    "very_low": VERY_LOW,
}

_RISK_MATRIX: dict[str, tuple[str, ...]] = {
    #        impact:   VL          L      M         H          VH
    VERY_HIGH: (VERY_LOW, LOW, MODERATE, HIGH, VERY_HIGH),
    HIGH: (VERY_LOW, LOW, MODERATE, HIGH, VERY_HIGH),
    MODERATE: (VERY_LOW, LOW, MODERATE, MODERATE, HIGH),
    LOW: (VERY_LOW, LOW, LOW, LOW, MODERATE),
    VERY_LOW: (VERY_LOW, VERY_LOW, VERY_LOW, LOW, LOW),
}


def nist_risk_level(likelihood: str | None, impact: str) -> str:
    """Calculate NIST SP 800-30 Table I-2 risk level from likelihood and impact."""
    if not likelihood or likelihood not in _RISK_MATRIX:
        return "unassessed"
    impact_level = _IMPACT_MAP.get(impact.lower(), MODERATE)
    col_idx = LEVEL_RANK.get(impact_level, 2)
    return _RISK_MATRIX[likelihood][col_idx]


def _extract_dns_structure_control(output_dir: Path) -> dict[str, Any]:
    hygiene_file = output_dir / "dns_hygiene.json"
    dm_file = output_dir / "domain_monitor.json"

    hygiene_data = load_json(hygiene_file, fallback=None)
    dm_data = load_json(dm_file, fallback=None)

    if hygiene_data is None and dm_data is None:
        return {
            "status": "not_checked",
            "coverage": {"checked": 0, "total": 0},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_findings": [],
            "evidence": [],
            "why": "DNS hygiene and domain monitoring stages were not run",
        }

    evidence: list[str] = []
    findings: list[dict[str, Any]] = []
    checked_domains: set[str] = set()
    total_domains: set[str] = set()

    if isinstance(hygiene_data, dict):
        evidence.append("dns_hygiene.json")
        for f in hygiene_data.get("findings") or []:
            findings.append({
                "id": f.get("kind", "dns_finding"),
                "domain": f.get("domain", ""),
                "severity": f.get("severity", "medium"),
                "detail": f.get("detail") or f.get("kind", ""),
            })
        for dom, ddata in (hygiene_data.get("domains") or {}).items():
            total_domains.add(dom)
            if isinstance(ddata, dict) and ddata.get("status") in ("ok", "findings"):
                checked_domains.add(dom)

    if isinstance(dm_data, dict):
        evidence.append("domain_monitor.json")
        for f in dm_data.get("findings") or []:
            findings.append({
                "id": f.get("kind", "domain_monitor_finding"),
                "domain": f.get("domain") or f.get("fqdn", ""),
                "severity": f.get("severity", "medium"),
                "detail": f.get("detail") or f.get("kind", ""),
            })
        for dom in dm_data.get("monitored_domains") or []:
            total_domains.add(dom)
            checked_domains.add(dom)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity", "medium").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    total_count = len(total_domains)
    checked_count = len(checked_domains)
    if total_count == 0 and findings:
        total_count = len(findings)
        checked_count = len(findings)

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        status = "fail"
        why = f"{sev_counts['critical'] + sev_counts['high']} high/critical DNS hygiene findings detected"
    elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
        status = "weak"
        why = f"{sev_counts['medium'] + sev_counts['low']} medium/low DNS hygiene findings detected"
    elif checked_count > 0:
        status = "ok"
        why = f"All {checked_count} domains passed DNS hygiene checks"
    else:
        status = "not_checked"
        why = "No domains checked for DNS hygiene"

    return {
        "status": status,
        "coverage": {"checked": checked_count, "total": total_count},
        "findings_by_severity": sev_counts,
        "top_findings": findings[:10],
        "evidence": evidence,
        "why": why,
    }


def _extract_tls_certificates_control(output_dir: Path) -> dict[str, Any]:
    tls_file = output_dir / "tls_posture.json"
    tls_data = load_json(tls_file, fallback=None)

    if not isinstance(tls_data, dict):
        return {
            "status": "not_checked",
            "coverage": {"checked": 0, "total": 0},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_findings": [],
            "evidence": [],
            "why": "TLS posture evaluation was not run",
        }

    findings_raw = tls_data.get("findings") or []
    targets_raw = tls_data.get("targets") or []
    total_targets = tls_data.get("total_targets") or len(targets_raw)
    checked_targets = len(targets_raw)

    findings: list[dict[str, Any]] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings_raw:
        sev = (f.get("severity") or "medium").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        findings.append({
            "id": f.get("kind", "tls_finding"),
            "domain": f.get("host", "") or f.get("target", ""),
            "severity": sev,
            "detail": f.get("detail") or f.get("kind", ""),
        })

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        status = "fail"
        why = f"{sev_counts['critical'] + sev_counts['high']} high/critical TLS posture findings (expired/weak/mismatch)"
    elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
        status = "weak"
        why = f"{sev_counts['medium'] + sev_counts['low']} medium/low TLS posture findings"
    elif checked_targets > 0 or tls_data.get("checked", False):
        status = "ok"
        why = f"All {checked_targets} inspected TLS endpoints passed validation"
    else:
        status = "not_checked"
        why = "No TLS endpoints inspected"

    return {
        "status": status,
        "coverage": {"checked": checked_targets, "total": total_targets},
        "findings_by_severity": sev_counts,
        "top_findings": findings[:10],
        "evidence": ["tls_posture.json"],
        "why": why,
    }


def _extract_mail_protection_control(output_dir: Path) -> dict[str, Any]:
    mail_file = output_dir / "mail_posture.json"
    mail_data = load_json(mail_file, fallback=None)

    if not isinstance(mail_data, dict):
        return {
            "status": "not_checked",
            "coverage": {"checked": 0, "total": 0},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_findings": [],
            "evidence": [],
            "why": "Mail authentication posture was not run",
        }

    findings_raw = mail_data.get("findings") or []
    domains_map = mail_data.get("domains") or {}
    checked_count = sum(
        1 for d in domains_map.values() if isinstance(d, dict) and d.get("status") in ("ok", "findings")
    )
    total_count = len(domains_map) or (len(findings_raw) if findings_raw else 0)

    findings: list[dict[str, Any]] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings_raw:
        sev = (f.get("severity") or "medium").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        findings.append({
            "id": f.get("kind", "mail_finding"),
            "domain": f.get("domain", ""),
            "severity": sev,
            "detail": f.get("detail") or f.get("kind", ""),
        })

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        status = "fail"
        why = f"{sev_counts['critical'] + sev_counts['high']} high/critical mail posture issues (SPF/DMARC/MX)"
    elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
        status = "weak"
        why = f"{sev_counts['medium'] + sev_counts['low']} medium/low mail posture issues"
    elif checked_count > 0:
        status = "ok"
        why = f"All {checked_count} mail domains have strong SPF/DMARC/MTA-STS protection"
    else:
        status = "not_checked"
        why = "No domains evaluated for mail posture"

    return {
        "status": status,
        "coverage": {"checked": checked_count, "total": total_count},
        "findings_by_severity": sev_counts,
        "top_findings": findings[:10],
        "evidence": ["mail_posture.json"],
        "why": why,
    }


def _extract_web_technologies_control(output_dir: Path) -> dict[str, Any]:
    fp_file = output_dir / "fingerprint.json"
    fp_data = load_json(fp_file, fallback=None)

    if not isinstance(fp_data, dict):
        return {
            "status": "not_checked",
            "coverage": {"checked": 0, "total": 0},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_findings": [],
            "evidence": [],
            "why": "Web technology fingerprinting was not run",
        }

    targets = fp_data.get("targets") or []
    checked_count = len(targets)
    total_count = fp_data.get("total_targets") or checked_count

    findings: list[dict[str, Any]] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in fp_data.get("findings") or []:
        sev = (f.get("severity") or "medium").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        findings.append({
            "id": f.get("kind", "fingerprint_finding"),
            "domain": f.get("host", "") or f.get("target", ""),
            "severity": sev,
            "detail": f.get("detail") or f.get("kind", ""),
        })

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        status = "fail"
        why = f"{sev_counts['critical'] + sev_counts['high']} high/critical tech stack exposures"
    elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
        status = "weak"
        why = f"{sev_counts['medium'] + sev_counts['low']} medium/low tech stack warnings"
    elif checked_count > 0:
        status = "ok"
        why = f"Identified {checked_count} web endpoints without severe technology misconfigurations"
    else:
        status = "not_checked"
        why = "No web targets fingerprinted"

    return {
        "status": status,
        "coverage": {"checked": checked_count, "total": total_count},
        "findings_by_severity": sev_counts,
        "top_findings": findings[:10],
        "evidence": ["fingerprint.json"],
        "why": why,
    }


def _extract_open_services_control(output_dir: Path) -> dict[str, Any]:
    vulns_file = output_dir / "vulnerabilities.json"
    summary_file = output_dir / "summary.json"
    ports_file = output_dir / "open_ports.txt"

    vulns_data = load_json(vulns_file, fallback=None)
    summary_data = load_json(summary_file, fallback=None)
    has_ports_file = ports_file.exists()

    if vulns_data is None and summary_data is None and not has_ports_file:
        return {
            "status": "not_checked",
            "coverage": {"checked": 0, "total": 0},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_findings": [],
            "evidence": [],
            "why": "Service and vulnerability scan was not run",
        }

    findings: list[dict[str, Any]] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    evidence = []

    if isinstance(vulns_data, list):
        evidence.append("vulnerabilities.json")
        for v in vulns_data:
            if not isinstance(v, dict):
                continue
            sev = (v.get("severity") or "unknown").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            findings.append({
                "id": v.get("cve") or v.get("script_id") or "vulnerability",
                "domain": f"{v.get('host', '')}:{v.get('port', '')}" if v.get("port") else v.get("host", ""),
                "severity": sev,
                "detail": f"{v.get('cve', '')} {v.get('script_id', '')}".strip(),
            })

    checked_hosts = 0
    total_hosts = 0
    if isinstance(summary_data, dict):
        checked_hosts = summary_data.get("alive_hosts") or 0
        total_hosts = summary_data.get("total_targets") or checked_hosts

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        status = "fail"
        why = f"{sev_counts['critical'] + sev_counts['high']} high/critical vulnerabilities found across open services"
    elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
        status = "weak"
        why = f"{sev_counts['medium'] + sev_counts['low']} medium/low findings across open services"
    elif has_ports_file or checked_hosts > 0 or vulns_data is not None:
        status = "ok"
        why = f"Scanned open services across {checked_hosts} host(s) with 0 detected vulnerabilities"
    else:
        status = "not_checked"
        why = "Open services scan not performed"

    return {
        "status": status,
        "coverage": {"checked": checked_hosts, "total": total_hosts},
        "findings_by_severity": sev_counts,
        "top_findings": findings[:10],
        "evidence": evidence or (["vulnerabilities.json"] if vulns_file.exists() else ["open_ports.txt"]),
        "why": why,
    }


def _extract_credential_leaks_control(output_dir: Path) -> dict[str, Any]:
    leaks_file = output_dir / "credential_leaks.json"
    leaks_data = load_json(leaks_file, fallback=None)

    if not isinstance(leaks_data, dict):
        return {
            "status": "not_checked",
            "coverage": {"checked": 0, "total": 0},
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_findings": [],
            "evidence": [],
            "why": "Credential leaks check was not configured or run",
        }

    findings_raw = leaks_data.get("findings") or []
    breaches_count = leaks_data.get("breaches_count") or len(findings_raw)
    checked_domains = leaks_data.get("checked_domains") or 0
    total_domains = leaks_data.get("total_domains") or checked_domains

    findings: list[dict[str, Any]] = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings_raw:
        sev = (f.get("severity") or "critical").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        findings.append({
            "id": f.get("kind", "credential_leak"),
            "domain": f.get("domain", ""),
            "severity": sev,
            "detail": f.get("detail", "Leaked corporate accounts detected"),
        })

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0 or breaches_count > 0:
        status = "fail"
        why = f"{breaches_count} corporate breach incident(s) detected with exposed credentials"
    elif sev_counts["medium"] > 0 or sev_counts["low"] > 0:
        status = "weak"
        why = f"{sev_counts['medium'] + sev_counts['low']} credential exposure warnings"
    elif checked_domains > 0:
        status = "ok"
        why = f"0 breaches found across {checked_domains} checked domain(s)"
    else:
        status = "not_checked"
        why = "No domains evaluated for credential leaks"

    return {
        "status": status,
        "coverage": {"checked": checked_domains, "total": total_domains},
        "findings_by_severity": sev_counts,
        "top_findings": findings[:10],
        "evidence": ["credential_leaks.json"],
        "why": why,
    }


_EXTRACTORS = {
    "dns_structure": _extract_dns_structure_control,
    "tls_certificates": _extract_tls_certificates_control,
    "mail_protection": _extract_mail_protection_control,
    "web_technologies": _extract_web_technologies_control,
    "open_services": _extract_open_services_control,
    "credential_leaks": _extract_credential_leaks_control,
}


def _control_likelihood(status: str, sev_counts: dict[str, int]) -> str | None:
    if status == "fail":
        if sev_counts.get("critical", 0) > 0:
            return VERY_HIGH
        return HIGH
    if status == "weak":
        if sev_counts.get("medium", 0) > 0:
            return MODERATE
        return LOW
    if status == "ok":
        return VERY_LOW
    return None


def evaluate_controls(output_dir: Path, config: ControlsConfig | None = None) -> dict[str, Any]:
    """Evaluate all 6 security controls for this run and build the matrix."""
    controls_list: list[dict[str, Any]] = []
    assessed_risk_levels: list[str] = []
    has_fail = False
    has_weak = False
    has_ok = False

    for defn in CONTROL_DEFINITIONS:
        cid = defn["id"]
        extractor = _EXTRACTORS[cid]
        result = extractor(output_dir)

        status = result["status"]
        sev_counts = result.get("findings_by_severity") or {}
        likelihood = _control_likelihood(status, sev_counts)
        impact = defn["impact"]
        risk = nist_risk_level(likelihood, impact)

        if risk != "unassessed":
            assessed_risk_levels.append(risk)

        if status == "fail":
            has_fail = True
        elif status == "weak":
            has_weak = True
        elif status == "ok":
            has_ok = True

        item = {
            "control": cid,
            "title": defn["title"],
            "status": status,
            "impact": impact,
            "coverage": result["coverage"],
            "findings_by_severity": sev_counts,
            "top_findings": result.get("top_findings", []),
            "evidence": result.get("evidence", []),
            "why": result.get("why", ""),
            "risk_level": risk,
        }
        controls_list.append(item)

    # Overall verdict
    if has_fail:
        overall_verdict = "fail"
    elif has_weak:
        overall_verdict = "weak"
    elif has_ok:
        overall_verdict = "ok"
    else:
        overall_verdict = "not_checked"

    # Overall risk: highest among assessed controls
    if assessed_risk_levels:
        overall_risk = max(assessed_risk_levels, key=lambda lvl: LEVEL_RANK.get(lvl, -1))
    else:
        overall_risk = "unassessed"

    summary = {
        "overall_verdict": overall_verdict,
        "overall_risk": overall_risk,
        "controls": controls_list,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    save_json(output_dir / "controls.json", summary)

    # Fold into summary.json if present
    summary_file = output_dir / "summary.json"
    summary_data = load_json(summary_file, fallback=None)
    if isinstance(summary_data, dict):
        summary_data["controls"] = summary
        save_json(summary_file, summary_data)

    # Append markdown section to summary.md if present
    summary_md_file = output_dir / "summary.md"
    if summary_md_file.exists():
        try:
            content = summary_md_file.read_text(encoding="utf-8")
            if "## Security Controls Matrix" not in content:
                md_lines = format_controls_markdown(summary)
                content += "\n" + "\n".join(md_lines) + "\n"
                summary_md_file.write_text(content, encoding="utf-8")
        except OSError:
            pass

    return summary


def format_controls_markdown(summary: dict[str, Any]) -> list[str]:
    """Generate Markdown representation of the controls matrix for summary.md."""
    lines = [
        "## Security Controls Matrix (org_profile)",
        "",
        f"- **Overall Posture Verdict:** `{summary.get('overall_verdict', 'not_checked').upper()}`",
        f"- **NIST SP 800-30 Risk:** `{summary.get('overall_risk', 'unassessed').replace('_', ' ').title()}`",
        "",
        "| Control | Status | Impact | Risk Level | Findings (C/H/M/L) | Assessment / Why |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for c in summary.get("controls") or []:
        title = c.get("title", "")
        status = (c.get("status") or "not_checked").upper()
        impact = (c.get("impact") or "").title()
        risk = (c.get("risk_level") or "unassessed").replace("_", " ").title()
        sev = c.get("findings_by_severity") or {}
        sev_str = f"{sev.get('critical', 0)}/{sev.get('high', 0)}/{sev.get('medium', 0)}/{sev.get('low', 0)}"
        why = c.get("why", "").replace("|", "-")
        lines.append(f"| {title} | `{status}` | {impact} | {risk} | {sev_str} | {why} |")

    lines.append("")
    return lines
