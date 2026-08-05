"""Canonical service/OS artifacts (octo.service.v1 / octo.os.v1).

Produced by Pulse (or future backends) and consumed by report.py.
See pulse/docs/shapoclyack-migration.md in onixus/GenDec.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ServiceRecord(BaseModel):
    """One open service endpoint."""

    schema_version: Literal["octo.service.v1"] = "octo.service.v1"
    ip: str
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""
    source: str = "pulse"
    # Optional display name / hostname
    host: str = ""


class OsMatchRank(BaseModel):
    name: str = ""
    accuracy: float = 0.0
    family: str = ""


class OsRecord(BaseModel):
    """OS fingerprint for one host."""

    schema_version: Literal["octo.os.v1"] = "octo.os.v1"
    ip: str
    family: str = "Unknown"
    detail: str = ""
    confidence: int = Field(default=0, ge=0, le=100)
    source: str = "pulse"
    ttl: int | None = None
    matches: list[OsMatchRank] = Field(default_factory=list)
    host: str = ""


#: Pulse finding classes (``pulse.scan.v2``). ``exposure`` and ``tls`` carry no
#: CVE id; ``keyword_cve`` is an unverified NVD keyword hit, not a confirmed
#: match. See GenDec ``docs/findings.md``.
FINDING_CLASSES = ("version_cve", "keyword_cve", "exposure", "tls")


class CveRecord(BaseModel):
    """One Pulse finding from ``--cve`` / ``--cve-online``.

    Despite the name this is the whole finding taxonomy, not only CVEs:
    ``cve_id`` is empty for ``exposure`` / ``tls`` classes. Pulse separates
    observations from hypotheses, and the hypothesis metadata below
    (``finding_class`` / ``confidence`` / ``requires_confirmation``) is what
    keeps an unverified keyword hit from being scored like a confirmed one.
    """

    schema_version: Literal["octo.cve.v1"] = "octo.cve.v1"
    cve_id: str = ""
    ip: str
    port: int = 0
    service: str = ""
    cvss: float | None = None
    severity: str = "unknown"
    title: str = ""
    summary: str = ""
    match_reason: str = ""
    source: str = "pulse"
    refs: list[str] = Field(default_factory=list)
    # Hypothesis metadata (Pulse pulse.scan.v2).
    finding_class: str = "version_cve"
    confidence: int = Field(default=0, ge=0, le=100)
    requires_confirmation: bool = False
    evidence: str = ""
    ruleset_version: str = ""
    # Pulse-supplied enrichment. Both are authoritative over the API's local
    # overlays when set, since Pulse ships the real EPSS/KEV data.
    epss: float | None = None
    in_kev: bool = False


def finding_key(record: CveRecord) -> str:
    """Stable identifier for a finding, including CVE-less ones.

    Findings are keyed downstream by ``host:port:cve`` (report dedupe) and by
    ``(tenant, ip, cve_id)`` in ClickHouse. An exposure finding has no CVE, so
    without a synthetic id every exposure on a host would collapse into a
    single row. Derived from class, port, and title so it stays stable across
    runs.
    """
    if record.cve_id:
        return record.cve_id
    slug = "".join(
        ch if ch.isalnum() else "-" for ch in (record.title or record.match_reason).lower()
    ).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    cls = record.finding_class or "finding"
    port = record.port or 0
    return f"pulse:{cls}:{port}:{slug[:60]}" if slug else f"pulse:{cls}:{port}"


def services_to_report_findings(services: list[ServiceRecord]) -> list[dict[str, Any]]:
    """Map to report.py service dict shape (host/port/protocol/service/product/version)."""
    out: list[dict[str, Any]] = []
    for s in services:
        out.append(
            {
                "host": s.ip,
                "port": str(s.port),
                "protocol": s.protocol,
                "service": s.service or "unknown",
                "product": s.product or (s.banner[:80] if s.banner else ""),
                "version": s.version,
                "hostname": s.host or "",
                "source": s.source,
            }
        )
    return out


def os_to_report_matches(os_records: list[OsRecord]) -> list[dict[str, Any]]:
    """Map to report.py os_matches dict shape (host/name/accuracy)."""
    out: list[dict[str, Any]] = []
    for o in os_records:
        name = o.detail or o.family or "Unknown"
        out.append(
            {
                "host": o.ip,
                "name": name,
                "accuracy": str(o.confidence),
                "family": o.family,
                "source": o.source,
                "hostname": o.host or "",
            }
        )
    return out


def cves_to_extra_vulnerabilities(cves: list[CveRecord]) -> list[dict[str, Any]]:
    """Map Pulse findings into report extra_vulnerabilities shape.

    Tagged ``source: "pulse"`` so reports can distinguish from nuclei/NSE
    (Phase 4.2 — replaces nmap-vulners on the default Pulse path).

    CVE-less findings (``exposure`` / ``tls``) keep an empty ``cve`` and are
    identified by the synthetic ``script_id`` from :func:`finding_key`, the
    same fallback the report dedupe and ClickHouse ingest already use for
    nuclei/NSE findings without a CVE.
    """
    out: list[dict[str, Any]] = []
    for c in cves:
        sev = (c.severity or "unknown").lower()
        if sev == "critical":
            severity = "critical"
        elif sev == "high":
            severity = "high"
        elif sev == "medium":
            severity = "medium"
        elif sev == "low":
            severity = "low"
        else:
            severity = "unknown"
        origin = (c.source or "local").strip() or "local"
        out.append(
            {
                "host": c.ip,
                "port": str(c.port) if c.port else "",
                "script_id": f"pulse:{origin}" if c.cve_id else finding_key(c),
                "source": "pulse",
                "cve": c.cve_id,
                "cvss": c.cvss,
                "severity": severity,
                "title": c.title or c.cve_id,
                "detail": c.summary or c.match_reason,
                # Threaded through to api.services.risk_scoring, which prefers
                # these over its own EPSS/KEV overlays and discounts findings
                # Pulse itself flags as unconfirmed.
                "finding_class": c.finding_class,
                "confidence": c.confidence,
                "requires_confirmation": c.requires_confirmation,
                "evidence": c.evidence,
                "ruleset_version": c.ruleset_version,
                "epss": c.epss,
                "in_kev": c.in_kev,
            }
        )
    return out
