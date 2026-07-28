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


class CveRecord(BaseModel):
    """Optional CVE from Pulse --cve / --cve-online."""

    schema_version: Literal["octo.cve.v1"] = "octo.cve.v1"
    cve_id: str
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
    """Map Pulse CVEs into report extra_vulnerabilities shape."""
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
        out.append(
            {
                "host": c.ip,
                "port": str(c.port) if c.port else "",
                "script_id": c.source or "pulse-cve",
                "cve": c.cve_id,
                "cvss": c.cvss,
                "severity": severity,
                "title": c.title or c.cve_id,
                "detail": c.summary or c.match_reason,
            }
        )
    return out
