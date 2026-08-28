from __future__ import annotations

import csv
import json
import os
import re
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from collections import Counter
from pathlib import Path

# Parsing goes through defusedxml (entity-expansion DoS: nmap XML embeds
# attacker-influenced banner/NSE text). The stdlib import stays for ET.Element
# and ET.ParseError -- defusedxml.ElementTree does not export Element.
from defusedxml.ElementTree import fromstring as safe_fromstring

from .cvss4 import Cvss4Database, enrich_vulnerabilities
from .asn_enrich import AsnDatabase, enrich_hosts_asn
from .geoip import GeoIpDatabase, attach_geo_to_records, enrich_hosts_geo
from .pulse_probe import load_service_artifacts
from .sarif_report import build_sarif_report
from .utils import save_json

_CVE_WITH_SCORE_RE = re.compile(r"(CVE-\d{4}-\d{3,7})\s+(\d{1,2}(?:\.\d+)?)", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _severity(cvss: float | None) -> str:
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "unknown"


def _extract_cves(output: str) -> list[tuple[str, float | None]]:
    """Extract (CVE, CVSS) pairs from NSE output (vulners/vulscan/vuln scripts)."""
    found: dict[str, float | None] = {}
    for match in _CVE_WITH_SCORE_RE.finditer(output):
        cve = match.group(1).upper()
        try:
            score: float | None = float(match.group(2))
        except ValueError:
            score = None
        existing = found.get(cve)
        if cve not in found or (score is not None and (existing is None or score > existing)):
            found[cve] = score
    for match in _CVE_RE.finditer(output):
        found.setdefault(match.group(0).upper(), None)
    return list(found.items())


def _host_address(host: ET.Element) -> str:
    for address in host.findall("address"):
        if address.attrib.get("addrtype") in ("ipv4", "ipv6"):
            return address.attrib.get("addr", "unknown")
    address_node = host.find("address")
    return address_node.attrib.get("addr", "unknown") if address_node is not None else "unknown"


def _script_record(host: str, port: str, script: ET.Element) -> dict:
    output = (script.attrib.get("output", "") or "").strip()
    has_cve = bool(_CVE_RE.search(output))
    return {
        "host": host,
        "port": port,
        "script_id": script.attrib.get("id", ""),
        "output": output,
        "vulnerable": "VULNERABLE" in output.upper() or has_cve,
    }


def _parse_nmap_xml(nmap_dir: Path) -> tuple[list[dict], list[dict], list[dict]]:
    """Return (services, os_matches, script_findings) parsed from Nmap XML files."""
    services: list[dict] = []
    os_matches: list[dict] = []
    script_findings: list[dict] = []

    for xml_file in sorted(nmap_dir.rglob("*.xml")):
        try:
            root = safe_fromstring(xml_file.read_text(encoding="utf-8"))
        except ET.ParseError:
            continue
        for host in root.findall("host"):
            address = _host_address(host)

            for osmatch in host.findall("./os/osmatch"):
                os_matches.append(
                    {
                        "host": address,
                        "name": osmatch.attrib.get("name", ""),
                        "accuracy": osmatch.attrib.get("accuracy", ""),
                    }
                )

            for script in host.findall("./hostscript/script"):
                script_findings.append(_script_record(address, "", script))

            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                service = port.find("service")
                portid = port.attrib.get("portid", "")
                services.append(
                    {
                        "host": address,
                        "port": portid,
                        "protocol": port.attrib.get("protocol", ""),
                        "service": (service.attrib.get("name", "unknown") if service is not None else "unknown"),
                        "product": (service.attrib.get("product", "") if service is not None else ""),
                        "version": (service.attrib.get("version", "") if service is not None else ""),
                    }
                )
                for script in port.findall("script"):
                    script_findings.append(_script_record(address, portid, script))

    return services, os_matches, script_findings


def _build_vulnerabilities(script_findings: list[dict]) -> list[dict]:
    """Turn raw NSE script output into structured, severity-ranked vulnerability findings."""
    vulnerabilities: list[dict] = []
    for finding in script_findings:
        output = finding["output"]
        cves = _extract_cves(output)
        if cves:
            for cve, cvss in cves:
                vulnerabilities.append(
                    {
                        "host": finding["host"],
                        "port": finding["port"],
                        "script_id": finding["script_id"],
                        "cve": cve,
                        "cvss": cvss,
                        "severity": _severity(cvss),
                        "source": "nmap-nse",
                    }
                )
        elif "VULNERABLE" in output.upper():
            vulnerabilities.append(
                {
                    "host": finding["host"],
                    "port": finding["port"],
                    "script_id": finding["script_id"],
                    "cve": None,
                    "cvss": None,
                    "severity": "unknown",
                    "source": "nmap-nse",
                }
            )

    vulnerabilities.sort(
        key=lambda item: (SEVERITY_ORDER.get(item["severity"], 0), item["cvss"] or 0.0),
        reverse=True,
    )
    return vulnerabilities


def _dedupe_vulnerabilities(vulnerabilities: list[dict]) -> list[dict]:
    """Drop duplicate host:port:CVE rows; keep first occurrence (higher-priority sources first).

    Rows without a CVE id are keyed by host:port:script_id so non-CVE
    VULNERABLE scripts still appear once.
    """
    seen: set[tuple[str, str, str]] = set()
    out: list[dict] = []
    for item in vulnerabilities:
        cve = item.get("cve")
        cve_key = str(cve).upper() if cve else f"script:{(item.get('script_id') or '')}"
        key = (str(item.get("host") or ""), str(item.get("port") or ""), cve_key)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _lookup_hostname(hostnames_map: dict, host: str) -> str:
    entry = hostnames_map.get(host) or {}
    primary = entry.get("primary")
    if isinstance(primary, str) and primary:
        return primary
    names = entry.get("names")
    if isinstance(names, list) and names:
        return str(names[0])
    return ""


def build_reports(
    output_dir: Path,
    total_targets: int,
    alive_hosts: list[str],
    open_ports: list[str],
    nmap_dir: Path,
    markdown_summary: bool,
    html_summary: bool,
    csv_export: bool,
    json_export: bool,
    sarif_export: bool = True,
    hostnames_map: dict | None = None,
    *,
    cvss4_enabled: bool = True,
    cvss4_database: Path | str | None = None,
    geoip_enabled: bool = True,
    geoip_database: Path | str | None = None,
    asn_enabled: bool = True,
    asn_database: Path | str | None = None,
    extra_vulnerabilities: list[dict] | None = None,
    report_primary: bool | None = None,
) -> None:
    """Build all configured report formats.

    ``report_primary``: whether Pulse artifacts (services.json/os.json) are
    the source of truth for this run, as resolved by scanner/main.py's
    env>profile>YAML backend precedence. Callers that already know this
    (i.e. scanner/main.py) should always pass it explicitly -- report
    generation must not re-derive it independently, since main.py's
    precedence resolution is the only place that can see profile-level
    overrides and is guaranteed fresh for the current invocation. When
    ``None`` (ad-hoc report regeneration, tests), falls back to
    OCTO_SERVICE_BACKEND plus the on-disk pulse/REPORT_PRIMARY marker.
    """
    hostnames = hostnames_map or {}
    # Prefer Pulse artifacts only when backend is pulse/hybrid (not mere shadow).
    # Shadow (nmap primary + dual-run) still writes services.json for diff, but
    # report must keep nmap as source of truth for services/OS.
    if report_primary is None:
        backend = os.environ.get("OCTO_SERVICE_BACKEND", "").strip().lower()
        prefer_pulse = backend in ("pulse", "hybrid") or (
            output_dir / "pulse" / "REPORT_PRIMARY"
        ).exists()
    else:
        prefer_pulse = report_primary

    pulse_artifacts = load_service_artifacts(output_dir)
    pulse_extra_vulns: list[dict] = []
    nmap_services, nmap_os, script_findings = _parse_nmap_xml(nmap_dir)

    services_source = "Nmap XML"
    if prefer_pulse and pulse_artifacts is not None:
        findings, os_matches, pulse_extra_vulns = pulse_artifacts
        if findings:
            services_source = "Pulse"
        else:
            findings = nmap_services
        if not os_matches:
            os_matches = nmap_os
    else:
        findings, os_matches = nmap_services, nmap_os
        # Still attach Pulse CVEs when shadow produced them
        if pulse_artifacts is not None:
            _, _, pulse_extra_vulns = pulse_artifacts
    if hostnames:
        for item in findings:
            item["hostname"] = _lookup_hostname(hostnames, item["host"])
        for item in script_findings:
            item["hostname"] = _lookup_hostname(hostnames, item["host"])
        for item in os_matches:
            item["hostname"] = _lookup_hostname(hostnames, item["host"])
    service_counter = Counter(item["service"] for item in findings)
    vulnerabilities = _build_vulnerabilities(script_findings)
    # Phase 4.2 CVE stack (default path, no nmap-vulners):
    #   Pulse --cve  → pulse_extra_vulns (source: pulse)
    #   Nuclei CVE   → extra_vulnerabilities (source: nuclei)
    #   NSE (legacy) → script_findings via _build_vulnerabilities
    # All feed CVSS4/EPSS/KEV enrichment below. Dedupe by host:port:CVE
    # (prefer first: NSE then Pulse then Nuclei when same id appears twice).
    if pulse_extra_vulns:
        vulnerabilities.extend(pulse_extra_vulns)
    if extra_vulnerabilities:
        vulnerabilities.extend(extra_vulnerabilities)
    vulnerabilities = _dedupe_vulnerabilities(vulnerabilities)
    vulnerabilities.sort(
        key=lambda item: (SEVERITY_ORDER.get(item["severity"], 0), item["cvss"] or 0.0),
        reverse=True,
    )

    if cvss4_enabled:
        cvss4_path = Path(cvss4_database) if cvss4_database else None
        enrich_vulnerabilities(vulnerabilities, Cvss4Database.load(cvss4_path))
    else:
        for item in vulnerabilities:
            item.setdefault("cvss4", None)
            item.setdefault("cvss4_vector", None)
            item.setdefault("cvss4_severity", None)

    geo_map: dict[str, dict[str, str]] = {}
    geo_db: GeoIpDatabase | None = None
    if geoip_enabled:
        geo_path = Path(geoip_database) if geoip_database else None
        geo_db = GeoIpDatabase.load(geo_path)
        try:
            hosts_for_geo = sorted(set(alive_hosts) | {str(v.get("host") or "") for v in vulnerabilities})
            hosts_for_geo = [h for h in hosts_for_geo if h]
            geo_map = enrich_hosts_geo(hosts_for_geo, geo_db)
            attach_geo_to_records(vulnerabilities, geo_map)
            attach_geo_to_records(findings, geo_map)
            attach_geo_to_records(script_findings, geo_map)
        finally:
            geo_db.close()
    else:
        for item in vulnerabilities:
            item.setdefault("country", None)
            item.setdefault("city", None)
            item.setdefault("country_iso", None)
            item.setdefault("latitude", None)
            item.setdefault("longitude", None)

    # ASN/org enrichment for alive hosts (attack-surface graph clustering).
    # Offline, fail-soft, mirrors GeoIP above.
    asn_map: dict[str, dict[str, str]] = {}
    if asn_enabled:
        asn_path = Path(asn_database) if asn_database else None
        asn_db = AsnDatabase.load(asn_path)
        try:
            asn_map = enrich_hosts_asn(sorted(set(alive_hosts)), asn_db)
        finally:
            asn_db.close()

    severity_counts = Counter(item["severity"] for item in vulnerabilities)
    vulnerable_hosts = sorted({item["host"] for item in vulnerabilities})
    hosts_with_names = sum(
        1 for host in alive_hosts if _lookup_hostname(hostnames, host)
    )
    country_counts = Counter(
        geo.get("country") or "unknown"
        for host in alive_hosts
        for geo in [geo_map.get(host, {})]
        if geo_map
    )

    best_os_by_host: dict[str, dict] = {}
    for match in os_matches:
        host = match["host"]
        current = best_os_by_host.get(host)
        if current is None or int(match["accuracy"] or 0) > int(current["accuracy"] or 0):
            best_os_by_host[host] = match

    summary = {
        "total_targets": total_targets,
        "alive_hosts": len(alive_hosts),
        "alive_hosts_with_names": hosts_with_names,
        "open_host_port_pairs": len(open_ports),
        "nmap_open_services": len(findings),
        "open_services_source": services_source,
        "os_detected_hosts": len(best_os_by_host),
        "nse_script_findings": len(script_findings),
        "potential_vulnerabilities": len(vulnerabilities),
        # Subset of the above the scanner itself flags as unconfirmed —
        # reachable-service exposures and unverified keyword CVE hits. Counted
        # in `potential_vulnerabilities` (they are potential by definition) but
        # broken out so the headline number can be read honestly.
        "unconfirmed_findings": sum(
            1
            for item in vulnerabilities
            if item.get("requires_confirmation")
            or str(item.get("finding_class") or "") in ("exposure", "keyword_cve")
        ),
        "vulnerable_hosts": len(vulnerable_hosts),
        "vulnerabilities_by_severity": {
            sev: severity_counts.get(sev, 0) for sev in ("critical", "high", "medium", "low", "unknown")
        },
        "hosts_by_country": dict(country_counts.most_common(50)) if country_counts else {},
        "top_services": service_counter.most_common(15),
    }
    save_json(output_dir / "summary.json", summary)

    def _os_accuracy(match: dict | None) -> int | None:
        if not match:
            return None
        try:
            return int(match.get("accuracy") or 0)
        except (TypeError, ValueError):
            return None

    alive_rows = [
        {
            "host": host,
            "hostname": _lookup_hostname(hostnames, host),
            "names": (hostnames.get(host) or {}).get("names", []),
            "country": (geo_map.get(host) or {}).get("country") or None,
            "city": (geo_map.get(host) or {}).get("city") or None,
            "country_iso": (geo_map.get(host) or {}).get("country_iso") or None,
            # Not `or None`: 0.0 is a real coordinate (the equator / the prime
            # meridian), and the Geo Map reads a missing value as "unlocated".
            "latitude": (geo_map.get(host) or {}).get("latitude"),
            "longitude": (geo_map.get(host) or {}).get("longitude"),
            "os_name": (best_os_by_host.get(host) or {}).get("name") or None,
            "os_accuracy": _os_accuracy(best_os_by_host.get(host)),
            "asn": (asn_map.get(host) or {}).get("asn") or None,
            "asn_org": (asn_map.get(host) or {}).get("asn_org") or None,
        }
        for host in sorted(set(alive_hosts))
    ]
    # Always export so the Web UI can list targets (with GeoIP when available).
    save_json(output_dir / "alive_hosts.json", alive_rows)
    if geo_map:
        save_json(output_dir / "geoip.json", geo_map)

    # OS and vulnerability findings are core deliverables and always exported.
    save_json(output_dir / "os_findings.json", os_matches)
    save_json(output_dir / "script_findings.json", script_findings)
    save_json(output_dir / "vulnerabilities.json", vulnerabilities)

    vuln_csv = output_dir / "vulnerabilities.csv"
    with vuln_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "host",
                "port",
                "severity",
                "cvss",
                "cvss4",
                "cvss4_vector",
                "cve",
                "script_id",
                "country",
                "city",
                "country_iso",
            ],
        )
        writer.writeheader()
        for item in vulnerabilities:
            writer.writerow({key: item.get(key, "") for key in writer.fieldnames})

    if json_export:
        save_json(output_dir / "findings.json", findings)
        (output_dir / "findings.jsonl").write_text(
            "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in findings),
            encoding="utf-8",
        )

    if sarif_export:
        build_sarif_report(output_dir, vulnerabilities, findings)

    if csv_export:
        csv_path = output_dir / "findings.csv"
        fieldnames = [
            "host",
            "hostname",
            "port",
            "protocol",
            "service",
            "product",
            "version",
            "country",
            "city",
            "country_iso",
        ]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for item in findings:
                writer.writerow({key: item.get(key, "") for key in fieldnames})

    if markdown_summary:
        sev = summary["vulnerabilities_by_severity"]
        md_lines = [
            "# Scan Summary",
            "",
            f"- Total targets: {summary['total_targets']}",
            f"- Alive hosts: {summary['alive_hosts']}",
            f"- Alive hosts with resolved names: {summary['alive_hosts_with_names']}",
            f"- Open host:port pairs: {summary['open_host_port_pairs']}",
            f"- Parsed open services from {summary['open_services_source']}: "
            f"{summary['nmap_open_services']}",
            f"- Hosts with OS detected: {summary['os_detected_hosts']}",
            f"- NSE script findings: {summary['nse_script_findings']}",
            f"- Potential vulnerabilities: {summary['potential_vulnerabilities']} "
            f"(across {summary['vulnerable_hosts']} hosts)",
            f"- Severity: critical {sev['critical']}, high {sev['high']}, "
            f"medium {sev['medium']}, low {sev['low']}, unknown {sev['unknown']}",
            "",
            "## Hosts by country",
        ]
        hosts_by_country = summary.get("hosts_by_country") or {}
        if hosts_by_country:
            for country, count in hosts_by_country.items():
                md_lines.append(f"- {country}: {count}")
        else:
            md_lines.append("- none (GeoIP database empty or disabled)")

        md_lines += ["", "## Top Services"]
        for service, count in summary["top_services"]:
            md_lines.append(f"- {service}: {count}")

        md_lines += ["", "## Operating Systems"]
        if best_os_by_host:
            for host, match in sorted(best_os_by_host.items()):
                md_lines.append(f"- {host}: {match['name']} (accuracy {match['accuracy']}%)")
        else:
            md_lines.append("- none detected")

        md_lines += ["", "## Vulnerabilities (highest severity first)"]
        if vulnerabilities:
            for item in vulnerabilities[:50]:
                location = f"{item['host']}:{item['port']}" if item["port"] else item["host"]
                cve = item["cve"] or item["script_id"]
                if item.get("cvss4") is not None:
                    cvss = f" CVSS4 {item['cvss4']}"
                elif item["cvss"] is not None:
                    cvss = f" CVSS {item['cvss']}"
                else:
                    cvss = ""
                geo_bits = [x for x in (item.get("city"), item.get("country")) if x]
                geo = f" [{', '.join(geo_bits)}]" if geo_bits else ""
                md_lines.append(
                    f"- [{item['severity'].upper()}] {location}{geo} {cve}{cvss} ({item['script_id']})"
                )
            if len(vulnerabilities) > 50:
                md_lines.append(f"- ... and {len(vulnerabilities) - 50} more (see vulnerabilities.json)")
        else:
            md_lines.append("- none detected")

        (output_dir / "summary.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if html_summary:
        summary_md = (output_dir / "summary.md").read_text(encoding="utf-8") if (output_dir / "summary.md").exists() else ""
        html = (
            "<html><head><meta charset='utf-8'><title>Scan Summary</title></head><body><pre>"
            + summary_md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            + "</pre></body></html>"
        )
        (output_dir / "summary.html").write_text(html, encoding="utf-8")
