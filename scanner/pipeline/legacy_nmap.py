"""Read the Nmap XML of runs recorded before the Nmap stage was removed (#548).

Nothing writes ``<run>/nmap/*.xml`` any more, but the platform keeps the
directories of past runs, and a report rebuild, a ``--resume`` of an old run,
the evidence collector (``evidence_artifacts.py``), the verification-coverage
reader (``api/services/verification_coverage.py``) and the retro CVE matcher
still read them. This module is the one parser of that format; it takes a
directory and returns plain dicts, and has no scanner or Nmap dependency.

The findings built from the script rows keep ``source: "nmap-nse"``, and the
service rows keep ``prober: nmap`` where the API stores them: those strings are
data in the database and are displayed as before.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from pathlib import Path

# Parsing goes through defusedxml (entity-expansion DoS: nmap XML embeds
# attacker-influenced banner/NSE text). The stdlib import stays for ET.Element
# and ET.ParseError -- defusedxml.ElementTree does not export Element.
from defusedxml.ElementTree import fromstring as safe_fromstring

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def _host_address(host: ET.Element) -> str:
    for address in host.findall("address"):
        if address.attrib.get("addrtype") in ("ipv4", "ipv6"):
            return address.attrib.get("addr", "unknown")
    address_node = host.find("address")
    return address_node.attrib.get("addr", "unknown") if address_node is not None else "unknown"


def _script_record(host: str, port: str, script: ET.Element, protocol: str | None = None) -> dict:
    output = (script.attrib.get("output", "") or "").strip()
    has_cve = bool(_CVE_RE.search(output))
    return {
        "host": host,
        "port": port,
        # tcp | udp from nmap's <port protocol=...>; None for a host script.
        # A UDP finding must never be judged by a TCP re-check (#451).
        "protocol": protocol,
        "script_id": script.attrib.get("id", ""),
        "output": output,
        "vulnerable": "VULNERABLE" in output.upper() or has_cve,
    }


def parse_nmap_xml(nmap_dir: Path) -> tuple[list[dict], list[dict], list[dict]]:
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
                        # Kept for the retro CVE matcher (docs/retro-cve-matching.md):
                        # extrainfo is where nmap puts the distribution hint
                        # ("Ubuntu Linux; protocol 2.0"), and <cpe> is the
                        # vendor:product it resolved. Both used to be dropped
                        # here, which left nothing to re-match a run against.
                        "extrainfo": (service.attrib.get("extrainfo", "") if service is not None else ""),
                        "cpe": (
                            [c.text.strip() for c in service.findall("cpe") if c.text and c.text.strip()]
                            if service is not None
                            else []
                        ),
                    }
                )
                for script in port.findall("script"):
                    script_findings.append(
                        _script_record(address, portid, script, port.attrib.get("protocol") or None)
                    )

    return services, os_matches, script_findings
