"""OASIS SARIF v2.1.0 vulnerability report exporter.

Generates standard Static Analysis Results Interchange Format (SARIF) JSON
compatible with GitHub Code Scanning, GitLab Security, DefectDojo, VS Code,
and SIEM / VM platforms.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .utils import save_json

LOG = logging.getLogger("shapoclyack.sarif")

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "unknown": "note",
}


def _sarif_level(severity: str | None) -> str:
    if not severity:
        return "note"
    return _SEVERITY_TO_SARIF_LEVEL.get(severity.lower(), "note")


def _format_target_uri(host: str, port: str | int | None) -> str:
    """Format an actionable target URI for SARIF locations."""
    host_str = str(host or "").strip()
    if not port:
        return f"host://{host_str}"
    port_str = str(port).strip()
    if port_str in ("443", "8443", "9443", "4443"):
        return f"https://{host_str}:{port_str}/"
    if port_str in ("80", "8080", "8000", "8008", "8888"):
        return f"http://{host_str}:{port_str}/"
    return f"tcp://{host_str}:{port_str}"


def _make_rule_id(item: dict[str, Any]) -> str:
    cve = (item.get("cve") or "").strip().upper()
    if cve:
        return cve
    script_id = (item.get("script_id") or "").strip()
    if script_id:
        return script_id
    return "UNKNOWN_VULNERABILITY"


def build_sarif_report(
    output_dir: Path,
    vulnerabilities: list[dict[str, Any]],
    findings: list[dict[str, Any]] | None = None,
    *,
    tool_version: str = "0.42.0",
) -> dict[str, Any]:
    """Generate and persist OASIS SARIF v2.1.0 report (sarif.json)."""
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for item in vulnerabilities:
        rule_id = _make_rule_id(item)
        severity = str(item.get("severity") or "unknown").lower()
        level = _sarif_level(severity)
        cvss = item.get("cvss4") if item.get("cvss4") is not None else item.get("cvss")
        cve = item.get("cve")
        script_id = item.get("script_id") or ""
        source = item.get("source") or "scanner"
        cwe_list = item.get("cwe") or []
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]

        if rule_id not in rules_map:
            rule_desc = f"Security vulnerability identified by {source} ({rule_id})"
            if cve:
                help_uri = f"https://nvd.nist.gov/vuln/detail/{cve}"
            else:
                help_uri = "https://github.com/onixus/Shapoclyack"

            rule_entry: dict[str, Any] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_").replace(":", "_"),
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": rule_desc},
                "defaultConfiguration": {"level": level},
                "helpUri": help_uri,
                "properties": {
                    "tags": ["security", "vulnerability", source] + [str(c) for c in cwe_list],
                    "precision": "high",
                },
            }
            if cvss is not None:
                rule_entry["properties"]["security-severity"] = str(cvss)
            rules_map[rule_id] = rule_entry

        host = str(item.get("host") or "")
        port = item.get("port")
        location_uri = _format_target_uri(host, port)

        msg_parts = [f"Found {rule_id} ({severity.upper()}) on {host}"]
        if port:
            msg_parts[0] += f":{port}"
        if cvss is not None:
            msg_parts.append(f"CVSS score {cvss}")
        if script_id and script_id != rule_id:
            msg_parts.append(f"via {script_id}")

        message_text = " - ".join(msg_parts)

        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location_uri,
                        }
                    }
                }
            ],
            "properties": {
                "host": host,
                "port": str(port) if port is not None else "",
                "severity": severity,
                "source": source,
            },
        }
        if cvss is not None:
            result_entry["properties"]["cvss"] = cvss
        if cve:
            result_entry["properties"]["cve"] = cve

        results.append(result_entry)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Shapoclyack",
                        "informationUri": "https://github.com/onixus/Shapoclyack",
                        "version": tool_version,
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    sarif_file = output_dir / "sarif.json"
    save_json(sarif_file, sarif_doc)
    LOG.info("SARIF report written to %s (%d results, %d rules)", sarif_file, len(results), len(rules_map))
    return sarif_doc
