"""Export Octo-man vulnerabilities to DefectDojo via Generic Findings Import.

Uses the DefectDojo API v2 ``/reimport-scan/`` (falls back-compatible with first
upload) with ``auto_create_context`` so Product / Engagement can be created on
the fly. Fail-soft: never raises to the pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from .config_schema import DefectDojoConfig
from .report import SEVERITY_ORDER

_DD_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "unknown": "Info",
}

SCAN_TYPE = "Generic Findings Import"


def _env_or(value: str, env_name: str) -> str:
    return value or os.environ.get(env_name, "")


def _meets_min_severity(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 0)


def _script_output_index(script_findings: list[dict[str, Any]]) -> dict[tuple[str, str, str], str]:
    index: dict[tuple[str, str, str], str] = {}
    for item in script_findings:
        host = str(item.get("host") or "")
        port = str(item.get("port") or "")
        script_id = str(item.get("script_id") or "")
        if not host or not script_id:
            continue
        index[(host, port, script_id)] = str(item.get("output") or "")
    return index


def map_vulnerabilities_to_generic_findings(
    vulnerabilities: list[dict[str, Any]],
    *,
    run_id: str,
    min_severity: str = "high",
    include_without_cve: bool = True,
    script_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a DefectDojo Generic Findings Import JSON document."""
    outputs = _script_output_index(script_findings or [])
    findings: list[dict[str, Any]] = []

    for item in vulnerabilities:
        severity = str(item.get("severity") or "unknown").lower()
        if not _meets_min_severity(severity, min_severity):
            continue

        cve = item.get("cve")
        script_id = str(item.get("script_id") or "")
        if not cve and not include_without_cve:
            continue

        host = str(item.get("host") or "")
        port = str(item.get("port") or "")
        title = str(cve) if cve else (script_id or "Octo-man finding")
        if host and port:
            title = f"{title} @ {host}:{port}"
        elif host:
            title = f"{title} @ {host}"

        description_parts = [
            f"Octo-man run `{run_id}`",
            f"Host: {host or 'n/a'}",
            f"Port: {port or 'n/a'}",
            f"NSE script: {script_id or 'n/a'}",
        ]
        if cve:
            description_parts.append(f"CVE: {cve}")
        cvss = item.get("cvss")
        if cvss is not None:
            description_parts.append(f"CVSS: {cvss}")
        script_out = outputs.get((host, port, script_id), "")
        if script_out:
            description_parts.append("")
            description_parts.append("NSE output:")
            description_parts.append(script_out[:4000])

        finding: dict[str, Any] = {
            "title": title,
            "severity": _DD_SEVERITY.get(severity, "Info"),
            "description": "\n".join(description_parts),
            "vuln_id_from_tool": f"{host}:{port}:{script_id}:{cve or 'none'}",
        }
        if cve:
            finding["cve"] = str(cve)
            finding["vulnerability_ids"] = [str(cve)]
        if cvss is not None:
            try:
                finding["cvssv3_score"] = float(cvss)
            except (TypeError, ValueError):
                pass
        if host:
            endpoint = f"{host}:{port}" if port else host
            finding["endpoints"] = [endpoint]
        if script_id:
            finding["service"] = script_id

        findings.append(finding)

    return {
        "name": f"Octo-man {run_id}",
        "type": "Octo-man",
        "findings": findings,
    }


def _encode_multipart(
    fields: dict[str, str],
    files: dict[str, tuple[str, bytes, str]],
) -> tuple[bytes, str]:
    boundary = f"----OctoManBoundary{uuid.uuid4().hex}"
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")
    for name, (filename, content, content_type) in files.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'
            ).encode("utf-8")
        )
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _post_reimport(
    *,
    base_url: str,
    api_key: str,
    fields: dict[str, str],
    file_bytes: bytes,
    filename: str,
    verify_ssl: bool,
    timeout: int = 60,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/api/v2/reimport-scan/"
    body, content_type = _encode_multipart(
        fields,
        {"file": (filename, file_bytes, "application/json")},
    )
    headers = {
        "Authorization": f"Token {api_key}",
        "Content-Type": content_type,
        "Accept": "application/json",
    }
    context = None if verify_ssl else ssl._create_unverified_context()  # noqa: S323
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        raw = response.read().decode("utf-8", errors="replace")
        status = getattr(response, "status", None) or response.getcode()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        payload = {"raw": raw[:2000]}
    return {"http_status": status, "response": payload}


def export_to_defectdojo(
    config: DefectDojoConfig,
    *,
    run_id: str,
    output_dir: Path,
) -> dict[str, Any]:
    """Map run artifacts and optionally upload to DefectDojo. Fail-soft."""
    result: dict[str, Any] = {
        "attempted": False,
        "status": None,
        "skipped_reason": None,
        "findings_count": 0,
        "url": None,
        "engagement_name": None,
        "product_name": None,
        "error": None,
        "http_status": None,
        "response": None,
        "payload_file": None,
    }

    if not config.enabled:
        result["skipped_reason"] = "defectdojo.disabled"
        return result

    vulns_path = output_dir / "vulnerabilities.json"
    if not vulns_path.exists():
        result["skipped_reason"] = "missing_vulnerabilities_json"
        logging.warning("DefectDojo export skipped: %s missing", vulns_path)
        return result

    vulnerabilities = json.loads(vulns_path.read_text(encoding="utf-8"))
    if not isinstance(vulnerabilities, list):
        result["skipped_reason"] = "invalid_vulnerabilities_json"
        return result

    script_findings: list[dict[str, Any]] = []
    scripts_path = output_dir / "script_findings.json"
    if scripts_path.exists():
        loaded = json.loads(scripts_path.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            script_findings = loaded

    payload = map_vulnerabilities_to_generic_findings(
        vulnerabilities,
        run_id=run_id,
        min_severity=config.min_severity,
        include_without_cve=config.include_without_cve,
        script_findings=script_findings,
    )
    findings_count = len(payload["findings"])
    result["findings_count"] = findings_count

    payload_path = output_dir / "defectdojo_findings.json"
    payload_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    result["payload_file"] = str(payload_path)

    if findings_count == 0:
        result["skipped_reason"] = "no_findings_after_filter"
        logging.info("DefectDojo export skipped: no findings ≥ %s", config.min_severity)
        return result

    base_url = _env_or(config.url, "OCTO_DEFECTDOJO_URL").rstrip("/")
    api_key = _env_or(config.api_key, "OCTO_DEFECTDOJO_API_KEY")
    if not base_url or not api_key:
        result["skipped_reason"] = "missing_credentials"
        result["error"] = "set defectdojo.url/api_key or OCTO_DEFECTDOJO_URL / OCTO_DEFECTDOJO_API_KEY"
        logging.warning("DefectDojo export enabled but credentials are incomplete")
        return result

    engagement_name = config.engagement_name or "Octo-man"
    product_name = config.product_name or "Octo-man"
    result["attempted"] = True
    result["url"] = base_url
    result["engagement_name"] = engagement_name
    result["product_name"] = product_name

    fields = {
        "scan_type": SCAN_TYPE,
        "minimum_severity": _DD_SEVERITY.get(config.min_severity, "Info"),
        "active": "true" if config.active else "false",
        "verified": "true" if config.verified else "false",
        "close_old_findings": "true" if config.close_old_findings else "false",
        "auto_create_context": "true" if config.auto_create_context else "false",
        "product_name": product_name,
        "product_type_name": config.product_type_name,
        "engagement_name": engagement_name,
        "test_title": config.test_title,
    }

    try:
        upload = _post_reimport(
            base_url=base_url,
            api_key=api_key,
            fields=fields,
            file_bytes=payload_path.read_bytes(),
            filename=f"octo-man-{run_id}.json",
            verify_ssl=config.verify_ssl,
            timeout=config.timeout_seconds,
        )
        result["http_status"] = upload["http_status"]
        result["response"] = upload["response"]
        if int(upload["http_status"] or 0) in (200, 201):
            result["status"] = "ok"
            logging.info(
                "DefectDojo export ok: %s findings → %s / %s",
                findings_count,
                product_name,
                engagement_name,
            )
        else:
            result["status"] = "error"
            result["error"] = f"HTTP {upload['http_status']}"
            logging.warning("DefectDojo export HTTP %s: %s", upload["http_status"], upload["response"])
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result["status"] = "error"
        if isinstance(exc, urllib.error.HTTPError):
            result["http_status"] = exc.code
            try:
                result["response"] = exc.read().decode("utf-8", errors="replace")[:2000]
            except Exception:  # noqa: BLE001
                result["response"] = None
        result["error"] = str(exc)
        logging.warning("DefectDojo export failed: %s", exc)

    return result
