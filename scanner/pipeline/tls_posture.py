"""TLS / certificate posture (Phase 9.2).

Reuses the already-collected NSE output from the ``nse`` stage -- this
module never runs nmap or opens a TLS connection itself. It parses the
free-text ``output`` attribute nmap's own ``ssl-cert`` / ``ssl-enum-ciphers``
scripts write into ``nmap/tcp/*.xml`` (and ``nmap/udp/*.xml``), the same XML
already walked generically by ``report.py``'s ``_parse_nmap_xml`` /
``_script_record``. No new scan and no Python TLS-handshake dependency
(``cryptography``/``pyopenssl``) is added here.

From ``ssl-cert`` output this module extracts certificate subject/issuer,
SAN, signature algorithm, public key size, and validity window, then flags:

  * ``cert_expired`` (critical) / ``cert_expiring_soon`` (medium) -- based on
    the certificate's "Not valid after" date vs. ``expiring_soon_days``.
  * ``self_signed`` (medium) -- a heuristic: subject commonName equals issuer
    commonName (case-insensitive), or (fallback) the raw subject/issuer
    strings are verbatim equal. Always tagged with a ``heuristic`` field --
    this is a signal, not a certain determination (a CA could legitimately
    reuse a CN, and this does not verify the chain).

From ``ssl-enum-ciphers`` output this module extracts each TLS/SSL protocol
version's cipher list and nmap's own per-cipher/least-strength letter grade,
then flags:

  * ``weak_protocol`` (high) -- SSLv2/SSLv3/TLSv1.0/TLSv1.1 offered at all.
  * ``weak_cipher_grade`` (medium) -- nmap graded the version's weakest
    cipher C/D/E/F.
  * ``weak_cipher_name`` (medium) -- a cipher name contains a known-weak
    substring (RC4, DES, 3DES, NULL, EXPORT, anon, MD5), independent of
    nmap's own grade.

HONESTY NOTE: nmap's NSE script ``output`` is free text meant for human
reading, not a stable, versioned schema -- nmap releases have changed this
formatting before and may again. All parsing here is regex/line-based and
fail-soft by construction: any field or line that doesn't match is skipped
or set to ``None`` rather than raising. A parse miss silently yields fewer
findings, never a crash.

OUT OF SCOPE: hostname/SAN-CN mismatch checking (comparing the certificate's
name(s) against the scanned target) is explicitly not implemented by this
module -- see the Phase 9.2 plan. Only cert expiry, the self-signed
heuristic, and weak protocol/cipher findings are produced.

SAFETY: disabled by default (``tls_posture.enabled = false``). The set of
host:port endpoints inspected is capped by ``max_targets`` -- past the cap,
remaining endpoints are skipped and the run is flagged "truncated" rather
than silently processing everything. Findings are reported only
(``tls_posture.json`` / ``tls_posture_findings.txt``) -- never merged into
scan scope or asset identity (same non-escalation principle as
``fingerprint.py`` / ``cloud_discovery.py``).
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config_schema import TlsPostureConfig
from .utils import save_json, write_lines

LOG = logging.getLogger("octo-man.tls_posture")

_WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
_WEAK_CIPHER_SUBSTRINGS = ("_RC4_", "_DES_", "_3DES_", "_NULL_", "_EXPORT_", "_anon_", "_MD5")
_WEAK_GRADES = ("C", "D", "E", "F")

_SSL_CERT_SCRIPT_ID = "ssl-cert"
_SSL_ENUM_CIPHERS_SCRIPT_ID = "ssl-enum-ciphers"

# ssl-cert output field regexes (re.MULTILINE, applied line-by-line semantics
# via `$` matching end-of-line).
_SUBJECT_RE = re.compile(r"^Subject:\s*(.+)$", re.MULTILINE)
_ISSUER_RE = re.compile(r"^Issuer:\s*(.+)$", re.MULTILINE)
_SAN_RE = re.compile(r"^Subject Alternative Name:\s*(.+)$", re.MULTILINE)
_SIG_ALG_RE = re.compile(r"^Signature Algorithm:\s*(.+)$", re.MULTILINE)
_PUBKEY_BITS_RE = re.compile(r"^Public Key bits:\s*(\d+)$", re.MULTILINE)
_NOT_BEFORE_RE = re.compile(r"^Not valid before:\s*(.+?)\s*$", re.MULTILINE)
_NOT_AFTER_RE = re.compile(r"^Not valid after:\s*(.+?)\s*$", re.MULTILINE)

# ssl-enum-ciphers line-by-line state machine regexes.
_VERSION_HEADER_RE = re.compile(r"^(TLSv1\.[0-3]|SSLv[23])\s*:\s*$")
_CIPHERS_HEADER_RE = re.compile(r"^\s*ciphers:\s*$")
_CIPHER_LINE_RE = re.compile(r"^\s+(TLS_\S+|SSL_\S+)\s*(?:\([^)]*\))?\s*-\s*([A-F])\s*$")
_LEAST_STRENGTH_RE = re.compile(r"^\s*least strength:\s*([A-F])\s*$")

# nmap's own commonName=... extraction from subject/issuer distinguished names.
_COMMON_NAME_RE = re.compile(r"commonName=([^/]+)")

_CERT_DATETIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%b %d %H:%M:%S %Y %Z",
    "%b %d %H:%M:%S %Y",
)


def _host_address(host: ET.Element) -> str:
    for address in host.findall("address"):
        if address.attrib.get("addrtype") in ("ipv4", "ipv6"):
            return address.attrib.get("addr", "unknown")
    address_node = host.find("address")
    return address_node.attrib.get("addr", "unknown") if address_node is not None else "unknown"


def _parse_cert_datetime(raw: str) -> datetime | None:
    raw = raw.strip()
    if not raw:
        return None
    for fmt in _CERT_DATETIME_FORMATS:
        try:
            parsed = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    LOG.debug("tls_posture: could not parse certificate datetime %r", raw)
    return None


def _parse_ssl_cert_output(output: str) -> dict[str, Any]:
    subject_match = _SUBJECT_RE.search(output)
    issuer_match = _ISSUER_RE.search(output)
    san_match = _SAN_RE.search(output)
    sig_alg_match = _SIG_ALG_RE.search(output)
    pubkey_bits_match = _PUBKEY_BITS_RE.search(output)
    not_before_match = _NOT_BEFORE_RE.search(output)
    not_after_match = _NOT_AFTER_RE.search(output)

    subject = subject_match.group(1).strip() if subject_match else None
    issuer = issuer_match.group(1).strip() if issuer_match else None

    not_before_raw = not_before_match.group(1).strip() if not_before_match else None
    not_after_raw = not_after_match.group(1).strip() if not_after_match else None
    not_before_dt = _parse_cert_datetime(not_before_raw) if not_before_raw else None
    not_after_dt = _parse_cert_datetime(not_after_raw) if not_after_raw else None

    public_key_bits: int | None = None
    if pubkey_bits_match:
        try:
            public_key_bits = int(pubkey_bits_match.group(1))
        except ValueError:
            public_key_bits = None

    return {
        "subject": subject,
        "issuer": issuer,
        "san": san_match.group(1).strip() if san_match else None,
        "signature_algorithm": sig_alg_match.group(1).strip() if sig_alg_match else None,
        "public_key_bits": public_key_bits,
        "not_before_raw": not_before_raw,
        "not_after_raw": not_after_raw,
        "not_before": not_before_dt.isoformat() if not_before_dt else None,
        "not_after": not_after_dt.isoformat() if not_after_dt else None,
        "parse_ok": bool(subject or issuer),
    }


def _parse_ssl_enum_ciphers_output(output: str) -> list[dict[str, Any]]:
    versions: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    collecting_ciphers = False

    for raw_line in output.splitlines():
        version_match = _VERSION_HEADER_RE.match(raw_line)
        if version_match:
            current = {"version": version_match.group(1), "ciphers": [], "least_strength": None}
            versions.append(current)
            collecting_ciphers = False
            continue

        if current is None:
            continue

        if _CIPHERS_HEADER_RE.match(raw_line):
            collecting_ciphers = True
            continue

        least_match = _LEAST_STRENGTH_RE.match(raw_line)
        if least_match:
            current["least_strength"] = least_match.group(1)
            collecting_ciphers = False
            continue

        if collecting_ciphers:
            cipher_match = _CIPHER_LINE_RE.match(raw_line)
            if cipher_match:
                current["ciphers"].append({"name": cipher_match.group(1), "grade": cipher_match.group(2)})
            # Unmatched lines while collecting (compressors, warnings, etc.)
            # are skipped silently -- fail-soft by construction.

    return versions


def _iter_ssl_scripts(nmap_dir: Path) -> list[tuple[str, str, str, str]]:
    """Yield (host, port, script_id, output) for ssl-cert/ssl-enum-ciphers script nodes."""
    results: list[tuple[str, str, str, str]] = []
    if not nmap_dir.exists():
        return results

    for xml_file in sorted(nmap_dir.rglob("*.xml")):
        try:
            root = ET.fromstring(xml_file.read_text(encoding="utf-8"))
        except ET.ParseError:
            continue
        for host in root.findall("host"):
            address = _host_address(host)
            for port in host.findall("./ports/port"):
                portid = port.attrib.get("portid", "")
                for script in port.findall("script"):
                    script_id = script.attrib.get("id", "")
                    if script_id not in (_SSL_CERT_SCRIPT_ID, _SSL_ENUM_CIPHERS_SCRIPT_ID):
                        continue
                    output = (script.attrib.get("output", "") or "").strip()
                    results.append((address, portid, script_id, output))

    return results


def _classify_cert(cert: dict[str, Any], now: datetime, expiring_soon_days: int) -> list[dict[str, Any]]:
    if not cert["parse_ok"]:
        return []

    issues: list[dict[str, Any]] = []

    not_after_raw = cert.get("not_after")
    if not_after_raw:
        try:
            parsed_not_after = datetime.fromisoformat(not_after_raw)
        except ValueError:
            parsed_not_after = None
        if parsed_not_after is not None:
            days_left = (parsed_not_after - now).days
            if days_left < 0:
                issues.append({"kind": "cert_expired", "severity": "critical", "days": days_left})
            elif days_left <= expiring_soon_days:
                issues.append({"kind": "cert_expiring_soon", "severity": "medium", "days": days_left})

    subject = cert.get("subject")
    issuer = cert.get("issuer")
    subject_cn_match = _COMMON_NAME_RE.search(subject) if subject else None
    issuer_cn_match = _COMMON_NAME_RE.search(issuer) if issuer else None

    if subject_cn_match and issuer_cn_match:
        subject_cn = subject_cn_match.group(1).strip().lower()
        issuer_cn = issuer_cn_match.group(1).strip().lower()
        if subject_cn == issuer_cn:
            issues.append({"kind": "self_signed", "severity": "medium", "heuristic": "cn_match"})
    elif subject and issuer and subject == issuer:
        issues.append({"kind": "self_signed", "severity": "medium", "heuristic": "subject_equals_issuer"})

    return issues


def _classify_ciphers(versions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for version in versions:
        version_name = version.get("version")
        if version_name in _WEAK_PROTOCOLS:
            issues.append({"kind": "weak_protocol", "severity": "high", "version": version_name})

        least_strength = version.get("least_strength")
        if least_strength in _WEAK_GRADES:
            issues.append(
                {
                    "kind": "weak_cipher_grade",
                    "severity": "medium",
                    "version": version_name,
                    "grade": least_strength,
                }
            )

        for cipher in version.get("ciphers", []):
            name = cipher.get("name", "")
            if any(needle in name for needle in _WEAK_CIPHER_SUBSTRINGS):
                issues.append(
                    {
                        "kind": "weak_cipher_name",
                        "severity": "medium",
                        "version": version_name,
                        "cipher": name,
                    }
                )

    return issues


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "tls_posture.json", result)
    lines: list[str] = []
    for finding in result["findings"]:
        issues = finding.get("issues") or []
        if not issues:
            continue
        kinds = ",".join(sorted({issue["kind"] for issue in issues}))
        lines.append(f"{finding['host']}:{finding['port']}:{kinds}")
    write_lines(output_dir / "tls_posture_findings.txt", lines)


def check_tls_posture(
    nmap_dir: Path,
    config: TlsPostureConfig,
    output_dir: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Parse ssl-cert/ssl-enum-ciphers NSE output already present in ``nmap_dir``."""
    now = now or datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "targets_considered": 0,
        "checked_count": 0,
        "findings": [],
        "truncated": False,
        "skipped_reason": None,
    }

    if not config.enabled:
        result["skipped_reason"] = "tls_posture.disabled"
        _persist(output_dir, result)
        return result

    scripts = _iter_ssl_scripts(nmap_dir)
    endpoints: dict[tuple[str, str], dict[str, str]] = {}
    for host, port, script_id, output in scripts:
        endpoints.setdefault((host, port), {})[script_id] = output

    result["targets_considered"] = len(endpoints)
    if not endpoints:
        result["skipped_reason"] = "no_tls_endpoints"
        _persist(output_dir, result)
        return result

    ordered_keys = sorted(endpoints.keys())
    truncated = len(ordered_keys) > config.max_targets
    ordered_keys = ordered_keys[: config.max_targets]

    findings: list[dict[str, Any]] = []
    for host, port in ordered_keys:
        scripts_by_id = endpoints[(host, port)]
        issues: list[dict[str, Any]] = []

        cert: dict[str, Any] | None = None
        cert_output = scripts_by_id.get(_SSL_CERT_SCRIPT_ID)
        if cert_output is not None:
            cert = _parse_ssl_cert_output(cert_output)
            issues.extend(_classify_cert(cert, now, config.expiring_soon_days))

        cipher_versions: list[dict[str, Any]] = []
        cipher_output = scripts_by_id.get(_SSL_ENUM_CIPHERS_SCRIPT_ID)
        if cipher_output is not None:
            cipher_versions = _parse_ssl_enum_ciphers_output(cipher_output)
            issues.extend(_classify_ciphers(cipher_versions))

        findings.append(
            {
                "host": host,
                "port": port,
                "cert": cert,
                "cipher_versions": cipher_versions,
                "issues": issues,
            }
        )

    result["checked_count"] = len(findings)
    result["findings"] = findings
    result["truncated"] = truncated

    with_issues = sum(1 for f in findings if f["issues"])
    _persist(output_dir, result)
    LOG.info(
        "tls_posture: %d endpoint(s) checked -> %d with finding(s)%s",
        len(findings),
        with_issues,
        " [truncated]" if truncated else "",
    )
    return result
