"""TLS / certificate posture (Phase 9.2 + Pulse Phase 4).

Primary path: reuses already-collected NSE output from the ``nse`` stage --
parses free-text ``output`` of nmap's ``ssl-cert`` / ``ssl-enum-ciphers``
scripts from ``nmap/tcp/*.xml`` (and ``nmap/udp/*.xml``), the same XML
walked generically by ``report.py``.

Fallback paths (Phase 4): when nmap XML has no SSL scripts (Pulse backend,
``--skip-nse``, empty nmap dir):

1. **Pulse TLS JSON** (preferred) — if ``pulse/tls.json`` or ``pulse/raw.json``
   contains a ``tls`` array from Pulse ``--cve`` / TLS probe, convert those
   cert/weak-protocol fields into the same finding shape (``source: pulse-tls``).
2. **stdlib probe** — when ``probe_fallback`` is enabled and Pulse TLS is
   missing, open a direct handshake via ``tls_probe`` (``source: pulse-tls-probe``).

Does not replace full nmap cipher grading; covers cert expiry, self-signed
heuristic, and weak protocol acceptance / negotiated protocol.

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

P4.1 adds one more finding, applied uniformly to all three sources after the
per-source parsing is done:

  * ``cert_name_mismatch`` (medium) -- the certificate's DNS identities (CN +
    SAN) cover none of the FQDNs the scan used to reach the endpoint. The
    expected names are the *forward* half of ``hostnames.json`` only; matching
    follows RFC 6125 wildcard rules. See ``cert_names.py`` for why PTR names
    are excluded and why an IP-only endpoint yields no finding.

SAFETY: disabled by default (``tls_posture.enabled = false``). The set of
host:port endpoints inspected is capped by ``max_targets`` -- past the cap,
remaining endpoints are skipped and the run is flagged "truncated" rather
than silently processing everything. Findings are reported only
(``tls_posture.json`` / ``tls_posture_findings.txt``) -- never merged into
scan scope or asset identity (same non-escalation principle as
``fingerprint.py`` / ``cloud_discovery.py``).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Parsing goes through defusedxml (entity-expansion DoS: nmap XML embeds
# attacker-influenced banner/NSE text). The stdlib import stays for ET.Element
# and ET.ParseError -- defusedxml.ElementTree does not export Element.
from defusedxml.ElementTree import fromstring as safe_fromstring

from .cert_names import expected_names, hostname_mismatch
from .config_schema import TlsPostureConfig
from .pulse_probe import load_pulse_tls_artifact
from .tls_probe import _parse_tls_endpoints, probe_tls_endpoints, write_tls_probe_json
from .utils import save_json, write_lines

LOG = logging.getLogger("shapoclyack.tls_posture")

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
            root = safe_fromstring(xml_file.read_text(encoding="utf-8"))
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



def _normalize_proto_label(raw: str) -> str:
    """Map Pulse rustls Debug / accepts labels to tls_posture version strings."""
    s = (raw or "").strip()
    low = s.lower().replace(" ", "")
    mapping = {
        "tlsv1_0": "TLSv1.0",
        "tlsv1.0": "TLSv1.0",
        "tls1_0": "TLSv1.0",
        "tls1.0": "TLSv1.0",
        "tlsv1_1": "TLSv1.1",
        "tlsv1.1": "TLSv1.1",
        "tls1_1": "TLSv1.1",
        "tls1.1": "TLSv1.1",
        "tlsv1_2": "TLSv1.2",
        "tlsv1.2": "TLSv1.2",
        "tlsv1_3": "TLSv1.3",
        "tlsv1.3": "TLSv1.3",
        "sslv3": "SSLv3",
        "sslv2": "SSLv2",
    }
    if low in mapping:
        return mapping[low]
    # already pretty?
    for p in _WEAK_PROTOCOLS:
        if p.lower() == low:
            return p
    return s or "unknown"


def _parse_pulse_datetime(raw: str | None) -> datetime | None:
    if not raw:
        return None
    raw = str(raw).strip()
    # Pulse/x509: "2026-09-21 8:37:24.0 +00:00:00" or ISO
    cleaned = raw.replace("+00:00:00", "+00:00")
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            # handle single-digit hour in pulse output
            candidate = cleaned
            if " " in candidate and "T" not in candidate:
                # pad hour if needed: "2026-09-21 8:37:24" -> "2026-09-21 08:37:24"
                parts = candidate.split(" ", 1)
                if len(parts) == 2 and parts[1] and parts[1][0].isdigit() and parts[1][1] == ":":
                    candidate = parts[0] + " 0" + parts[1]
            dt = datetime.strptime(candidate, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # last resort: fromisoformat after cleanup
    try:
        iso = cleaned.replace(" ", "T", 1).split("+")[0]
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _pulse_tls_target_keys(artifact: dict[str, Any]) -> set[tuple[str, str]]:
    """Union of (ip, port) keys covered by ``tls[]`` rows and tls-class ``findings``.

    Mirrors the key extraction in findings_from_pulse_tls so truncation checks
    account for endpoints that only appear via findings (no matching tls row).
    """
    keys: set[tuple[str, str]] = set()
    for row in artifact.get("tls") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        try:
            port_i = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not ip or port_i < 1:
            continue
        keys.add((ip, str(port_i)))
    for f in artifact.get("findings") or []:
        if not isinstance(f, dict):
            continue
        if str(f.get("finding_class") or "").lower() != "tls":
            continue
        ip = str(f.get("ip") or "").strip()
        try:
            port = str(int(f.get("port") or 0))
        except (TypeError, ValueError):
            continue
        if not ip or port == "0":
            continue
        keys.add((ip, port))
    return keys


def findings_from_pulse_tls(
    artifact: dict[str, Any],
    *,
    now: datetime,
    expiring_soon_days: int,
    max_targets: int,
) -> list[dict[str, Any]]:
    """Convert Pulse ``tls[]`` (+ optional tls-class findings) to tls_posture rows."""
    by_key: dict[tuple[str, str], dict[str, Any]] = {}

    for row in artifact.get("tls") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        host_disp = str(row.get("host") or ip).strip()
        try:
            port_i = int(row.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not ip or port_i < 1:
            continue
        port = str(port_i)
        key = (ip, port)

        not_before_raw = row.get("not_before")
        not_after_raw = row.get("not_after")
        not_before_dt = _parse_pulse_datetime(
            str(not_before_raw) if not_before_raw is not None else None
        )
        not_after_dt = _parse_pulse_datetime(
            str(not_after_raw) if not_after_raw is not None else None
        )

        subject_cn = row.get("subject_cn")
        issuer_cn = row.get("issuer_cn")
        san = row.get("san")
        if isinstance(san, list):
            san_str = ", ".join(str(x) for x in san)
        else:
            san_str = str(san) if san else None

        cert = {
            "subject": subject_cn,
            "issuer": issuer_cn,
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "san": san_str,
            "not_before_raw": str(not_before_raw) if not_before_raw else None,
            "not_after_raw": str(not_after_raw) if not_after_raw else None,
            "not_before": not_before_dt.isoformat() if not_before_dt else None,
            "not_after": not_after_dt.isoformat() if not_after_dt else None,
            "parse_ok": bool(subject_cn or issuer_cn or not_after_dt),
        }

        issues: list[dict[str, Any]] = []
        # Prefer explicit Pulse flags, recompute days against *our* now for consistency
        if row.get("expired") or (not_after_dt is not None and not_after_dt < now):
            days = None
            if not_after_dt is not None:
                days = (not_after_dt - now).days
            elif row.get("expires_in_days") is not None:
                try:
                    days = int(row["expires_in_days"])
                except (TypeError, ValueError):
                    days = None
            issues.append(
                {
                    "kind": "cert_expired",
                    "severity": "critical",
                    "days": days,
                    "detail": str(not_after_raw or ""),
                }
            )
        else:
            days_left = None
            if not_after_dt is not None:
                days_left = (not_after_dt - now).days
            elif row.get("expires_in_days") is not None:
                try:
                    days_left = int(row["expires_in_days"])
                except (TypeError, ValueError):
                    days_left = None
            if days_left is not None and 0 <= days_left <= expiring_soon_days:
                issues.append(
                    {
                        "kind": "cert_expiring_soon",
                        "severity": "medium",
                        "days": days_left,
                        "detail": f"expires in {days_left}d ({not_after_raw})",
                    }
                )

        if row.get("self_signed"):
            issues.append(
                {
                    "kind": "self_signed",
                    "severity": "medium",
                    "heuristic": True,
                    "detail": f"subject_cn={subject_cn!r} issuer_cn={issuer_cn!r}",
                }
            )

        weak_accepted = row.get("accepts_weak_protocols") or []
        if isinstance(weak_accepted, list):
            for proto in weak_accepted:
                label = _normalize_proto_label(str(proto))
                if label in _WEAK_PROTOCOLS or str(proto).upper().startswith("TLSV1"):
                    issues.append(
                        {
                            "kind": "weak_protocol",
                            "severity": "high",
                            "version": label,
                            "detail": f"server accepts {label} (pulse legacy probe)",
                            "requires_confirmation": True,
                        }
                    )

        negotiated = row.get("negotiated_protocol")
        neg_label = _normalize_proto_label(str(negotiated)) if negotiated else None
        if neg_label in _WEAK_PROTOCOLS:
            # avoid dup if already listed from accepts_weak
            if not any(
                i.get("kind") == "weak_protocol" and i.get("version") == neg_label
                for i in issues
            ):
                issues.append(
                    {
                        "kind": "weak_protocol",
                        "severity": "high",
                        "version": neg_label,
                        "detail": f"negotiated {neg_label}",
                    }
                )

        cipher_versions: list[dict[str, Any]] = []
        if neg_label:
            cipher_versions.append(
                {"version": neg_label, "ciphers": [], "least_strength": None}
            )

        by_key[key] = {
            "host": ip,
            "port": port,
            "host_display": host_disp,
            "cert": cert,
            "cipher_versions": cipher_versions,
            "issues": issues,
            "source": "pulse-tls",
            "negotiated_protocol": neg_label,
            "accepts_weak_protocols": [
                _normalize_proto_label(str(p)) for p in (weak_accepted or [])
            ]
            if isinstance(weak_accepted, list)
            else [],
        }

    # Merge finding_class=tls rows that might not have a tls[] entry (rare)
    for f in artifact.get("findings") or []:
        if not isinstance(f, dict):
            continue
        if str(f.get("finding_class") or "").lower() != "tls":
            continue
        ip = str(f.get("ip") or "").strip()
        try:
            port = str(int(f.get("port") or 0))
        except (TypeError, ValueError):
            continue
        if not ip or port == "0":
            continue
        key = (ip, port)
        entry = by_key.get(key)
        if entry is None:
            entry = {
                "host": ip,
                "port": port,
                "cert": None,
                "cipher_versions": [],
                "issues": [],
                "source": "pulse-tls",
            }
            by_key[key] = entry
        title = str(f.get("title") or "").lower()
        evidence = str(f.get("evidence") or f.get("summary") or "")
        kind = None
        severity = str(f.get("severity") or "medium").lower()
        if "expired" in title:
            kind = "cert_expired"
            severity = "critical"
        elif "expiring" in title:
            kind = "cert_expiring_soon"
        elif "self-signed" in title or "self_signed" in title:
            kind = "self_signed"
        elif "weak" in title:
            kind = "weak_protocol"
            severity = "high"
        if kind and not any(i.get("kind") == kind for i in entry["issues"]):
            issue = {
                "kind": kind,
                "severity": severity,
                "detail": evidence or title,
            }
            if f.get("requires_confirmation"):
                issue["requires_confirmation"] = True
            entry["issues"].append(issue)

    ordered = sorted(by_key.values(), key=lambda r: (r["host"], int(r["port"])))
    if len(ordered) > max_targets:
        ordered = ordered[:max_targets]
    return ordered


def _apply_hostname_mismatch(
    findings: list[dict[str, Any]],
    hostnames_map: dict[str, Any] | None,
    *,
    enabled: bool,
) -> int:
    """Add ``cert_name_mismatch`` issues in place; return how many were added.

    Runs after per-source parsing so all three sources (nmap NSE, Pulse TLS,
    stdlib probe) get the identical check against the identical expected-name
    set -- the sources disagree about cert *formatting*, not about what a
    certificate is for.
    """
    if not enabled:
        return 0

    lookup = hostnames_map or {}
    added = 0
    for finding in findings:
        issues = finding.get("issues")
        if issues is None:
            continue
        host = str(finding.get("host") or "")
        names = expected_names(lookup.get(host))
        # The endpoint may also be *named* by the record itself: the probe path
        # keys on whatever ``open_ports`` held, and a Pulse row carries the host
        # it dialled. When that is an FQDN rather than an address, it is the
        # name the scan actually asked for -- the strongest expectation there is.
        for candidate in (host, finding.get("host_display")):
            name = str(candidate or "").strip().lower().rstrip(".")
            if not name or name in names:
                continue
            try:
                ipaddress.ip_address(name)
            except ValueError:
                names.append(name)
        issue = hostname_mismatch(finding.get("cert"), names)
        if issue is None:
            continue
        if any(i.get("kind") == "cert_name_mismatch" for i in issues):
            continue
        issues.append(issue)
        added += 1
    return added


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
    open_ports: list[str] | None = None,
    hostnames: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build TLS posture findings from nmap NSE, Pulse TLS JSON, or stdlib probe.

    Priority:
      1. nmap ``ssl-cert`` / ``ssl-enum-ciphers`` (richest cipher grades)
      2. Pulse ``pulse/tls.json`` / ``pulse/raw.json`` ``tls`` array
      3. stdlib ``tls_probe`` when ``probe_fallback`` and ``open_ports`` set

    ``hostnames`` is the ``hostnames.json`` map (ip -> forward/reverse names);
    without it the P4.1 ``cert_name_mismatch`` check has nothing to compare
    against and is skipped.
    """
    now = now or datetime.now(timezone.utc)
    result: dict[str, Any] = {
        "targets_considered": 0,
        "checked_count": 0,
        "findings": [],
        "truncated": False,
        "skipped_reason": None,
        "source": None,
    }

    if not config.enabled:
        result["skipped_reason"] = "tls_posture.disabled"
        _persist(output_dir, result)
        return result

    scripts = _iter_ssl_scripts(nmap_dir)
    endpoints: dict[tuple[str, str], dict[str, str]] = {}
    for host, port, script_id, output in scripts:
        endpoints.setdefault((host, port), {})[script_id] = output

    if endpoints:
        result["targets_considered"] = len(endpoints)
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
                    "source": "nmap-nse",
                }
            )

        _apply_hostname_mismatch(findings, hostnames, enabled=config.hostname_mismatch)

        result["checked_count"] = len(findings)
        result["findings"] = findings
        result["truncated"] = truncated
        result["source"] = "nmap-nse"
        with_issues = sum(1 for f in findings if f["issues"])
        _persist(output_dir, result)
        LOG.info(
            "tls_posture: %d endpoint(s) checked (nmap) -> %d with finding(s)%s",
            len(findings),
            with_issues,
            " [truncated]" if truncated else "",
        )
        return result

    # --- Phase 4.3: Pulse TLS JSON (from pulse_probe --cve / TLS stage) ---
    pulse_art = load_pulse_tls_artifact(output_dir)
    if pulse_art is not None:
        target_keys = _pulse_tls_target_keys(pulse_art)
        truncated = len(target_keys) > config.max_targets
        pulse_findings = findings_from_pulse_tls(
            pulse_art,
            now=now,
            expiring_soon_days=config.expiring_soon_days,
            max_targets=config.max_targets,
        )
        if pulse_findings:
            _apply_hostname_mismatch(
                pulse_findings, hostnames, enabled=config.hostname_mismatch
            )
            result["targets_considered"] = min(len(target_keys) or len(pulse_findings), config.max_targets)
            result["checked_count"] = len(pulse_findings)
            result["findings"] = pulse_findings
            result["truncated"] = truncated
            result["source"] = "pulse-tls"
            with_issues = sum(1 for f in pulse_findings if f.get("issues"))
            _persist(output_dir, result)
            LOG.info(
                "tls_posture: %d endpoint(s) checked (pulse-tls) -> %d with finding(s)%s",
                len(pulse_findings),
                with_issues,
                " [truncated]" if truncated else "",
            )
            return result
        LOG.info("tls_posture: pulse tls artifact present but empty after convert; trying probe_fallback")

    # --- Phase 4 fallback: direct TLS probe when nmap + pulse TLS missing ---
    if not config.probe_fallback:
        result["skipped_reason"] = "no_tls_endpoints"
        _persist(output_dir, result)
        return result

    if not open_ports:
        result["skipped_reason"] = "no_tls_endpoints"
        _persist(output_dir, result)
        return result

    considered = _parse_tls_endpoints(open_ports, set(config.probe_tls_ports))
    truncated = len(considered) > config.max_targets
    probe_findings = probe_tls_endpoints(
        open_ports,
        max_targets=config.max_targets,
        timeout_seconds=config.probe_timeout_seconds,
        concurrency=config.probe_concurrency,
        expiring_soon_days=config.expiring_soon_days,
        tls_ports=set(config.probe_tls_ports),
        now=now,
    )
    _apply_hostname_mismatch(probe_findings, hostnames, enabled=config.hostname_mismatch)
    write_tls_probe_json(output_dir, probe_findings)

    result["targets_considered"] = min(len(considered), config.max_targets)
    result["checked_count"] = len(probe_findings)
    result["findings"] = probe_findings
    result["truncated"] = truncated
    result["source"] = "pulse-tls-probe"
    if not probe_findings:
        result["skipped_reason"] = "no_tls_endpoints"
    with_issues = sum(1 for f in probe_findings if f.get("issues"))
    _persist(output_dir, result)
    LOG.info(
        "tls_posture: %d endpoint(s) checked (tls-probe) -> %d with finding(s)%s",
        len(probe_findings),
        with_issues,
        " [truncated]" if truncated else "",
    )
    return result
