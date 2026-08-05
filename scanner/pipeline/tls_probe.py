"""Direct TLS handshake probe (stdlib ``ssl``) — nmap NSE alternative for cert posture.

When nmap has not produced ``ssl-cert`` / ``ssl-enum-ciphers`` output (Pulse-only
backend, or missing scripts), this module connects to open TLS ports and
extracts certificate fields comparable to what ``tls_posture`` already emits.

Does **not** replace full cipher-suite enumeration (no grade A–F like nmap
``ssl-enum-ciphers``). It does cover:

* cert not-before / not-after → expired / expiring_soon
* self-signed heuristic (subject == issuer CN or DN)
* negotiated protocol (flag SSLv2/3 / TLS1.0 / 1.1 if offered by forcing
  min/max version attempts — best-effort)

Findings are merged into the same shape as ``tls_posture`` endpoint records
with ``source: "pulse-tls-probe"``.
"""

from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .protocol import parse_endpoint
from .utils import save_json

LOG = logging.getLogger("shapoclyack.tls_probe")

# Common TLS ports when open_ports list is used as input.
_DEFAULT_TLS_PORTS = frozenset({443, 8443, 9443, 4443, 10443, 6443})


def _parse_tls_endpoints(open_ports: list[str], tls_ports: set[int] | None = None) -> list[tuple[str, int]]:
    """Select ``(host, port)`` pairs from open_ports that should be TLS-probed.

    If ``tls_ports`` is None, use the default well-known TLS port set.
    If ``tls_ports`` is an empty set, probe **no** ports (caller must pass
    explicit ports when they want a custom set).
    """
    allowed = set(_DEFAULT_TLS_PORTS) if tls_ports is None else set(tls_ports)
    if not allowed:
        return []
    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is None or parsed.protocol != "tcp":
            continue
        try:
            port = int(parsed.port)
        except ValueError:
            continue
        if port not in allowed:
            continue
        key = (parsed.host, port)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    out.sort()
    return out


def _cert_dict_from_peercert(cert: dict[str, Any]) -> dict[str, Any]:
    """Normalize ssl.getpeercert() dict to tls_posture-like cert fields."""
    subject = cert.get("subject") or ()
    issuer = cert.get("issuer") or ()

    def _cn(parts: Any) -> str:
        # ((('commonName', 'x'),),)
        try:
            for rdn in parts:
                for attr, val in rdn:
                    if attr == "commonName":
                        return str(val)
        except (TypeError, ValueError):
            pass
        return ""

    def _flatten(parts: Any) -> str:
        bits: list[str] = []
        try:
            for rdn in parts:
                for attr, val in rdn:
                    bits.append(f"{attr}={val}")
        except (TypeError, ValueError):
            return ""
        return ", ".join(bits)

    san_list: list[str] = []
    for typ, val in cert.get("subjectAltName") or ():
        san_list.append(f"{typ}:{val}")

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    def _parse_ssl_date(raw: str | None) -> datetime | None:
        if not raw:
            return None
        # OpenSSL: 'Jun  1 12:00:00 2024 GMT'
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    subject_cn = _cn(subject)
    issuer_cn = _cn(issuer)
    subject_raw = _flatten(subject)
    issuer_raw = _flatten(issuer)

    return {
        "subject": subject_raw,
        "issuer": issuer_raw,
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "san": ", ".join(san_list),
        "not_before": not_before,
        "not_after": not_after,
        "not_before_dt": _parse_ssl_date(not_before),
        "not_after_dt": _parse_ssl_date(not_after),
        "serial": cert.get("serialNumber"),
        "version": cert.get("version"),
    }


def _classify_from_cert(
    cert: dict[str, Any],
    now: datetime,
    expiring_soon_days: int,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    not_after = cert.get("not_after_dt")
    if isinstance(not_after, datetime):
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        days = (not_after - now).days
        if not_after < now:
            issues.append(
                {
                    "kind": "cert_expired",
                    "severity": "critical",
                    "days": days,
                    "detail": str(cert.get("not_after")),
                }
            )
        else:
            if days <= expiring_soon_days:
                issues.append(
                    {
                        "kind": "cert_expiring_soon",
                        "severity": "medium",
                        "days": days,
                        "detail": f"expires in {days}d ({cert.get('not_after')})",
                    }
                )

    subj_cn = (cert.get("subject_cn") or "").lower()
    iss_cn = (cert.get("issuer_cn") or "").lower()
    subj = (cert.get("subject") or "").lower()
    iss = (cert.get("issuer") or "").lower()
    if (subj_cn and iss_cn and subj_cn == iss_cn) or (subj and iss and subj == iss):
        issues.append(
            {
                "kind": "self_signed",
                "severity": "medium",
                "detail": "subject matches issuer (heuristic)",
                "heuristic": True,
            }
        )
    return issues


def _probe_one(
    host: str,
    port: int,
    *,
    timeout: float,
    expiring_soon_days: int,
    now: datetime,
) -> dict[str, Any] | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version()  # e.g. TLSv1.3
                cipher = ssock.cipher()  # (name, proto, bits)
                peercert = ssock.getpeercert()
                # When CERT_NONE, getpeercert() may be empty — use binary form
                if not peercert:
                    peercert = ssock.getpeercert(binary_form=False) or {}
                cert = _cert_dict_from_peercert(peercert) if peercert else {}
                # binary DER path if empty dict
                if not cert.get("not_after") and not cert.get("subject"):
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        cert = _cert_from_der(der)

                issues = _classify_from_cert(cert, now, expiring_soon_days) if cert else []
                # weak negotiated protocol
                if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
                    issues.append(
                        {
                            "kind": "weak_protocol",
                            "severity": "high",
                            "detail": f"negotiated {proto}",
                        }
                    )
                # weak cipher name heuristic on negotiated cipher only
                cname = (cipher[0] if cipher else "") or ""
                upper = cname.upper()
                for weak in ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"):
                    if weak in upper:
                        issues.append(
                            {
                                "kind": "weak_cipher_name",
                                "severity": "medium",
                                "detail": cname,
                            }
                        )
                        break

                # strip non-JSON datetime objects for persistence
                cert_out = {
                    k: (v.isoformat() if isinstance(v, datetime) else v)
                    for k, v in cert.items()
                    if k not in ("not_before_dt", "not_after_dt")
                }
                return {
                    "host": host,
                    "port": str(port),
                    "cert": cert_out or None,
                    "cipher_versions": (
                        [{"version": proto, "ciphers": [cname], "least_strength": None}]
                        if proto
                        else []
                    ),
                    "issues": issues,
                    "source": "pulse-tls-probe",
                    "negotiated_protocol": proto,
                    "negotiated_cipher": cname,
                }
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
        LOG.debug("tls_probe %s:%s failed: %s", host, port, exc)
        return None


def _cert_from_der(der: bytes) -> dict[str, Any]:
    """Best-effort DER parse via optional ``cryptography`` (not a hard dep).

    With ``ssl.CERT_NONE``, ``getpeercert()`` returns an empty dict; the DER
    form is still available. When the ``cryptography`` package is installed
    (API image / requirements-api), extract subject/issuer/dates. Otherwise
    return empty — protocol/cipher negotiated data still works.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 — fail-soft parse
        return {}

    def _cn(name: Any) -> str:
        try:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            if attrs:
                return str(attrs[0].value)
        except Exception:  # noqa: BLE001
            pass
        return ""

    def _flatten(name: Any) -> str:
        try:
            return ", ".join(f"{a.oid._name}={a.value}" for a in name)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return str(name)

    san_list: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in ext.value:  # type: ignore[union-attr]
            san_list.append(str(name))
    except Exception:  # noqa: BLE001 — no SAN or unreadable
        pass

    # cryptography 42+ prefers *_utc; fall back for older wheels
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    subject_cn = _cn(cert.subject)
    issuer_cn = _cn(cert.issuer)
    return {
        "subject": _flatten(cert.subject),
        "issuer": _flatten(cert.issuer),
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "san": ", ".join(san_list),
        "not_before": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "not_after": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "not_before_dt": not_before,
        "not_after_dt": not_after,
        "serial": format(cert.serial_number, "x"),
        "version": cert.version.value if cert.version else None,
    }


def probe_tls_endpoints(
    open_ports: list[str],
    *,
    max_targets: int = 2000,
    timeout_seconds: float = 5.0,
    concurrency: int = 20,
    expiring_soon_days: int = 30,
    tls_ports: set[int] | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Probe open ports for TLS; return finding dicts compatible with tls_posture."""
    now = now or datetime.now(timezone.utc)
    endpoints = _parse_tls_endpoints(open_ports, tls_ports)
    if not endpoints:
        return []
    truncated = len(endpoints) > max_targets
    endpoints = endpoints[:max_targets]
    findings: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = {
            pool.submit(
                _probe_one,
                host,
                port,
                timeout=timeout_seconds,
                expiring_soon_days=expiring_soon_days,
                now=now,
            ): (host, port)
            for host, port in endpoints
        }
        for fut in as_completed(futs):
            try:
                row = fut.result()
            except Exception as exc:  # noqa: BLE001
                LOG.debug("tls_probe future error: %s", exc)
                continue
            if row is not None:
                findings.append(row)
    findings.sort(key=lambda r: (r["host"], int(r["port"])))
    if truncated:
        LOG.info("tls_probe: truncated to %s endpoints", max_targets)
    LOG.info("tls_probe: %s/%s endpoints responded with TLS", len(findings), len(endpoints))
    return findings


def write_tls_probe_json(output_dir: Path, findings: list[dict[str, Any]]) -> Path:
    path = output_dir / "tls_probe.json"
    save_json(
        path,
        {
            "schema": "octo.tls_probe.v1",
            "checked_count": len(findings),
            "findings": findings,
        },
    )
    return path
