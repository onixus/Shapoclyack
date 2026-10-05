"""Direct TLS handshake probe (stdlib ``ssl``) — nmap NSE alternative for cert posture.

When nmap has not produced ``ssl-cert`` / ``ssl-enum-ciphers`` output (Pulse-only
backend, or missing scripts), this module connects to open TLS ports and
extracts certificate fields comparable to what ``tls_posture`` already emits.

Does **not** replace full cipher-suite enumeration (no grade A–F like nmap
``ssl-enum-ciphers``). Per endpoint it makes at most four handshakes, one
after another inside the caller's ``concurrency`` pool, each bounded by
``timeout_seconds``:

1. **Main handshake.** Verifies the presented chain against the system trust
   store (plus ``ca_bundle``) -- chain only: the name is ``cert_name_mismatch``'s
   job and the validity window ``cert_expired``'s, so neither is checked here.
   It offers every version the local OpenSSL can still speak, so a server
   whose *highest* version is TLS 1.0 answers instead of vanishing.
2. **Collect handshake** (``CERT_NONE``), only when the chain did not verify,
   to read the certificate the verifying handshake refused.
3. **TLS 1.0 and TLS 1.1 handshakes**, each pinned to one version (min = max),
   unless ``probe_legacy_protocols`` is off. A server that also speaks TLS 1.3
   picks 1.3 in (1); only a ClientHello that offers nothing newer shows that
   it still accepts 1.0.

An unreachable or silent endpoint costs one ``timeout_seconds``, as before:
nothing after (1) is attempted.

Flags (same shapes as the nmap path):

* ``cert_expired`` / ``cert_expiring_soon`` -- not-after vs. ``expiring_soon_days``
* ``self_signed`` -- subject == issuer heuristic, dropped when the chain verifies
* ``cert_untrusted`` -- the chain does not verify to a trusted anchor
* ``weak_key`` / ``weak_signature`` -- from the leaf's DER (``cert_strength.py``)
* ``weak_protocol`` -- TLS 1.0 / 1.1 completed a handshake
* ``weak_cipher_name`` -- on the negotiated cipher

HONESTY: every check records what it actually established under ``checks``.
A protocol is ``accepted`` only when a handshake at that version completed and
``rejected`` only when the server answered and turned it down. A connection
that timed out, or a handshake the *local* stack aborted, is ``inconclusive``;
a version the local OpenSSL cannot offer at all is ``not_performed`` -- checked
by building the ClientHello in memory first, so a crypto policy that forbids
TLS 1.0 on the scanner host never reads as "the server refuses TLS 1.0".
SSLv2/SSLv3 are ``not_testable``: modern OpenSSL builds cannot send them.
``rejected`` means "rejected OpenSSL's DEFAULT cipher list at security level
0"; a server that offers TLS 1.0 only with ciphers OpenSSL 3 no longer has
(RC4, export) reads as rejected. nmap ``ssl-enum-ciphers`` remains the full
enumerator.

Findings are merged into the same shape as ``tls_posture`` endpoint records
with ``source: "pulse-tls-probe"``.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import ssl
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cert_strength import cert_strength_issues
from .protocol import parse_endpoint
from .utils import save_json

LOG = logging.getLogger("shapoclyack.tls_probe")

# Common TLS ports when open_ports list is used as input.
_DEFAULT_TLS_PORTS = frozenset({443, 8443, 9443, 4443, 10443, 6443})

# An assessment client has to finish the handshakes a browser refuses -- the
# 1024-bit key or the TLS 1.0 session *is* the finding. OpenSSL 3 refuses both
# above security level 0, and at level 1+ its chain verification reports "EE
# key too weak" before it ever says whether the chain is trusted.
_ASSESSMENT_CIPHERS = "DEFAULT:@SECLEVEL=0"

# Old servers often lack RFC 5746 secure renegotiation, and OpenSSL 3 refuses
# to talk to them by default -- exactly the servers the legacy checks are for.
_OP_LEGACY_SERVER_CONNECT = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

# X509_V_FLAG_NO_CHECK_TIME (OpenSSL >= 1.1.0, x509_vfy.h). The ssl module has
# no name for it; SSLContext.verify_flags passes the bit to OpenSSL as is.
_X509_V_FLAG_NO_CHECK_TIME = 0x200000

# Verification failures that say nothing about trust: the validity window
# (switched off above; kept in case a build ignores the flag) and OpenSSL's
# security-level checks on key size and digest.
_NOT_TRUST_VERIFY_CODES = frozenset({9, 10, 13, 14, 66, 67, 68})

# (label, ssl.TLSVersion member, ssl.HAS_* flag, ClientHello client_version)
_LEGACY_PROTOCOLS = (
    ("TLSv1.0", "TLSv1", "HAS_TLSv1", b"\x03\x01"),
    ("TLSv1.1", "TLSv1_1", "HAS_TLSv1_1", b"\x03\x02"),
)
_NOT_TESTABLE_PROTOCOLS = ("SSLv2", "SSLv3")
_WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"})
_PROTOCOL_ORDER = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

# ssl.SSLError reasons that mean the *server* turned the handshake down: it
# answered with another version or with something that is not TLS at all.
# Alerts the server sent (TLSV1_ALERT_PROTOCOL_VERSION, SSLV3_ALERT_HANDSHAKE_
# FAILURE, ...) are matched by their ALERT in the name.
_SERVER_REFUSAL_REASONS = frozenset(
    {
        "WRONG_VERSION_NUMBER",
        "UNSUPPORTED_PROTOCOL",
        "VERSION_TOO_LOW",
        "WRONG_SSL_VERSION",
        "UNKNOWN_PROTOCOL",
        "UNEXPECTED_EOF_WHILE_READING",
    }
)

# OpenSSL's hashed CA directory entries (c_rehash / update-ca-certificates).
_HASHED_CERT_RE = re.compile(r"^[0-9a-f]{8}\.\d+$")


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


@dataclass(frozen=True)
class ProbeContexts:
    """The SSL contexts one probe run shares across its worker threads.

    Built once by :func:`build_probe_contexts` -- loading the trust store and
    checking what the local OpenSSL can offer are per-run facts, not
    per-endpoint ones.
    """

    collect: ssl.SSLContext
    verify: ssl.SSLContext | None = None
    trust_skip_reason: str | None = None
    legacy: dict[str, ssl.SSLContext] = field(default_factory=dict)
    legacy_skipped: dict[str, str] = field(default_factory=dict)


def _set_minimum_version(ctx: ssl.SSLContext, version: ssl.TLSVersion) -> None:
    with warnings.catch_warnings():
        # Python deprecates TLS 1.0/1.1 for *use*; offering them is what this
        # check is for. Contexts are built before the worker pool starts, so
        # the process-wide filter change does not race another thread.
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = version


def _client_hello_refusal(ctx: ssl.SSLContext, label: str, client_version: bytes) -> str | None:
    """Why the local stack cannot offer ``label``; ``None`` when its ClientHello does.

    Builds the ClientHello in memory -- no socket -- and reads its version
    field. OpenSSL refuses here (NO_PROTOCOLS_AVAILABLE) when the build, its
    security level or a system crypto policy leaves nothing to offer at that
    version. Without this, that refusal would surface as a failed handshake
    and read as "the server does not accept TLS 1.0".
    """
    outgoing = ssl.MemoryBIO()
    tls = ctx.wrap_bio(ssl.MemoryBIO(), outgoing, server_side=False)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass  # ClientHello written, waiting for a server that is not there
    except ssl.SSLError as exc:
        return f"local OpenSSL cannot offer {label}: {exc.reason or exc}"
    hello = outgoing.read()
    # TLS record header (5 bytes), handshake header (4), then client_version.
    if len(hello) < 11 or hello[0] != 0x16 or hello[5] != 0x01:
        return f"local OpenSSL produced no {label} ClientHello"
    if hello[9:11] != client_version:
        return f"local OpenSSL offers version 0x{hello[9:11].hex()} instead of {label}"
    return None


def _legacy_context(
    label: str, version_name: str, has_flag: str, client_version: bytes
) -> tuple[ssl.SSLContext | None, str | None]:
    """A ``CERT_NONE`` context pinned to one legacy version, or the reason there is none."""
    version = getattr(ssl.TLSVersion, version_name, None)
    if not getattr(ssl, has_flag, False) or version is None:
        return None, f"local OpenSSL was built without {label}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= _OP_LEGACY_SERVER_CONNECT
    try:
        ctx.set_ciphers(_ASSESSMENT_CIPHERS)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
    except (ValueError, ssl.SSLError) as exc:
        return None, f"local OpenSSL refused a {label}-only context: {exc}"
    reason = _client_hello_refusal(ctx, label, client_version)
    if reason is not None:
        return None, reason
    return ctx, None


def _trust_store_gap(ctx: ssl.SSLContext) -> str | None:
    """Why the system store cannot judge a chain; ``None`` when it holds anchors.

    An empty store (a container without ca-certificates) would make every
    public certificate "untrusted". ``cert_store_stats`` counts the CA file and
    the Windows store; a hashed CA directory (Debian's /etc/ssl/certs) is only
    read on demand, so its entries are counted on disk instead.
    """
    if ctx.cert_store_stats().get("x509_ca", 0) > 0:
        return None
    capath = ssl.get_default_verify_paths().capath
    if capath:
        try:
            if any(_HASHED_CERT_RE.match(name) for name in os.listdir(capath)):
                return None
        except OSError:
            pass
    return "no system trust anchors (is ca-certificates installed?)"


def _verify_context(floor: ssl.TLSVersion, ca_bundle: str | None) -> tuple[ssl.SSLContext | None, str | None]:
    """The main handshake's chain-verifying context, or why trust cannot be judged."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.options |= _OP_LEGACY_SERVER_CONNECT
    ctx.set_ciphers(_ASSESSMENT_CIPHERS)
    _set_minimum_version(ctx, floor)
    # Python 3.13 turns on VERIFY_X509_STRICT in create_default_context: RFC
    # 5280 pedantry (a missing AKI) is not what "the chain is untrusted" means.
    ctx.verify_flags = (int(ctx.verify_flags) | _X509_V_FLAG_NO_CHECK_TIME) & ~int(
        getattr(ssl, "VERIFY_X509_STRICT", 0)
    )
    gap = _trust_store_gap(ctx)
    if gap is not None:
        return None, gap
    if ca_bundle:
        try:
            ctx.load_verify_locations(cafile=ca_bundle)
        except (OSError, ssl.SSLError) as exc:
            # Judging against the system store alone would flag every endpoint
            # of the internal PKI the bundle exists for.
            return None, f"tls_posture.ca_bundle {ca_bundle!r} could not be loaded: {exc}"
    return ctx, None


def build_probe_contexts(
    *, probe_legacy_protocols: bool = True, ca_bundle: str | None = None
) -> ProbeContexts:
    """Build the contexts for one probe run (see the module docstring)."""
    legacy: dict[str, ssl.SSLContext] = {}
    legacy_skipped: dict[str, str] = {}
    floor = ssl.TLSVersion.TLSv1_2
    for label, version_name, has_flag, client_version in reversed(_LEGACY_PROTOCOLS):
        ctx, reason = _legacy_context(label, version_name, has_flag, client_version)
        if ctx is None:
            legacy_skipped[label] = reason or "not available"
            continue
        # The main handshake reaches as low as the local stack can go.
        floor = getattr(ssl.TLSVersion, version_name)
        if probe_legacy_protocols:
            legacy[label] = ctx
        else:
            legacy_skipped[label] = "tls_posture.probe_legacy_protocols is off"

    collect = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    collect.check_hostname = False
    collect.verify_mode = ssl.CERT_NONE
    collect.options |= _OP_LEGACY_SERVER_CONNECT
    collect.set_ciphers(_ASSESSMENT_CIPHERS)
    _set_minimum_version(collect, floor)

    verify, trust_skip_reason = _verify_context(floor, ca_bundle)
    if trust_skip_reason is not None:
        LOG.warning("tls_probe: chain trust not checked: %s", trust_skip_reason)
    for label, reason in sorted(legacy_skipped.items()):
        LOG.info("tls_probe: %s check not performed: %s", label, reason)
    return ProbeContexts(
        collect=collect,
        verify=verify,
        trust_skip_reason=trust_skip_reason,
        legacy=dict(sorted(legacy.items())),
        legacy_skipped=legacy_skipped,
    )


class _Unreachable(Exception):
    """The TCP connection itself failed: nothing was learned about TLS."""


@dataclass
class _Handshake:
    version: str | None
    cipher: str
    peercert: dict[str, Any]
    der: bytes | None


def _protocol_label(raw: str | None) -> str | None:
    # ssl.SSLSocket.version() spells TLS 1.0 "TLSv1"; tls_posture spells it "TLSv1.0".
    return "TLSv1.0" if raw == "TLSv1" else raw


def _handshake(
    ctx: ssl.SSLContext, host: str, port: int, server_hostname: str, timeout: float
) -> _Handshake:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise _Unreachable(str(exc)) from exc
    with sock:
        with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
            cipher = ssock.cipher()  # (name, proto, bits)
            return _Handshake(
                version=_protocol_label(ssock.version()),
                cipher=(cipher[0] if cipher else "") or "",
                # Empty under CERT_NONE; decoded by the stdlib once verified.
                peercert=ssock.getpeercert() or {},
                der=ssock.getpeercert(binary_form=True),
            )


def _server_refusal(exc: BaseException) -> str | None:
    """The server's "no" in ``exc``, or ``None`` when it says nothing about the server."""
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionError)):
        return f"server closed the connection ({exc.__class__.__name__})"
    if isinstance(exc, ssl.SSLError):
        reason = str(exc.reason or "")
        if "ALERT" in reason or reason in _SERVER_REFUSAL_REASONS:
            return reason
    return None


def _trust_from_verify_error(exc: ssl.SSLCertVerificationError) -> dict[str, Any]:
    code = getattr(exc, "verify_code", None)
    message = getattr(exc, "verify_message", None) or str(exc)
    if code in _NOT_TRUST_VERIFY_CODES:
        return {
            "status": "inconclusive",
            "detail": f"verification stopped on a non-trust check: {message}",
            "verify_code": code,
        }
    return {"status": "untrusted", "detail": message, "verify_code": code}


def _describe(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    return str(reason) if reason else f"{exc.__class__.__name__}: {exc}"


def _load_leaf(der: bytes | None) -> tuple[Any, str | None]:
    """Parse the leaf DER with ``cryptography``: ``(cert, None)`` or ``(None, why not)``.

    ``cryptography`` is not a dependency of the scanner image
    (requirements.txt) -- the all-in-one image has it through
    requirements-api.txt. Without it the key and signature checks report
    ``not_performed`` instead of passing silently.
    """
    if not der:
        return None, "server presented no certificate"
    try:
        from cryptography import x509
    except ImportError:
        return None, "cryptography package not installed: key size and signature algorithm not read"
    try:
        return x509.load_der_x509_certificate(der), None
    except Exception as exc:  # noqa: BLE001 — fail-soft parse
        return None, f"certificate DER not parseable: {exc}"


def _strength_fields(leaf: Any) -> dict[str, Any]:
    """``public_key_type`` / ``public_key_bits`` / ``signature_algorithm`` of a leaf."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    oid = leaf.signature_algorithm_oid
    name = getattr(oid, "_name", None)
    out: dict[str, Any] = {
        "public_key_type": None,
        "public_key_bits": None,
        "signature_algorithm": name if name and name != "Unknown OID" else oid.dotted_string,
    }
    try:
        key = leaf.public_key()
    except Exception:  # noqa: BLE001 — key type cryptography does not support
        return out
    if isinstance(key, rsa.RSAPublicKey):
        out.update(public_key_type="rsa", public_key_bits=key.key_size)
    elif isinstance(key, dsa.DSAPublicKey):
        out.update(public_key_type="dsa", public_key_bits=key.key_size)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        out.update(public_key_type="ec", public_key_bits=key.curve.key_size)
    elif isinstance(key, ed25519.Ed25519PublicKey):
        out.update(public_key_type="ed25519")
    elif isinstance(key, ed448.Ed448PublicKey):
        out.update(public_key_type="ed448")
    return out


def _cert_from_handshake(hs: _Handshake) -> tuple[dict[str, Any], dict[str, Any]]:
    """The normalized cert dict of one handshake, and the ``cert_strength`` check record."""
    leaf, reason = _load_leaf(hs.der)
    if hs.peercert:
        cert = _cert_dict_from_peercert(hs.peercert)
    elif leaf is not None:
        cert = _cert_fields(leaf)
    else:
        cert = {}
    if leaf is None:
        return cert, {"status": "not_performed", "detail": reason}
    cert.update(_strength_fields(leaf))
    return cert, {"status": "performed"}


def _probe_one(
    host: str,
    port: int,
    *,
    timeout: float,
    expiring_soon_days: int,
    now: datetime,
    sni: str | None = None,
    contexts: ProbeContexts | None = None,
) -> dict[str, Any] | None:
    """Handshake with one endpoint. ``sni`` overrides the name sent in SNI.

    Connecting to an address makes the server answer with its *default* virtual
    host's certificate, which says nothing about the name the operator actually
    scanned. When a name for this address is known, ask for it -- otherwise the
    certificate collected here cannot support a name check (the caller reads
    the ``sni`` field back to decide exactly that).
    """
    contexts = contexts or build_probe_contexts()
    server_hostname = sni or host

    def connect(ctx: ssl.SSLContext) -> _Handshake:
        return _handshake(ctx, host, port, server_hostname, timeout)

    main: _Handshake | None = None
    trust: dict[str, Any] = {"status": "not_performed", "detail": contexts.trust_skip_reason}
    try:
        if contexts.verify is not None:
            try:
                main = connect(contexts.verify)
                trust = {"status": "trusted"}
            except ssl.SSLCertVerificationError as exc:
                trust = _trust_from_verify_error(exc)
                main = connect(contexts.collect)
        else:
            main = connect(contexts.collect)
    except (_Unreachable, TimeoutError) as exc:
        # Nothing answered, or it answered and then said nothing: a legacy
        # ClientHello would wait out the same timeout, twice.
        LOG.debug("tls_probe %s:%s failed: %s", host, port, exc)
        return None
    except (OSError, ssl.SSLError, ValueError) as exc:
        # Something answered and refused the widest ClientHello. Old servers
        # that choke on a modern one (version intolerance) may still take a
        # ClientHello pinned to TLS 1.0, so the legacy checks still run.
        LOG.debug("tls_probe %s:%s main handshake failed: %s", host, port, exc)
        if contexts.verify is not None and trust["status"] == "not_performed":
            trust = {"status": "inconclusive", "detail": f"no handshake completed: {_describe(exc)}"}

    completed: dict[str, _Handshake] = {}
    if main is not None and main.version:
        completed[main.version] = main

    protocols: dict[str, dict[str, Any]] = {
        label: {
            "status": "not_testable",
            "detail": f"modern OpenSSL cannot send an {label} ClientHello; acceptance unknown",
        }
        for label in _NOT_TESTABLE_PROTOCOLS
    }
    for label, _version_name, _has_flag, _client_version in _LEGACY_PROTOCOLS:
        if label in completed:
            protocols[label] = {"status": "accepted", "detail": "negotiated by the main handshake"}
            continue
        ctx = contexts.legacy.get(label)
        if ctx is None:
            protocols[label] = {
                "status": "not_performed",
                "detail": contexts.legacy_skipped.get(label, "not configured"),
            }
            continue
        try:
            hs = connect(ctx)
        except (_Unreachable, TimeoutError) as exc:
            protocols[label] = {"status": "inconclusive", "detail": _describe(exc)}
            continue
        except (OSError, ssl.SSLError, ValueError) as exc:
            refusal = _server_refusal(exc)
            if refusal is not None:
                protocols[label] = {"status": "rejected", "detail": refusal}
            else:
                protocols[label] = {
                    "status": "inconclusive",
                    "detail": f"handshake aborted locally: {_describe(exc)}",
                }
            continue
        if hs.version == label:
            completed[label] = hs
            protocols[label] = {"status": "accepted"}
        else:
            protocols[label] = {"status": "inconclusive", "detail": f"handshake completed as {hs.version}"}

    if not completed:
        return None
    accepted = sorted(completed, key=lambda v: _PROTOCOL_ORDER.index(v) if v in _PROTOCOL_ORDER else 99)
    base = main if main is not None else completed[accepted[0]]

    cert, strength = _cert_from_handshake(base)
    issues = _classify_from_cert(cert, now, expiring_soon_days) if cert else []
    if trust["status"] == "trusted":
        # The chain verified to an anchor the operator trusts (the system store
        # or ca_bundle): a matching subject and issuer is not "nobody vouches".
        issues = [issue for issue in issues if issue["kind"] != "self_signed"]
    elif trust["status"] == "untrusted":
        issues.append(
            {
                "kind": "cert_untrusted",
                "severity": "medium",
                "detail": trust["detail"],
                "verify_code": trust.get("verify_code"),
            }
        )
    issues.extend(cert_strength_issues(cert))
    for version in accepted:
        if version in _WEAK_PROTOCOLS:
            issues.append(
                {
                    "kind": "weak_protocol",
                    "severity": "high",
                    "version": version,
                    "detail": f"server accepts {version} (handshake completed)",
                }
            )
    # weak cipher name heuristic on negotiated cipher only
    cname = base.cipher
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
        "sni": server_hostname,
        "cert": cert_out or None,
        "cipher_versions": [
            {"version": version, "ciphers": [completed[version].cipher], "least_strength": None}
            for version in accepted
        ],
        "issues": issues,
        "source": "pulse-tls-probe",
        "negotiated_protocol": base.version,
        "negotiated_cipher": cname,
        "accepted_protocols": accepted,
        "checks": {
            "protocols": dict(sorted(protocols.items(), key=lambda kv: _PROTOCOL_ORDER.index(kv[0]))),
            "chain_trust": {k: v for k, v in trust.items() if v is not None},
            "cert_strength": strength,
        },
    }


def _cert_fields(cert: Any) -> dict[str, Any]:
    """Subject/issuer/SAN/validity of a ``cryptography`` certificate, in probe shape.

    With ``ssl.CERT_NONE``, ``getpeercert()`` returns an empty dict; the DER
    form is still available, and this is how an unverified certificate gets
    its fields (see :func:`_load_leaf` for when ``cryptography`` is missing).
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

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
        # Rendered in the same "TYPE:value" form the stdlib and nmap paths use,
        # rather than cryptography's ``<DNSName(value='x')>`` repr, so the P4.1
        # name check reads one shape whatever produced the certificate.
        for name in ext.value:  # type: ignore[union-attr]
            if isinstance(name, x509.DNSName):
                san_list.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                san_list.append(f"IP Address:{name.value}")
            else:
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
    sni_by_host: dict[str, str] | None = None,
    probe_legacy_protocols: bool = True,
    ca_bundle: str | None = None,
) -> list[dict[str, Any]]:
    """Probe open ports for TLS; return finding dicts compatible with tls_posture.

    ``sni_by_host`` maps an address to the name to send in SNI (the FQDN that
    resolved to it). Without an entry the address itself is used, and the row's
    ``sni`` field records which it was. ``probe_legacy_protocols`` and
    ``ca_bundle`` are the ``tls_posture`` config keys of the same names.
    """
    now = now or datetime.now(timezone.utc)
    endpoints = _parse_tls_endpoints(open_ports, tls_ports)
    if not endpoints:
        return []
    truncated = len(endpoints) > max_targets
    endpoints = endpoints[:max_targets]
    contexts = build_probe_contexts(
        probe_legacy_protocols=probe_legacy_protocols, ca_bundle=ca_bundle
    )
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
                sni=(sni_by_host or {}).get(host),
                contexts=contexts,
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
