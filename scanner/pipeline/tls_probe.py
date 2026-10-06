"""Direct TLS handshake probe (stdlib ``ssl``) — nmap NSE alternative for cert posture.

When nmap has not produced ``ssl-cert`` / ``ssl-enum-ciphers`` output (Pulse-only
backend, or missing scripts), this module connects to open TLS ports and
extracts certificate fields comparable to what ``tls_posture`` already emits.

Does **not** replace full cipher-suite enumeration (no grade A–F like nmap
``ssl-enum-ciphers``). Per endpoint it makes at most four connections, one
after another inside the caller's ``concurrency`` pool, each handshake bounded
by ``timeout_seconds``:

1. **Main handshake.** Offers every version the local OpenSSL can still speak,
   so a server whose *highest* version is TLS 1.0 answers. When chain trust is
   due (see CHAIN TRUST below) it verifies the presented chain against the
   system store plus ``ca_bundle`` with the time check on, as an ordinary
   client does (names are ``cert_name_mismatch``'s job). A failure *on time*
   earns one more, untimed verification -- the connection that replaces (2) --
   to tell "trusted, a CA certificate outside its window" from "untrusted".
2. **Collect handshake** (``CERT_NONE``), only when the chain did not verify,
   so protocol and cipher come from a completed handshake. Should it fail,
   what the first connection already showed is kept.
3. **TLS 1.0 and TLS 1.1 handshakes**, each pinned to one version, unless
   ``probe_legacy_protocols`` is off. A server that also speaks TLS 1.3 picks
   1.3 in (1); only a ClientHello offering nothing newer shows it still takes 1.0.

Every handshake runs over memory BIOs, so the server's plaintext records are
read as they arrive: the version its ServerHello chose, a CertificateRequest,
an alert. That -- not OpenSSL's error string, which says how the *client*
failed -- is what the protocol checks are classified on. An endpoint that
answers nothing costs one timeout and yields no row; one that answered in TLS
yields a row even when no handshake completed.

CHAIN TRUST (``tls_posture.chain_trust``): ``public_only`` (default) judges the
chain only when the address the probe connected to is publicly routable
(``safe_http.is_public_address``, NAT64 included) or a ``ca_bundle`` is
configured -- an intranet's own CA is not a finding until the operator has
said which CAs are theirs. ``always`` judges every endpoint, ``off`` none.

Flags (same shapes as the nmap path):

* ``cert_expired`` / ``cert_expiring_soon`` / ``cert_not_yet_valid`` -- the leaf's window
* ``cert_chain_expired`` -- a CA certificate of the verified chain is outside its window
* ``self_signed`` -- certain when verification said so (code 18), a heuristic
  otherwise, and dropped when the chain verifies
* ``cert_untrusted`` -- the chain does not verify to a trusted anchor
* ``weak_key`` / ``weak_signature`` -- from the leaf's DER (``cert_strength.py``)
* ``weak_protocol`` -- a TLS 1.0 / 1.1 handshake completed

HONESTY: every check records what it established under ``checks``. A protocol
is ``accepted`` only when a handshake at that version completed, and
``rejected`` only on a version-specific answer: a ``protocol_version`` alert,
or a ServerHello choosing another version. A ``handshake_failure`` alert before
the ServerHello is ``inconclusive`` -- a refused version and a refused cipher
list look the same -- as are a reset, a timeout, a server that asked for a
client certificate (``client_cert_requested``) and a handshake the *local*
stack aborted. A version the local OpenSSL cannot offer at all is
``not_performed`` (the ClientHello is built in memory first, so a crypto
policy on the scanner host never reads as the server refusing TLS 1.0), and
so is one the server chose but the local policy would not finish (OpenSSL 3.0
refusing the server's SHA-1 signature after the ServerHello);
checks switched off by ``probe_legacy_protocols`` are ``not_evaluated``
(``reason: disabled``); SSLv2/SSLv3 are ``not_testable``. A CertificateRequest
is visible only up to TLS 1.2 (TLS 1.3 encrypts it). The probe offers OpenSSL's ``DEFAULT`` list
at security level 0, which on OpenSSL 3 holds no RC4/DES/NULL/EXPORT/anon
suite: it cannot see weak ciphers, and nmap ``ssl-enum-ciphers`` remains the
enumerator.

Findings are merged into the same shape as ``tls_posture`` endpoint records
with ``source: "pulse-tls-probe"``.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cert_strength import cert_strength_issues
from .protocol import parse_endpoint
from .safe_http import is_public_address
from .utils import save_json

LOG = logging.getLogger("shapoclyack.tls_probe")

# Common TLS ports when open_ports list is used as input.
_DEFAULT_TLS_PORTS = frozenset({443, 8443, 9443, 4443, 10443, 6443})

CHAIN_TRUST_MODES = ("public_only", "always", "off")

# An assessment client has to finish the handshakes a browser refuses -- the
# 1024-bit key or the TLS 1.0 session *is* the finding. OpenSSL 3 refuses both
# above security level 0, and at level 1+ its chain verification reports "EE
# key too weak" before it ever says whether the chain is trusted.
_ASSESSMENT_CIPHERS = "DEFAULT:@SECLEVEL=0"

# Old servers often lack RFC 5746 secure renegotiation, and OpenSSL 3 refuses
# to talk to them by default -- exactly the servers the legacy checks are for.
_OP_LEGACY_SERVER_CONNECT = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

# X509_V_FLAG_NO_CHECK_TIME (OpenSSL >= 1.1.0, x509_vfy.h). The ssl module has
# no name for it; SSLContext.verify_flags passes the bit to OpenSSL as is. The
# chain is verified with the time check first, as an ordinary client does; only
# when that fails on time (codes 9/10) is it verified again without, to tell
# "trusted but a CA certificate is outside its window" (cert_chain_expired)
# from "untrusted". Verifying without the time check first would let OpenSSL
# pick an expired duplicate intermediate the server also sends, where an
# ordinary client picks the valid one.
_X509_V_FLAG_NO_CHECK_TIME = 0x200000

# Verification failures that say nothing about trust: the validity window
# (switched off above; kept in case a build ignores the flag) and OpenSSL's
# security-level checks on key size and digest.
_NOT_TRUST_VERIFY_CODES = frozenset({9, 10, 13, 14, 66, 67, 68})
# X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: the leaf is its own issuer.
_VERIFY_SELF_SIGNED_LEAF = 18
# X509_V_ERR_CERT_NOT_YET_VALID / X509_V_ERR_CERT_HAS_EXPIRED.
_TIME_VERIFY_CODES = frozenset({9, 10})

# (label, ssl.TLSVersion member, ssl.HAS_* flag, ClientHello client_version)
_LEGACY_PROTOCOLS = (
    ("TLSv1.0", "TLSv1", "HAS_TLSv1", b"\x03\x01"),
    ("TLSv1.1", "TLSv1_1", "HAS_TLSv1_1", b"\x03\x02"),
)
_NOT_TESTABLE_PROTOCOLS = ("SSLv2", "SSLv3")
_WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"})
_PROTOCOL_ORDER = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_TLS_VERSION_LABELS = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

# TLS record layer and handshake message types the observer reads (RFC 8446).
_RECORD_CHANGE_CIPHER_SPEC = 20
_RECORD_ALERT = 21
_RECORD_HANDSHAKE = 22
_RECORD_TYPES = frozenset({20, 21, 22, 23})
_MAX_RECORD_LENGTH = 2**14 + 2048
_MSG_SERVER_HELLO = 2
_MSG_CERTIFICATE_REQUEST = 13
_EXT_SUPPORTED_VERSIONS = 43
_ALERT_PROTOCOL_VERSION = 70
_ALERT_LEVEL_FATAL = 2
_ALERT_NAMES = {
    0: "close_notify",
    10: "unexpected_message",
    40: "handshake_failure",
    42: "bad_certificate",
    47: "illegal_parameter",
    48: "unknown_ca",
    50: "decode_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    112: "unrecognized_name",
    116: "certificate_required",
}

# ssl.SSLError reasons OpenSSL raises when the server's answer was at another
# version. Used only when the records themselves did not show it.
_VERSION_REFUSAL_REASONS = frozenset(
    {
        "WRONG_VERSION_NUMBER",
        "UNSUPPORTED_PROTOCOL",
        "VERSION_TOO_LOW",
        "WRONG_SSL_VERSION",
        "TLSV1_ALERT_PROTOCOL_VERSION",
    }
)

# ssl.SSLError reasons the *local* stack raises when its own security policy
# will not accept what the server sent after choosing the version (OpenSSL 3.0
# on Ubuntu builds a TLS 1.0 ClientHello at security level 1 and then refuses
# the SHA-1 signature). The server accepted the version; the scanner host
# could not finish the check.
_LOCAL_POLICY_REASONS = frozenset(
    {
        "LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED",
        "DH_KEY_TOO_SMALL",
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
    not_before = cert.get("not_before_dt")
    if isinstance(not_before, datetime):
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_before > now:
            issues.append(
                {
                    "kind": "cert_not_yet_valid",
                    "severity": "medium",
                    "detail": f"valid from {cert.get('not_before')}",
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
    # ``verify`` keeps OpenSSL's time check, as an ordinary client does;
    # ``verify_untimed`` drops it, to tell a chain that is untrusted from one
    # that is trusted but outside its validity window.
    verify: ssl.SSLContext | None = None
    verify_untimed: ssl.SSLContext | None = None
    trust_skip_reason: str | None = None
    trust_store: str | None = None
    chain_trust: str = "public_only"
    ca_bundle_configured: bool = False
    legacy: dict[str, ssl.SSLContext] = field(default_factory=dict)
    legacy_skipped: dict[str, str] = field(default_factory=dict)
    legacy_disabled: frozenset[str] = frozenset()


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


def _verify_context(
    floor: ssl.TLSVersion, ca_bundle: str | None, *, check_time: bool = True
) -> tuple[ssl.SSLContext | None, str | None, str | None]:
    """A chain-verifying context, with or without OpenSSL's time check.

    Returns ``(context, None, store)`` where ``store`` names what the chain is
    judged against, or ``(None, reason, None)`` when trust cannot be judged.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.options |= _OP_LEGACY_SERVER_CONNECT
    ctx.set_ciphers(_ASSESSMENT_CIPHERS)
    _set_minimum_version(ctx, floor)
    # Python 3.13 turns on VERIFY_X509_STRICT in create_default_context: RFC
    # 5280 pedantry (a missing AKI) is not what "the chain is untrusted" means.
    flags = int(ctx.verify_flags) & ~int(getattr(ssl, "VERIFY_X509_STRICT", 0))
    if not check_time:
        flags |= _X509_V_FLAG_NO_CHECK_TIME
    ctx.verify_flags = flags
    gap = _trust_store_gap(ctx)
    if ca_bundle:
        try:
            ctx.load_verify_locations(cafile=ca_bundle)
        except (OSError, ssl.SSLError) as exc:
            # Judging against the system store alone would flag every endpoint
            # of the internal PKI the bundle exists for.
            return None, f"tls_posture.ca_bundle {ca_bundle!r} could not be loaded: {exc}", None
        # The operator named the CAs to trust: an empty system store does not
        # stop the check, it only narrows what a chain can verify against.
        return ctx, None, "ca_bundle" if gap is not None else "system+ca_bundle"
    if gap is not None:
        return None, gap, None
    return ctx, None, "system"


def build_probe_contexts(
    *,
    probe_legacy_protocols: bool = True,
    ca_bundle: str | None = None,
    chain_trust: str = "public_only",
) -> ProbeContexts:
    """Build the contexts for one probe run (see the module docstring)."""
    if chain_trust not in CHAIN_TRUST_MODES:
        raise ValueError(f"chain_trust must be one of {', '.join(CHAIN_TRUST_MODES)}, not {chain_trust!r}")
    legacy: dict[str, ssl.SSLContext] = {}
    legacy_skipped: dict[str, str] = {}
    legacy_disabled: set[str] = set()
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
            # Switched off by configuration: by design, not a check that failed.
            legacy_disabled.add(label)

    collect = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    collect.check_hostname = False
    collect.verify_mode = ssl.CERT_NONE
    collect.options |= _OP_LEGACY_SERVER_CONNECT
    collect.set_ciphers(_ASSESSMENT_CIPHERS)
    _set_minimum_version(collect, floor)

    verify: ssl.SSLContext | None = None
    verify_untimed: ssl.SSLContext | None = None
    trust_skip_reason: str | None = None
    trust_store: str | None = None
    if chain_trust != "off":
        verify, trust_skip_reason, trust_store = _verify_context(floor, ca_bundle)
        if verify is not None:
            verify_untimed, _reason, _store = _verify_context(floor, ca_bundle, check_time=False)
        if trust_skip_reason is not None:
            LOG.warning("tls_probe: chain trust not checked: %s", trust_skip_reason)
        elif trust_store == "ca_bundle":
            LOG.warning("tls_probe: no system trust anchors; chains are judged against ca_bundle alone")
    for label, reason in sorted(legacy_skipped.items()):
        LOG.info("tls_probe: %s check not performed: %s", label, reason)
    return ProbeContexts(
        collect=collect,
        verify=verify,
        verify_untimed=verify_untimed,
        trust_skip_reason=trust_skip_reason,
        trust_store=trust_store,
        chain_trust=chain_trust,
        ca_bundle_configured=bool(ca_bundle),
        legacy=dict(sorted(legacy.items())),
        legacy_skipped=legacy_skipped,
        legacy_disabled=frozenset(legacy_disabled),
    )


class _Unreachable(Exception):
    """The TCP connection itself failed: nothing was learned about TLS."""


class _ServerRecords:
    """What the server's plaintext TLS records said during one handshake.

    Fed every byte the server sends. Until the server's ChangeCipherSpec (TLS
    1.2 and older), or after a ServerHello that chose TLS 1.3, the handshake
    messages and alerts are plaintext: the version the ServerHello chose, a
    CertificateRequest, an alert description. Anything that is not a TLS
    record stream makes ``not_tls`` true and stops the parse.
    """

    def __init__(self) -> None:
        self.tls_seen = False
        self.not_tls = False
        self.server_hello_version: str | None = None
        self.certificate_request = False
        self.alert: int | None = None
        self._alert_fatal = False
        self._encrypted = False
        self._buffer = bytearray()
        self._handshake = bytearray()

    def feed(self, data: bytes) -> None:
        if self.not_tls:
            return
        self._buffer += data
        while len(self._buffer) >= 5:
            content_type, major = self._buffer[0], self._buffer[1]
            length = int.from_bytes(self._buffer[3:5], "big")
            if content_type not in _RECORD_TYPES or major != 3 or length > _MAX_RECORD_LENGTH:
                self.not_tls = True
                return
            if len(self._buffer) < 5 + length:
                return
            body = bytes(self._buffer[5 : 5 + length])
            del self._buffer[: 5 + length]
            self.tls_seen = True
            if content_type == _RECORD_CHANGE_CIPHER_SPEC:
                self._encrypted = True
            elif self._encrypted:
                continue
            elif content_type == _RECORD_ALERT and len(body) >= 2:
                # The first fatal alert is the server's verdict; a warning
                # before it (unrecognized_name, say) is not.
                fatal = body[0] == _ALERT_LEVEL_FATAL
                if self.alert is None or (fatal and not self._alert_fatal):
                    self.alert = body[1]
                    self._alert_fatal = fatal
            elif content_type == _RECORD_HANDSHAKE:
                self._handshake += body
                self._read_messages()

    def _read_messages(self) -> None:
        while len(self._handshake) >= 4 and not self._encrypted:
            msg_type = self._handshake[0]
            length = int.from_bytes(self._handshake[1:4], "big")
            if len(self._handshake) < 4 + length:
                return
            body = bytes(self._handshake[4 : 4 + length])
            del self._handshake[: 4 + length]
            if msg_type == _MSG_SERVER_HELLO:
                version = _server_hello_version(body)
                if version is not None:
                    self.server_hello_version = _TLS_VERSION_LABELS.get(version, f"0x{version:04x}")
                    if version == 0x0304:
                        # Everything after a TLS 1.3 ServerHello is encrypted.
                        self._encrypted = True
            elif msg_type == _MSG_CERTIFICATE_REQUEST:
                self.certificate_request = True


def _server_hello_version(body: bytes) -> int | None:
    """The version a ServerHello chose: ``supported_versions`` if present (TLS
    1.3), else its legacy_version field."""
    if len(body) < 2:
        return None
    version = int.from_bytes(body[0:2], "big")
    pos = 2 + 32  # legacy_version, random
    if len(body) < pos + 1:
        return version
    pos += 1 + body[pos]  # session id
    pos += 2 + 1  # cipher suite, compression method
    if len(body) < pos + 2:
        return version
    end = pos + 2 + int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    while pos + 4 <= min(end, len(body)):
        ext_type = int.from_bytes(body[pos : pos + 2], "big")
        ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
        if ext_type == _EXT_SUPPORTED_VERSIONS and ext_len == 2 and pos + 6 <= len(body):
            return int.from_bytes(body[pos + 4 : pos + 6], "big")
        pos += 4 + ext_len
    return version


@dataclass
class _Attempt:
    """What one connection established, whether or not its handshake completed."""

    records: _ServerRecords
    completed: bool = False
    version: str | None = None
    cipher: str = ""
    leaf: dict[str, Any] = field(default_factory=dict)
    der: bytes | None = None
    verified_chain: list[dict[str, Any]] | None = None
    error: BaseException | None = None


def _protocol_label(raw: str | None) -> str | None:
    # ssl.SSLObject.version() spells TLS 1.0 "TLSv1"; tls_posture spells it "TLSv1.0".
    return "TLSv1.0" if raw == "TLSv1" else raw


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise _Unreachable(str(exc)) from exc


def _is_public_peer(peer: str) -> bool:
    """Whether a connected-to address is publicly routable, by the scanner's one rule.

    ``safe_http.is_public_address`` judges a NAT64 or IPv4-mapped address by
    the IPv4 address it delivers to, so ``64:ff9b::a00:5`` is 10.0.0.5 here too.
    """
    try:
        address = ipaddress.ip_address(peer.split("%", 1)[0])
    except ValueError:
        return False
    return is_public_address(address)


def _peer_is_public(sock: socket.socket) -> tuple[str, bool]:
    """The address actually connected to, and whether it is publicly routable."""
    try:
        peer = str(sock.getpeername()[0])
    except OSError:
        return "", False
    return peer, _is_public_peer(peer)


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("handshake timed out")
    return left


def _flush(sock: socket.socket, outgoing: ssl.MemoryBIO, deadline: float) -> None:
    data = outgoing.read()
    if data:
        sock.settimeout(_remaining(deadline))
        sock.sendall(data)


def _presented_chain(tls: ssl.SSLObject) -> list[tuple[dict[str, Any], bytes]] | None:
    """The certificates the server sent, decoded by the stdlib.

    ``getpeercert()`` is empty under ``CERT_NONE`` and raises after a failed
    verification; the chain OpenSSL kept is reachable through the object's
    ``get_unverified_chain`` -- private in 3.10-3.12, behind the public 3.13
    method of the same name. ``None`` when this Python has no such method.
    """
    getter = getattr(getattr(tls, "_sslobj", None), "get_unverified_chain", None)
    if getter is None:
        return None
    try:
        chain = getter() or []
        return [(cert.get_info(), ssl.PEM_cert_to_DER_cert(cert.public_bytes())) for cert in chain]
    except (ssl.SSLError, ValueError, AttributeError) as exc:
        LOG.debug("tls_probe: presented chain unreadable: %s", exc)
        return None


def _verified_chain(tls: ssl.SSLObject) -> list[dict[str, Any]] | None:
    """The chain OpenSSL verified, leaf first, decoded; ``None`` when unavailable."""
    getter = getattr(getattr(tls, "_sslobj", None), "get_verified_chain", None)
    if getter is None:
        return None
    try:
        return [cert.get_info() for cert in getter() or []]
    except (ssl.SSLError, ValueError, AttributeError) as exc:
        LOG.debug("tls_probe: verified chain unreadable: %s", exc)
        return None


def _handshake(sock: socket.socket, ctx: ssl.SSLContext, server_hostname: str, timeout: float) -> _Attempt:
    """One TLS handshake over ``sock``, run over memory BIOs.

    Never raises for a TLS-level failure: the error is kept on the attempt
    together with what the server's records showed before it.
    """
    records = _ServerRecords()
    attempt = _Attempt(records=records)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    try:
        tls = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=server_hostname)
    except ValueError as exc:  # a server_hostname the ssl module refuses
        attempt.error = exc
        return attempt
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                if incoming.eof:
                    raise ConnectionAbortedError("server closed the connection") from None
                _flush(sock, outgoing, deadline)
                sock.settimeout(_remaining(deadline))
                data = sock.recv(65536)
                records.feed(data)
                if data:
                    incoming.write(data)
                else:
                    incoming.write_eof()
        _flush(sock, outgoing, deadline)
        attempt.completed = True
    except (ssl.SSLError, OSError) as exc:
        attempt.error = exc
        alert = outgoing.read()
        if alert:
            try:
                sock.sendall(alert)
            except OSError as send_exc:
                # Our alert is a courtesy to the server's logs; the connection
                # is being dropped either way.
                LOG.debug("tls_probe: alert not sent: %s", send_exc)

    attempt.version = _protocol_label(tls.version()) if attempt.completed else records.server_hello_version
    cipher = tls.cipher()  # set once the ServerHello was read, even if the handshake then failed
    attempt.cipher = (cipher[0] if cipher else "") or ""
    chain = _presented_chain(tls)
    if chain:
        attempt.leaf, attempt.der = chain[0]
    elif attempt.completed:
        attempt.leaf = tls.getpeercert() or {}
        attempt.der = tls.getpeercert(binary_form=True)
    if attempt.completed and ctx.verify_mode != ssl.CERT_NONE:
        attempt.verified_chain = _verified_chain(tls)
    return attempt


def _describe(exc: BaseException | None) -> str:
    if exc is None:
        return "unknown failure"
    reason = getattr(exc, "reason", None)
    return str(reason) if reason else f"{exc.__class__.__name__}: {exc}"


def _alert_name(code: int) -> str:
    return _ALERT_NAMES.get(code, f"alert {code}")


def _legacy_status(attempt: _Attempt, label: str) -> dict[str, Any]:
    """Classify one pinned-version attempt (see HONESTY in the module docstring)."""
    records = attempt.records
    if attempt.completed:
        if attempt.version == label:
            return {"status": "accepted"}
        return {"status": "inconclusive", "detail": f"handshake completed as {attempt.version}"}

    chosen = records.server_hello_version
    if chosen is not None and chosen != label:
        return {"status": "rejected", "detail": f"server answered with {chosen}", "server_hello_version": chosen}
    if chosen == label:
        check: dict[str, Any] = {"status": "inconclusive", "server_hello_version": chosen}
        local_reason = getattr(attempt.error, "reason", None)
        if local_reason in _LOCAL_POLICY_REASONS:
            check["status"] = "not_performed"
            check["detail"] = (
                f"server chose {label}; local OpenSSL policy would not finish the handshake ({local_reason})"
            )
        elif records.certificate_request:
            check["client_cert_requested"] = True
            check["detail"] = (
                f"server chose {label} and asked for a client certificate; "
                f"without one the handshake ended ({_describe(attempt.error)})"
            )
        else:
            check["detail"] = f"server chose {label}, then the handshake failed: {_describe(attempt.error)}"
        return check
    if records.alert == _ALERT_PROTOCOL_VERSION:
        return {"status": "rejected", "detail": "protocol_version alert"}
    if records.alert is not None:
        return {
            "status": "inconclusive",
            "detail": (
                f"{_alert_name(records.alert)} alert before any ServerHello: "
                "a refused version and a refused cipher list look the same"
            ),
        }
    if records.not_tls:
        return {"status": "inconclusive", "detail": "server did not answer in TLS"}
    reason = getattr(attempt.error, "reason", None)
    if records.tls_seen and reason in _VERSION_REFUSAL_REASONS:
        return {"status": "rejected", "detail": str(reason)}
    if isinstance(attempt.error, (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionError)):
        return {
            "status": "inconclusive",
            "detail": "server hung up without a TLS answer (a refusal, a connection limit or a middlebox)",
        }
    if isinstance(attempt.error, TimeoutError):
        return {"status": "inconclusive", "detail": "no answer before the timeout"}
    return {"status": "inconclusive", "detail": f"handshake aborted locally: {_describe(attempt.error)}"}


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


def _trust_skip(contexts: ProbeContexts, peer: str, peer_public: bool) -> dict[str, Any] | None:
    """The ``chain_trust`` record when the chain is not to be judged, else ``None``."""
    if contexts.chain_trust == "off":
        return {"status": "not_evaluated", "reason": "disabled", "detail": "tls_posture.chain_trust is off"}
    if contexts.chain_trust == "public_only" and not contexts.ca_bundle_configured and not peer_public:
        return {
            "status": "not_evaluated",
            "reason": "internal_address",
            "detail": (
                f"{peer or 'the address'} is not publicly routable; set tls_posture.ca_bundle "
                "to the internal CAs (or chain_trust: always) to judge it"
            ),
        }
    if contexts.verify is None:
        return {"status": "not_performed", "detail": contexts.trust_skip_reason}
    return None


def _in_window(info: dict[str, Any] | None, now: datetime) -> bool | None:
    """Whether a stdlib-decoded certificate is within its validity window now;
    ``None`` when its dates are unknown."""
    if not info:
        return None
    cert = _cert_dict_from_peercert(info)
    not_after, not_before = cert.get("not_after_dt"), cert.get("not_before_dt")
    if not isinstance(not_after, datetime) or not isinstance(not_before, datetime):
        return None
    return not_before <= now <= not_after


def _chain_validity(
    chain: list[dict[str, Any]] | None, now: datetime
) -> tuple[list[dict[str, Any]], str | None]:
    """Which CA certificate of a chain failed OpenSSL's time check.

    Called only when verification with the time check failed on time and the
    untimed one then verified ``chain``. Returns the issues and, when the
    answer cannot be told, why not.
    """
    if chain is None:
        return [], "this Python exposes no verified chain"
    issues: list[dict[str, Any]] = []
    for depth, info in enumerate(chain[1:], start=1):
        cert = _cert_dict_from_peercert(info)
        name = cert.get("subject") or f"depth {depth}"
        not_after = cert.get("not_after_dt")
        not_before = cert.get("not_before_dt")
        if isinstance(not_after, datetime) and not_after < now:
            issues.append(
                {
                    "kind": "cert_chain_expired",
                    "severity": "high",
                    "depth": depth,
                    "subject": name,
                    "detail": f"{name} in the verified chain expired {cert.get('not_after')}",
                }
            )
        elif isinstance(not_before, datetime) and not_before > now:
            issues.append(
                {
                    "kind": "cert_not_yet_valid",
                    "severity": "medium",
                    "depth": depth,
                    "subject": name,
                    "detail": f"{name} in the verified chain is valid from {cert.get('not_before')}",
                }
            )
    if chain and _in_window(chain[0], now) is False:
        if not issues:
            # Every CA certificate is within its window: the time failure was
            # the leaf's own, which cert_expired / cert_not_yet_valid report.
            return [], None
        # The untimed verification may have picked an expired twin a client
        # would not; with the leaf failing too, the two cannot be told apart.
        return [], "the leaf and a CA certificate are both outside their windows; which one a client trips on cannot be told"
    if not issues:
        return [], "the time check failed, but no certificate of the re-verified chain is outside its window"
    return issues, None


def _load_leaf(der: bytes | None) -> tuple[Any, str | None]:
    """Parse the leaf DER with ``cryptography``: ``(cert, None)`` or ``(None, why not)``.

    Both images install ``cryptography`` (requirements.txt and
    requirements-api.txt); a host that runs the scanner without it gets key and
    signature checks recorded as ``not_performed`` rather than passed silently.
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


# Signature algorithms cryptography reports as "Unknown OID": the MD2/MD4
# RSA OIDs and the OIW sha1WithRSA. Named here so cert_strength can judge them.
_SIGNATURE_OID_NAMES = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.3.14.3.2.29": "sha1WithRSA",
}


def _strength_fields(leaf: Any) -> dict[str, Any]:
    """``public_key_type`` / ``public_key_bits`` / ``signature_algorithm`` of a leaf."""
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    oid = leaf.signature_algorithm_oid
    name = _SIGNATURE_OID_NAMES.get(oid.dotted_string) or getattr(oid, "_name", None)
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


def _cert_from_attempt(attempt: _Attempt | None) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The normalized cert dict, and the ``cert_fields`` / ``cert_strength`` check records."""
    if attempt is None or not (attempt.leaf or attempt.der):
        missing = {"status": "not_performed", "detail": "no certificate received"}
        return {}, missing, dict(missing)
    leaf, reason = _load_leaf(attempt.der)
    if attempt.leaf:
        cert = _cert_dict_from_peercert(attempt.leaf)
    elif leaf is not None:
        cert = _cert_fields(leaf)
    else:
        cert = {}
    if isinstance(cert.get("not_after_dt"), datetime):
        fields_check: dict[str, Any] = {"status": "performed"}
    else:
        fields_check = {"status": "not_performed", "detail": "certificate fields could not be decoded"}
    if leaf is None:
        return cert, fields_check, {"status": "not_performed", "detail": reason}
    cert.update(_strength_fields(leaf))
    return cert, fields_check, {"status": "performed"}


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

    try:
        sock = _connect(host, port, timeout)
    except _Unreachable as exc:
        LOG.debug("tls_probe %s:%s unreachable: %s", host, port, exc)
        return None
    with sock:
        peer, peer_public = _peer_is_public(sock)
        skip = _trust_skip(contexts, peer, peer_public)
        # _trust_skip answers "not_performed" whenever there is no verify context.
        main_ctx = contexts.verify if skip is None else contexts.collect
        main = _handshake(sock, main_ctx or contexts.collect, server_hostname, timeout)

    if not main.completed and not main.records.tls_seen:
        if main.records.not_tls or isinstance(main.error, TimeoutError):
            # Not TLS, or nothing said at all: a pinned ClientHello would wait
            # out the same timeout, twice.
            LOG.debug("tls_probe %s:%s no TLS answer: %s", host, port, _describe(main.error))
            return None
        # Hung up on the widest ClientHello without a word. Old servers that
        # choke on a modern one (version intolerance) may still take one
        # pinned to TLS 1.0, so the legacy checks run before giving up.

    # The main handshake verified with the time check, as an ordinary client
    # does. Only a failure *on time* earns a second, untimed verification: it
    # tells "trusted, but something is outside its window" from "untrusted".
    retry: _Attempt | None = None
    time_failure: str | None = None
    chain_issue_without_depth: dict[str, Any] | None = None
    if skip is not None:
        trust = skip
    elif main.completed:
        # The whole chain, leaf included, passed OpenSSL's time check.
        trust = {"status": "trusted", "store": contexts.trust_store, "validity_checked": True}
    elif (
        isinstance(main.error, ssl.SSLCertVerificationError)
        and getattr(main.error, "verify_code", None) in _TIME_VERIFY_CODES
        and contexts.verify_untimed is not None
    ):
        time_failure = getattr(main.error, "verify_message", None) or str(main.error)
        try:
            with _connect(host, port, timeout) as sock:
                retry = _handshake(sock, contexts.verify_untimed, server_hostname, timeout)
        except _Unreachable as exc:
            LOG.debug("tls_probe %s:%s untimed verification unreachable: %s", host, port, exc)
        if retry is not None and retry.completed:
            trust = {"status": "trusted", "store": contexts.trust_store, "time_check": time_failure}
        elif retry is not None and isinstance(retry.error, ssl.SSLCertVerificationError):
            trust = _trust_from_verify_error(retry.error)
            trust["store"] = contexts.trust_store
        else:
            trust = {
                "status": "inconclusive",
                "detail": f"time check failed ({time_failure}) and the untimed verification did not complete",
            }
            if _in_window(main.leaf, now) is True:
                # OpenSSL checks time only on a chain it has built to a trust
                # anchor (an unanchored one fails with code 20 first), so a
                # time failure with the leaf in its window names a CA
                # certificate -- which one, the lost re-verification would have said.
                chain_issue_without_depth = {
                    "kind": "cert_chain_expired",
                    "severity": "high",
                    "detail": f"a CA certificate of the chain failed the time check: {time_failure}",
                }
    elif isinstance(main.error, ssl.SSLCertVerificationError):
        trust = _trust_from_verify_error(main.error)
        trust["store"] = contexts.trust_store
    else:
        trust = {"status": "inconclusive", "detail": f"no handshake completed: {_describe(main.error)}"}

    collect: _Attempt | None = None
    if isinstance(main.error, ssl.SSLCertVerificationError) and time_failure is None:
        # The verifying handshake stopped at the certificate; a second one
        # without verification shows protocol and cipher of a completed
        # handshake. If it fails, the first one's ServerHello and certificate
        # still stand.
        try:
            with _connect(host, port, timeout) as sock:
                collect = _handshake(sock, contexts.collect, server_hostname, timeout)
        except _Unreachable as exc:
            LOG.debug("tls_probe %s:%s collect handshake unreachable: %s", host, port, exc)

    attempts: list[_Attempt] = [a for a in (collect, retry, main) if a is not None]
    completed: dict[str, _Attempt] = {}
    for attempt in attempts:
        if attempt.completed and attempt.version:
            completed.setdefault(attempt.version, attempt)

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
        if label in contexts.legacy_disabled:
            protocols[label] = {
                "status": "not_evaluated",
                "reason": "disabled",
                "detail": "tls_posture.probe_legacy_protocols is off",
            }
            continue
        ctx = contexts.legacy.get(label)
        if ctx is None:
            protocols[label] = {
                "status": "not_performed",
                "detail": contexts.legacy_skipped.get(label, "not configured"),
            }
            continue
        try:
            with _connect(host, port, timeout) as sock:
                attempt = _handshake(sock, ctx, server_hostname, timeout)
        except _Unreachable as exc:
            protocols[label] = {"status": "inconclusive", "detail": f"connection failed: {exc}"}
            continue
        attempts.append(attempt)
        protocols[label] = _legacy_status(attempt, label)
        if protocols[label]["status"] == "accepted":
            completed[label] = attempt

    if not completed and not any(a.records.tls_seen for a in attempts):
        return None
    accepted = sorted(completed, key=lambda v: _PROTOCOL_ORDER.index(v) if v in _PROTOCOL_ORDER else 99)
    # The best a client got: the main handshake, else the highest version a
    # pinned one completed (a server that refused the modern ClientHello).
    base = next((a for a in (collect, retry, main) if a is not None and a.completed), None)
    if base is None and accepted:
        base = completed[accepted[-1]]
    cert_source = base or next((a for a in attempts if a.leaf or a.der), None)

    cert, fields_check, strength_check = _cert_from_attempt(cert_source)
    issues = _classify_from_cert(cert, now, expiring_soon_days) if cert else []
    if trust["status"] == "trusted":
        # The chain verified to an anchor the operator trusts (the system store
        # or ca_bundle): a matching subject and issuer is not "nobody vouches".
        issues = [issue for issue in issues if issue["kind"] != "self_signed"]
        if time_failure is not None and retry is not None:
            validity_issues, validity_gap = _chain_validity(retry.verified_chain, now)
            issues.extend(validity_issues)
            trust["validity_checked"] = validity_gap is None
            if validity_gap is not None:
                trust["validity_detail"] = validity_gap
    elif trust["status"] == "untrusted" and trust.get("verify_code") == _VERIFY_SELF_SIGNED_LEAF:
        # Verification established what the heuristic guesses: one finding,
        # and a certain one, rather than self_signed plus cert_untrusted.
        issues = [issue for issue in issues if issue["kind"] != "self_signed"]
        issues.append(
            {
                "kind": "self_signed",
                "severity": "medium",
                "detail": "self-signed certificate (chain verification)",
                "heuristic": False,
            }
        )
    elif trust["status"] == "untrusted":
        issues.append(
            {
                "kind": "cert_untrusted",
                "severity": "medium",
                "detail": trust["detail"],
                "verify_code": trust.get("verify_code"),
            }
        )
    if chain_issue_without_depth is not None:
        issues.append(chain_issue_without_depth)
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
    # Weak cipher name on the negotiated cipher. OpenSSL 3's DEFAULT list at
    # security level 0 offers none of these suites, so with current images the
    # server cannot pick one and this never fires; older OpenSSL builds still
    # offer 3DES.
    cname = base.cipher if base is not None else ""
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
    row: dict[str, Any] = {
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
        # Without a completed handshake, what the main one's ServerHello chose.
        "negotiated_protocol": base.version if base is not None else main.version,
        "negotiated_cipher": cname,
        "accepted_protocols": accepted,
        "checks": {
            "protocols": dict(sorted(protocols.items(), key=lambda kv: _PROTOCOL_ORDER.index(kv[0]))),
            "chain_trust": {k: v for k, v in trust.items() if v is not None},
            "cert_fields": fields_check,
            "cert_strength": strength_check,
        },
    }
    if any(a.records.certificate_request for a in attempts):
        row["client_cert_requested"] = True
    return row


def _cert_fields(cert: Any) -> dict[str, Any]:
    """Subject/issuer/SAN/validity of a ``cryptography`` certificate, in probe shape.

    The fallback for a Python whose ``ssl`` cannot hand back the presented
    chain decoded (see :func:`_presented_chain`).
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
    chain_trust: str = "public_only",
) -> list[dict[str, Any]]:
    """Probe open ports for TLS; return finding dicts compatible with tls_posture.

    ``sni_by_host`` maps an address to the name to send in SNI (the FQDN that
    resolved to it). Without an entry the address itself is used, and the row's
    ``sni`` field records which it was. ``probe_legacy_protocols``,
    ``ca_bundle`` and ``chain_trust`` are the ``tls_posture`` config keys of the
    same names.
    """
    now = now or datetime.now(timezone.utc)
    endpoints = _parse_tls_endpoints(open_ports, tls_ports)
    if not endpoints:
        return []
    truncated = len(endpoints) > max_targets
    endpoints = endpoints[:max_targets]
    contexts = build_probe_contexts(
        probe_legacy_protocols=probe_legacy_protocols, ca_bundle=ca_bundle, chain_trust=chain_trust
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
