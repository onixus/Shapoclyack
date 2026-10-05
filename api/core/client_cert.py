"""Which client certificate a sensor or endpoint agent presented (#309).

Two ways a verified client certificate reaches the API, and this module is the
only place that reads either:

**Direct TLS.** The API's own listener (``OCTO_API_TLS_CERT``) asks for a client
certificate signed by ``OCTO_AGENT_MTLS_CLIENT_CA`` (``ssl.CERT_OPTIONAL``, so
the console on the same port keeps working without one). OpenSSL has verified
the chain by the time a request exists; uvicorn just does not hand the result
to the application, so :func:`peer_certificate_protocol` wraps its HTTP
protocol and copies the peer's DER into the per-connection ASGI ``state``. A
client cannot write there: it is filled from the socket, not from the request.

**A TLS-terminating ingress.** ingress-nginx with ``auth-tls-verify-client``
verifies the certificate itself and forwards the verdict and the certificate
as the ``ssl-client-verify`` / ``ssl-client-cert`` request headers. Headers
are something any client can write, so they are believed **only** when the
socket peer is in ``OCTO_AGENT_MTLS_TRUSTED_PROXIES`` — deliberately a list of
its own rather than ``OCTO_TRUSTED_PROXIES``: that one decides whose
``X-Forwarded-For`` keys a rate-limit bucket, this one decides whose word
authenticates a sensor. From any other peer the headers are ignored, and the
request is treated as one that presented no certificate at all. When a client
CA is configured, a forwarded certificate is also checked against it here, so
an ingress pointed at the wrong CA Secret does not quietly widen who gets in.

Nothing here decides *whether* a certificate is required or *whom* it belongs
to — that is ``api/services/agent_certs.py``. This module answers "what was
presented, and can it be believed".
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Sequence
from urllib.parse import quote, unquote, urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID

from api.core.client_ip import parse_trusted_proxies

logger = logging.getLogger(__name__)

#: ``scope["state"]`` key the TLS listener's protocol fills (see module doc).
TLS_PEER_CERT_STATE_KEY = "shapoclyack_tls_peer_cert_der"

#: The headers ingress-nginx sets with ``auth-tls-verify-client`` and
#: ``auth-tls-pass-certificate-to-upstream: "true"``. The certificate is
#: ``$ssl_client_escaped_cert``: the PEM, URL-encoded.
VERIFY_HEADER = "ssl-client-verify"
CERT_HEADER = "ssl-client-cert"
#: ``$ssl_client_s_dn``, which ingress-nginx sets whenever auth-tls is on —
#: with or without passing the certificate itself. See the cross-check in
#: :func:`presented_certificate`.
SUBJECT_HEADER = "ssl-client-subject-dn"
VERIFY_SUCCESS = "SUCCESS"

#: A forwarded certificate longer than this is not parsed. A leaf with a few
#: SANs is 1–2 KiB of PEM, escaped a little more; this is the cost a client
#: can make every request pay before anything is checked.
MAX_FORWARDED_CERT_BYTES = 16 * 1024

SOURCE_TLS = "tls"
SOURCE_PROXY = "proxy"

#: ``spiffe://<trust domain>/tenant/<tenant_id>/<sensor|agent>/<agent_id>``.
#: ``sensor`` is the scanning node, ``agent`` the Lariska endpoint agent; both
#: name a row in ``agents`` and bind the same way.
SPIFFE_SCHEME = "spiffe"
SPIFFE_KINDS = ("sensor", "agent")


@dataclass(frozen=True)
class CertIdentity:
    """The sensor or agent a certificate's SPIFFE URI names."""

    trust_domain: str
    tenant_id: str
    kind: str
    agent_id: str

    @property
    def uri(self) -> str:
        return spiffe_uri(self.trust_domain, self.tenant_id, self.kind, self.agent_id)


@dataclass(frozen=True)
class PresentedCert:
    """A client certificate that has been verified by something we trust."""

    fingerprint_sha256: str
    serial_hex: str
    subject: str
    not_before: datetime
    not_after: datetime
    identities: tuple[CertIdentity, ...]
    source: str


@dataclass(frozen=True)
class Presentation:
    """What a request carried: a certificate, or ``None`` and why there is none.

    ``note`` is for the refusal an operator reads when ``required`` turns a
    sensor away — "forwarded headers from an untrusted peer were ignored" is
    the one-line answer to the most likely misconfiguration, and nothing else
    surfaces it.
    """

    cert: PresentedCert | None = None
    note: str | None = None


@dataclass(frozen=True)
class _Bundle:
    certs: tuple[x509.Certificate, ...] = field(default_factory=tuple)


def _naive_utc(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def spiffe_uri(trust_domain: str, tenant_id: str, kind: str, agent_id: str) -> str:
    """The URI a certificate for this identity carries; segments are escaped."""
    return (
        f"{SPIFFE_SCHEME}://{trust_domain}/tenant/{quote(tenant_id, safe='')}"
        f"/{kind}/{quote(agent_id, safe='')}"
    )


def parse_spiffe_uri(value: str) -> CertIdentity | None:
    """``CertIdentity`` for a well-formed URI of this shape, else ``None``."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme != SPIFFE_SCHEME or not parts.netloc or parts.query or parts.fragment:
        return None
    segments = parts.path.split("/")
    # ["", "tenant", t, kind, id]
    if len(segments) != 5 or segments[0] or segments[1] != "tenant":
        return None
    tenant_id, kind, agent_id = unquote(segments[2]), segments[3], unquote(segments[4])
    if kind not in SPIFFE_KINDS or not tenant_id or not agent_id:
        return None
    return CertIdentity(parts.netloc.lower(), tenant_id, kind, agent_id)


def describe(cert: x509.Certificate, *, source: str) -> PresentedCert:
    """Reduce a parsed certificate to what binding and the audit trail need."""
    identities: list[CertIdentity] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
            identity = parse_spiffe_uri(uri)
            if identity is not None:
                identities.append(identity)
    return PresentedCert(
        fingerprint_sha256=fingerprint(cert),
        serial_hex=format(cert.serial_number, "x"),
        subject=cert.subject.rfc4514_string()[:512],
        not_before=_naive_utc(cert.not_valid_before_utc),
        not_after=_naive_utc(cert.not_valid_after_utc),
        identities=tuple(identities),
        source=source,
    )


def fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 over the DER, lower-case hex — what ``openssl x509 -fingerprint
    -sha256`` prints, without the colons."""
    from cryptography.hazmat.primitives.serialization import Encoding

    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def normalise_fingerprint(value: str) -> str:
    """Accept ``AB:CD:…`` as well as ``abcd…``; ``ValueError`` for anything else."""
    cleaned = (value or "").strip().replace(":", "").lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("fingerprint must be a SHA-256 digest: 64 hex characters")
    return cleaned


def normalise_serial(value: str) -> str:
    """Serial as unpadded lower-case hex, as :func:`describe` stores it."""
    cleaned = (value or "").strip().replace(":", "").lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    try:
        return format(int(cleaned, 16), "x")
    except ValueError as exc:
        raise ValueError("serial must be hexadecimal") from exc


def load_pem_certificate(pem: str | bytes) -> x509.Certificate:
    """The first certificate in ``pem``; ``ValueError`` when there is none."""
    data = pem.encode("ascii", errors="replace") if isinstance(pem, str) else pem
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise ValueError("not a PEM certificate") from exc
    if not certs:
        raise ValueError("not a PEM certificate")
    return certs[0]


@lru_cache(maxsize=8)
def _bundle_at(path: str, mtime_ns: int) -> _Bundle:
    del mtime_ns  # the cache key: a rotated bundle is re-read
    with open(path, "rb") as handle:
        return _Bundle(tuple(x509.load_pem_x509_certificates(handle.read())))


def load_ca_bundle(path: str) -> tuple[x509.Certificate, ...]:
    """The CA certificates at ``path``, re-read when the file changes."""
    return _bundle_at(path, os.stat(path).st_mtime_ns).certs


def issued_by_bundle(cert: x509.Certificate, bundle: Sequence[x509.Certificate]) -> bool:
    """Whether one certificate of ``bundle`` signed ``cert`` directly.

    A forwarded certificate is the leaf alone — ingress-nginx passes nothing
    else — so the bundle must hold the CA that issues sensor certificates
    (the cert-manager Issuer's CA, or ``OCTO_AGENT_MTLS_ISSUER_CERT``), not
    only a root above it.
    """
    for ca in bundle:
        if ca.subject != cert.issuer:
            continue
        try:
            cert.verify_directly_issued_by(ca)
        except (InvalidSignature, ValueError, TypeError):
            continue
        return True
    return False


def is_usable_now(cert: x509.Certificate, now: datetime) -> str | None:
    """Why ``cert`` cannot authenticate a client at ``now``, or ``None``."""
    if _naive_utc(cert.not_valid_before_utc) > now:
        return "the client certificate is not valid yet"
    if _naive_utc(cert.not_valid_after_utc) <= now:
        return "the client certificate has expired"
    try:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return None
    if ExtendedKeyUsageOID.CLIENT_AUTH not in usage:
        return "the client certificate is not issued for client authentication"
    return None


def _is_trusted(peer: str | None, networks: Sequence[Any]) -> bool:
    try:
        address = ipaddress.ip_address((peer or "").strip())
    except ValueError:
        return False
    return any(address in network for network in networks)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def presented_certificate(
    *,
    scope_state: dict[str, Any] | None,
    peer: str | None,
    headers: Any,
    trusted_proxies: Sequence[str],
    client_ca_path: str,
    now: datetime | None = None,
) -> Presentation:
    """The verified client certificate behind one request, if there is one.

    ``headers`` is anything with a case-insensitive ``get`` (Starlette's
    ``Headers``). The order is the direct TLS peer first — the socket's own
    handshake is the stronger statement — then the trusted proxy's headers.
    """
    current = now or _now()
    der = (scope_state or {}).get(TLS_PEER_CERT_STATE_KEY)
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
        except ValueError:
            # OpenSSL accepted it, so this is not reachable in practice; if it
            # ever is, "no certificate" is the answer that cannot let anybody
            # in under ``required``.
            logger.warning("TLS peer certificate could not be parsed; treating it as absent")
            return Presentation(note="the TLS client certificate could not be parsed")
        return Presentation(cert=describe(cert, source=SOURCE_TLS))

    verify = (headers.get(VERIFY_HEADER) or "").strip()
    raw = headers.get(CERT_HEADER) or ""
    if not verify and not raw:
        return Presentation()
    networks = parse_trusted_proxies(trusted_proxies)
    if not _is_trusted(peer, networks):
        return Presentation(
            note=(
                "client certificate headers from a peer that is not in "
                "OCTO_AGENT_MTLS_TRUSTED_PROXIES were ignored"
            ),
        )
    if verify != VERIFY_SUCCESS:
        # NONE (nothing presented) or FAILED:<reason> — the ingress's verdict,
        # which is the only one it can give about a certificate it rejected.
        return Presentation(
            note=f"the ingress did not verify a client certificate ({verify[:80] or 'no verdict'})"
        )
    if len(raw) > MAX_FORWARDED_CERT_BYTES:
        return Presentation(note="the forwarded client certificate is too large")
    try:
        cert = load_pem_certificate(unquote(raw))
    except ValueError:
        return Presentation(note="the forwarded client certificate is not a PEM certificate")
    problem = is_usable_now(cert, current)
    if problem:
        return Presentation(note=problem)
    subject_dn = headers.get(SUBJECT_HEADER)
    if subject_dn is not None and subject_dn.strip() != cert.subject.rfc4514_string():
        # nginx overwrites ``ssl-client-subject-dn`` from the handshake, but
        # sets ``ssl-client-cert`` only with auth-tls-pass-certificate-to-
        # upstream: without it, the certificate header is whatever the client
        # wrote — another sensor's public certificate, next to a handshake
        # made with its own. The two disagreeing is that misconfiguration.
        logger.warning(
            "The client certificate forwarded by %s does not match the subject the "
            "ingress verified; is auth-tls-pass-certificate-to-upstream \"true\"?",
            peer,
        )
        return Presentation(
            note="the forwarded client certificate does not match the subject the ingress verified"
        )
    if client_ca_path:
        try:
            bundle = load_ca_bundle(client_ca_path)
        except (OSError, ValueError):
            logger.exception("OCTO_AGENT_MTLS_CLIENT_CA %s is unreadable", client_ca_path)
            return Presentation(note="the API cannot read its client CA bundle")
        if not issued_by_bundle(cert, bundle):
            # The ingress verified it against *some* CA, and not ours: the
            # auth-tls-secret and OCTO_AGENT_MTLS_CLIENT_CA disagree.
            logger.warning(
                "A client certificate forwarded by %s as verified was not issued by "
                "OCTO_AGENT_MTLS_CLIENT_CA; check the ingress auth-tls-secret",
                peer,
            )
            return Presentation(
                note="the forwarded client certificate is not issued by the configured client CA"
            )
    return Presentation(cert=describe(cert, source=SOURCE_PROXY))


def peer_certificate_protocol(base: type) -> type:
    """``base`` (a uvicorn HTTP protocol) that exposes the TLS peer certificate.

    uvicorn copies its ``app_state`` into every request's ``scope["state"]``;
    replacing it per connection with a copy that carries the peer's DER is the
    one hook that needs no change to how uvicorn builds a scope. The asyncio
    SSL transport calls ``connection_made`` after the handshake, so the
    certificate is final by then.
    """

    class PeerCertificateProtocol(base):  # type: ignore[valid-type, misc]
        def connection_made(self, transport):  # type: ignore[no-untyped-def]
            super().connection_made(transport)
            ssl_object = transport.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            if der:
                self.app_state = {**self.app_state, TLS_PEER_CERT_STATE_KEY: der}

    PeerCertificateProtocol.__name__ = f"PeerCertificate{base.__name__}"
    PeerCertificateProtocol.__qualname__ = PeerCertificateProtocol.__name__
    return PeerCertificateProtocol


def listener_protocol_class() -> type:
    """The protocol uvicorn's ``http="auto"`` would pick, with the peer hook."""
    try:
        from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

        return peer_certificate_protocol(HttpToolsProtocol)
    except ImportError:  # pragma: no cover - httptools is in the API image
        from uvicorn.protocols.http.h11_impl import H11Protocol

        return peer_certificate_protocol(H11Protocol)
