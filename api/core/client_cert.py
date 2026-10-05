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
request is treated as one that presented no certificate at all. A forwarded
certificate is also checked against ``OCTO_AGENT_MTLS_CLIENT_CA`` here — and
without one it is not believed at all (start-up refuses that configuration;
this is the same rule for a ``Settings`` built around start-up) — so an
ingress pointed at the wrong CA Secret, or a pod in the trusted range that is
not the ingress, does not quietly widen who gets in.

What the header path proves is weaker than the API's own handshake: the
ingress verified that *somebody* held the key, and the API sees the
certificate it says that was. The API cannot check possession itself, so a
host the ingress does not front, but that can reach the API port from a
trusted address, needs only a sensor's public certificate and its token.
That is why the trusted list should name the ingress controller and nothing
else, and why a NetworkPolicy should keep everything else off the port
(``k8s/shapoclyack/examples/agent-mtls-api-patch.yaml``).

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


# --- the subject nginx forwards ----------------------------------------------
#
# ``$ssl_client_s_dn`` is OpenSSL's ``X509_NAME_print_ex(…, XN_FLAG_RFC2253)``:
# RDNs last-first, OpenSSL's short names (``emailAddress``, ``INN``), every
# byte past ASCII as ``\XX`` of its UTF-8, an attribute of a type it does not
# know as ``#`` + the DER of its value in hex, and the AVAs of a multi-valued
# RDN in whatever order it likes. cryptography's ``rfc4514_string`` agrees on
# none of that, so the two are compared as names: a list of RDNs, each a set
# of (OID, value).

#: Attribute names either spelling uses, lower-cased, to their OIDs. One that
#: is not here and is not a dotted OID makes the subject unreadable, which is
#: a refusal, never a match.
_DN_ATTRIBUTE_OIDS = {
    "cn": "2.5.4.3",
    "sn": "2.5.4.4",
    "serialnumber": "2.5.4.5",
    "c": "2.5.4.6",
    "l": "2.5.4.7",
    "st": "2.5.4.8",
    "street": "2.5.4.9",
    "o": "2.5.4.10",
    "ou": "2.5.4.11",
    "title": "2.5.4.12",
    "businesscategory": "2.5.4.15",
    "postalcode": "2.5.4.17",
    "gn": "2.5.4.42",
    "givenname": "2.5.4.42",
    "initials": "2.5.4.43",
    "generationqualifier": "2.5.4.44",
    "dnqualifier": "2.5.4.46",
    "pseudonym": "2.5.4.65",
    "organizationidentifier": "2.5.4.97",
    "emailaddress": "1.2.840.113549.1.9.1",
    "dc": "0.9.2342.19200300.100.1.25",
    "uid": "0.9.2342.19200300.100.1.1",
    "jurisdictionl": "1.3.6.1.4.1.311.60.2.1.1",
    "jurisdictionst": "1.3.6.1.4.1.311.60.2.1.2",
    "jurisdictionc": "1.3.6.1.4.1.311.60.2.1.3",
    # The Russian qualified-certificate attributes OpenSSL names.
    "inn": "1.2.643.3.131.1.1",
    "ogrn": "1.2.643.100.1",
    "snils": "1.2.643.100.3",
    "innle": "1.2.643.100.4",
    "ogrnip": "1.2.643.100.5",
}
_HEX = frozenset("0123456789abcdefABCDEF")
#: DER string tags a ``#``-dumped value may carry, and how their bytes read.
_DER_STRING_CODECS = {
    0x0C: "utf-8",  # UTF8String
    0x12: "ascii",  # NumericString
    0x13: "ascii",  # PrintableString
    0x14: "latin-1",  # T61String, as OpenSSL reads it
    0x16: "ascii",  # IA5String
    0x1A: "ascii",  # VisibleString
    0x1C: "utf-32-be",  # UniversalString
    0x1E: "utf-16-be",  # BMPString
}

DistinguishedName = tuple[tuple[tuple[str, str], ...], ...]


def _attribute_oid(name: str) -> str | None:
    cleaned = name.strip()
    if cleaned and all(part.isdigit() for part in cleaned.split(".")) and "." in cleaned:
        return cleaned
    return _DN_ATTRIBUTE_OIDS.get(cleaned.lower())


def _der_string(hex_value: str) -> str | None:
    """The text of a ``#``-dumped DER string, or ``None``."""
    try:
        data = bytes.fromhex(hex_value)
    except ValueError:
        return None
    if len(data) < 2 or data[0] not in _DER_STRING_CODECS:
        return None
    length, offset = data[1], 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or len(data) < 2 + count:
            return None
        length, offset = int.from_bytes(data[2 : 2 + count], "big"), 2 + count
    if len(data) != offset + length:
        return None
    try:
        return data[offset:].decode(_DER_STRING_CODECS[data[0]])
    except UnicodeDecodeError:
        return None


def _read_value(text: str, start: int) -> tuple[str | None, int]:
    """One attribute value from ``start`` up to an unescaped ``,`` or ``+``."""
    end = len(text)
    if start < end and text[start] == "#":
        stop = start + 1
        while stop < end and text[stop] not in ",+":
            stop += 1
        return _der_string(text[start + 1 : stop]), stop
    raw = bytearray()
    index = start
    while index < end and text[index] not in ",+":
        char = text[index]
        if char != "\\":
            raw += char.encode("utf-8")
            index += 1
            continue
        pair = text[index + 1 : index + 3]
        if len(pair) == 2 and pair[0] in _HEX and pair[1] in _HEX:
            raw.append(int(pair, 16))
            index += 3
        elif index + 1 < end:
            raw += text[index + 1].encode("utf-8")
            index += 2
        else:
            return None, end
    try:
        return raw.decode("utf-8"), index
    except UnicodeDecodeError:
        return None, index


def parse_rfc2253(text: str) -> DistinguishedName | None:
    """An RFC 2253 / 4514 string as RDNs in the order written; ``None`` if unreadable."""
    if not text.strip():
        return None
    rdns: list[tuple[tuple[str, str], ...]] = []
    avas: list[tuple[str, str]] = []
    index = 0
    while True:
        equals = text.find("=", index)
        if equals < 0:
            return None
        oid = _attribute_oid(text[index:equals])
        if oid is None:
            return None
        value, index = _read_value(text, equals + 1)
        if value is None:
            return None
        avas.append((oid, value))
        if index >= len(text) or text[index] == ",":
            rdns.append(tuple(sorted(avas)))
            avas = []
        if index >= len(text):
            return tuple(rdns)
        index += 1


def _name_as_written(name: x509.Name) -> DistinguishedName:
    """``name`` in the shape :func:`parse_rfc2253` gives, RDNs last-first as both write them."""
    return tuple(
        tuple(
            sorted(
                (attribute.oid.dotted_string, attribute.value)
                if isinstance(attribute.value, str)
                # A bit-string attribute (x500UniqueIdentifier) has no text
                # either side could agree on: never equal to anything parsed.
                else (attribute.oid.dotted_string, "\x00" + attribute.value.hex())
                for attribute in rdn
            )
        )
        for rdn in reversed(name.rdns)
    )


def subject_matches(dn: str, subject: x509.Name) -> bool:
    """Whether the forwarded ``dn`` names ``subject``, as a name rather than as a string."""
    text = dn.strip()
    trailing = len(text) - len(text.rstrip("\\"))
    if trailing % 2:
        # A value ending in an escaped space (a backslash, then a space) loses the space to the
        # HTTP layer, which trims header values; it was a space.
        text += " "
    parsed = parse_rfc2253(text)
    return parsed is not None and parsed == _name_as_written(subject)


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_trusted_proxies(entries: Sequence[str]) -> tuple[Network, ...]:
    """``OCTO_AGENT_MTLS_TRUSTED_PROXIES`` as networks; ``ValueError`` names a bad entry.

    Strict, unlike ``api.core.client_ip.parse_trusted_proxies``: dropping an
    entry there only makes a rate limiter coarser, while here it is an
    ingress whose sensors are all refused — so start-up refuses it instead
    (``api.settings``), and a host name, which this list cannot hold, is said
    to be one.
    """
    networks: list[Network] = []
    for entry in entries:
        cleaned = entry.strip()
        if not cleaned:
            continue
        try:
            networks.append(ipaddress.ip_network(cleaned, strict=False))
        except ValueError as exc:
            raise ValueError(
                f"{cleaned!r} is not an IP address or CIDR (a host name cannot be trusted "
                "here: name the ingress controller's pod or node addresses)"
            ) from exc
    return tuple(networks)


@lru_cache(maxsize=8)
def _trusted_networks(entries: tuple[str, ...]) -> tuple[Network, ...]:
    """Parsed once per distinct list, not once per request."""
    return parse_trusted_proxies(entries)


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
    try:
        networks = _trusted_networks(tuple(trusted_proxies))
    except ValueError:
        # Start-up refuses this list; a Settings built around it trusts nobody.
        networks = ()
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
    if not client_ca_path:
        # The ingress's SUCCESS says the chain ended at *its* CA. Without ours
        # to check against, a pod in the trusted range could forward any
        # self-signed certificate naming any sensor.
        return Presentation(
            note=(
                "a forwarded client certificate is believed only when OCTO_AGENT_MTLS_CLIENT_CA "
                "is set to check it against, and it is not"
            )
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
    if subject_dn is not None and not subject_matches(subject_dn, cert.subject):
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
