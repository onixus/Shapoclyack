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
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID


logger = logging.getLogger(__name__)

#: ``scope["state"]`` key the TLS listener's protocol fills (see module doc).
TLS_PEER_CERT_STATE_KEY = "shapoclyack_tls_peer_cert_der"
#: ``scope["state"]`` key for the socket's own peer address, which the same
#: protocol fills on every connection, TLS or not (:func:`socket_peer`).
SOCKET_PEER_STATE_KEY = "shapoclyack_socket_peer"

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
    certificate_pem: str = ""


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
        certificate_pem=cert.public_bytes(Encoding.PEM).decode("ascii"),
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


#: How many intermediates :func:`issued_by_bundle` follows from a leaf to the
#: bundle. Sensor PKIs are a root and one issuing CA; the bound is so that a
#: cycle in an operator's bundle cannot loop.
MAX_CHAIN_INTERMEDIATES = 4


def _directly_issued(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    if ca.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(ca)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _is_ca(cert: x509.Certificate, now: datetime) -> bool:
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return (
        constraints.ca
        and _naive_utc(cert.not_valid_before_utc) <= now < _naive_utc(cert.not_valid_after_utc)
    )


def issued_by_bundle(
    cert: x509.Certificate,
    bundle: Sequence[x509.Certificate],
    intermediates: Sequence[x509.Certificate] = (),
    *,
    now: datetime | None = None,
) -> bool:
    """Whether ``cert`` chains to a certificate of ``bundle``.

    Directly, or through ``intermediates`` — CA certificates the API knows
    for itself, which is ``OCTO_AGENT_MTLS_ISSUER_CERT``: a forwarded
    certificate is the leaf alone (ingress-nginx passes nothing else), so with
    a root as the client CA and an intermediate as the issuer the link between
    the two has to come from here. An intermediate counts only while it is a
    CA and valid, and only up to :data:`MAX_CHAIN_INTERMEDIATES` of them.
    A leaf from another intermediate under the same root is not believed:
    put that intermediate in the bundle.
    """
    current = now or _now()
    if any(_directly_issued(cert, ca) for ca in bundle):
        return True
    candidates = [ca for ca in intermediates if _is_ca(ca, current)]
    child = cert
    for _ in range(MAX_CHAIN_INTERMEDIATES):
        parent = next((ca for ca in candidates if _directly_issued(child, ca)), None)
        if parent is None:
            return False
        if any(_directly_issued(parent, ca) for ca in bundle):
            return True
        candidates.remove(parent)
        child = parent
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

#: Attribute names to OIDs: every name OpenSSL 3.x prints for an attribute of
#: these arcs under ``-nameopt RFC2253`` (``openssl list -objects``; captured
#: from 3.6 and checked against 4.0, and pinned by
#: ``tests/test_agent_mtls.py``), spelt as OpenSSL spells them. Matched by
#: case first: OpenSSL's ``UID`` is userId and its ``uid`` uniqueIdentifier,
#: and reading one as the other is a different name taken for the same one.
#: A name that is not here — and not a dotted OID — makes the subject
#: unreadable, which is a refusal, never a match.
_DN_ATTRIBUTE_OIDS = {
    # X.520 (2.5.4)
    "CN": "2.5.4.3",
    "SN": "2.5.4.4",
    "serialNumber": "2.5.4.5",
    "C": "2.5.4.6",
    "L": "2.5.4.7",
    "ST": "2.5.4.8",
    "street": "2.5.4.9",
    "O": "2.5.4.10",
    "OU": "2.5.4.11",
    "title": "2.5.4.12",
    "description": "2.5.4.13",
    "searchGuide": "2.5.4.14",
    "businessCategory": "2.5.4.15",
    "postalAddress": "2.5.4.16",
    "postalCode": "2.5.4.17",
    "postOfficeBox": "2.5.4.18",
    "physicalDeliveryOfficeName": "2.5.4.19",
    "telephoneNumber": "2.5.4.20",
    "telexNumber": "2.5.4.21",
    "teletexTerminalIdentifier": "2.5.4.22",
    "facsimileTelephoneNumber": "2.5.4.23",
    "x121Address": "2.5.4.24",
    "internationaliSDNNumber": "2.5.4.25",
    "registeredAddress": "2.5.4.26",
    "destinationIndicator": "2.5.4.27",
    "preferredDeliveryMethod": "2.5.4.28",
    "presentationAddress": "2.5.4.29",
    "supportedApplicationContext": "2.5.4.30",
    "member": "2.5.4.31",
    "owner": "2.5.4.32",
    "roleOccupant": "2.5.4.33",
    "seeAlso": "2.5.4.34",
    "userPassword": "2.5.4.35",
    "userCertificate": "2.5.4.36",
    "cACertificate": "2.5.4.37",
    "authorityRevocationList": "2.5.4.38",
    "certificateRevocationList": "2.5.4.39",
    "crossCertificatePair": "2.5.4.40",
    "name": "2.5.4.41",
    "GN": "2.5.4.42",
    "initials": "2.5.4.43",
    "generationQualifier": "2.5.4.44",
    "x500UniqueIdentifier": "2.5.4.45",
    "dnQualifier": "2.5.4.46",
    "enhancedSearchGuide": "2.5.4.47",
    "protocolInformation": "2.5.4.48",
    "distinguishedName": "2.5.4.49",
    "uniqueMember": "2.5.4.50",
    "houseIdentifier": "2.5.4.51",
    "supportedAlgorithms": "2.5.4.52",
    "deltaRevocationList": "2.5.4.53",
    "dmdName": "2.5.4.54",
    "pseudonym": "2.5.4.65",
    "role": "2.5.4.72",
    "organizationIdentifier": "2.5.4.97",
    "c3": "2.5.4.98",
    "n3": "2.5.4.99",
    "dnsName": "2.5.4.100",
    # PKCS #9 (1.2.840.113549.1.9)
    "emailAddress": "1.2.840.113549.1.9.1",
    "unstructuredName": "1.2.840.113549.1.9.2",
    "contentType": "1.2.840.113549.1.9.3",
    "messageDigest": "1.2.840.113549.1.9.4",
    "signingTime": "1.2.840.113549.1.9.5",
    "countersignature": "1.2.840.113549.1.9.6",
    "challengePassword": "1.2.840.113549.1.9.7",
    "unstructuredAddress": "1.2.840.113549.1.9.8",
    "extendedCertificateAttributes": "1.2.840.113549.1.9.9",
    "extReq": "1.2.840.113549.1.9.14",
    "SMIME-CAPS": "1.2.840.113549.1.9.15",
    "SMIME": "1.2.840.113549.1.9.16",
    "friendlyName": "1.2.840.113549.1.9.20",
    "localKeyID": "1.2.840.113549.1.9.21",
    "id-aa-CMSAlgorithmProtection": "1.2.840.113549.1.9.52",
    # RFC 4519 / pilot attributes (0.9.2342.19200300.100.1)
    "UID": "0.9.2342.19200300.100.1.1",
    "textEncodedORAddress": "0.9.2342.19200300.100.1.2",
    "mail": "0.9.2342.19200300.100.1.3",
    "info": "0.9.2342.19200300.100.1.4",
    "favouriteDrink": "0.9.2342.19200300.100.1.5",
    "roomNumber": "0.9.2342.19200300.100.1.6",
    "photo": "0.9.2342.19200300.100.1.7",
    "userClass": "0.9.2342.19200300.100.1.8",
    "host": "0.9.2342.19200300.100.1.9",
    "manager": "0.9.2342.19200300.100.1.10",
    "documentIdentifier": "0.9.2342.19200300.100.1.11",
    "documentTitle": "0.9.2342.19200300.100.1.12",
    "documentVersion": "0.9.2342.19200300.100.1.13",
    "documentAuthor": "0.9.2342.19200300.100.1.14",
    "documentLocation": "0.9.2342.19200300.100.1.15",
    "homeTelephoneNumber": "0.9.2342.19200300.100.1.20",
    "secretary": "0.9.2342.19200300.100.1.21",
    "otherMailbox": "0.9.2342.19200300.100.1.22",
    "lastModifiedTime": "0.9.2342.19200300.100.1.23",
    "lastModifiedBy": "0.9.2342.19200300.100.1.24",
    "DC": "0.9.2342.19200300.100.1.25",
    "aRecord": "0.9.2342.19200300.100.1.26",
    "pilotAttributeType27": "0.9.2342.19200300.100.1.27",
    "mXRecord": "0.9.2342.19200300.100.1.28",
    "nSRecord": "0.9.2342.19200300.100.1.29",
    "sOARecord": "0.9.2342.19200300.100.1.30",
    "cNAMERecord": "0.9.2342.19200300.100.1.31",
    "associatedDomain": "0.9.2342.19200300.100.1.37",
    "associatedName": "0.9.2342.19200300.100.1.38",
    "homePostalAddress": "0.9.2342.19200300.100.1.39",
    "personalTitle": "0.9.2342.19200300.100.1.40",
    "mobileTelephoneNumber": "0.9.2342.19200300.100.1.41",
    "pagerTelephoneNumber": "0.9.2342.19200300.100.1.42",
    "friendlyCountryName": "0.9.2342.19200300.100.1.43",
    "uid": "0.9.2342.19200300.100.1.44",
    "organizationalStatus": "0.9.2342.19200300.100.1.45",
    "janetMailbox": "0.9.2342.19200300.100.1.46",
    "mailPreferenceOption": "0.9.2342.19200300.100.1.47",
    "buildingName": "0.9.2342.19200300.100.1.48",
    "dSAQuality": "0.9.2342.19200300.100.1.49",
    "singleLevelQuality": "0.9.2342.19200300.100.1.50",
    "subtreeMinimumQuality": "0.9.2342.19200300.100.1.51",
    "subtreeMaximumQuality": "0.9.2342.19200300.100.1.52",
    "personalSignature": "0.9.2342.19200300.100.1.53",
    "dITRedirect": "0.9.2342.19200300.100.1.54",
    "audio": "0.9.2342.19200300.100.1.55",
    "documentPublisher": "0.9.2342.19200300.100.1.56",
    # EV jurisdiction (1.3.6.1.4.1.311.60.2.1)
    "jurisdictionL": "1.3.6.1.4.1.311.60.2.1.1",
    "jurisdictionST": "1.3.6.1.4.1.311.60.2.1.2",
    "jurisdictionC": "1.3.6.1.4.1.311.60.2.1.3",
    # Russian qualified-certificate attributes (1.2.643)
    "INN": "1.2.643.3.131.1.1",
    "OGRN": "1.2.643.100.1",
    "SNILS": "1.2.643.100.3",
    "OGRNIP": "1.2.643.100.5",
    "subjectSignTool": "1.2.643.100.111",
    "issuerSignTool": "1.2.643.100.112",
    "classSignTool": "1.2.643.100.113",
    # Spellings OpenSSL does not print but others do: cryptography's
    # ``rfc4514_string`` writes STREET, and INNLE is a qualified-certificate
    # attribute OpenSSL 3.6 dumps by OID.
    "STREET": "2.5.4.9",
    "INNLE": "1.2.643.100.4",
}


def _folded_names(names: dict[str, str]) -> dict[str, str]:
    """The case-insensitive fallback (RFC 4514 names are), for the names whose
    lower case is one name only — ``uid`` is two, so neither is in it."""
    folded: dict[str, set[str]] = {}
    for name, oid in names.items():
        folded.setdefault(name.lower(), set()).add(oid)
    return {name: next(iter(oids)) for name, oids in folded.items() if len(oids) == 1}


_DN_ATTRIBUTE_OIDS_FOLDED = _folded_names(_DN_ATTRIBUTE_OIDS)
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
    return _DN_ATTRIBUTE_OIDS.get(cleaned) or _DN_ATTRIBUTE_OIDS_FOLDED.get(cleaned.lower())


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
    intermediates_path: str = "",
    now: datetime | None = None,
) -> Presentation:
    """The verified client certificate behind one request, if there is one.

    ``headers`` is anything with a case-insensitive ``get`` (Starlette's
    ``Headers``). The order is the direct TLS peer first — the socket's own
    handshake is the stronger statement — then the trusted proxy's headers.
    ``peer`` is the socket's address (:func:`socket_peer`), never one a
    proxy header named. ``intermediates_path`` is the issuer certificate a
    forwarded leaf may chain through (:func:`issued_by_bundle`).
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
        intermediates = (
            load_ca_bundle(intermediates_path)
            if intermediates_path and intermediates_path != client_ca_path
            else ()
        )
    except (OSError, ValueError):
        logger.exception(
            "The client CA bundle %s (or the issuer certificate %s) is unreadable",
            client_ca_path,
            intermediates_path,
        )
        return Presentation(note="the API cannot read its client CA bundle")
    if not issued_by_bundle(cert, bundle, intermediates, now=current):
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


def socket_peer(scope: Any) -> str | None:
    """The address of the socket a request came in on.

    Not ``scope["client"]``: uvicorn's proxy-headers middleware (on by
    default) rewrites that from ``X-Forwarded-For`` for any peer in
    ``FORWARDED_ALLOW_IPS``, and set to ``*`` — the usual advice for uvicorn
    behind an ingress — it lets any client name the ingress's address and have
    its ``ssl-client-*`` headers believed. The protocol below records the
    socket's address before any middleware runs; ``scope["client"]`` is the
    answer only where that protocol is not in use (the test client, an
    embedding server), and there nothing rewrites it.
    """
    state = scope.get("state") or {}
    if SOCKET_PEER_STATE_KEY in state:
        return state[SOCKET_PEER_STATE_KEY] or None
    client = scope.get("client")
    return client[0] if client else None


def peer_certificate_protocol(base: type) -> type:
    """``base`` (a uvicorn HTTP protocol) that exposes the socket's peer.

    Its address always (:func:`socket_peer`), and the TLS peer certificate
    when there is one. uvicorn copies its ``app_state`` into every request's
    ``scope["state"]``; replacing it per connection with a copy that carries
    both is the one hook that needs no change to how uvicorn builds a scope.
    The asyncio SSL transport calls ``connection_made`` after the handshake,
    so the certificate is final by then.
    """

    class PeerCertificateProtocol(base):  # type: ignore[valid-type, misc]
        def connection_made(self, transport):  # type: ignore[no-untyped-def]
            super().connection_made(transport)
            peername = transport.get_extra_info("peername")
            peer = peername[0] if isinstance(peername, (tuple, list)) and peername else ""
            state = {**self.app_state, SOCKET_PEER_STATE_KEY: str(peer)}
            ssl_object = transport.get_extra_info("ssl_object")
            der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            if der:
                state[TLS_PEER_CERT_STATE_KEY] = der
            self.app_state = state

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
