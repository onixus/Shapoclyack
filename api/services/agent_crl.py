"""Issuer-scoped TLS revocation lists, exported only by a platform operator.

TLS has no tenant context. Never turn an arbitrary tenant's fingerprint
tombstone or pin of somebody else's public certificate into a global TLS
ban. Automatic entries must name the owning row's SPIFFE identity. An
operator may supply a PEM explicitly to approve a legacy/unbound entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Iterable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448
from sqlalchemy import select

from api.core import client_cert
from api.db import models, tenant_scope
from api.db.engine import get_session
from api.settings import Settings


@dataclass(frozen=True)
class ExportedCRL:
    pem: bytes
    entries: int
    api_only: int
    other_issuer: int
    next_update: datetime


def export(
    settings: Settings,
    *,
    certificates: Iterable[x509.Certificate] = (),
    lifetime_seconds: int = 3600,
    now: datetime | None = None,
) -> ExportedCRL:
    """Sign one CA's CRL from committed revocations across all tenants.

    ``certificates`` is explicit operator approval, not untrusted request input:
    it supplies historical PEMs and permits unbound/tombstone records matching
    those exact fingerprints. Other CA's serials are never signed by this CA.
    An unresolved live legacy row fails export instead of guessing an issuer.
    """
    now = (now or datetime.now(UTC)).astimezone(UTC)
    if not 60 <= lifetime_seconds <= 86400:
        raise ValueError("CRL lifetime must be between 60 and 86400 seconds")
    issuer = client_cert.load_pem_certificate(
        open_file(settings.agent_mtls_issuer_cert)
    )
    key = serialization.load_pem_private_key(
        open_file(settings.agent_mtls_issuer_key), password=None
    )
    if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("CRL issuer must be a CA")
    try:
        usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("CRL issuer must declare cRLSign key usage") from exc
    if not usage.crl_sign:
        raise ValueError("CRL issuer must allow cRLSign")
    encoding = serialization.Encoding.DER
    form = serialization.PublicFormat.SubjectPublicKeyInfo
    if issuer.public_key().public_bytes(
        encoding, form
    ) != key.public_key().public_bytes(encoding, form):
        raise ValueError("CRL issuer certificate and private key do not match")
    if not issuer.not_valid_before_utc <= now < issuer.not_valid_after_utc:
        raise ValueError("CRL issuer is not currently valid")
    next_update = min(
        now + timedelta(seconds=lifetime_seconds), issuer.not_valid_after_utc
    )
    approved = {client_cert.fingerprint(cert): cert for cert in certificates}
    entries: dict[int, datetime] = {}
    api_only = other_issuer = 0
    missing: list[str] = []
    # This helper has no HTTP route: its caller already has the database and
    # CA signing key. Declare the global scope explicitly for RLS.
    with (
        tenant_scope.system("platform CRL exporter"),
        get_session(settings.postgres_url) as session,
    ):
        rows = session.execute(
            select(models.AgentClientCert).where(
                models.AgentClientCert.revoked_at.is_not(None)
            )
        ).scalars()
        for row in rows:
            explicit = row.fingerprint_sha256 in approved
            cert = approved.get(row.fingerprint_sha256)
            if cert is None and row.certificate_pem:
                cert = client_cert.load_pem_certificate(row.certificate_pem)
            if cert is None:
                if row.source == "tombstone":
                    api_only += 1
                elif row.not_after is None or row.not_after.replace(tzinfo=UTC) > now:
                    missing.append(row.fingerprint_sha256)
                continue
            if client_cert.fingerprint(cert) != row.fingerprint_sha256:
                raise ValueError("Stored certificate does not match its fingerprint")
            if cert.not_valid_after_utc <= now:
                continue
            try:
                cert.verify_directly_issued_by(issuer)
            except (InvalidSignature, ValueError, TypeError):
                other_issuer += 1
                continue
            described = client_cert.describe(cert, source="crl")
            owns_identity = any(
                identity.trust_domain == settings.agent_mtls_trust_domain
                and identity.tenant_id == row.tenant_id
                and identity.agent_id == row.agent_id
                for identity in described.identities
            )
            if not explicit and (row.source == "tombstone" or not owns_identity):
                api_only += 1
                continue
            revoked = min(row.revoked_at.replace(tzinfo=UTC), now)
            previous = entries.get(cert.serial_number, revoked)
            entries[cert.serial_number] = min(previous, revoked)
    if missing:
        raise ValueError(
            "Live revoked legacy certificates need --certificate PEM (issuer cannot be guessed): "
            + ", ".join(sorted(missing))
        )
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(now - timedelta(seconds=30))
        .next_update(next_update)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()),
            False,
        )
        .add_extension(x509.CRLNumber(int(now.timestamp() * 1_000_000)), False)
    )
    for serial, revoked in sorted(entries.items()):
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked)
            .build()
        )
    algorithm = (
        None
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
        else hashes.SHA256()
    )
    crl = builder.sign(key, algorithm)
    return ExportedCRL(
        crl.public_bytes(serialization.Encoding.PEM),
        len(entries),
        api_only,
        other_issuer,
        next_update,
    )


def open_file(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()
