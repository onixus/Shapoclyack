"""Client certificates of sensors and endpoint agents: binding, issuance, revocation (#309).

A bearer token says which sensor is calling; a client certificate is what makes
a stolen token useless on another host. This module decides the second
question — *is the certificate this request presented the token's agent's own*
— and keeps the record that question is answered from. What was presented, and
whether it can be believed at all, is ``api/core/client_cert.py``.

**Binding.** A certificate belongs to exactly one ``(tenant_id, agent_id)``:

1. the one its SPIFFE URI names — ``spiffe://<OCTO_AGENT_MTLS_TRUST_DOMAIN>/
   tenant/<tenant>/sensor/<agent_id>`` (``/agent/`` for an endpoint agent), the
   form this API signs and the one a cert-manager ``Certificate`` is told to
   carry; or, when it names none,
2. the agent an operator pinned its fingerprint to.

Any other agent's token with it is a mismatch, refused and audited — sensor A's
certificate does not make sensor B's token good, nor the reverse. A certificate
whose fingerprint is revoked in the token's tenant is refused whatever it
names, on the very next request: there is no cache in between.

**Modes** (``OCTO_AGENT_MTLS_MODE``): ``off`` never looks; ``optional`` binds
what is presented and lets a request without a certificate through, which is
how a fleet migrates; ``required`` refuses a request without one. One
exception under ``required``, and only on ``POST /api/agent/certificate``: an
agent with no live certificate on record may enrol without one — otherwise no
sensor could ever get its first. That makes the floor of ``required`` "the
provisioning key, for an agent that holds no certificate yet", which is what
it was before; everything past enrolment needs the key *and* the certificate.

**Revocation locks.** That exception would undo a revocation: once the
operator revokes the stolen host's certificate nothing live is left, and the
host's token enrols it a new one on its next poll. So an operator's
revocation of a certificate the agent held also locks the agent
(``agent_cert_enrolments``): enrolment without a certificate is refused, and
so is any request without one under ``optional`` too, until an operator
resets the enrolment — a separate, audited act (:func:`reset_enrolment`). A
certificate that merely ran out locks nothing: a sensor that was offline past
its expiry enrols again by itself, as operations.md promises. Neither does a
tombstone, nor revoking what is already revoked. The lock is keyed by
``(tenant, agent id)`` and survives deleting the agent.

Issuance, revocation and reset of one agent are serialised on that row
(``SELECT … FOR UPDATE``), and :func:`issue` re-checks under it what
:func:`bind` checked without it: otherwise a renewal in flight outlives a
"revoke all", and two enrolments by token after a reset both succeed.

**Refusals are 403, never 401,** with the reason in the
:data:`REFUSAL_HEADER` header: a sensor answers 401 by re-exchanging its
provisioning key, which succeeds and is refused again, at the poll rate.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import and_, func, or_, select, update

from api.core import client_cert
from api.core.client_cert import Presentation, PresentedCert
from api.db import models
from api.db.engine import get_session, insert_if_absent, insert_or_skip
from api.services import audit as audit_service
from api.settings import Settings

_log = logging.getLogger(__name__)

MODE_OFF = "off"
MODE_OPTIONAL = "optional"
MODE_REQUIRED = "required"

SOURCE_CSR = "csr"
SOURCE_PINNED = "pinned"
SOURCE_OBSERVED = "observed"
SOURCE_TOMBSTONE = "tombstone"

#: Response header naming why a certificate was refused, for the sensor to act
#: on (renew, re-enrol, or stop) — the detail string is prose for an operator.
REFUSAL_HEADER = "X-Client-Cert-Error"
REASON_MISSING = "missing"
REASON_REVOKED = "revoked"
REASON_MISMATCH = "mismatch"
REASON_UNBOUND = "unbound"
REASON_EXPIRED = "expired"
REASON_NO_IDENTITY = "no-identity"
REASON_LOCKED = "enrolment-locked"

#: A sensor refused for presenting nothing while it holds a live certificate
#: on record — somebody else enrolled first, or it lost its key — is written
#: to the audit trail at most once per agent per this interval, across
#: replicas; it polls every few seconds and the trail is not a poll log.
CONFLICT_AUDIT_INTERVAL = timedelta(hours=1)
#: How long the fleet view keeps counting such an agent after the last row.
CONFLICT_WINDOW = timedelta(days=1)

#: Certificates this API signs for one agent that stay live after a new one is
#: issued: the new one and the one before it, which is the overlap a rotation
#: needs. Older ones are revoked as ``superseded`` at issue time, so a token
#: that can call the enrolment route cannot pile certificates up.
LIVE_ISSUED_PER_AGENT = 2

_MIN_RSA_BITS = 2048
_EC_CURVES = (ec.SECP256R1, ec.SECP384R1)
#: Backdated against clock skew between the API and a sensor: a certificate
#: "not valid yet" for the first minute is a sensor refused for no reason.
_BACKDATE = timedelta(minutes=5)


class ClientCertRefused(PermissionError):
    """The request's certificate (or its absence) does not authenticate this agent."""

    def __init__(self, reason: str, message: str, *, holds_live_cert: bool = False) -> None:
        super().__init__(message)
        self.reason = reason
        #: Refused for presenting nothing while a live certificate of this
        #: agent is on record (see :data:`CONFLICT_AUDIT_INTERVAL`).
        self.holds_live_cert = holds_live_cert


@dataclass(frozen=True)
class IssuedCert:
    certificate_pem: str
    ca_certificate_pem: str
    fingerprint_sha256: str
    serial_hex: str
    spiffe_id: str
    not_before: datetime
    not_after: datetime
    renew_after: datetime


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def iso(value: datetime | None) -> str | None:
    return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if value else None


def kind_segment(agent_kind: str) -> str:
    """The SPIFFE path segment for an ``agents.agent_kind``."""
    return "agent" if agent_kind == "endpoint" else "sensor"


def _is_live(row: models.AgentClientCert, now: datetime) -> bool:
    return (
        row.revoked_at is None
        and row.source != SOURCE_TOMBSTONE
        and (row.not_after is None or row.not_after > now)
    )


def _has_live_cert(session: Any, *, tenant_id: str, agent_id: str, now: datetime) -> bool:
    rows = session.execute(
        select(models.AgentClientCert).where(
            models.AgentClientCert.tenant_id == tenant_id,
            models.AgentClientCert.agent_id == agent_id,
            models.AgentClientCert.revoked_at.is_(None),
        )
    ).scalars().all()
    return any(_is_live(row, now) for row in rows)


def has_live_cert(settings: Settings, *, tenant_id: str, agent_id: str) -> bool:
    """Whether the agent holds an unrevoked, unexpired certificate on record."""
    with get_session(settings.postgres_url) as session:
        return _has_live_cert(session, tenant_id=tenant_id, agent_id=agent_id, now=_now())


def _is_locked(session: Any, *, tenant_id: str, agent_id: str) -> bool:
    locked_at = session.execute(
        select(models.AgentCertEnrolment.locked_at).where(
            models.AgentCertEnrolment.tenant_id == tenant_id,
            models.AgentCertEnrolment.agent_id == agent_id,
        )
    ).scalar_one_or_none()
    return locked_at is not None


def is_locked(settings: Settings, *, tenant_id: str, agent_id: str) -> bool:
    """Whether an operator's revocation keeps this agent from working without a certificate."""
    with get_session(settings.postgres_url) as session:
        return _is_locked(session, tenant_id=tenant_id, agent_id=agent_id)


def _enrolment_row(session: Any, *, tenant_id: str, agent_id: str) -> models.AgentCertEnrolment:
    """The agent's ``agent_cert_enrolments`` row, created blank if absent, locked for update."""
    insert_or_skip(
        session,
        models.AgentCertEnrolment(tenant_id=tenant_id, agent_id=agent_id),
        conflict=["tenant_id", "agent_id"],
    )
    return session.execute(
        select(models.AgentCertEnrolment)
        .where(
            models.AgentCertEnrolment.tenant_id == tenant_id,
            models.AgentCertEnrolment.agent_id == agent_id,
        )
        .with_for_update()
    ).scalar_one()


def _refuse_locked(agent_id: str) -> ClientCertRefused:
    return ClientCertRefused(
        REASON_LOCKED,
        f"A client certificate of agent {agent_id} was revoked by an operator, which also "
        "stops it enrolling or calling without a certificate. An operator must reset its "
        "enrolment (POST /api/agents/{id}/certificates/reset-enrolment) before it can "
        "enrol again (docs/operations.md § Sensor client certificates).",
    )


def _refuse_missing(presentation: Presentation, *, holds_live_cert: bool = False) -> ClientCertRefused:
    message = (
        "This installation requires sensors and endpoint agents to present a "
        "client certificate (OCTO_AGENT_MTLS_MODE=required), and this request "
        "presented none"
    )
    if presentation.note:
        message += f": {presentation.note}"
    if holds_live_cert:
        return ClientCertRefused(
            REASON_MISSING,
            message + ". This agent already holds a live certificate on record, so a new "
            "one is issued only to a request presenting it; if this host does not have "
            "it, an operator must revoke it and reset the enrolment "
            "(docs/operations.md § Sensor client certificates).",
            holds_live_cert=True,
        )
    return ClientCertRefused(
        REASON_MISSING,
        message + ". Enrol with POST /api/agent/certificate or mount the "
        "cert-manager certificate (docs/operations.md § Sensor client certificates).",
    )


def bind(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str | None,
    presentation: Presentation,
    mode: str | None = None,
    bootstrap: bool = False,
) -> PresentedCert | None:
    """Check the presented certificate against the token's agent; raise if it is not its own.

    ``mode`` defaults to ``OCTO_AGENT_MTLS_MODE``; the enrolment route passes
    ``required`` with ``bootstrap`` (see the module doc). Returns the bound
    certificate, or ``None`` when none was presented and none was needed.
    Raises :class:`ClientCertRefused`.
    """
    effective = mode or settings.agent_mtls_mode
    if effective == MODE_OFF:
        return None
    cert = presentation.cert
    if not agent_id:
        # A legacy shared token (or a token without an agent id) names nobody
        # a certificate could be bound to.
        if effective == MODE_REQUIRED:
            raise ClientCertRefused(
                REASON_NO_IDENTITY,
                "A client certificate can only be bound to a per-agent token; the "
                "legacy shared OCTO_AGENT_TOKEN is refused under "
                "OCTO_AGENT_MTLS_MODE=required. Re-install the agent with a "
                "provisioning key.",
            )
        return None
    if cert is None:
        with get_session(settings.postgres_url) as session:
            if _is_locked(session, tenant_id=tenant_id, agent_id=agent_id):
                raise _refuse_locked(agent_id)
            if effective == MODE_OPTIONAL:
                return None
            live = _has_live_cert(session, tenant_id=tenant_id, agent_id=agent_id, now=_now())
        if bootstrap and not live:
            return None
        raise _refuse_missing(presentation, holds_live_cert=live)

    now = _now()
    if cert.not_after <= now:
        raise ClientCertRefused(REASON_EXPIRED, "The client certificate has expired")
    claimed = [
        identity
        for identity in cert.identities
        if identity.trust_domain == settings.agent_mtls_trust_domain
    ]
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.AgentClientCert).where(
                models.AgentClientCert.tenant_id == tenant_id,
                models.AgentClientCert.fingerprint_sha256 == cert.fingerprint_sha256,
            )
        ).scalar_one_or_none()
        if row is not None and row.revoked_at is not None:
            raise ClientCertRefused(
                REASON_REVOKED,
                f"Client certificate {cert.fingerprint_sha256[:16]}… was revoked"
                + (f": {row.revoked_reason}" if row.revoked_reason else ""),
            )
        if claimed:
            if any(i.tenant_id != tenant_id or i.agent_id != agent_id for i in claimed):
                raise ClientCertRefused(
                    REASON_MISMATCH,
                    "The client certificate names a different sensor than the token; "
                    "a certificate authenticates only the agent it was issued to",
                )
            if row is not None and row.agent_id != agent_id:
                raise ClientCertRefused(
                    REASON_MISMATCH,
                    "The client certificate is pinned to a different agent than the token's",
                )
            if row is None:
                # First sight of a certificate cert-manager (or any CA we trust)
                # issued for this agent: recorded so it is listed, counted for
                # expiry and revocable by serial. Losing the race to another
                # replica's identical row is the same outcome.
                insert_if_absent(
                    session,
                    models.AgentClientCert(
                        cert_id=uuid.uuid4().hex,
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        fingerprint_sha256=cert.fingerprint_sha256,
                        serial_hex=cert.serial_hex,
                        subject=cert.subject,
                        source=SOURCE_OBSERVED,
                        not_before=cert.not_before,
                        not_after=cert.not_after,
                        created_at=now,
                        created_by=agent_id,
                    ),
                    key=cert.fingerprint_sha256,
                )
            return cert
        if row is None:
            raise ClientCertRefused(
                REASON_UNBOUND,
                "The client certificate is not bound to any agent: it carries no "
                f"spiffe://{settings.agent_mtls_trust_domain}/… identity and its "
                "fingerprint is not pinned in this tenant",
            )
        if row.agent_id != agent_id:
            raise ClientCertRefused(
                REASON_MISMATCH,
                "The client certificate is pinned to a different agent than the token's",
            )
        return cert


def _claim_conflict_row(settings: Settings, *, tenant_id: str, agent_id: str) -> bool:
    """Stamp ``conflict_at``; True when no replica has written the row this interval."""
    now = _now()
    with get_session(settings.postgres_url) as session:
        _enrolment_row(session, tenant_id=tenant_id, agent_id=agent_id)
        claimed = session.execute(
            update(models.AgentCertEnrolment)
            .where(
                models.AgentCertEnrolment.tenant_id == tenant_id,
                models.AgentCertEnrolment.agent_id == agent_id,
                or_(
                    models.AgentCertEnrolment.conflict_at.is_(None),
                    models.AgentCertEnrolment.conflict_at <= now - CONFLICT_AUDIT_INTERVAL,
                ),
            )
            .values(conflict_at=now)
        )
        return bool(claimed.rowcount)


def record_refusal(
    settings: Settings,
    context: audit_service.AuditContext,
    *,
    tenant_id: str,
    agent_id: str | None,
    refusal: ClientCertRefused,
    presentation: Presentation,
) -> None:
    """Write a refused certificate to the administrative trail, best-effort.

    A presented certificate that is not the token's agent's own is somebody
    holding one credential of one sensor and another of a second — the event
    this whole feature exists to notice. Best-effort like
    ``scan_policy.record_block``: the request is already refused, and losing
    the row must not turn a 403 into a 500.

    A request that presented *nothing* under ``required`` is not recorded: a
    fleet that has not enrolled yet polls every few seconds, and a row per poll
    would bury the trail; it is logged instead. Except when the agent holds a
    live certificate on record: then another host enrolled with its token
    first (or it lost its key), which is the one event that says the token is
    somewhere else — recorded once per :data:`CONFLICT_AUDIT_INTERVAL` and
    counted in the fleet view. A ``enrolment-locked`` refusal repeats what the
    revocation already recorded, so it is logged only.
    """
    if refusal.reason in (REASON_MISSING, REASON_LOCKED):
        _log.info(
            "Agent %s in tenant %s refused: no client certificate (%s; %s)",
            agent_id,
            tenant_id,
            refusal.reason,
            presentation.note or "none presented",
        )
        if not (refusal.holds_live_cert and agent_id):
            return
    cert = presentation.cert
    try:
        if refusal.holds_live_cert and agent_id and not _claim_conflict_row(
            settings, tenant_id=tenant_id, agent_id=agent_id
        ):
            return
        audit_service.record_standalone(
            context,
            action=audit_service.ACTION_AGENT_CERT_REFUSED,
            resource_type="agent",
            resource_id=agent_id or "",
            tenant_id=tenant_id,
            after={
                "reason": refusal.reason,
                "detail": str(refusal)[:500],
                "fingerprint_sha256": cert.fingerprint_sha256 if cert else "",
                "serial": cert.serial_hex if cert else "",
                "presented_identities": [i.uri for i in cert.identities] if cert else [],
                "via": cert.source if cert else "",
                "agent_holds_live_certificate": refusal.holds_live_cert,
            },
        )
    except Exception:  # noqa: BLE001 - see docstring
        _log.warning(
            "Could not record the refused client certificate of agent %s",
            agent_id,
            exc_info=True,
        )


# --- issuance -----------------------------------------------------------------


def issuance_enabled(settings: Settings) -> bool:
    return bool(settings.agent_mtls_issuer_cert and settings.agent_mtls_issuer_key)


def _load_issuer(settings: Settings) -> tuple[x509.Certificate, Any]:
    with open(settings.agent_mtls_issuer_cert, "rb") as handle:
        issuer_cert = client_cert.load_pem_certificate(handle.read())
    with open(settings.agent_mtls_issuer_key, "rb") as handle:
        issuer_key = serialization.load_pem_private_key(handle.read(), password=None)
    return issuer_cert, issuer_key


def _check_public_key(public_key: Any) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < _MIN_RSA_BITS:
            raise ValueError(f"RSA keys must be at least {_MIN_RSA_BITS} bits")
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, _EC_CURVES):
            raise ValueError("EC keys must be on P-256 or P-384")
        return
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return
    raise ValueError("the CSR's key must be RSA (2048+), EC (P-256/P-384) or Ed25519")


def issue(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    agent_kind: str,
    csr_pem: str,
    presented: PresentedCert | None = None,
    audit: audit_service.AuditContext | None = None,
) -> IssuedCert:
    """Sign ``csr_pem`` for this agent with ``OCTO_AGENT_MTLS_ISSUER_*``.

    Only the CSR's public key is used. Subject and SANs are the server's: the
    identity is the token's, whatever the CSR asks for — a CSR is a request,
    and a sensor that could name its own SPIFFE URI would be choosing whose
    certificate it gets. ``LookupError`` when issuance is not configured,
    ``ValueError`` for a CSR that is not usable.

    ``presented`` is the certificate :func:`bind` accepted for this request,
    ``None`` for a first enrolment by token alone. What ``bind`` decided is
    decided again here, under the agent's ``agent_cert_enrolments`` row
    locked for update — the lock :func:`revoke` and :func:`reset_enrolment`
    take too. Without it a renewal that passed ``bind`` just before an
    operator's "revoke all" committed would insert a live certificate just
    after it, and two enrolments by token racing after a reset would both be
    issued one. :class:`ClientCertRefused` when the answer changed.
    """
    if not issuance_enabled(settings):
        raise LookupError(
            "Certificate issuance is not configured on this installation "
            "(OCTO_AGENT_MTLS_ISSUER_CERT / OCTO_AGENT_MTLS_ISSUER_KEY)"
        )
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii", errors="replace"))
    except ValueError as exc:
        raise ValueError("csr is not a PEM certificate signing request") from exc
    if not csr.is_signature_valid:
        raise ValueError("the CSR's signature does not verify")
    public_key = csr.public_key()
    _check_public_key(public_key)

    issuer_cert, issuer_key = _load_issuer(settings)
    now = _now()
    not_before = now - _BACKDATE
    not_after = now + timedelta(days=settings.agent_mtls_cert_days)
    spiffe_id = client_cert.spiffe_uri(
        settings.agent_mtls_trust_domain, tenant_id, kind_segment(agent_kind), agent_id
    )
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id[:64])]))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=UTC))
        .not_valid_after(not_after.replace(tzinfo=UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
            critical=False,
        )
    )
    algorithm = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = builder.sign(issuer_key, algorithm)
    described = client_cert.describe(cert, source=SOURCE_CSR)

    with get_session(settings.postgres_url) as session:
        enrolment = _enrolment_row(session, tenant_id=tenant_id, agent_id=agent_id)
        if presented is not None:
            held = session.execute(
                select(models.AgentClientCert).where(
                    models.AgentClientCert.tenant_id == tenant_id,
                    models.AgentClientCert.fingerprint_sha256 == presented.fingerprint_sha256,
                )
            ).scalar_one_or_none()
            if held is not None and held.revoked_at is not None:
                raise ClientCertRefused(
                    REASON_REVOKED,
                    f"Client certificate {presented.fingerprint_sha256[:16]}… was revoked"
                    + (f": {held.revoked_reason}" if held.revoked_reason else ""),
                )
        elif enrolment.locked_at is not None:
            raise _refuse_locked(agent_id)
        elif _has_live_cert(session, tenant_id=tenant_id, agent_id=agent_id, now=now):
            raise _refuse_missing(Presentation(), holds_live_cert=True)
        previous = session.execute(
            select(models.AgentClientCert)
            .where(
                models.AgentClientCert.tenant_id == tenant_id,
                models.AgentClientCert.agent_id == agent_id,
                models.AgentClientCert.source == SOURCE_CSR,
                models.AgentClientCert.revoked_at.is_(None),
            )
            .order_by(models.AgentClientCert.created_at.desc())
        ).scalars().all()
        superseded = [row for row in previous if _is_live(row, now)][LIVE_ISSUED_PER_AGENT - 1 :]
        for row in superseded:
            row.revoked_at = now
            row.revoked_by = agent_id
            row.revoked_reason = "superseded by a newer certificate"
        session.add(
            models.AgentClientCert(
                cert_id=uuid.uuid4().hex,
                tenant_id=tenant_id,
                agent_id=agent_id,
                fingerprint_sha256=described.fingerprint_sha256,
                serial_hex=described.serial_hex,
                subject=described.subject,
                source=SOURCE_CSR,
                not_before=described.not_before,
                not_after=described.not_after,
                created_at=now,
                created_by=agent_id,
            )
        )
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_AGENT_CERT_ISSUE,
            resource_type="agent",
            resource_id=agent_id,
            tenant_id=tenant_id,
            after={
                "fingerprint_sha256": described.fingerprint_sha256,
                "serial": described.serial_hex,
                "spiffe_id": spiffe_id,
                "not_after": iso(described.not_after),
                "superseded": [row.fingerprint_sha256 for row in superseded],
            },
        )

    lifetime = described.not_after - described.not_before
    return IssuedCert(
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        ca_certificate_pem=issuer_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        fingerprint_sha256=described.fingerprint_sha256,
        serial_hex=described.serial_hex,
        spiffe_id=spiffe_id,
        not_before=described.not_before,
        not_after=described.not_after,
        # Two thirds in, cert-manager's default: a sensor offline for a third
        # of the lifetime still comes back with time to renew.
        renew_after=described.not_before + lifetime * 2 / 3,
    )


# --- operator side ------------------------------------------------------------


def _to_dict(row: models.AgentClientCert, now: datetime, warn_days: int) -> dict[str, Any]:
    if row.revoked_at is not None:
        state = "revoked"
    elif row.not_after is not None and row.not_after <= now:
        state = "expired"
    elif row.not_after is not None and row.not_after <= now + timedelta(days=warn_days):
        state = "expiring"
    else:
        state = "valid"
    return {
        "cert_id": row.cert_id,
        "agent_id": row.agent_id,
        "tenant_id": row.tenant_id,
        "fingerprint_sha256": row.fingerprint_sha256,
        "serial": row.serial_hex,
        "subject": row.subject,
        "source": row.source,
        "state": state,
        "not_before": iso(row.not_before),
        "not_after": iso(row.not_after),
        "created_at": iso(row.created_at),
        "created_by": row.created_by,
        "revoked_at": iso(row.revoked_at),
        "revoked_by": row.revoked_by,
        "revoked_reason": row.revoked_reason,
    }


def list_certs(settings: Settings, *, tenant_id: str, agent_id: str) -> list[dict[str, Any]]:
    """Every certificate on record for one agent, newest first."""
    now = _now()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AgentClientCert)
            .where(
                models.AgentClientCert.tenant_id == tenant_id,
                models.AgentClientCert.agent_id == agent_id,
            )
            .order_by(models.AgentClientCert.created_at.desc())
        ).scalars().all()
        return [_to_dict(row, now, settings.agent_mtls_expiry_warn_days) for row in rows]


def pin(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    certificate_pem: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Bind a certificate to an agent by its fingerprint.

    For a certificate the platform did not sign and whose SAN does not name the
    sensor — an enterprise PKI that issues by host name. ``ValueError`` when
    the certificate names a *different* agent (the URI would win at binding
    anyway, so the pin would be a lie), when it is not from the configured
    client CA, or when its fingerprint is already revoked or pinned elsewhere.
    """
    try:
        cert = client_cert.load_pem_certificate(certificate_pem)
    except ValueError as exc:
        raise ValueError("certificate is not a PEM certificate") from exc
    described = client_cert.describe(cert, source="pinned")
    now = _now()
    if described.not_after <= now:
        raise ValueError("the certificate has already expired")
    for identity in described.identities:
        if identity.trust_domain == settings.agent_mtls_trust_domain and (
            identity.tenant_id != tenant_id or identity.agent_id != agent_id
        ):
            raise ValueError(f"the certificate names {identity.uri}, not this agent")
    ca_path = settings.agent_mtls_ca_path()
    if ca_path and not client_cert.issued_by_bundle(cert, client_cert.load_ca_bundle(ca_path)):
        raise ValueError("the certificate is not issued by OCTO_AGENT_MTLS_CLIENT_CA")
    with get_session(settings.postgres_url) as session:
        existing = session.execute(
            select(models.AgentClientCert).where(
                models.AgentClientCert.tenant_id == tenant_id,
                models.AgentClientCert.fingerprint_sha256 == described.fingerprint_sha256,
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.revoked_at is not None:
                raise ValueError("this certificate is revoked and cannot be pinned again")
            if existing.agent_id != agent_id:
                raise ValueError("this certificate is already bound to another agent")
            return _to_dict(existing, now, settings.agent_mtls_expiry_warn_days)
        row = models.AgentClientCert(
            cert_id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            agent_id=agent_id,
            fingerprint_sha256=described.fingerprint_sha256,
            serial_hex=described.serial_hex,
            subject=described.subject,
            source=SOURCE_PINNED,
            not_before=described.not_before,
            not_after=described.not_after,
            created_at=now,
            created_by=(audit.actor if audit else "system"),
        )
        session.add(row)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_AGENT_CERT_PIN,
            resource_type="agent",
            resource_id=agent_id,
            tenant_id=tenant_id,
            after={
                "fingerprint_sha256": described.fingerprint_sha256,
                "serial": described.serial_hex,
                "subject": described.subject,
                "not_after": iso(described.not_after),
            },
        )
        return _to_dict(row, now, settings.agent_mtls_expiry_warn_days)


def revoke(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    fingerprint: str | None = None,
    serial: str | None = None,
    revoke_all: bool = False,
    reason: str = "",
    audit: audit_service.AuditContext | None = None,
) -> list[dict[str, Any]]:
    """Revoke one agent's certificates; effective on the next request.

    Exactly one of ``fingerprint``, ``serial`` or ``revoke_all``. A fingerprint
    the platform has never seen is recorded as a ``tombstone``, so a
    certificate can be revoked before its first use; a serial has to match a
    certificate on record (``LookupError``), because a serial alone does not
    say which CA issued it.

    Revoking a certificate the agent held — one on record that was not
    revoked yet, expired or not — also locks the agent (see the module doc):
    no enrolment by token alone, and no request without a certificate, until
    :func:`reset_enrolment`. A tombstone, or a certificate already revoked
    (a superseded one, say), locks nothing: the agent never held the first,
    and the second changes nothing about what it holds — locking on either
    would shut a sensor working without a certificate under ``optional``
    out for a revocation that was not about it. ``revoke_all`` is what a
    stolen or copied host calls for; it is not a reset, and it stops the
    host's *identity*, not the host — a host that holds the provisioning key
    exchanges it for a token under another agent id (docs/operations.md
    § Sensor client certificates).

    The agent's enrolment row is locked for update first, as :func:`issue`
    does, so a renewal in flight either commits before this reads the
    agent's certificates (and is revoked with them) or sees the revocation.
    """
    chosen = [bool(fingerprint), bool(serial), bool(revoke_all)]
    if sum(chosen) != 1:
        raise ValueError("give exactly one of fingerprint, serial or all")
    now = _now()
    actor = audit.actor if audit else "system"
    cleaned_reason = (reason or "").strip()[:512] or None
    with get_session(settings.postgres_url) as session:
        enrolment = _enrolment_row(session, tenant_id=tenant_id, agent_id=agent_id)
        base = select(models.AgentClientCert).where(
            models.AgentClientCert.tenant_id == tenant_id,
        )
        rows: list[models.AgentClientCert]
        if fingerprint:
            digest = client_cert.normalise_fingerprint(fingerprint)
            row = session.execute(
                base.where(models.AgentClientCert.fingerprint_sha256 == digest)
            ).scalar_one_or_none()
            if row is not None and row.agent_id != agent_id:
                # Same answer as "no such agent": which agent a fingerprint is
                # bound to is not something a mistyped request should learn.
                raise LookupError("No such certificate for this agent")
            if row is None:
                row = models.AgentClientCert(
                    cert_id=uuid.uuid4().hex,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    fingerprint_sha256=digest,
                    source=SOURCE_TOMBSTONE,
                    created_at=now,
                    created_by=actor,
                )
                session.add(row)
            rows = [row]
        elif serial:
            wanted = client_cert.normalise_serial(serial)
            rows = list(
                session.execute(
                    base.where(
                        models.AgentClientCert.agent_id == agent_id,
                        models.AgentClientCert.serial_hex == wanted,
                    )
                ).scalars()
            )
            if not rows:
                raise LookupError(
                    "No certificate with that serial is on record for this agent; "
                    "revoke it by fingerprint instead"
                )
        else:
            rows = list(
                session.execute(
                    base.where(models.AgentClientCert.agent_id == agent_id)
                ).scalars()
            )
        changed = [row for row in rows if row.revoked_at is None]
        held = [row for row in changed if row.source != SOURCE_TOMBSTONE]
        for row in changed:
            row.revoked_at = now
            row.revoked_by = actor
            row.revoked_reason = cleaned_reason
        newly_locked = bool(held) and enrolment.locked_at is None
        if newly_locked:
            enrolment.locked_at = now
            enrolment.locked_by = actor
            enrolment.locked_reason = cleaned_reason
        session.flush()
        if changed or newly_locked:
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_AGENT_CERT_REVOKE,
                resource_type="agent",
                resource_id=agent_id,
                tenant_id=tenant_id,
                after={
                    "fingerprints": [row.fingerprint_sha256 for row in changed],
                    "serials": [row.serial_hex for row in changed if row.serial_hex],
                    "reason": cleaned_reason or "",
                    "enrolment_locked": enrolment.locked_at is not None,
                },
            )
        return [_to_dict(row, now, settings.agent_mtls_expiry_warn_days) for row in rows]


def reset_enrolment(
    settings: Settings,
    *,
    tenant_id: str,
    agent_id: str,
    reason: str = "",
    audit: audit_service.AuditContext | None = None,
) -> list[dict[str, Any]]:
    """Let one agent enrol from scratch by its token again; the operator's deliberate act.

    Revokes every certificate of the agent still unrevoked — "from scratch"
    means the old key stops working too — lifts the lock a revocation set,
    and clears the conflict marker. The next ``POST /api/agent/certificate``
    by this agent's token, without a certificate, is issued one; the one
    after that is a renewal again. Whoever enrols first wins that race, so
    revoke a leaked provisioning key *before* resetting
    (docs/operations.md § Sensor client certificates).
    """
    now = _now()
    actor = audit.actor if audit else "system"
    cleaned_reason = (reason or "").strip()[:512] or None
    with get_session(settings.postgres_url) as session:
        # First, as in :func:`issue`: an enrolment in flight is either among
        # the rows revoked below or issued after the reset, never between.
        enrolment = _enrolment_row(session, tenant_id=tenant_id, agent_id=agent_id)
        rows = list(
            session.execute(
                select(models.AgentClientCert)
                .where(
                    models.AgentClientCert.tenant_id == tenant_id,
                    models.AgentClientCert.agent_id == agent_id,
                )
                .order_by(models.AgentClientCert.created_at.desc())
            ).scalars()
        )
        revoked = [row for row in rows if row.revoked_at is None]
        for row in revoked:
            row.revoked_at = now
            row.revoked_by = actor
            row.revoked_reason = "enrolment reset" + (f": {cleaned_reason}" if cleaned_reason else "")
        was_locked = enrolment.locked_at is not None
        enrolment.locked_at = None
        enrolment.locked_by = None
        enrolment.locked_reason = None
        enrolment.reset_at = now
        enrolment.reset_by = actor
        enrolment.reset_reason = cleaned_reason
        enrolment.conflict_at = None
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_AGENT_CERT_ENROLMENT_RESET,
            resource_type="agent",
            resource_id=agent_id,
            tenant_id=tenant_id,
            after={
                "reason": cleaned_reason or "",
                "was_locked": was_locked,
                "revoked_fingerprints": [row.fingerprint_sha256 for row in revoked],
            },
        )
        return [_to_dict(row, now, settings.agent_mtls_expiry_warn_days) for row in rows]


def enrolment_tenant(settings: Settings, *, tenant_id: str | None, agent_id: str) -> str:
    """The tenant of the enrolment record of an agent that no longer exists.

    A lock outlives the agent it was set on: deleting a sensor is not a
    revocation (``agents.delete_agent``), and a host still holding its token
    re-registers under the same id — still locked. So the operator resets a
    deleted agent's enrolment by its id, and this finds whose it is: in
    ``tenant_id``, or in any tenant for an unscoped platform admin when
    exactly one has it. ``LookupError`` otherwise, the same answer as for an
    agent that does not exist.
    """
    with get_session(settings.postgres_url) as session:
        query = select(models.AgentCertEnrolment.tenant_id).where(
            models.AgentCertEnrolment.agent_id == agent_id
        )
        if tenant_id:
            query = query.where(models.AgentCertEnrolment.tenant_id == tenant_id)
        tenants = session.execute(query).scalars().all()
    if len(tenants) != 1:
        raise LookupError("Agent not found")
    return tenants[0]


@dataclass(frozen=True)
class FleetCertificates:
    """The certificate tiles of the fleet summary."""

    #: Agents holding a live (unrevoked, unexpired) certificate.
    agents_with_cert: int = 0
    #: ...of which the newest runs out within the warning window.
    expiring: int = 0
    #: Agents whose certificates have all run out (none revoked-only).
    expired: int = 0
    #: Agents an operator's revocation locked, waiting for a reset — an agent
    #: deleted since included: its id stays locked until reset.
    locked: int = 0
    #: Agents refused within :data:`CONFLICT_WINDOW` for presenting nothing
    #: while holding a live certificate — another host has their token.
    conflicts: int = 0


def fleet_certificates(
    session: Any, *, tenant_id: str | None, now: datetime, warn_days: int
) -> FleetCertificates:
    """Count agents by the state of their newest unrevoked certificate."""
    query = (
        select(
            models.AgentClientCert.tenant_id,
            models.AgentClientCert.agent_id,
            func.max(models.AgentClientCert.not_after),
        )
        # Only agents that still exist: the rows outlive a deleted agent so
        # its revocations do, but a deleted sensor is nobody's renewal to do.
        .join(
            models.Agent,
            and_(
                models.Agent.agent_id == models.AgentClientCert.agent_id,
                models.Agent.tenant_id == models.AgentClientCert.tenant_id,
            ),
        )
        .where(
            models.AgentClientCert.revoked_at.is_(None),
            models.AgentClientCert.source != SOURCE_TOMBSTONE,
            models.AgentClientCert.not_after.is_not(None),
        )
        .group_by(models.AgentClientCert.tenant_id, models.AgentClientCert.agent_id)
    )
    if tenant_id:
        query = query.where(models.AgentClientCert.tenant_id == tenant_id)
    live = expiring = expired = 0
    horizon = now + timedelta(days=warn_days)
    for _tenant, _agent, newest in session.execute(query):
        if newest <= now:
            expired += 1
            continue
        live += 1
        if newest <= horizon:
            expiring += 1
    # Every enrolment row, the agent deleted or not: a lock outlives the
    # agent it was set on (``reset_enrolment`` lifts it by id), and a lock
    # nobody can see is one nobody lifts.
    enrolments = select(
        models.AgentCertEnrolment.locked_at, models.AgentCertEnrolment.conflict_at
    )
    if tenant_id:
        enrolments = enrolments.where(models.AgentCertEnrolment.tenant_id == tenant_id)
    locked = conflicts = 0
    for locked_at, conflict_at in session.execute(enrolments):
        locked += locked_at is not None
        conflicts += conflict_at is not None and conflict_at > now - CONFLICT_WINDOW
    return FleetCertificates(
        agents_with_cert=live,
        expiring=expiring,
        expired=expired,
        locked=locked,
        conflicts=conflicts,
    )
