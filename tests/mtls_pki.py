"""A throwaway PKI for the client-certificate tests (#309).

Generated per test with ``cryptography``, never checked in: a CA, server
certificates for ``127.0.0.1``, and sensor client certificates with or without
a SPIFFE URI. Times are relative to now — nothing here is a calendar date.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TRUST_DOMAIN = "shapoclyack"


def spiffe(tenant_id: str, agent_id: str, kind: str = "sensor", domain: str = TRUST_DOMAIN) -> str:
    return f"spiffe://{domain}/tenant/{quote(tenant_id, safe='')}/{kind}/{quote(agent_id, safe='')}"


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@dataclass
class Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @property
    def key_pem(self) -> bytes:
        return _pem_key(self.key)

    @property
    def fingerprint(self) -> str:
        import hashlib

        return hashlib.sha256(self.cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    @property
    def serial_hex(self) -> str:
        return format(self.cert.serial_number, "x")

    def write(self, directory: Path, name: str) -> tuple[Path, Path]:
        cert_path = directory / f"{name}.crt"
        key_path = directory / f"{name}.key"
        cert_path.write_text(self.pem, encoding="ascii")
        key_path.write_bytes(self.key_pem)
        return cert_path, key_path


class CA:
    def __init__(self, name: str = "Sensor Test CA") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False
            )
            .sign(self.key, hashes.SHA256())
        )

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def write(self, directory: Path, name: str = "ca") -> tuple[Path, Path]:
        cert_path = directory / f"{name}.crt"
        key_path = directory / f"{name}.key"
        cert_path.write_text(self.pem, encoding="ascii")
        key_path.write_bytes(_pem_key(self.key))
        return cert_path, key_path

    def _issue(
        self,
        common_name: str,
        sans: list[x509.GeneralName],
        usage: x509.ObjectIdentifier,
        *,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
    ) -> Issued:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or now - timedelta(minutes=5))
            .not_valid_after(not_after or now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return Issued(builder.sign(self.key, hashes.SHA256()), key)

    def sensor(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        kind: str = "sensor",
        domain: str = TRUST_DOMAIN,
        not_after: datetime | None = None,
    ) -> Issued:
        return self._issue(
            agent_id,
            [x509.UniformResourceIdentifier(spiffe(tenant_id, agent_id, kind, domain))],
            ExtendedKeyUsageOID.CLIENT_AUTH,
            not_after=not_after,
        )

    def plain_client(self, common_name: str = "host-17.corp.example") -> Issued:
        """A client certificate that names a host, not a sensor (enterprise PKI)."""
        return self._issue(
            common_name,
            [x509.DNSName(common_name)],
            ExtendedKeyUsageOID.CLIENT_AUTH,
        )

    def server(self, host: str = "127.0.0.1") -> Issued:
        return self._issue(
            host,
            [x509.IPAddress(ipaddress.ip_address(host)), x509.DNSName("localhost")],
            ExtendedKeyUsageOID.SERVER_AUTH,
        )
