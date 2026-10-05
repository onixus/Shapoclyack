"""The sensor's client certificate: which one, where, and when to renew it (#309).

Two ways a sensor gets one, chosen by the operator:

**Mounted** — ``OCTO_AGENT_TLS_CLIENT_CERT`` / ``OCTO_AGENT_TLS_CLIENT_KEY``
name files something else keeps current: a cert-manager ``Certificate``'s
Secret, a host's own PKI agent. The sensor only reads them, and re-reads them
when they change on disk, so a rotation reaches the next request without a
restart.

**Enrolled** — the same two paths plus ``OCTO_AGENT_MTLS_ENROLL=true``: the
sensor makes its own key, sends a CSR to ``POST /api/agent/certificate`` and
writes what comes back to those paths, then renews at the ``renew_after`` the
API answered with (two thirds of the lifetime). A renewal presents the current
certificate, which is what the API requires of an agent that already holds
one. The key never leaves the host and is written ``0600``.

Key generation uses ``cryptography`` when it is importable (it is in the
container image) and the ``openssl`` binary otherwise — a native sensor's
virtualenv (requirements-agent.txt) does not carry ``cryptography``, and every
host that has a CA store has ``openssl``.

The certificate rides on the same proxy-aware opener as every other call
(``agent/egress.py``). A TLS-inspecting proxy that re-signs the connection
cannot forward a client certificate, so the API's host has to be in
``OCTO_NO_PROXY`` or exempt from inspection on such a network.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import ssl
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from agent import egress

LOG = logging.getLogger("octo-agent")

CERT_VAR = "OCTO_AGENT_TLS_CLIENT_CERT"
KEY_VAR = "OCTO_AGENT_TLS_CLIENT_KEY"
ENROL_VAR = "OCTO_AGENT_MTLS_ENROLL"

#: How often the loop looks at the files and the renewal time. A stat() and a
#: clock read; the point is that a rotated Secret is picked up within a
#: minute, not that it is free.
CHECK_INTERVAL_SECONDS = 60.0

#: After a failed enrolment, how long before the next try — enough that a
#: refusing API is not asked at the poll rate, short enough that a sensor whose
#: certificate is running out tries several times before it does.
RETRY_SECONDS = 300.0

_TRUTHY = {"1", "true", "yes", "on"}


class ClientCertConfigError(egress.EgressConfigError):
    """The client certificate settings cannot work as given."""


def _meta_path(cert_path: Path) -> Path:
    return cert_path.with_name(cert_path.name + ".json")


def _parse_time(value: Any) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class ClientCertificate:
    """One sensor's certificate and key on disk, and the decision to renew them."""

    def __init__(self, cert_path: Path, key_path: Path, *, enrol: bool = False) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.enrol = enrol
        self._loaded_stamp: tuple[int, int] | None = None
        self._forced = False
        self._next_attempt = 0.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ClientCertificate | None":
        source = os.environ if env is None else env
        cert = (source.get(CERT_VAR) or "").strip()
        key = (source.get(KEY_VAR) or "").strip()
        enrol = (source.get(ENROL_VAR) or "").strip().lower() in _TRUTHY
        if not cert and not key:
            if enrol:
                raise ClientCertConfigError(
                    f"{ENROL_VAR} is set, but {CERT_VAR} and {KEY_VAR} are not: name the "
                    "two files the enrolled certificate and key are kept in"
                )
            return None
        if not cert or not key:
            missing = KEY_VAR if cert else CERT_VAR
            raise ClientCertConfigError(
                f"The client certificate is half-configured: {missing} is unset. "
                "Set both, or neither."
            )
        instance = cls(Path(cert), Path(key), enrol=enrol)
        if not enrol and not instance.present():
            raise ClientCertConfigError(
                f"{CERT_VAR}={cert} / {KEY_VAR}={key}: the files do not exist, and "
                f"{ENROL_VAR} is not set to make them"
            )
        return instance

    # --- reading ---------------------------------------------------------------

    def present(self) -> bool:
        return self.cert_path.is_file() and self.key_path.is_file()

    def _stamp(self) -> tuple[int, int] | None:
        try:
            return (self.cert_path.stat().st_mtime_ns, self.key_path.stat().st_mtime_ns)
        except OSError:
            return None

    def ssl_context(self) -> ssl.SSLContext:
        """The egress context, presenting this certificate when it exists."""
        context = egress.ssl_context()
        if self.present():
            try:
                context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
            except (OSError, ssl.SSLError) as exc:
                raise ClientCertConfigError(
                    f"Cannot load the client certificate {self.cert_path} / {self.key_path}: {exc}"
                ) from exc
        self._loaded_stamp = self._stamp()
        return context

    def changed_on_disk(self) -> bool:
        """Whether the files differ from what the current context was built from."""
        return self._stamp() != self._loaded_stamp

    def renew_after(self) -> float | None:
        """When this enrolled certificate should be replaced, from its metadata."""
        try:
            meta = json.loads(_meta_path(self.cert_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return _parse_time(meta.get("renew_after"))

    def enrolment_due(self, now: float | None = None) -> bool:
        """Whether to ask the API for a certificate now (enrolled mode only)."""
        if not self.enrol:
            return False
        current = time.time() if now is None else now
        if current < self._next_attempt:
            return False
        if self._forced or not self.present():
            return True
        due = self.renew_after()
        # A certificate with no metadata was not written by this module (or
        # the file was lost): renewing it is the way to learn its lifetime.
        return due is None or current >= due

    def force_enrolment(self) -> None:
        """The API refused the current certificate; replace it at the next check.

        Does not cut short a retry delay a failed enrolment set: the refusal
        repeats on every poll, and the enrolment it asks for must not.
        """
        self._forced = True

    def enrolment_failed(self, now: float | None = None) -> None:
        self._next_attempt = (time.time() if now is None else now) + RETRY_SECONDS

    def retry_pending(self, now: float | None = None) -> bool:
        """Whether a failed enrolment's retry delay is still running.

        A revoked sensor's enrolment is refused until an operator resets it;
        polling the API every few seconds in the meantime only fills the
        audit trail with the same refusal.
        """
        return (time.time() if now is None else now) < self._next_attempt

    # --- writing ---------------------------------------------------------------

    def install(self, key_pem: bytes, issued: Mapping[str, Any]) -> None:
        """Write a new key, certificate and metadata, each atomically.

        Key first: a crash between the two leaves a new key with the old
        certificate, which fails to load and is replaced at the next check —
        never an old key with a certificate for a different one being sent.
        """
        certificate = str(issued.get("certificate") or "")
        if "BEGIN CERTIFICATE" not in certificate:
            raise ClientCertConfigError("The API's enrolment answer carries no certificate")
        _atomic_write(self.key_path, key_pem, mode=0o600)
        _atomic_write(self.cert_path, certificate.encode("ascii"), mode=0o644)
        meta = {
            "fingerprint_sha256": issued.get("fingerprint_sha256"),
            "serial": issued.get("serial"),
            "spiffe_id": issued.get("spiffe_id"),
            "not_after": issued.get("not_after"),
            "renew_after": issued.get("renew_after"),
        }
        _atomic_write(
            _meta_path(self.cert_path), json.dumps(meta, indent=2).encode("utf-8"), mode=0o644
        )
        self._forced = False
        self._next_attempt = 0.0


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def generate_key_and_csr(common_name: str) -> tuple[bytes, str]:
    """A fresh P-256 key (PEM) and a CSR for it.

    The CSR's subject is a courtesy: the API names the certificate after the
    token's agent whatever the CSR says.
    """
    try:
        return _generate_with_cryptography(common_name)
    except ImportError:
        return _generate_with_openssl(common_name)


def _generate_with_cryptography(common_name: str) -> tuple[bytes, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64])]))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _generate_with_openssl(common_name: str) -> tuple[bytes, str]:
    binary = shutil.which("openssl")
    if binary is None:
        raise ClientCertConfigError(
            "Enrolling a client certificate needs the Python 'cryptography' package or "
            "the 'openssl' binary, and this host has neither"
        )
    # Only characters a subject can carry without escaping: the name is a
    # courtesy (see above), so dropping the rest costs nothing.
    safe = "".join(c for c in common_name if c.isalnum() or c in "-_.")[:64] or "sensor"
    with tempfile.TemporaryDirectory(prefix="octo-csr-") as workdir:
        key_path = Path(workdir) / "key.pem"
        # ecparam + req rather than ``req -newkey ec``: the same two commands
        # work on OpenSSL 1.1, 3.x and LibreSSL.
        subprocess.run(
            [binary, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_path)],
            check=True,
            capture_output=True,
            timeout=30,
        )
        result = subprocess.run(
            [binary, "req", "-new", "-key", str(key_path), "-subj", f"/CN={safe}", "-sha256"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return key_path.read_bytes(), result.stdout.decode("ascii")
