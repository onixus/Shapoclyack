"""The sensor's ed25519 key for signing run archives (#366).

The sensor generates the key itself and keeps the private half in a file only
it can read; only the public half ever leaves the host, on registration, where
the API pins it (first use wins; see ``api/services/agents.py``). Every
results upload then carries a signature over the archive's SHA-256 *and* the
job it belongs to, so a stolen bearer token cannot forge a run, and an archive
cannot be moved to another job, attempt or sensor.

Signing is best effort on the sensor side: when the key cannot be created or
read (a read-only home in a container without a volume), the sensor logs it
once and uploads unsigned, which the API accepts or refuses according to
``OCTO_REQUIRE_SIGNED_RESULTS``. Losing the ability to sign must not stop a
sensor from scanning.

``signing_message`` is the API's ``result_integrity.signing_message`` byte for
byte; ``tests/test_result_integrity.py`` pins both to one vector.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

LOG = logging.getLogger("octo-agent")

KEY_FILE_VAR = "OCTO_AGENT_RESULT_KEY_FILE"
DISABLE_VAR = "OCTO_AGENT_RESULT_SIGNING"
SIGNING_DOMAIN = "shapoclyack-run-archive-v1"
_FALSY = {"0", "false", "no", "off"}


def signing_message(
    *,
    agent_id: str,
    job_id: str,
    run_id: str | None,
    exit_code: int,
    attempt: int | None,
    archive_sha256: str,
) -> bytes:
    return "\n".join(
        [
            SIGNING_DOMAIN,
            f"agent={agent_id}",
            f"job={job_id}",
            f"run={run_id or ''}",
            f"exit={int(exit_code)}",
            f"attempt={'' if attempt is None else int(attempt)}",
            f"sha256={archive_sha256}",
        ]
    ).encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_key_path(agent_id_file: str | None = None) -> Path:
    """``OCTO_AGENT_RESULT_KEY_FILE``, else next to the saved agent id, else the home dir."""
    configured = os.environ.get(KEY_FILE_VAR, "").strip()
    if configured:
        return Path(configured)
    if agent_id_file:
        return Path(agent_id_file).parent / "result-signing.key"
    return Path.home() / ".shapoclyack-sensor" / "result-signing.key"


class ResultSigner:
    """An ed25519 private key plus the operations the sensor needs from it."""

    def __init__(self, key: Any) -> None:
        from cryptography.hazmat.primitives import serialization

        self._key = key
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.public_key_b64 = base64.b64encode(raw).decode("ascii")
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    @classmethod
    def load_or_create(cls, path: Path) -> ResultSigner:
        """The key at ``path``; created (0600, atomically) when absent. Raises ``OSError``/``ValueError``."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        try:
            return cls(
                serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[arg-type]
            )
        except FileNotFoundError:
            pass
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".result-key.", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(pem)
                handle.flush()
                os.fsync(handle.fileno())
            # link() instead of replace(): two processes starting together must
            # end up with one key, not each keep a different one in memory.
            try:
                os.link(tmp, path)
            except FileExistsError:
                return cls.load_or_create(path)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        return cls(key)

    def sign_upload(
        self,
        *,
        agent_id: str,
        job_id: str,
        run_id: str | None,
        exit_code: int,
        attempt: int | None,
        archive_path: Path,
    ) -> str:
        message = signing_message(
            agent_id=agent_id,
            job_id=job_id,
            run_id=run_id,
            exit_code=exit_code,
            attempt=attempt,
            archive_sha256=file_sha256(archive_path),
        )
        return base64.b64encode(self._key.sign(message)).decode("ascii")


def load_signer(agent_id_file: str | None = None) -> ResultSigner | None:
    """The sensor's signer, or ``None`` (logged) when signing is off or impossible."""
    if os.environ.get(DISABLE_VAR, "").strip().lower() in _FALSY:
        LOG.info("Result signing is disabled (%s)", DISABLE_VAR)
        return None
    path = default_key_path(agent_id_file)
    try:
        signer = ResultSigner.load_or_create(path)
    except (OSError, ValueError, ImportError) as exc:
        # An explicitly configured path that cannot be used is a deployment
        # error (a volume that is not writable): loud, because a sensor whose
        # key the API has pinned has its uploads refused while it is unsigned.
        log = LOG.error if os.environ.get(KEY_FILE_VAR, "").strip() else LOG.warning
        log(
            "Result signing key unavailable at %s (%s); uploads will be unsigned. "
            "Set %s to a writable, persistent path",
            path,
            exc,
            KEY_FILE_VAR,
        )
        return None
    LOG.info("Result signing key %s loaded from %s", signer.key_id, path)
    return signer
