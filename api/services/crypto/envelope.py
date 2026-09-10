"""The ciphertext format, the KEK providers, and wrap/unwrap (#310).

**Envelope, not a single key.** Every write mints its own 256-bit data key
(DEK), encrypts the value with it under AES-256-GCM, and stores the DEK
wrapped by the key-encryption key (KEK). The KEK therefore never touches a
value directly: rotating it rewraps a 32-byte blob per row instead of
re-encrypting every secret, and a DEK recovered from one row decrypts that row
and nothing else.

**The stored form is self-describing**::

    v1:<kek_id>:<b64 wrapped dek>:<b64 nonce>:<b64 ciphertext>

``kek_id`` is a non-secret 16-hex-character label derived from the key material
(see :func:`_key_id`), so a row states which key opens it rather than relying on
an ordering convention between ``OCTO_MASTER_KEY`` and
``OCTO_MASTER_KEY_PREVIOUS``. That is what makes rotation resumable: during one
the table legitimately holds rows under two ids at once.

The wrapped DEK is ``nonce || ciphertext`` of its own AES-256-GCM operation
rather than a sixth field, because the wrap nonce is an implementation detail of
the wrap and pairs with exactly one blob.

**Every operation is bound to a context** (``webhook_subscriptions.secret``,
``webhook_subscriptions.headers``) as GCM additional data. A ciphertext lifted
out of one column therefore does not decrypt in another. It does *not* bind the
row id: re-encryption and a row copy would both have to rewrite the ciphertext,
and the threat this addresses is a reader of the database, not a writer of it.

**Reading accepts plaintext.** A value with no ``v1:`` prefix is returned as it
was stored — that is what lets a running installation be encrypted online
(``python -m api.db.reencrypt_secrets``) instead of during a migration window,
and what keeps a rollback to the previous image readable. Writing produces
plaintext only when no key is configured at all, which ``OCTO_ENV=prod`` refuses
for an installation that has integration secrets (see ``startup.py``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import secrets
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Bumping this is a format change, not a key change: readers keep accepting
# every version they know, writers emit exactly one.
FORMAT_VERSION = "v1"

# AES-256 for both halves of the envelope. 12-byte nonces are the GCM native
# size — anything else is hashed into one internally, which buys nothing.
_KEY_BYTES = 32
_NONCE_BYTES = 12

# Number of ``:``-separated fields in the stored form. Named so the parser and
# the docstring above cannot drift apart.
_FIELD_COUNT = 5

# Domain separation for the key id: it is published in every row, and deriving
# it from a bare sha256 of the key would make each row a free oracle for
# "is the master key X?" against a candidate list.
_KEY_ID_DOMAIN = b"shapoclyack/kek-id/v1"
_KEY_ID_HEX_CHARS = 16

MASTER_KEY_ENV = "OCTO_MASTER_KEY"
PREVIOUS_KEYS_ENV = "OCTO_MASTER_KEY_PREVIOUS"
PROVIDER_ENV = "OCTO_MASTER_KEY_PROVIDER"

PROVIDER_LOCAL = "local"
# Named but not implemented: the interface below is the seam a Vault Transit or
# a cloud KMS client plugs into, and naming them is how an operator finds out
# from the refusal message that this build does not carry one.
PROVIDER_REMOTE = ("vault-transit", "aws-kms", "gcp-kms")


class MasterKeyError(ValueError):
    """``OCTO_MASTER_KEY``/``OCTO_MASTER_KEY_PREVIOUS`` is not a usable key."""


class KeyProviderNotConfigured(RuntimeError):
    """A KEK provider was named that this build has no client for."""


class SecretDecryptionError(RuntimeError):
    """A stored value is malformed, was tampered with, or its key is absent.

    Deliberately not a subclass of ``ValueError``: the routes translate a
    service ``ValueError`` into 400, and none of these three is a caller's
    fault — they are configuration or integrity problems, i.e. a 500 and a log
    line for the operator.
    """


# --------------------------------------------------------------------------
# KEK providers
# --------------------------------------------------------------------------


class KeyProvider(ABC):
    """Where the key-encryption key lives.

    Two methods, because that is the whole contract an envelope needs: wrap a
    fresh DEK under the key new writes use, and unwrap one under whichever key
    a stored row names. A Vault Transit or KMS provider implements the same two
    as remote calls; nothing above this class knows the difference.
    """

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Label of the key new writes are wrapped with."""

    @abstractmethod
    def wrap(self, dek: bytes, *, context: str) -> bytes:
        """Return the DEK encrypted under the current KEK."""

    @abstractmethod
    def unwrap(self, wrapped: bytes, *, key_id: str, context: str) -> bytes:
        """Return the DEK from ``wrapped``, which was wrapped under ``key_id``."""


class LocalKeyProvider(KeyProvider):
    """KEKs supplied as environment variables, the only provider that ships.

    ``OCTO_MASTER_KEY`` wraps new writes; every key in
    ``OCTO_MASTER_KEY_PREVIOUS`` (comma- or whitespace-separated) can still
    unwrap. Both accept 32 bytes as base64 or as hex, because the two obvious
    ways to produce one — ``openssl rand -base64 32`` and ``openssl rand -hex
    32`` — should both simply work.

    Keys are held by id rather than in a list, so an installation part-way
    through a rotation reads rows under either key without the caller knowing
    which is which.
    """

    def __init__(self, key: bytes, previous: tuple[bytes, ...] = ()) -> None:
        self._current_id = _key_id(key)
        # Current last: a key repeated in OCTO_MASTER_KEY_PREVIOUS is the same
        # entry, not a conflicting one, and the current id must win the label.
        self._keys: dict[str, bytes] = {_key_id(item): item for item in previous}
        self._keys[self._current_id] = key

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "LocalKeyProvider | None":
        """Build from the environment, or ``None`` when no key is set."""
        env = os.environ if environ is None else environ
        raw = (env.get(MASTER_KEY_ENV) or "").strip()
        if not raw:
            return None
        previous = tuple(
            _decode_key(item, PREVIOUS_KEYS_ENV)
            for item in (env.get(PREVIOUS_KEYS_ENV) or "").replace(",", " ").split()
        )
        return cls(_decode_key(raw, MASTER_KEY_ENV), previous)

    @property
    def key_id(self) -> str:
        return self._current_id

    def known_key_ids(self) -> tuple[str, ...]:
        """Every id this provider can unwrap, current first. For diagnostics."""
        others = sorted(k for k in self._keys if k != self._current_id)
        return (self._current_id, *others)

    def wrap(self, dek: bytes, *, context: str) -> bytes:
        return _seal(self._keys[self._current_id], dek, context=f"kek:{context}")

    def unwrap(self, wrapped: bytes, *, key_id: str, context: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise SecretDecryptionError(
                f"No master key with id {key_id} is configured. The value was written "
                f"under a different {MASTER_KEY_ENV}; put that key in "
                f"{PREVIOUS_KEYS_ENV} (comma-separated) and re-run "
                "`python -m api.db.reencrypt_secrets --rotate`."
            )
        return _open(key, wrapped, context=f"kek:{context}")


class RemoteKeyProvider(KeyProvider):
    """The seam for Vault Transit / cloud KMS — an interface, not a client.

    It exists so that "where does the KEK live" is a provider choice rather
    than an assumption baked into every call site, and so that an operator who
    sets ``OCTO_MASTER_KEY_PROVIDER=vault-transit`` today gets a refusal that
    names what is missing instead of a build that silently falls back to a
    local key. Implementing one is a matter of filling in these two methods.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def _refuse(self) -> "KeyProviderNotConfigured":
        return KeyProviderNotConfigured(
            f"{PROVIDER_ENV}={self._name} is not implemented in this build: only "
            f"'{PROVIDER_LOCAL}' ({MASTER_KEY_ENV}) carries a client. The provider "
            "interface exists so a Vault Transit / KMS client can be added without "
            "touching the callers — see docs/operations.md § Secrets at rest."
        )

    @property
    def key_id(self) -> str:
        raise self._refuse()

    def wrap(self, dek: bytes, *, context: str) -> bytes:
        raise self._refuse()

    def unwrap(self, wrapped: bytes, *, key_id: str, context: str) -> bytes:
        raise self._refuse()


def build_provider(environ: dict[str, str] | None = None) -> KeyProvider | None:
    """Resolve the configured provider, or ``None`` when there is no key.

    ``None`` is a state, not an error: an installation with no integration
    secrets never needs a key, and a dev box is allowed to run without one.
    ``startup.py`` is what decides whether this particular installation may.
    """
    env = os.environ if environ is None else environ
    name = (env.get(PROVIDER_ENV) or PROVIDER_LOCAL).strip().lower() or PROVIDER_LOCAL
    if name in PROVIDER_REMOTE:
        return RemoteKeyProvider(name)
    if name != PROVIDER_LOCAL:
        raise MasterKeyError(
            f"{PROVIDER_ENV} must be one of "
            f"{', '.join((PROVIDER_LOCAL, *PROVIDER_REMOTE))} (got an unrecognised value)."
        )
    return LocalKeyProvider.from_env(env)


def _decode_key(raw: str, variable: str) -> bytes:
    """32 key bytes from base64 or hex, or a message naming how to make one."""
    candidate = raw.strip()
    key: bytes | None = None
    if len(candidate) == _KEY_BYTES * 2:
        try:
            key = bytes.fromhex(candidate)
        except ValueError:
            key = None
    if key is None:
        try:
            key = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            key = None
    if key is None or len(key) != _KEY_BYTES:
        raise MasterKeyError(
            f"{variable} must be {_KEY_BYTES} bytes as base64 or hex.\n"
            "    Generate one with: openssl rand -base64 32"
        )
    return key


def _key_id(key: bytes) -> str:
    return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:_KEY_ID_HEX_CHARS]


# --------------------------------------------------------------------------
# AEAD primitives
# --------------------------------------------------------------------------


def _seal(key: bytes, plaintext: bytes, *, context: str) -> bytes:
    nonce = secrets.token_bytes(_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, context.encode("utf-8"))


def _open(key: bytes, blob: bytes, *, context: str) -> bytes:
    if len(blob) <= _NONCE_BYTES:
        raise SecretDecryptionError("Stored value is truncated.")
    try:
        return AESGCM(key).decrypt(
            blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], context.encode("utf-8")
        )
    except InvalidTag as exc:
        raise SecretDecryptionError(
            "Stored value failed its authentication tag: it was modified, it belongs "
            "to a different column, or it was written under a different key."
        ) from exc


# --------------------------------------------------------------------------
# Module state
# --------------------------------------------------------------------------

_provider: KeyProvider | None = None


def configure(provider: KeyProvider | None = None) -> None:
    """Point the module at a KEK provider; ``None`` re-reads the environment.

    Module-level like every other service's ``configure`` here: encryption is a
    property of the process, and threading a cipher object through the webhook
    service, the dispatch loop and the re-encryption CLI would be three copies
    of the same wiring.
    """
    global _provider
    _provider = build_provider() if provider is None else provider


def reset_for_tests() -> None:
    global _provider
    _provider = None


def current_provider() -> KeyProvider | None:
    return _provider


def encryption_enabled() -> bool:
    return _provider is not None


def current_key_id() -> str | None:
    """The id new writes are wrapped with, or ``None`` when writes are plaintext."""
    return None if _provider is None else _provider.key_id


# --------------------------------------------------------------------------
# The stored form
# --------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(raw: str, field: str) -> bytes:
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SecretDecryptionError(f"Stored value has a malformed {field} field.") from exc


def _split(value: str) -> tuple[str, str, str, str] | None:
    """``(kek_id, wrapped, nonce, ciphertext)`` if ``value`` is in stored form.

    Strict rather than a prefix test, because the alternative reading of a
    ``v1:``-prefixed string is "an operator pasted a token that starts like
    that": a shape check on all five fields is what keeps such a token being
    treated as plaintext, which is what it is.
    """
    parts = value.split(":")
    if len(parts) != _FIELD_COUNT or parts[0] != FORMAT_VERSION:
        return None
    version, kek_id, wrapped, nonce, ciphertext = parts
    if not (kek_id and wrapped and nonce and ciphertext):
        return None
    if len(kek_id) != _KEY_ID_HEX_CHARS or any(c not in "0123456789abcdef" for c in kek_id):
        return None
    return kek_id, wrapped, nonce, ciphertext


def is_encrypted(value: str | None) -> bool:
    """Whether ``value`` is a stored envelope rather than legacy plaintext."""
    return bool(value) and _split(str(value)) is not None


def key_id_of(value: str | None) -> str | None:
    """The KEK id a stored value names, or ``None`` if it is plaintext."""
    parsed = _split(value) if value else None
    return None if parsed is None else parsed[0]


def encrypt_secret(value: str, *, context: str) -> str:
    """Encrypt ``value`` for ``context``, or return it unchanged with no key.

    Already-encrypted input is returned as-is rather than double-wrapped: the
    write paths call this on whatever the row currently holds, and a value that
    is already in stored form is already at rest correctly.
    """
    if _provider is None or not value or is_encrypted(value):
        return value
    dek = secrets.token_bytes(_KEY_BYTES)
    sealed = _seal(dek, value.encode("utf-8"), context=context)
    wrapped = _provider.wrap(dek, context=context)
    return ":".join(
        (
            FORMAT_VERSION,
            _provider.key_id,
            _b64(wrapped),
            _b64(sealed[:_NONCE_BYTES]),
            _b64(sealed[_NONCE_BYTES:]),
        )
    )


def decrypt_secret(value: str | None, *, context: str) -> str | None:
    """Decrypt a stored value; legacy plaintext is returned as it was stored."""
    if not value:
        return value
    parsed = _split(value)
    if parsed is None:
        return value
    kek_id, wrapped, nonce, ciphertext = parsed
    if _provider is None:
        raise SecretDecryptionError(
            f"An encrypted secret was read but no key is configured: set "
            f"{MASTER_KEY_ENV} to the key with id {kek_id} — see "
            "docs/operations.md § Secrets at rest."
        )
    dek = _provider.unwrap(
        _unb64(wrapped, "wrapped-key"), key_id=kek_id, context=context
    )
    plaintext = _open(
        dek, _unb64(nonce, "nonce") + _unb64(ciphertext, "ciphertext"), context=context
    )
    return plaintext.decode("utf-8")
