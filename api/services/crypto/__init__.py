"""Envelope encryption for the integration secrets this installation stores (#310).

Integration credentials — the webhook HMAC key and the header values that carry
a Jira / ServiceNow / DefectDojo token — used to sit in Postgres as typed. A
dump, a backup, a read replica or a shell in the API pod therefore handed over
every tenant's tracker tokens at once, and the API-level redaction in
``integrations/secure_webhooks.py`` did nothing about that: it hides the values
from a *reader of the API*, which is a different threat than a reader of the
database.

Module split:
  - ``envelope.py`` — the ciphertext format, the KEK providers and the
                      wrap/unwrap primitives. No database, no models.
  - ``startup.py``  — the ``OCTO_ENV=prod`` fail-closed check, which is the one
                      thing here that has to look at rows.
"""

from .envelope import (
    FORMAT_VERSION,
    KeyProviderNotConfigured,
    MasterKeyError,
    SecretDecryptionError,
    configure,
    current_key_id,
    decrypt_secret,
    encrypt_secret,
    encryption_enabled,
    is_encrypted,
)

__all__ = [
    "FORMAT_VERSION",
    "KeyProviderNotConfigured",
    "MasterKeyError",
    "SecretDecryptionError",
    "configure",
    "current_key_id",
    "decrypt_secret",
    "encrypt_secret",
    "encryption_enabled",
    "is_encrypted",
]
