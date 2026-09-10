"""Envelope encryption of the integration secrets in Postgres (#310).

Two halves. The first needs no database: it is about the format and the key
providers, and every assertion is on bytes. The second is the property the
ticket is actually about — that ``webhook_subscriptions`` stops holding a
tracker token as typed — and it can only be checked against real rows.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import pytest

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.db import reencrypt_secrets
from api.services import tenants as tenants_service
from api.services.crypto import envelope
from api.services.crypto import startup as crypto_startup
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import webhooks
from api.settings import ENV_PROD, InsecureConfigurationError, Settings
from tests.conftest import make_settings, requires_postgres

KEY_A = base64.b64encode(b"A" * 32).decode("ascii")
KEY_B = (b"B" * 32).hex()

CONTEXT = webhooks.SECRET_CONTEXT


@pytest.fixture(autouse=True)
def _clean_provider():
    """The provider is module state; no test may inherit another's key."""
    envelope.reset_for_tests()
    yield
    envelope.reset_for_tests()


def _use(key: str, previous: str = "") -> None:
    envelope.configure(
        envelope.LocalKeyProvider.from_env(
            {envelope.MASTER_KEY_ENV: key, envelope.PREVIOUS_KEYS_ENV: previous}
        )
    )


# --------------------------------------------------------------------------
# Format and key providers
# --------------------------------------------------------------------------


def test_roundtrip_produces_the_documented_shape():
    _use(KEY_A)
    stored = envelope.encrypt_secret("jira-api-token", context=CONTEXT)

    version, kek_id, wrapped, nonce, ciphertext = stored.split(":")
    assert version == envelope.FORMAT_VERSION
    assert kek_id == envelope.current_key_id()
    # Each field for what it is, not merely for being non-empty base64: a
    # nonce of the wrong width and a ciphertext that happens to be the
    # plaintext would both survive a truthiness check.
    assert len(base64.b64decode(nonce, validate=True)) == envelope._NONCE_BYTES
    assert len(base64.b64decode(wrapped, validate=True)) == envelope._NONCE_BYTES + 32 + 16
    body = base64.b64decode(ciphertext, validate=True)
    assert len(body) == len(b"jira-api-token") + 16  # AES-GCM adds only its tag
    assert b"jira-api-token" not in body
    assert "jira-api-token" not in stored
    assert envelope.is_encrypted(stored)
    assert envelope.decrypt_secret(stored, context=CONTEXT) == "jira-api-token"


def test_every_write_gets_its_own_data_key():
    _use(KEY_A)
    first = envelope.encrypt_secret("same", context=CONTEXT)
    second = envelope.encrypt_secret("same", context=CONTEXT)
    assert first != second
    assert first.split(":")[2] != second.split(":")[2]


def test_tampered_ciphertext_is_refused_not_returned():
    _use(KEY_A)
    version, kek_id, wrapped, nonce, ciphertext = envelope.encrypt_secret(
        "jira-api-token", context=CONTEXT
    ).split(":")
    raw = bytearray(base64.b64decode(ciphertext))
    raw[0] ^= 0x01
    tampered = ":".join(
        (version, kek_id, wrapped, nonce, base64.b64encode(bytes(raw)).decode("ascii"))
    )

    with pytest.raises(envelope.SecretDecryptionError):
        envelope.decrypt_secret(tampered, context=CONTEXT)


def test_ciphertext_does_not_decrypt_in_another_column():
    _use(KEY_A)
    stored = envelope.encrypt_secret("jira-api-token", context=CONTEXT)
    with pytest.raises(envelope.SecretDecryptionError):
        envelope.decrypt_secret(stored, context=webhooks.HEADERS_CONTEXT)


def test_previous_key_still_reads_and_rotation_relabels():
    _use(KEY_A)
    old_id = envelope.current_key_id()
    stored = envelope.encrypt_secret("jira-api-token", context=CONTEXT)

    _use(KEY_B, previous=KEY_A)
    assert envelope.current_key_id() != old_id
    # The old row is still readable, and rewrapping moves it onto the new key.
    assert envelope.decrypt_secret(stored, context=CONTEXT) == "jira-api-token"
    rewrapped = envelope.encrypt_secret("jira-api-token", context=CONTEXT)
    assert envelope.key_id_of(rewrapped) == envelope.current_key_id()

    # Dropping the old key from OCTO_MASTER_KEY_PREVIOUS is what makes the
    # un-rotated row unreadable — the failure a rotation must not be left in.
    _use(KEY_B)
    with pytest.raises(envelope.SecretDecryptionError):
        envelope.decrypt_secret(stored, context=CONTEXT)
    assert envelope.decrypt_secret(rewrapped, context=CONTEXT) == "jira-api-token"


def test_legacy_plaintext_is_read_as_stored():
    _use(KEY_A)
    assert envelope.decrypt_secret("legacy-token", context=CONTEXT) == "legacy-token"
    assert not envelope.is_encrypted("legacy-token")
    # A token that merely starts like the prefix is plaintext, not a broken row.
    assert not envelope.is_encrypted("v1:not-an-envelope")
    assert envelope.decrypt_secret("v1:not-an-envelope", context=CONTEXT) == "v1:not-an-envelope"


def test_encrypted_value_without_a_key_refuses_rather_than_leaking_ciphertext():
    _use(KEY_A)
    stored = envelope.encrypt_secret("jira-api-token", context=CONTEXT)
    envelope.reset_for_tests()

    assert envelope.encrypt_secret("plain", context=CONTEXT) == "plain"
    with pytest.raises(envelope.SecretDecryptionError):
        envelope.decrypt_secret(stored, context=CONTEXT)


def test_master_key_must_be_32_bytes():
    with pytest.raises(envelope.MasterKeyError):
        envelope.LocalKeyProvider.from_env({envelope.MASTER_KEY_ENV: "too-short"})
    assert envelope.LocalKeyProvider.from_env({envelope.MASTER_KEY_ENV: "  "}) is None


def test_remote_provider_is_an_interface_and_says_so():
    provider = envelope.build_provider({envelope.PROVIDER_ENV: "vault-transit"})
    assert isinstance(provider, envelope.RemoteKeyProvider)
    with pytest.raises(envelope.KeyProviderNotConfigured):
        provider.key_id
    with pytest.raises(envelope.MasterKeyError):
        envelope.build_provider({envelope.PROVIDER_ENV: "sticky-note"})


# --------------------------------------------------------------------------
# The rows
# --------------------------------------------------------------------------


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    value = make_settings(tmp_path)
    tenants_service.configure(value)
    tenants_service.load_tenants(value)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(value)
    webhooks.configure(value)
    webhooks.reset_for_tests()
    return value


def _subscribe(settings: Settings, **overrides) -> dict:
    payload = {
        "tenant_id": "default",
        "name": "soc",
        "url": "https://receiver.example/hook",
        "created_by": "admin",
    }
    payload.update(overrides)
    return webhooks.create_subscription(**payload)


def _row(settings: Settings, subscription_id: str) -> models.WebhookSubscription:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebhookSubscription, subscription_id)
        assert row is not None
        session.expunge(row)
        return row


def _event(event_id: str = "ev-crypto") -> dict:
    return {
        "kind": "new_cve",
        "tenant_id": "default",
        "event_id": event_id,
        "run_id": "run-1",
        "host": "10.0.0.1",
        "port": 443,
        "occurred_at": "2026-08-14T09:00:00+00:00",
        "source": "run_diff",
        "data": {"severity": "critical", "cve": "CVE-2026-1"},
    }


@requires_postgres
def test_stored_row_holds_no_plaintext_secret_or_header(settings):
    _use(KEY_A)
    created = _subscribe(
        settings, headers={"Authorization": "Bearer jira-api-token"}, secret="hmac-key"
    )

    row = _row(settings, created["subscription_id"])
    assert row.secret is not None and envelope.is_encrypted(row.secret)
    assert "hmac-key" not in row.secret
    assert envelope.is_encrypted(row.headers["Authorization"])
    assert "jira-api-token" not in row.headers["Authorization"]
    assert row.key_id == envelope.current_key_id()

    # The service surface is unchanged: the secret comes back once, from the
    # request that set it. What was entered is readable exactly where an
    # outbound call needs it, and nowhere on the read path.
    assert created["secret"] == "hmac-key"
    secret, headers = webhooks._base.endpoint_credentials(row)
    assert (secret, headers) == ("hmac-key", {"Authorization": "Bearer jira-api-token"})
    assert webhooks._base.get_subscription(created["subscription_id"])["headers"] == {
        "Authorization": "***"
    }


@requires_postgres
def test_api_redaction_is_unchanged_and_never_shows_ciphertext(settings):
    _use(KEY_A)
    created = _subscribe(settings, headers={"Authorization": "Bearer jira-api-token"})

    fetched = webhooks.get_subscription(created["subscription_id"])
    assert fetched["headers"] == {"Authorization": "***"}
    assert "secret" not in fetched
    assert "jira-api-token" not in repr(fetched)
    assert envelope.FORMAT_VERSION + ":" not in repr(fetched)


@requires_postgres
def test_delivery_signs_with_the_decrypted_secret(settings):
    _use(KEY_A)
    created = _subscribe(settings, headers={"X-Api-Key": "gateway-token"})
    sent: dict = {}

    def _capture(url, body, headers, **kwargs):
        sent["body"] = body
        sent["headers"] = headers
        return delivery_transport.DeliveryResult(
            ok=True, status_code=204, error=None, retryable=False
        )

    webhooks.enqueue_event(_event())
    assert webhooks.dispatch_once(post=_capture)["delivered"] == 1

    assert sent["headers"]["X-Api-Key"] == "gateway-token"
    assert sent["headers"][delivery_transport.SIGNATURE_HEADER] == delivery_transport.sign(
        created["secret"], sent["headers"][delivery_transport.TIMESTAMP_HEADER], sent["body"]
    )


@requires_postgres
def test_editing_a_name_rewraps_nothing_but_a_rotation_moves_the_row(settings):
    _use(KEY_A)
    created = _subscribe(settings, secret="hmac-key")
    before = _row(settings, created["subscription_id"]).secret

    webhooks.update_subscription(created["subscription_id"], name="soc-renamed")
    assert _row(settings, created["subscription_id"]).secret == before

    _use(KEY_B, previous=KEY_A)
    webhooks.update_subscription(created["subscription_id"], name="soc-rotated")
    row = _row(settings, created["subscription_id"])
    assert row.key_id == envelope.current_key_id()
    assert envelope.key_id_of(row.secret) == envelope.current_key_id()
    assert envelope.decrypt_secret(row.secret, context=CONTEXT) == "hmac-key"


@requires_postgres
def test_reencrypt_command_encrypts_rotates_and_decrypts(settings):
    # A row written before #310: no key configured, so it lands as typed.
    created = _subscribe(
        settings, secret="hmac-key", headers={"Authorization": "Bearer jira-api-token"}
    )
    row = _row(settings, created["subscription_id"])
    assert row.secret == "hmac-key" and row.key_id is None

    _use(KEY_A)
    assert reencrypt_secrets.run(settings.postgres_url, dry_run=True).changed == 1
    assert _row(settings, created["subscription_id"]).secret == "hmac-key"

    assert reencrypt_secrets.run(settings.postgres_url).changed == 1
    row = _row(settings, created["subscription_id"])
    assert envelope.is_encrypted(row.secret) and row.key_id == envelope.current_key_id()
    # Resumable: a second pass has nothing left to do.
    assert reencrypt_secrets.run(settings.postgres_url) == reencrypt_secrets.Outcome(
        scanned=1, changed=0, skipped=1
    )

    # A default pass is not a rotation: rows on the previous key stay there.
    _use(KEY_B, previous=KEY_A)
    assert reencrypt_secrets.run(settings.postgres_url).changed == 0
    assert _row(settings, created["subscription_id"]).key_id != envelope.current_key_id()

    assert reencrypt_secrets.run(settings.postgres_url, rotate=True).changed == 1
    assert _row(settings, created["subscription_id"]).key_id == envelope.current_key_id()

    assert reencrypt_secrets.run(settings.postgres_url, decrypt=True).changed == 1
    row = _row(settings, created["subscription_id"])
    assert row.secret == "hmac-key" and row.key_id is None
    assert row.headers == {"Authorization": "Bearer jira-api-token"}


# --------------------------------------------------------------------------
# A row nobody can read
# --------------------------------------------------------------------------
#
# The state every path below has to survive: a subscription written under a key
# this process does not have. It is not exotic — an operator who dropped
# ``OCTO_MASTER_KEY_PREVIOUS`` one step too early in a rotation, or a database
# restored against a different key, produces exactly this. What must not happen
# is one such row taking the tenant's other subscriptions down with it.


def _unreadable_subscription(settings: Settings, **overrides) -> dict:
    """Write a row under ``KEY_B``, then leave the process holding only ``KEY_A``.

    Both columns carry something: a path that decrypts only the headers and a
    path that decrypts only the signing secret are each broken by exactly one
    of them, and a helper that covers one of the two hides the other.
    """
    payload = {"secret": "lost-hmac-key", "headers": {"X-Api-Key": "gateway-token"}}
    payload.update(overrides)
    _use(KEY_B)
    created = _subscribe(settings, name="lost", **payload)
    _use(KEY_A)
    with pytest.raises(envelope.SecretDecryptionError):
        webhooks._base.endpoint_credentials(_row(settings, created["subscription_id"]))
    return created


@requires_postgres
def test_fan_out_does_not_read_secrets_and_keeps_the_event(settings):
    """Routing asks about enabled/kinds/severity, none of which is encrypted."""
    lost = _unreadable_subscription(settings)
    healthy = _subscribe(settings, name="healthy", secret="hmac-key")

    queued = webhooks.enqueue_event(_event())

    assert len(queued) == 2
    with get_session(settings.postgres_url) as session:
        targets = set(
            session.scalars(
                select(models.WebhookDelivery.subscription_id).where(
                    models.WebhookDelivery.delivery_id.in_(queued)
                )
            )
        )
    assert targets == {lost["subscription_id"], healthy["subscription_id"]}


@requires_postgres
def test_an_undecryptable_row_dead_letters_without_stalling_the_batch(settings):
    lost = _unreadable_subscription(settings)
    _subscribe(settings, name="healthy", secret="hmac-key")
    webhooks.enqueue_event(_event())

    sent: list[str] = []

    def _capture(url, body, headers, **kwargs):
        sent.append(url)
        return delivery_transport.DeliveryResult(
            ok=True, status_code=204, error=None, retryable=False
        )

    outcome = webhooks.dispatch_once(post=_capture)

    # The healthy subscription is delivered in the same batch, and the row that
    # cannot be signed goes to the DLQ at once rather than spending
    # `webhook_max_attempts` to arrive at the same place.
    assert (outcome["delivered"], outcome["dead"], outcome["retrying"]) == (1, 1, 0)
    assert len(sent) == 1

    dead, total = webhooks.list_deliveries(status="dead")
    assert total == 1
    assert dead[0]["subscription_id"] == lost["subscription_id"]
    assert dead[0]["attempts"] == 1
    # The dead letter says why without saying what: no ciphertext, no secret.
    assert "SecretDecryptionError" in dead[0]["last_error"]
    assert "lost-hmac-key" not in repr(dead)
    assert envelope.FORMAT_VERSION + ":" not in repr(dead)

    # And the queue is genuinely empty afterwards, not holding a released claim.
    assert webhooks.dispatch_once(post=_capture)["attempted"] == 0


@requires_postgres
def test_the_read_path_holds_no_key_at_all(settings):
    """List and get answer for a row they could not decrypt — they never try."""
    lost = _unreadable_subscription(settings)
    healthy = _subscribe(settings, name="healthy", secret="hmac-key")
    envelope.reset_for_tests()  # not even KEY_A now

    items, total = webhooks.list_subscriptions("default")
    assert total == 2
    assert {item["subscription_id"] for item in items} == {
        lost["subscription_id"],
        healthy["subscription_id"],
    }

    fetched = webhooks.get_subscription(lost["subscription_id"])
    assert fetched["headers"] == {"X-Api-Key": "***"}
    assert fetched["has_secret"] is True
    assert "gateway-token" not in repr(items)
    assert envelope.FORMAT_VERSION + ":" not in repr(items)


@requires_postgres
def test_rotation_leaves_an_unreadable_row_alone_and_reports_it(settings):
    lost = _unreadable_subscription(settings)
    _subscribe(settings, name="healthy", secret="hmac-key")
    before = _row(settings, lost["subscription_id"]).secret

    outcome = reencrypt_secrets.run(settings.postgres_url, rotate=True)

    # One row rotated (the healthy one is already current, so: skipped), one
    # named as failed — and the pass reached the second row at all, which is
    # the defect: it used to abort on the first row it could not read.
    assert (outcome.scanned, outcome.changed, outcome.skipped, outcome.failed) == (2, 0, 1, 1)
    assert _row(settings, lost["subscription_id"]).secret == before
    assert reencrypt_secrets.main(["--rotate"]) == 1


@requires_postgres
def test_prod_refuses_to_store_a_new_secret_without_a_key(settings):
    """The startup check answered for the rows that existed at boot, only."""
    settings.env = ENV_PROD

    with pytest.raises(InsecureConfigurationError) as excinfo:
        _subscribe(settings, name="new-in-prod", secret="hmac-key")
    assert envelope.MASTER_KEY_ENV in str(excinfo.value)
    assert webhooks.list_subscriptions("default")[1] == 0

    # Configured, the very same call is fine — the refusal is about the key.
    _use(KEY_A)
    created = _subscribe(settings, name="new-in-prod", secret="hmac-key")
    assert envelope.is_encrypted(_row(settings, created["subscription_id"]).secret)

    # An edit that would add a header value to an unprotected installation is
    # refused on the same terms, and changes nothing.
    envelope.reset_for_tests()
    with pytest.raises(InsecureConfigurationError):
        webhooks.update_subscription(
            created["subscription_id"], headers={"X-Api-Key": "gateway-token"}
        )
    assert _row(settings, created["subscription_id"]).headers == {}


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------


@requires_postgres
def test_prod_without_a_key_refuses_once_a_secret_is_stored(settings, caplog):
    settings.env = ENV_PROD

    # Nothing stored yet: a key is not demanded of an installation with no
    # integrations, but the omission is on the record.
    with caplog.at_level(logging.WARNING):
        crypto_startup.bootstrap(settings)
    assert envelope.MASTER_KEY_ENV in caplog.text

    # The row this check is about is one an older build wrote as typed, so it
    # is planted under `dev` — a `prod` write of it is refused outright, which
    # is the test below.
    settings.env = "dev"
    _subscribe(settings, secret="hmac-key")
    settings.env = ENV_PROD

    with pytest.raises(InsecureConfigurationError) as excinfo:
        crypto_startup.bootstrap(settings)
    assert envelope.MASTER_KEY_ENV in str(excinfo.value)
    assert "reencrypt_secrets" in str(excinfo.value)


@requires_postgres
def test_dev_without_a_key_warns_and_keeps_running(settings, caplog):
    _subscribe(settings, secret="hmac-key")
    with caplog.at_level(logging.WARNING):
        crypto_startup.bootstrap(settings)
    assert envelope.MASTER_KEY_ENV in caplog.text
    assert not envelope.encryption_enabled()


@requires_postgres
def test_configured_key_is_accepted_in_prod(settings, monkeypatch):
    settings.env = ENV_PROD
    monkeypatch.setenv(envelope.MASTER_KEY_ENV, KEY_A)
    crypto_startup.bootstrap(settings)
    assert envelope.encryption_enabled()

    _subscribe(settings, secret="hmac-key")
    crypto_startup.bootstrap(settings)
    assert envelope.encryption_enabled()


@requires_postgres
def test_headers_only_subscription_also_counts_as_stored_secrets(settings):
    """A ticket transport carries its token in a header and no `secret` at all."""
    created = _subscribe(
        settings,
        transport="jira",
        headers={"Authorization": "Bearer jira-api-token"},
        transport_config={"project_key": "SEC", "issue_type": "Task"},
    )
    assert _row(settings, created["subscription_id"]).secret is None

    settings.env = ENV_PROD
    with pytest.raises(InsecureConfigurationError):
        crypto_startup.bootstrap(settings)
