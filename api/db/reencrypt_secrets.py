"""Online (re-)encryption of the secrets this platform stores in Postgres (#310).

Three tables: ``webhook_subscriptions`` (the integration credentials this
command was written for), ``users.mfa_secret`` (the TOTP seeds, #315) and
``notification_channels.secret`` (the per-tenant Slack/Teams/Mattermost
incoming-webhook URLs and DefectDojo tokens, #351). One tally covers all of
them, because an operator rotating a key wants one answer to "is the old key
still needed", not one per feature.

Three passes over the same rows, chosen by flag:

* default — encrypt what is still plaintext, leaving encrypted rows alone;
* ``--rotate`` — additionally rewrap rows whose KEK id is not the current one,
  which needs the old key in ``OCTO_MASTER_KEY_PREVIOUS``;
* ``--decrypt`` — write every value back as plaintext, which is what a rollback
  to a pre-#310 image needs while the key is still configured.

**Online, not a migration.** The stored form is self-describing and the read
path accepts plaintext, so a half-finished pass is a working installation, and
running this against a live API is safe: each row is read, transformed and
written inside its own short transaction, taking ``SELECT … FOR UPDATE`` on the
row so a concurrent PATCH of the same subscription is serialised against it
rather than lost. Rerunning it is a no-op for the rows already done — that is
what makes it resumable after an interrupt.

It is deliberately *not* wired into the API's startup or into the migration
initContainer: a data pass that rewrites credentials is an operator action
taken with the runbook open (docs/operations.md § Secrets at rest), not
something a pod does on its way up.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import dataclass

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services.crypto import envelope
from api.services.integrations import channels as channels_service
from api.services.integrations import webhooks as webhooks_service

_log = logging.getLogger("api.db.reencrypt_secrets")


@dataclass
class Outcome:
    """What the pass did, in rows. Printed, and asserted on by the tests."""

    scanned: int = 0
    changed: int = 0
    skipped: int = 0
    #: Rows left as they were because their key is not configured. A rotation
    #: is precisely the moment a table legitimately holds several KEK ids, so
    #: one row written under a key nobody kept must not end the pass before the
    #: rows that *can* be rewrapped — it must be named at the end instead.
    failed: int = 0


def _database_url() -> str:
    url = os.environ.get("OCTO_POSTGRES_URL", "").strip()
    if not url:
        raise RuntimeError(
            "OCTO_POSTGRES_URL must be set to re-encrypt secrets.\n"
            "  This is the same connection the API uses; see docs/configuration.md."
        )
    return url


def _target(value: str | None, *, context: str, rotate: bool, decrypt: bool) -> str | None:
    """The form ``value`` should be stored in, or ``value`` when it already is.

    The early returns are what keeps a default pass from quietly doing a
    rotation's work: a value that is already an envelope is only touched when
    ``--rotate`` says so, and then only if its key is not the current one. They
    also mean the default pass decrypts nothing, so it runs without the old
    keys being configured at all.
    """
    if not value:
        return value
    if decrypt:
        return envelope.decrypt_secret(value, context=context)
    if envelope.is_encrypted(value):
        if not rotate or envelope.key_id_of(value) == envelope.current_key_id():
            return value
    return envelope.encrypt_secret(
        envelope.decrypt_secret(value, context=context) or "", context=context
    )


def run(url: str, *, rotate: bool = False, decrypt: bool = False, dry_run: bool = False) -> Outcome:
    """Bring every stored secret to the target form, in one tally.

    Three tables, because three tables hold credentials: ``webhook_subscriptions``
    (the integration secrets #310 was about), the TOTP seeds in
    ``users.mfa_secret`` since #315, and the per-tenant notification channels
    since #351. A rotation that covered only the first would leave every
    enrolled admin's seed — and every tenant's Slack URL — under a key the
    operator believes they have retired, which is the failure mode this command
    exists to prevent.
    """
    outcome = Outcome()

    with get_session(url) as session:
        subscription_ids = list(
            session.scalars(
                select(models.WebhookSubscription.subscription_id).order_by(
                    models.WebhookSubscription.subscription_id
                )
            )
        )

    for subscription_id in subscription_ids:
        outcome.scanned += 1
        with get_session(url) as session:
            row = session.scalar(
                select(models.WebhookSubscription)
                .where(models.WebhookSubscription.subscription_id == subscription_id)
                .with_for_update()
            )
            if row is None:  # deleted between the two transactions
                outcome.scanned -= 1
                continue

            try:
                secret = _target(
                    row.secret,
                    context=webhooks_service.SECRET_CONTEXT,
                    rotate=rotate,
                    decrypt=decrypt,
                )
                headers = {
                    str(name): _target(
                        str(value),
                        context=webhooks_service.HEADERS_CONTEXT,
                        rotate=rotate,
                        decrypt=decrypt,
                    )
                    for name, value in (row.headers or {}).items()
                }
            except envelope.SecretDecryptionError as exc:
                # Per row, not per pass: the whole point of walking the table is
                # to move the rows that can move. Aborting on the first row
                # written under a key nobody kept would leave the operator with
                # a partial pass and no idea which rows it managed. The row is
                # left exactly as it was and named in the tally; the command
                # exits non-zero so a script does not read this as success.
                outcome.failed += 1
                _log.warning(
                    "Subscription %s left unchanged: %s", subscription_id, exc
                )
                continue
            # Derived from the values rather than assumed to be the current key:
            # a default pass leaves rows on an older KEK alone, and the mirror
            # has to keep saying so. A row that somehow carries two keys reports
            # none, which is what puts it back in scope for the next pass.
            key_ids = {envelope.key_id_of(value) for value in (secret, *headers.values()) if value}
            key_id = key_ids.pop() if len(key_ids) == 1 else None

            if (secret, headers, key_id) == (row.secret, dict(row.headers or {}), row.key_id):
                outcome.skipped += 1
                continue

            outcome.changed += 1
            if dry_run:
                continue
            row.secret = secret
            row.headers = headers
            row.key_id = key_id

    _run_user_secrets(url, outcome, rotate=rotate, decrypt=decrypt, dry_run=dry_run)
    _run_channel_secrets(url, outcome, rotate=rotate, decrypt=decrypt, dry_run=dry_run)
    return outcome


def _run_channel_secrets(
    url: str, outcome: Outcome, *, rotate: bool, decrypt: bool, dry_run: bool
) -> None:
    """The same pass over ``notification_channels.secret`` (#351).

    One column rather than two, so no ``headers`` loop — but the same per-row
    ``FOR UPDATE`` and the same per-row failure handling: a Slack URL written
    under a key nobody kept must not stop the rows that can be rewrapped.
    Channels with no credential (email, whose recipients are not a secret) are
    not scanned at all, for the same reason accounts that never enrolled are
    not: counting them would report a pass over rows where nothing was at
    stake.
    """
    with get_session(url) as session:
        channel_ids = list(
            session.scalars(
                select(models.NotificationChannel.channel_id)
                .where(models.NotificationChannel.secret.is_not(None))
                .order_by(models.NotificationChannel.channel_id)
            )
        )

    for channel_id in channel_ids:
        outcome.scanned += 1
        with get_session(url) as session:
            row = session.scalar(
                select(models.NotificationChannel)
                .where(models.NotificationChannel.channel_id == channel_id)
                .with_for_update()
            )
            if row is None or not row.secret:  # deleted between the two transactions
                outcome.scanned -= 1
                continue
            try:
                target = _target(
                    row.secret,
                    context=channels_service.SECRET_CONTEXT,
                    rotate=rotate,
                    decrypt=decrypt,
                )
            except envelope.SecretDecryptionError as exc:
                outcome.failed += 1
                _log.warning("Channel %s left unchanged: %s", channel_id, exc)
                continue
            # Derived from the value just as the subscription pass derives it,
            # never assumed to be the current key: a default pass leaves rows on
            # an older KEK alone and the mirror has to keep saying so.
            key_id = envelope.key_id_of(target) if target else None
            if (target, key_id) == (row.secret, row.key_id):
                outcome.skipped += 1
                continue
            outcome.changed += 1
            if dry_run:
                continue
            row.secret = target
            row.key_id = key_id


def _run_user_secrets(
    url: str, outcome: Outcome, *, rotate: bool, decrypt: bool, dry_run: bool
) -> None:
    """The same pass over ``users.mfa_secret`` (#315), into the same tally.

    Accounts that never enrolled are not scanned at all: they hold no secret,
    so counting them would report a pass over the whole user table when nothing
    was ever at stake. There is no ``key_id`` mirror column here — the users
    table is small and read by primary key, so "which rows are on the old key"
    is a parse of the few rows that have a secret rather than a query that
    needs an index maintained on every login.
    """
    from api.services import mfa as mfa_service

    with get_session(url) as session:
        usernames = list(
            session.scalars(
                select(models.User.username)
                .where(models.User.mfa_secret.is_not(None))
                .order_by(models.User.username)
            )
        )

    for username in usernames:
        outcome.scanned += 1
        with get_session(url) as session:
            row = session.scalar(
                select(models.User).where(models.User.username == username).with_for_update()
            )
            if row is None or not row.mfa_secret:  # disenrolled between the two transactions
                outcome.scanned -= 1
                continue
            try:
                target = _target(
                    row.mfa_secret,
                    context=mfa_service.SECRET_CONTEXT,
                    rotate=rotate,
                    decrypt=decrypt,
                )
            except envelope.SecretDecryptionError as exc:
                outcome.failed += 1
                _log.warning("Account %s left unchanged: %s", username, exc)
                continue
            if target == row.mfa_secret:
                outcome.skipped += 1
                continue
            outcome.changed += 1
            if dry_run:
                continue
            row.mfa_secret = target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt, rotate or decrypt the integration secrets stored in Postgres."
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help=(
            f"Also rewrap rows written under an older KEK. The old key must be listed "
            f"in {envelope.PREVIOUS_KEYS_ENV}."
        ),
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Write every secret back as plaintext (rollback to a pre-#310 image).",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Report what would change and write nothing."
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.rotate and args.decrypt:
        _log.error("--rotate and --decrypt ask for opposite things; pick one.")
        return 2

    try:
        envelope.configure()
        # --decrypt needs a key to *read* with; the encrypting passes need one
        # to write with. Either way, no key means nothing this command can do.
        if not envelope.encryption_enabled():
            raise RuntimeError(
                f"{envelope.MASTER_KEY_ENV} is unset. Generate a key with "
                "`openssl rand -base64 32` and export it for this command — see "
                "docs/operations.md § Secrets at rest."
            )
        outcome = run(
            _database_url(), rotate=args.rotate, decrypt=args.decrypt, dry_run=args.dry_run
        )
    except Exception as exc:  # noqa: BLE001 - this is a CLI boundary
        _log.error("%s", exc)
        return 1

    _log.info(
        "%s: %d row(s) scanned, %d %s, %d already in the target form",
        "Would rewrite" if args.dry_run else "Rewrote",
        outcome.scanned,
        outcome.changed,
        "to change" if args.dry_run else "rewritten",
        outcome.skipped,
    )
    if outcome.failed:
        _log.error(
            "%d row(s) could not be read and were left as they are. Put the "
            "key that wrote them in %s and run this again; until then their "
            "deliveries dead-letter.",
            outcome.failed,
            envelope.PREVIOUS_KEYS_ENV,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    sys.exit(main())
