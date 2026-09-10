"""Fail-closed startup check for secrets at rest (#310).

Refusing to start whenever ``OCTO_MASTER_KEY`` is unset would break every
existing prod installation on upgrade, and would demand a key from an
installation that has no integration secrets to protect. Refusing to start only
when there *are* secrets is the same rule the rest of the fail-closed checks
follow (``api/settings.py::_validate_production``): distinguish "forgot to
configure" from "does not use this".

So the question this asks the database is deliberately narrow and cheap — "does
any row hold integration secret material?" — and it is asked once, at startup,
against a table capped at ``webhook_max_subscriptions_per_tenant`` rows per
tenant. Both answers are actionable:

* rows that are already encrypted cannot be read at all without the key, so the
  process would come up and fail every delivery instead;
* rows that are still plaintext are exactly what #310 is about, and starting
  would mean deciding to keep them that way.
"""

from __future__ import annotations

import logging

from sqlalchemy import Text, cast, func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services.crypto import envelope
from api.settings import ENV_PROD, InsecureConfigurationError, Settings

logger = logging.getLogger(__name__)

_REFUSAL = (
    f"Refusing to start: this installation stores secrets at rest but "
    f"{envelope.MASTER_KEY_ENV} is unset.\n\n"
    "  Webhook signing secrets and the header values that carry a Jira /\n"
    "  ServiceNow / DefectDojo token live in the webhook_subscriptions table,\n"
    "  the per-tenant Slack URLs and DefectDojo tokens live in\n"
    "  notification_channels, and the TOTP seeds of every enrolled account live\n"
    "  in users.mfa_secret.\n"
    "  Without a master key they are written to Postgres as typed, so a dump, a\n"
    "  backup or a read replica hands over every tenant's tracker tokens; rows\n"
    "  that are already encrypted cannot be read back at all.\n\n"
    f"  Generate a key with: openssl rand -base64 32\n"
    f"  Put it in {envelope.MASTER_KEY_ENV} (Secret shapoclyack-api-users, or the\n"
    "  ExternalSecret in k8s/shapoclyack/examples/), then encrypt what is already\n"
    "  stored with: python -m api.db.reencrypt_secrets\n\n"
    "  See docs/operations.md § Secrets at rest."
)


def _has_stored_mfa_secrets(settings: Settings) -> bool:
    """Whether any account has enrolled a second factor (#315).

    Asked alongside the webhook question and for the same reason: a TOTP seed
    written as typed is a value that lets a database reader generate an admin's
    codes, and an installation that has some must not come up without the key
    that was meant to be protecting them.
    """
    with get_session(settings.postgres_url) as session:
        found = session.execute(
            select(models.User.username)
            .where(models.User.mfa_secret.is_not(None))
            .limit(1)
        ).first()
    return found is not None


def _has_stored_integration_secrets(settings: Settings) -> bool:
    """Whether any subscription carries a secret or a configured header.

    ``length(headers::text) > 2`` is "not the empty object": the column is JSON
    on both Postgres and the SQLite dev fallback, and neither compares a JSON
    value to ``{}`` portably. No index — the predicate is a full scan of a small
    table run once per process start, and an index maintained on every webhook
    write to serve that would be the wrong trade.
    """
    with get_session(settings.postgres_url) as session:
        found = session.execute(
            select(models.WebhookSubscription.subscription_id)
            .where(
                or_(
                    models.WebhookSubscription.key_id.is_not(None),
                    models.WebhookSubscription.secret.is_not(None),
                    func.length(cast(models.WebhookSubscription.headers, Text)) > 2,
                )
            )
            .limit(1)
        ).first()
    return found is not None


def _has_stored_channel_secrets(settings: Settings) -> bool:
    """Whether any notification channel carries a credential (#351).

    Asked alongside the two questions above and for the same reason: a Slack
    incoming-webhook URL written as typed lets a database reader post into a
    customer's operations channel, and a DefectDojo token lets them write
    findings into it.

    ``secret``/``key_id`` and no JSON predicate, unlike the webhook question:
    ``config`` here holds recipients and product names, which are not secret
    material and must not make an installation demand a key it has no use for.
    """
    with get_session(settings.postgres_url) as session:
        found = session.execute(
            select(models.NotificationChannel.channel_id)
            .where(
                or_(
                    models.NotificationChannel.key_id.is_not(None),
                    models.NotificationChannel.secret.is_not(None),
                )
            )
            .limit(1)
        ).first()
    return found is not None


def bootstrap(settings: Settings) -> None:
    """Resolve the KEK provider and decide whether this install may run without one.

    Called from ``create_app()`` after the stores are up, next to
    ``users_service.bootstrap`` and for the same reason: only the database can
    tell an installation that needs a key from one that does not.
    """
    envelope.configure()
    if envelope.encryption_enabled():
        # Reading the id here rather than at the first write: a provider this
        # build has no client for (OCTO_MASTER_KEY_PROVIDER=vault-transit) must
        # refuse at startup, not on the first webhook an operator creates.
        logger.info(
            "Integration secrets are encrypted at rest with key id %s",
            envelope.current_key_id(),
        )
        return

    if not (
        _has_stored_integration_secrets(settings)
        or _has_stored_mfa_secrets(settings)
        or _has_stored_channel_secrets(settings)
    ):
        logger.warning(
            "%s is unset: integration secrets and TOTP seeds would be stored in "
            "Postgres as typed. "
            "Nothing is stored yet, so this is not refused — set the key before "
            "configuring a webhook, a ticket integration or a notification "
            "channel, or enrolling MFA.",
            envelope.MASTER_KEY_ENV,
        )
        return

    if settings.env != ENV_PROD:
        logger.warning(
            "%s is unset and secrets are already stored: they stay in "
            "Postgres as typed. Allowed under OCTO_ENV=%s only.",
            envelope.MASTER_KEY_ENV,
            settings.env,
        )
        return

    raise InsecureConfigurationError(_REFUSAL)
