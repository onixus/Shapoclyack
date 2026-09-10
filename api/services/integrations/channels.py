"""Per-tenant notification channels and the finished-run fan-out (#351).

The database half: which tenant wants a finished run announced where
(``notification_channels``), and the one query the fan-out asks —
*this tenant's* enabled channels. That query is the whole point of the feature.
Before it, ``scanner/pipeline/alerts.py`` read ``OCTO_SLACK_WEBHOOK`` and
``scanner/pipeline/defectdojo.py`` read ``OCTO_DEFECTDOJO_*``, so on an MSSP
installation every tenant's scan announced itself in one channel and every
tenant's findings were imported into one product — with nothing in the code
holding a tenant id at the point the decision was made.

Nothing here opens a socket: ``channel_transports.py`` owns the wire. Same
split, and the same reason, as ``webhooks.py`` / ``delivery.py``.

**No delivery queue.** Unlike an event webhook a run summary is not replayed:
:func:`notify_run_complete` sends once, records the outcome on the row and
returns. A summary that arrives twenty minutes late describes a run the
operator has already opened in the console, and the artifacts it summarises are
in ``runs/{run_id}`` either way. The failure is visible — ``last_status`` on the
channel, a warning in the job log — rather than silent.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import tenants as tenants_service
from api.services.crypto import envelope as crypto
from api.services.integrations import channel_transports as transports
from api.services.integrations.delivery import post as _default_post
from api.settings import ENV_PROD, InsecureConfigurationError, Settings
from scanner.pipeline.alerts import format_alert_message

LOG = logging.getLogger("shapoclyack.channels")

_settings: Settings | None = None

#: Bound into the AEAD, exactly as the webhook contexts are: a ciphertext moved
#: from a webhook subscription's ``secret`` into a channel's fails its tag
#: instead of decrypting into a working credential in another table.
SECRET_CONTEXT = "notification_channels.secret"

#: A stored credential this process cannot open: a KEK that is not configured,
#: one that is configured but is not the one that wrote the row, or a provider
#: this build has no client for. Handled per channel rather than per fan-out.
_CRYPTO_ERRORS = (
    crypto.SecretDecryptionError,
    crypto.KeyProviderNotConfigured,
    crypto.MasterKeyError,
)

_PLAINTEXT_WRITE_REFUSAL = (
    "Refusing to store a notification-channel credential in plaintext: {key} is unset.\n\n"
    "  A Slack/Teams/Mattermost channel's incoming-webhook URL and a DefectDojo\n"
    "  API token would be written to Postgres as typed — the defect #310 closed\n"
    "  for webhook subscriptions. The startup check only sees the rows that\n"
    "  existed when the process came up, so the write path refuses in its own\n"
    "  right.\n\n"
    "  Generate a key with: openssl rand -base64 32\n"
    "  Put it in {key} and roll the API — see docs/operations.md § Secrets at rest."
)


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "channels.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.NotificationChannel).delete()


# --------------------------------------------------------------------------
# Secrets at rest (#310)
# --------------------------------------------------------------------------


def _encrypt_row_secrets(row: models.NotificationChannel) -> None:
    """Encrypt the row's credential and record the key that opens it.

    A copy of ``webhooks._encrypt_row_secrets`` for a table with one secret
    column instead of two, and it stays a copy rather than a shared helper on
    purpose: the AEAD context is per column, so the thing the two would share
    is three lines of ``if`` around a value each of them names differently.
    """
    if row.secret and not crypto.encryption_enabled() and _require_settings().env == ENV_PROD:
        raise InsecureConfigurationError(
            _PLAINTEXT_WRITE_REFUSAL.format(key=crypto.MASTER_KEY_ENV)
        )
    if row.secret and not (
        crypto.encryption_enabled() and crypto.key_id_of(row.secret) == crypto.current_key_id()
    ):
        # A value already under the current key is left untouched, so renaming
        # a channel does no cryptography; the rewrap branch decrypts first and
        # therefore needs the old key in OCTO_MASTER_KEY_PREVIOUS.
        row.secret = crypto.encrypt_secret(
            crypto.decrypt_secret(row.secret, context=SECRET_CONTEXT) or "",
            context=SECRET_CONTEXT,
        )
    # NULL when the row carries nothing secret — an email channel — because the
    # startup check reads a non-NULL key_id as "this installation stores
    # secrets at rest", and an address list is not one.
    row.key_id = crypto.current_key_id() if row.secret else None


def channel_credential(row: models.NotificationChannel) -> str | None:
    """The channel's credential, decrypted for one outbound send.

    The single named way to turn the stored envelope back into a webhook URL or
    an API token. A row whose key is not configured raises here rather than
    POSTing a ciphertext at Slack.
    """
    return crypto.decrypt_secret(row.secret, context=SECRET_CONTEXT)


# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------


def _to_dict(row: models.NotificationChannel) -> dict[str, Any]:
    """Serialise a channel. The credential is never part of the result.

    Only ``has_secret``, and not even once at creation — unlike a webhook
    signing secret, which this platform generates and the operator has to be
    able to paste into the receiver, every credential here is one the operator
    already holds. There is nothing to hand back, so nothing is.
    """
    return {
        "channel_id": row.channel_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "kind": row.kind,
        "enabled": row.enabled,
        "min_severity": row.min_severity,
        "endpoint": row.endpoint,
        "config": dict(row.config or {}),
        "has_secret": bool(row.secret),
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
        "last_send_at": _iso(row.last_send_at),
        "last_status": row.last_status,
    }


def create_channel(
    *,
    tenant_id: str,
    name: str,
    kind: str,
    endpoint: str | None = None,
    secret: str | None = None,
    config: dict[str, Any] | None = None,
    min_severity: str | None = None,
    enabled: bool = True,
    created_by: str | None = None,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Create one channel for one tenant.

    Every validation the adapter needs runs here, before the row exists: a
    channel that cannot send is not a configuration an operator should have to
    discover from the next scan's log.
    """
    settings = _require_settings()
    name = (name or "").strip()
    if not name:
        raise ValueError("channel name required")
    if tenants_service.get_tenant(tenant_id) is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")

    channel_kind = transports.validate_kind(kind)
    row = models.NotificationChannel(
        channel_id=f"nc_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        name=name,
        kind=channel_kind,
        enabled=bool(enabled),
        min_severity=transports.validate_min_severity(min_severity),
        endpoint=transports.validate_endpoint(
            channel_kind, endpoint, allow_private=settings.webhook_allow_private_targets
        ),
        config=transports.validate_config(channel_kind, config),
        secret=transports.validate_secret(
            channel_kind, secret, allow_private=settings.webhook_allow_private_targets
        ),
        created_at=_now(),
        created_by=created_by,
        updated_at=_now(),
    )
    _encrypt_row_secrets(row)
    with get_session(settings.postgres_url) as session:
        # Count-then-insert serialised on the tenant row, as webhook
        # subscriptions do (#153): two concurrent creates can both pass the
        # count at N-1 otherwise. A no-op on SQLite, whose writers are
        # serialised by the file lock.
        session.execute(
            select(models.Tenant.tenant_id)
            .where(models.Tenant.tenant_id == tenant_id)
            .with_for_update()
        ).all()
        existing = session.execute(
            select(func.count())
            .select_from(models.NotificationChannel)
            .where(models.NotificationChannel.tenant_id == tenant_id)
        ).scalar_one()
        if existing >= settings.notification_channel_max_per_tenant:
            raise ValueError(
                f"tenant {tenant_id} already has {existing} notification channels "
                f"(limit {settings.notification_channel_max_per_tenant})"
            )
        session.add(row)
        session.flush()
        result = _to_dict(row)
        # In the same transaction as the row: deciding where this tenant's
        # exposure data is sent is an administrative act, and the trail must
        # not record one that rolled back. ``after`` is the serialised row,
        # which holds no credential — only ``has_secret``.
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_NOTIFICATION_CHANNEL_CREATE,
            resource_type="notification_channel",
            resource_id=row.channel_id,
            tenant_id=tenant_id,
            after=result,
        )
    return result


def list_channels(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """A tenant's channels, oldest first. ``None`` is the cross-tenant view.

    Unpaginated, unlike the webhook list: the table is capped at
    ``notification_channel_max_per_tenant`` rows per tenant, so a page
    parameter would be a knob with nothing behind it. The cross-tenant view is
    the unscoped platform admin's, and is bounded by the number of tenants.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        query = select(models.NotificationChannel)
        if tenant_id:
            query = query.where(models.NotificationChannel.tenant_id == tenant_id)
        rows = session.execute(
            query.order_by(
                models.NotificationChannel.created_at,
                models.NotificationChannel.channel_id,
            )
        ).scalars().all()
        return [_to_dict(row) for row in rows]


def get_channel(channel_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.NotificationChannel, channel_id)
        return _to_dict(row) if row else None


def update_channel(
    channel_id: str,
    *,
    audit: audit_service.AuditContext | None = None,
    **fields: Any,
) -> dict[str, Any] | None:
    """Patch one channel. ``kind`` is not patchable — recreate instead.

    A channel's kind decides what every other column means (whether ``secret``
    is a URL or a token, whether ``endpoint`` is allowed at all), so a PATCH
    that changed it would have to revalidate the row against knobs the request
    did not send. Refusing it is one line; getting it subtly wrong is a Slack
    URL POSTed to DefectDojo as a token.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        # Locked, not merely fetched: ``reencrypt_secrets`` rewrites the same
        # row under ``SELECT … FOR UPDATE``, and the runbook promises a
        # concurrent edit is serialised against that pass rather than lost.
        row = session.scalar(
            select(models.NotificationChannel)
            .where(models.NotificationChannel.channel_id == channel_id)
            .with_for_update()
        )
        if row is None:
            return None
        before = _to_dict(row)
        if "kind" in fields and transports.validate_kind(fields["kind"]) != row.kind:
            raise ValueError(
                f"a channel's kind cannot be changed (it is {row.kind}); "
                "delete this channel and create the new one"
            )
        if "name" in fields:
            name = str(fields["name"]).strip()
            if not name:
                raise ValueError("channel name required")
            row.name = name
        if "enabled" in fields:
            row.enabled = bool(fields["enabled"])
        if "min_severity" in fields:
            row.min_severity = transports.validate_min_severity(fields["min_severity"])
        if "endpoint" in fields:
            row.endpoint = transports.validate_endpoint(
                row.kind,
                fields["endpoint"],
                allow_private=settings.webhook_allow_private_targets,
            )
        if "config" in fields:
            row.config = transports.validate_config(row.kind, fields["config"])
        if "secret" in fields:
            row.secret = transports.validate_secret(
                row.kind,
                fields["secret"],
                allow_private=settings.webhook_allow_private_targets,
            )
        row.updated_at = _now()
        _encrypt_row_secrets(row)
        session.flush()
        result = _to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_NOTIFICATION_CHANNEL_UPDATE,
            resource_type="notification_channel",
            resource_id=channel_id,
            tenant_id=row.tenant_id,
            before=before,
            after=result,
        )
    return result


def delete_channel(
    channel_id: str, *, audit: audit_service.AuditContext | None = None
) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.NotificationChannel, channel_id)
        if row is None:
            return False
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_NOTIFICATION_CHANNEL_DELETE,
            resource_type="notification_channel",
            resource_id=channel_id,
            tenant_id=row.tenant_id,
            before=_to_dict(row),
        )
        session.delete(row)
        return True


# --------------------------------------------------------------------------
# The fan-out
# --------------------------------------------------------------------------


def _load_json(path: Path, fallback: Any) -> Any:
    """Read one run artifact, or the fallback. Never raises.

    A run whose ``summary.json`` is unreadable still gets a notification —
    "the scan finished and produced nothing readable" is the alert somebody
    most wants — so a missing artifact degrades the message rather than
    cancelling it.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback


def _record_outcome(
    settings: Settings, channel_id: str, outcome: transports.SendOutcome, now: datetime
) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.NotificationChannel, channel_id)
        if row is None:  # pragma: no cover - deleted mid-send
            return
        row.last_send_at = now
        row.last_status = (outcome.status if outcome.ok else (outcome.detail or outcome.status))[
            :200
        ]


def _send_one(
    settings: Settings,
    channel: dict[str, Any],
    *,
    credential: str | None,
    run_id: str,
    run_dir: Path,
    summary: dict[str, Any],
    diff: dict[str, Any] | None,
    post_fn=None,
) -> transports.SendOutcome:
    kind = channel["kind"]
    if kind in transports.CHAT_KINDS:
        text = format_alert_message(
            run_id=run_id,
            summary=summary,
            diff=diff,
            min_severity=channel["min_severity"],
        )
        return transports.send_chat(
            kind,
            webhook_url=credential or "",
            text=text,
            config=channel["config"],
            timeout_seconds=settings.notification_channel_timeout_seconds,
            allow_private=settings.webhook_allow_private_targets,
            post_fn=post_fn or _default_post,
        )
    if kind == "email":
        text = format_alert_message(
            run_id=run_id,
            summary=summary,
            diff=diff,
            min_severity=channel["min_severity"],
        )
        return transports.send_email(
            settings,
            recipients=list(channel["config"].get("to") or []),
            subject=f"Shapoclyack scan complete ({run_id})",
            # The chat message's Slack-flavoured markers read as noise in a
            # plain-text mail, exactly as the scanner stage stripped them.
            text=text.replace("*", "").replace("`", ""),
        )
    if kind == "defectdojo":
        vulnerabilities = _load_json(run_dir / "vulnerabilities.json", [])
        if not isinstance(vulnerabilities, list):
            return transports.SendOutcome(
                ok=False, status="skipped", detail="run has no readable vulnerabilities.json"
            )
        script_findings = _load_json(run_dir / "script_findings.json", [])
        document = transports.defectdojo_document(
            vulnerabilities,
            run_id=run_id,
            min_severity=channel["min_severity"],
            script_findings=script_findings if isinstance(script_findings, list) else [],
        )
        if not document["findings"]:
            # Not an error, and deliberately not an empty import either: a
            # reimport with no findings and ``close_old_findings`` on would
            # close every finding the last scan opened.
            return transports.SendOutcome(
                ok=True,
                status="skipped",
                detail=f"no findings ≥ {channel['min_severity']}",
            )
        return transports.send_defectdojo(
            endpoint=channel["endpoint"] or "",
            token=credential or "",
            run_id=run_id,
            document=document,
            config=channel["config"],
            min_severity=channel["min_severity"],
            timeout_seconds=settings.notification_channel_timeout_seconds,
            allow_private=settings.webhook_allow_private_targets,
            post_fn=post_fn or _default_post,
        )
    return transports.SendOutcome(  # pragma: no cover - validate_kind is the gate
        ok=False, status="error", detail=f"unknown channel kind {kind}"
    )


def notify_run_complete(
    *,
    tenant_id: str,
    run_id: str,
    run_dir: Path,
    post_fn=None,
) -> list[dict[str, Any]]:
    """Announce one finished run to *this tenant's* enabled channels.

    The tenant filter in the query below is the whole fix: it is the first time
    the code that decides where an alert goes holds the id of the tenant the
    run belongs to. A channel belonging to another tenant is not merely
    unselected — it is not read at all.

    Returns one entry per channel it tried, for the caller's log. Never raises:
    a channel that cannot be decrypted, a receiver that is down and a relay
    that refuses the recipients are all reported as data, because none of them
    is a reason to fail the scan that has already succeeded.

    ``post_fn`` is the injection seam the tests drive; production passes
    nothing and gets ``delivery.post``.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.NotificationChannel).where(
                models.NotificationChannel.tenant_id == tenant_id,
                models.NotificationChannel.enabled.is_(True),
            )
        ).scalars().all()
        # Decrypted inside the session, serialised out of it: the send itself
        # takes seconds against a third party and must not hold a transaction
        # open, the same rule the delivery loop follows.
        targets: list[tuple[dict[str, Any], str | None, str | None]] = []
        for row in rows:
            try:
                targets.append((_to_dict(row), channel_credential(row), None))
            except _CRYPTO_ERRORS as exc:
                # One row under a key nobody kept must not cost the tenant its
                # other channels — the same per-row rule ``reencrypt_secrets``
                # follows. Narrow on purpose: only "this row cannot be opened"
                # is a per-channel failure, and anything else is a bug this
                # function should not be hiding.
                targets.append((_to_dict(row), None, f"{type(exc).__name__}: {exc}"))

    summary = _load_json(run_dir / "summary.json", {})
    diff = _load_json(run_dir / "diff.json", None)
    results: list[dict[str, Any]] = []
    for channel, credential, failure in targets:
        if failure:
            outcome = transports.SendOutcome(ok=False, status="error", detail=failure)
        else:
            try:
                outcome = _send_one(
                    settings,
                    channel,
                    credential=credential,
                    run_id=run_id,
                    run_dir=run_dir,
                    summary=summary if isinstance(summary, dict) else {},
                    diff=diff if isinstance(diff, dict) else None,
                    post_fn=post_fn,
                )
            except Exception as exc:  # noqa: BLE001 - one channel, not the run
                LOG.warning(
                    "Notification channel %s (%s) failed for run %s",
                    channel["channel_id"],
                    channel["kind"],
                    run_id,
                    exc_info=True,
                )
                outcome = transports.SendOutcome(
                    ok=False, status="error", detail=f"{type(exc).__name__}: {exc}"[:200]
                )
        _record_outcome(settings, channel["channel_id"], outcome, _now())
        if not outcome.ok:
            LOG.warning(
                "Notification channel %s (%s, tenant=%s) did not send run %s: %s",
                channel["channel_id"],
                channel["kind"],
                tenant_id,
                run_id,
                outcome.detail,
            )
        results.append(
            {
                "channel_id": channel["channel_id"],
                "kind": channel["kind"],
                "status": outcome.status,
                "detail": outcome.detail,
            }
        )
    return results
