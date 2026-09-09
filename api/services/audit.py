"""The administrative audit trail: who changed what, and to what (#327).

``auth_audit`` next door owns ``auth_events`` — logins, refusals, trust
changes. This module owns ``audit_events``, which answers the other half of
the question an auditor asks: not "who got in" but "what did they do once they
were in". The two stay separate because their lifetimes are: the login trail
doubles as the rate limiter's counter and is pruned on the login path, while
these rows are append-only in the database itself (#329) and are removed only
by the privileged sweep in :mod:`api.services.audit_retention`.

**Recorded in the caller's session, on purpose.** :func:`record` takes the
session the change itself is being made in, so the row and the change commit
or roll back together. A membership that was granted but not recorded, or
recorded but not granted, is worse than either — the first is a silent change,
the second is a trail that lies. The route builds an :class:`AuditContext`
from its ``Request`` (actor, client address, user agent, ``X-Request-Id``) and
hands it to the service, which is the layer that has the session.

**Secrets never reach ``before``/``after``.** :func:`redact` walks both
documents and replaces the value of anything whose field name reads like a
credential — passwords and their hashes, token plaintexts and hashes,
provisioning keys, webhook and client secrets. It replaces rather than drops,
so the trail still shows *that* a password was set without showing what to.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Iterator

from sqlalchemy import func, select, tuple_

from api.core.client_ip import parse_trusted_proxies, resolve_client_ip
from api.db import models
from api.db.engine import get_session
from api.settings import Settings

logger = logging.getLogger(__name__)

# What the actor is, not what it is called. A service token and the console
# account that minted it can carry the same name; only this tells them apart.
ACTOR_USER = "user"
ACTOR_SERVICE_TOKEN = "service_token"
ACTOR_AGENT = "agent"
ACTOR_SYSTEM = "system"
ACTOR_TYPES = (ACTOR_USER, ACTOR_SERVICE_TOKEN, ACTOR_AGENT, ACTOR_SYSTEM)

# ``resource.verb``. Kept as constants so the console's filter and the export's
# consumers have a closed set to switch on, and so a typo at a call site is a
# NameError rather than a row nobody will ever find again.
ACTION_USER_CREATE = "user.create"
ACTION_USER_ROLE = "user.role_change"
ACTION_USER_DISABLE = "user.disable"
ACTION_USER_DELETE = "user.delete"
ACTION_MEMBERSHIP_GRANT = "membership.grant"
ACTION_MEMBERSHIP_REVOKE = "membership.revoke"
ACTION_SERVICE_TOKEN_CREATE = "service_token.create"
ACTION_SERVICE_TOKEN_REVOKE = "service_token.revoke"
ACTION_PROVISIONING_KEY_CREATE = "provisioning_key.create"
ACTION_PROVISIONING_KEY_REVOKE = "provisioning_key.revoke"
ACTION_AGENT_REGISTER = "agent.register"
ACTION_REPORT_DOWNLOAD = "report.download"
ACTION_SCAN_SCOPE_REPLACE = "scan_scope.replace"
ACTION_CONFIG_UPDATE = "config.update"

#: The value stored in place of a secret. Not the empty string and not a
#: dropped key: "this field was set, and its value is not in the audit trail"
#: is itself information an auditor wants.
REDACTED = "[redacted]"

# Exact field names that carry credential material.
_REDACTED_NAMES = frozenset(
    {
        "password",
        "current_password",
        "new_password",
        "password_hash",
        "token",
        "token_hash",
        "key",
        "key_hash",
        "secret",
        "credentials",
    }
)
# ...and the suffixes that cover the ones nobody has written yet. A field named
# ``*_secret`` or ``*_token`` in a future model is redacted without this file
# being edited, which is the direction the default should fail in.
_REDACTED_SUFFIXES = ("_password", "_secret", "_token", "_key", "_hash")

# Serialised documents past this are stored as a marker instead. ``before``/
# ``after`` describe one resource; anything this large is a payload that has
# escaped its route's own limits, and the audit table is the wrong place to
# discover that.
_MAX_DOCUMENT_BYTES = 16 * 1024

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "audit.configure() not called"
    return _settings


def _now() -> datetime:
    # Naive UTC, matching every other timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in _REDACTED_NAMES or lowered.endswith(_REDACTED_SUFFIXES)


def redact(payload: Any) -> Any:
    """Copy ``payload`` with every credential-looking field replaced.

    Recursive, because the shapes handed in are nested — a scan scope is a list
    of entries, a config override is a tree. Values that are neither dict nor
    list are returned as they are: this decides by *field name*, since a bare
    string carries nothing that says whether it is a hostname or a token.
    """
    if isinstance(payload, dict):
        return {
            key: REDACTED if _is_secret_name(str(key)) else redact(value)
            for key, value in payload.items()
        }
    if isinstance(payload, (list, tuple)):
        return [redact(item) for item in payload]
    return payload


def _document(payload: Any) -> dict[str, Any] | None:
    """A redacted, size-capped, JSON-serialisable document, or None."""
    if payload is None:
        return None
    cleaned = redact(payload)
    if not isinstance(cleaned, dict):
        cleaned = {"value": cleaned}
    try:
        encoded = json.dumps(cleaned, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return {"unserialisable": True}
    if len(encoded) > _MAX_DOCUMENT_BYTES:
        return {"truncated": True, "bytes": len(encoded)}
    # Round-tripped so what is stored is exactly what ``json.dumps`` accepted:
    # a datetime that ``default=str`` rendered must not go on to the JSON column
    # as a datetime object.
    return json.loads(encoded)


@dataclass(frozen=True)
class AuditContext:
    """Who is making a change and from where — everything but the change itself.

    Built once per request by :func:`context_from_request` and passed down to
    whichever service performs the change, so the service layer never has to
    know what a ``Request`` is.
    """

    actor: str
    actor_type: str = ACTOR_USER
    client_ip: str = ""
    user_agent: str = ""
    request_id: str | None = None


def system_context(actor: str = "system") -> AuditContext:
    """Context for a change no request asked for — a worker, a migration, a CLI."""
    return AuditContext(actor=actor, actor_type=ACTOR_SYSTEM)


def context_from_request(
    request, settings: Settings, *, actor: str, actor_type: str | None = None
) -> AuditContext:
    """Read the actor's address, client and request id off one request.

    ``client_ip`` goes through the same trusted-proxy resolution the login
    limiter uses, never a raw ``X-Forwarded-For``: an audit row that names an
    address the caller chose for itself is worse than one with no address.

    ``request_id`` is ``X-Request-Id`` when the caller (or the ingress) sent
    one and None otherwise — this deliberately does not invent one, so the
    value in the trail always matches a value that existed on the wire.
    """
    headers = request.headers
    if actor_type is None:
        # A presented service token is stashed on the request by
        # ``api.auth._authenticate_service_token``; a route whose caller is an
        # agent says so itself, since an agent never reaches that code path.
        actor_type = (
            ACTOR_SERVICE_TOKEN
            if getattr(request.state, "service_token", None) is not None
            else ACTOR_USER
        )
    client_ip = resolve_client_ip(
        request.client.host if request.client else None,
        headers.get("x-forwarded-for"),
        parse_trusted_proxies(settings.trusted_proxies),
    )
    request_id = (headers.get("x-request-id") or "").strip() or None
    return AuditContext(
        actor=actor,
        actor_type=actor_type,
        client_ip=client_ip[:64],
        user_agent=(headers.get("user-agent") or "")[:256],
        request_id=request_id[:128] if request_id else None,
    )


def record(
    session,
    context: AuditContext | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    tenant_id: str | None = None,
    before: Any = None,
    after: Any = None,
) -> None:
    """Append one row **to the caller's session**, so it commits with the change.

    ``context`` may be None: that is the call path with no request behind it
    (a test helper, a worker), and it records the change as ``system`` rather
    than dropping it. Nothing here flushes — the caller's transaction decides
    when both writes land.
    """
    ctx = context or system_context()
    session.add(
        models.AuditEvent(
            occurred_at=_now(),
            tenant_id=tenant_id,
            actor=(ctx.actor or "")[:128],
            actor_type=ctx.actor_type if ctx.actor_type in ACTOR_TYPES else ACTOR_SYSTEM,
            action=action,
            resource_type=resource_type,
            resource_id=(resource_id or "")[:255],
            before=_document(before),
            after=_document(after),
            client_ip=ctx.client_ip,
            user_agent=ctx.user_agent,
            request_id=ctx.request_id,
        )
    )


def record_standalone(
    context: AuditContext | None,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    tenant_id: str | None = None,
    before: Any = None,
    after: Any = None,
) -> None:
    """Record in a transaction of its own, for changes that have no session.

    Used where the audited act is not a database write at all — downloading a
    report is a file read, and there is no transaction to join. Everything that
    *does* write should use :func:`record` instead: this variant can commit
    while the change it describes rolls back.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        record(
            session,
            context,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            before=before,
            after=after,
        )


def _to_dict(row: models.AuditEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "occurred_at": _iso(row.occurred_at),
        "tenant_id": row.tenant_id,
        "actor": row.actor,
        "actor_type": row.actor_type,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "before": row.before,
        "after": row.after,
        "client_ip": row.client_ip,
        "user_agent": row.user_agent,
        "request_id": row.request_id,
    }


def _conditions(
    *,
    tenant_id: str | None,
    actor: str | None,
    action: str | None,
    resource_type: str | None,
    resource_id: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list:
    """The filter set shared by the page and the export, so they cannot drift.

    ``tenant_id`` None means "every tenant", which is a platform admin's
    listing; a tenant admin's route always passes their own. Rows with a NULL
    tenant (platform-level acts) therefore never appear in a tenant-scoped
    answer — they were not done in that tenant.
    """
    conditions = []
    if tenant_id is not None:
        conditions.append(models.AuditEvent.tenant_id == tenant_id)
    if actor:
        conditions.append(models.AuditEvent.actor == actor)
    if action:
        conditions.append(models.AuditEvent.action == action)
    if resource_type:
        conditions.append(models.AuditEvent.resource_type == resource_type)
    if resource_id:
        conditions.append(models.AuditEvent.resource_id == resource_id)
    if since is not None:
        conditions.append(models.AuditEvent.occurred_at >= since)
    if until is not None:
        conditions.append(models.AuditEvent.occurred_at <= until)
    return conditions


def list_events(
    *,
    tenant_id: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """Newest-first page, with ``total`` counted after filtering.

    Filtered and counted in SQL like the other Postgres-backed lists (ROADMAP
    P3.2). ``id`` breaks ties on the timestamp: two changes can share one at
    this resolution, and an unstable order repeats or skips a row across pages.
    """
    settings = _require_settings()
    conditions = _conditions(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since,
        until=until,
    )
    with get_session(settings.postgres_url) as session:
        total = session.execute(
            select(func.count()).select_from(models.AuditEvent).where(*conditions)
        ).scalar_one()
        rows = (
            session.execute(
                select(models.AuditEvent)
                .where(*conditions)
                .order_by(models.AuditEvent.occurred_at.desc(), models.AuditEvent.id.desc())
                .offset(offset)
                .limit(limit)
            )
            .scalars()
            .all()
        )
        return [_to_dict(row) for row in rows], int(total)


def iter_events(
    *,
    tenant_id: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    batch_size: int = 500,
) -> Iterator[dict[str, Any]]:
    """Every matching row, newest first, in batches — the export's reader.

    Keyset paging on ``(occurred_at, id)`` rather than a growing OFFSET: the
    table is append-only and busy, so an export that walked offsets would
    re-read what a concurrent insert had shifted, and the deep pages would each
    cost the database everything before them. Each batch is its own short
    transaction, so a slow client streaming a year of history does not hold one
    open for the length of the download.
    """
    settings = _require_settings()
    conditions = _conditions(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since,
        until=until,
    )
    cursor: tuple[datetime, int] | None = None
    while True:
        with get_session(settings.postgres_url) as session:
            stmt = select(models.AuditEvent).where(*conditions)
            if cursor is not None:
                stmt = stmt.where(
                    tuple_(models.AuditEvent.occurred_at, models.AuditEvent.id) < cursor
                )
            rows = (
                session.execute(
                    stmt.order_by(
                        models.AuditEvent.occurred_at.desc(), models.AuditEvent.id.desc()
                    ).limit(batch_size)
                )
                .scalars()
                .all()
            )
            batch = [_to_dict(row) for row in rows]
            cursor = (rows[-1].occurred_at, rows[-1].id) if rows else None
        yield from batch
        if len(batch) < batch_size:
            return


def reset_for_tests() -> None:
    """Empty the trail between tests, through the privileged prune function.

    A plain DELETE is refused by the trigger migration 0037 installs — which is
    the point of #329 — so the suite empties the table the same way retention
    does. The SQLite dev fallback has neither trigger nor function and takes
    the delete directly.
    """
    from api.services import audit_retention

    audit_retention.prune(_require_settings(), cutoff=datetime.max)
