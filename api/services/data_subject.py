"""Data-subject requests for console accounts: export and erasure (#332).

A console account is a person — a name in ``users.username``, an address, an
identity at the customer's IdP, the addresses they signed in from — and a DPA
has to be able to answer two requests about them: *give me what you hold*
(GDPR Art. 15/20, 152-ФЗ ст. 14) and *delete it* (Art. 17, ст. 21). Both are
platform-admin acts, because accounts are platform-level: a tenant admin can
take somebody out of their tenant, never out of the installation.

**The pseudonym.** The administrative trail is append-only in the database
(#329) and names every actor by username; so do some thirty ``*_by`` columns
across the schema — who approved a scope, who accepted a risk, who requested a
scan. None of those can be rewritten, and most must not be: "who accepted this
risk" is the control, and an erasure request is not a way to make it unanswered.
So erasure keeps the **username** and removes everything that ties it to a
person. The account row stays as a tombstone (``users.erased_at``) holding the
name alone, which is what makes the name *stable*: freed, it could be issued to
somebody else, and the trail would start attributing a stranger's history to
them. What is left is a pseudonym whose key — the address, the IdP subject —
the platform no longer has.

That is only as good as the username itself. An installation whose usernames
*are* addresses (``OCTO_OIDC_USERNAME_CLAIM=email``) keeps the address in the
trail until the trail ages out; docs/data-retention.md says so, and says to
prefer an opaque claim for exactly this reason.

What erasure removes, in one transaction with its audit row:

* on the account: the password hash, the email and its verified flag, the IdP
  issuer and subject, the TOTP secret, recovery codes and enrolment time; the
  account is disabled, its role lowered to ``viewer`` and every token it holds
  refused (``token_version`` moves on);
* rows that exist only for the account: memberships, security keys and
  passkeys, pending WebAuthn challenges, sign-in sessions and their refresh
  tokens, the logout denylist;
* its address from the recipients of every scheduled report.

What it keeps, and why, is :data:`SUBJECT_COLUMNS` below — one entry per
column that can name an account, which ``tests/test_data_subject.py`` checks
against the models so a column added later cannot be forgotten by both.

Guard rails: nobody erases their own account (the request is answered by
somebody else, and the platform would otherwise sign the requester out halfway
through), the last platform admin cannot be erased, an account whose tenant is
on legal hold cannot be erased (Art. 17(3)(e)), and the route is behind a
step-up. Erasing an account already erased changes nothing and says so.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, delete, func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import legal_hold
from api.services import service_tokens as service_tokens_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.data-subject")

EXPORT_FORMAT = "shapoclyack.data-subject-export"
EXPORT_VERSION = 1

#: Per-statement cap for the export and the erasure (review round 1). Both read
#: the audit trail and the findings by columns nothing indexes for them, and an
#: index on ``audit_events`` would need its owner — the role the GRANT layout
#: takes away from the migration. A minute is generous for a request.
STATEMENT_TIMEOUT_MS = 60_000

# What erasure does to a column that can name an account.
DELETED = "deleted"  # the row exists only for the account and goes with it
CLEARED = "cleared"  # the value is removed from a row that stays
PSEUDONYM = "pseudonym"  # the username stays, as the pseudonym it becomes
RETAINED = "retained"  # kept as it is, for the reason given, until it ages out

#: Every column that can hold a console username or an account's address, with
#: what erasure does to it and why. ``(table, column): (treatment, reason)``.
SUBJECT_COLUMNS: dict[tuple[str, str], tuple[str, str]] = {
    ("users", "username"): (
        PSEUDONYM,
        "the account's key; kept as a tombstone so the name is never reissued",
    ),
    ("users", "email"): (CLEARED, "contact data"),
    ("users", "email_verified"): (CLEARED, "goes with the address"),
    ("users", "created_by"): (PSEUDONYM, "who created the account"),
    ("webauthn_credentials", "username"): (DELETED, "the account's security keys"),
    ("webauthn_challenges", "username"): (DELETED, "ceremonies in flight"),
    ("user_tenants", "username"): (DELETED, "memberships; each revocation is audited"),
    ("user_tenants", "created_by"): (PSEUDONYM, "who granted a membership"),
    ("revoked_tokens", "username"): (DELETED, "logout denylist; token_version refuses all"),
    ("session_families", "username"): (DELETED, "sign-in sessions and refresh tokens"),
    ("auth_events", "username"): (
        RETAINED,
        "sign-in security log (legitimate interest, Art. 6(1)(f)); ages out "
        "after OCTO_AUTH_EVENT_RETENTION_DAYS",
    ),
    ("audit_events", "actor"): (
        RETAINED,
        "append-only administrative trail (#329); legal obligation and "
        "legitimate interest; ages out with the audit window",
    ),
    ("report_schedules", "recipients"): (CLEARED, "the account's address, where listed"),
    ("idempotency_records", "actor"): (RETAINED, "expires by itself within 24 hours"),
    ("config_overrides", "updated_by"): (PSEUDONYM, "attribution"),
    ("tenants", "change_freeze_by"): (PSEUDONYM, "attribution"),
    # The tenant lifecycle (#325): who suspended or deleted a customer, and the
    # deletion journal that outlives the tenant as its tombstone.
    ("tenants", "status_changed_by"): (PSEUDONYM, "who suspended or resumed the tenant"),
    ("tenant_deletions", "requested_by"): (PSEUDONYM, "deletion journal"),
    ("tenant_deletions", "approved_by"): (PSEUDONYM, "deletion journal"),
    ("tenant_deletions", "cancelled_by"): (PSEUDONYM, "deletion journal"),
    ("service_tokens", "created_by"): (PSEUDONYM, "attribution"),
    ("roles", "created_by"): (PSEUDONYM, "attribution"),
    ("asset_context_events", "actor"): (PSEUDONYM, "attribution of an asset edit"),
    ("scan_schedules", "created_by"): (PSEUDONYM, "attribution"),
    ("maintenance_windows", "created_by"): (PSEUDONYM, "attribution"),
    ("maintenance_windows", "updated_by"): (PSEUDONYM, "attribution"),
    ("webhook_subscriptions", "created_by"): (PSEUDONYM, "attribution"),
    ("notification_channels", "created_by"): (PSEUDONYM, "attribution"),
    ("sla_policies", "created_by"): (PSEUDONYM, "attribution"),
    ("vulnerabilities", "state_changed_by"): (PSEUDONYM, "remediation record"),
    ("vulnerabilities", "assignee"): (PSEUDONYM, "remediation record"),
    ("vulnerabilities", "exception_by"): (PSEUDONYM, "risk-acceptance register"),
    ("vulnerabilities", "exception_approved_requested_by"): (
        PSEUDONYM,
        "risk-acceptance register",
    ),
    ("vulnerabilities", "exception_requested_by"): (PSEUDONYM, "risk-acceptance register"),
    ("vulnerabilities", "exception_decided_by"): (PSEUDONYM, "risk-acceptance register"),
    ("vulnerabilities", "fp_marked_by"): (PSEUDONYM, "remediation record"),
    ("vulnerability_events", "actor"): (PSEUDONYM, "remediation trail"),
    ("wordlists", "created_by"): (PSEUDONYM, "attribution"),
    ("agent_groups", "created_by"): (PSEUDONYM, "attribution"),
    ("jobs", "requested_by"): (PSEUDONYM, "who started a scan"),
    ("tenant_scan_scopes", "approved_by"): (PSEUDONYM, "scope-approval record"),
    ("tenant_scan_policies", "updated_by"): (PSEUDONYM, "attribution"),
    ("tenant_branding", "updated_by"): (PSEUDONYM, "attribution"),
    ("report_templates", "created_by"): (PSEUDONYM, "attribution"),
    ("report_schedules", "created_by"): (PSEUDONYM, "attribution"),
    ("generated_reports", "generated_by"): (PSEUDONYM, "attribution"),
    ("tenant_promoted_domains", "promoted_by"): (PSEUDONYM, "attribution"),
    ("tenant_quotas", "updated_by"): (PSEUDONYM, "attribution"),
    ("sla_escalation_policies", "updated_by"): (PSEUDONYM, "attribution"),
    ("endpoint_agent_releases", "uploaded_by"): (PSEUDONYM, "attribution"),
    ("endpoint_agent_policies", "updated_by"): (PSEUDONYM, "attribution"),
    ("retro_match_state", "refresh_requested_by"): (PSEUDONYM, "attribution"),
    ("tenant_retention_policies", "updated_by"): (PSEUDONYM, "attribution"),
    ("tenant_legal_holds", "set_by"): (PSEUDONYM, "who placed a hold"),
    # JSON documents (review round 1): no column name says a document holds an
    # address, so every JSON column is decided here or below.
    ("notification_channels", "config"): (
        CLEARED,
        'the account\'s address in an email channel\'s "to"; a channel left '
        "with no recipient is switched off",
    ),
    ("users", "mfa_recovery_codes"): (CLEARED, "second-factor recovery codes"),
    ("webauthn_credentials", "transports"): (DELETED, "goes with the security key"),
    ("audit_events", "before"): (RETAINED, "append-only trail; see audit_events.actor"),
    ("audit_events", "after"): (RETAINED, "append-only trail; see audit_events.actor"),
    ("generated_reports", "delivery"): (
        RETAINED,
        "log of a disclosure already made; ages out with the report",
    ),
    ("webhook_deliveries", "payload"): (
        RETAINED,
        "what was sent where, may name the account as an actor; ages out with "
        "the webhook window",
    ),
    ("vulnerability_events", "detail"): (PSEUDONYM, "remediation trail"),
    ("idempotency_records", "response"): (RETAINED, "expires by itself within 24 hours"),
    ("nats_outbox", "payload"): (RETAINED, "a message in flight, deleted once published"),
}

#: Columns that look like they name an account and do not, so the check in the
#: test can tell a decision from an omission.
NOT_SUBJECT_COLUMNS: dict[tuple[str, str], str] = {
    ("agent_deployments", "username"): "the SSH account on the target host",
    ("assets", "owner_email"): "the asset's owner, tenant business data the tenant edits",
    ("tenant_branding", "contact_email"): "the tenant's published contact address",
    ("vulnerabilities", "owner_team"): "a team name",
    ("sla_escalation_policies", "escalate_owner_team"): "a team name",
    ("jobs", "owner_id"): "a job-queue owner token, not a person",
    ("audit_events", "actor_type"): "what kind of actor, not who",
    # JSON documents that carry no console account.
    ("agent_deployments", "logs"): "the SSH push's log against the target host",
    ("agents", "labels"): "host labels",
    ("endpoint_devices", "labels"): "host labels",
    ("asset_services", "cpe"): "a service fingerprint",
    ("asset_services", "match_summary"): "a CVE match summary",
    ("config_overrides", "data"): "scanner configuration",
    ("endpoint_agent_policies", "settings"): "agent collection settings",
    ("endpoint_inventory_snapshots", "collector_warnings"): "agent warnings about a host",
    ("endpoint_inventory_snapshots", "response"): "the ingest answer sent to the agent",
    ("jobs", "command"): "the scanner command line",
    ("jobs", "scan_options"): "scan parameters",
    ("jobs", "target_counts"): "counts of targets",
    ("maintenance_windows", "scope_targets"): "network targets",
    ("report_templates", "sections"): "report layout",
    ("retro_match_state", "last_stats"): "matcher counters",
    ("risk_score_snapshots", "by_risk_level_open"): "counters",
    ("risk_score_snapshots", "by_severity_open"): "counters",
    ("risk_score_snapshots", "by_sla"): "counters",
    ("risk_score_snapshots", "by_state"): "counters",
    ("scan_schedules", "scan_options"): "scan parameters",
    # Counts per table and store, by construction (#325): the tombstone of a
    # purge names no account, which is what lets it outlive the tenant.
    ("tenant_deletion_steps", "counts"): "counters",
    ("tenant_deletions", "outcome"): "counters per store",
    ("scan_schedules", "targets"): "network targets",
    ("software_cve_matches", "evidence"): "package versions and advisories",
    ("tenant_scan_policies", "avoid_ports"): "port numbers",
    ("tenant_scan_scopes", "agent_groups"): "sensor group names",
    ("vulnerabilities", "cwe"): "weakness identifiers",
    ("vulnerabilities", "fp_evidence"): "the scanner evidence a false-positive verdict rests on",
    ("vulnerabilities", "match_evidence"): "why a retro match was made",
    ("webhook_subscriptions", "event_kinds"): "event names",
    ("webhook_subscriptions", "headers"): "HTTP headers for the receiver, set by the tenant",
    ("webhook_subscriptions", "transport_config"): "tracker project/table/test ids",
}


class ErasureRefused(Exception):
    """An erasure the platform will not perform. Routes answer 409."""


def _now() -> datetime:
    # Naive UTC, like the columns.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.isoformat() + "Z"


def _attribution_columns() -> dict[str, tuple[Any, list[Any]]]:
    """``{table: (table, [string columns that name an account])}``, by table name."""
    grouped: dict[str, tuple[Any, list[Any]]] = {}
    for mapper in models.Base.registry.mappers:
        table = mapper.local_table
        for column in table.columns:
            treatment = SUBJECT_COLUMNS.get((table.name, column.name))
            if treatment is None or treatment[0] != PSEUDONYM:
                continue
            if (table.name, column.name) == ("users", "username") or isinstance(
                column.type, JSON
            ):
                continue
            grouped.setdefault(table.name, (table, []))[1].append(column)
    return dict(sorted(grouped.items()))


# -- export --------------------------------------------------------------------


def export_user(
    settings: Settings,
    username: str,
    *,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Everything the platform holds about one account, as one JSON document.

    Raises LookupError for an account that does not exist.

    The audit rows are listed without their ``before``/``after`` documents:
    those describe what the account *did to* other accounts and tenants, and
    Art. 15(4) keeps other people's data out of one person's copy. Attributions
    — rows elsewhere that name the account — are counted per column rather
    than copied: they are the tenants' operational records, and the controller
    answering the request decides which of them to disclose.

    The export is itself recorded (``user.export``) in the same transaction:
    a bulk copy of one person's data leaving the platform is the thing a
    reviewer of the trail most wants to find.

    Raises :class:`ExportTooSlow` when a statement runs past
    :data:`STATEMENT_TIMEOUT_MS`; nothing is recorded then, because nothing
    left the platform.
    """
    try:
        return _export(settings, username, audit)
    except OperationalError as exc:
        if _timed_out(exc):
            raise ExportTooSlow(
                f"the export of {username!r} stopped at its statement timeout "
                f"({STATEMENT_TIMEOUT_MS // 1000} s): the audit trail or the findings are "
                "too large to scan inside a request right now. Retry off-peak."
            ) from exc
        raise


def _export(
    settings: Settings, username: str, audit: audit_service.AuditContext | None
) -> dict[str, Any]:
    with get_session(settings.postgres_url) as session:
        _bound(session)
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        document = {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "generated_at": _iso(_now()),
            "subject": username,
            "account": _account(row),
            "memberships": _memberships(session, username),
            "security_keys": _security_keys(session, username),
            "sessions": _sessions(session, username),
            "sign_in_history": _sign_ins(session, username),
            "administrative_activity": _audit_rows(
                session,
                models.AuditEvent.actor == username,
                models.AuditEvent.actor_type == audit_service.ACTOR_USER,
            ),
            "changes_to_account": _audit_rows(
                session,
                models.AuditEvent.resource_type == "user",
                models.AuditEvent.resource_id == username,
            ),
            "report_recipient_of": _report_schedules_listing(session, row.email),
            "notification_recipient_of": _channels_listing(session, row.email),
            "attributions": _attributions(session, username),
            "retention": {
                "sign_in_history_days": settings.auth_event_retention_days,
                "note": (
                    "The administrative trail is append-only and kept for the audit "
                    "window of each tenant; see docs/data-retention.md."
                ),
            },
        }
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_EXPORT,
            resource_type="user",
            resource_id=username,
            after={
                section: len(document[section])
                for section in (
                    "memberships",
                    "security_keys",
                    "sessions",
                    "sign_in_history",
                    "administrative_activity",
                    "changes_to_account",
                    "report_recipient_of",
                    "notification_recipient_of",
                )
            },
        )
        return document


def _account(row: models.User) -> dict[str, Any]:
    codes = list(row.mfa_recovery_codes or [])
    return {
        "username": row.username,
        "role": row.role,
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
        "disabled_at": _iso(row.disabled_at),
        "erased_at": _iso(row.erased_at),
        "password_set": bool(row.password_hash),
        "password_changed_at": _iso(row.password_changed_at),
        "email": row.email,
        "email_verified": bool(row.email_verified),
        # The IdP identity *is* the subject's data, unlike on the users page:
        # a DSAR answer that omitted it would omit the key that links them.
        "sso_identity": (
            {"issuer": row.oidc_issuer, "subject": row.oidc_subject}
            if row.oidc_subject
            else None
        ),
        # That a factor exists and when; never the secret, never a code hash.
        "mfa_enabled_at": _iso(row.mfa_enabled_at),
        "recovery_codes_remaining": sum(1 for code in codes if not code.get("used_at")),
    }


def _memberships(session: Session, username: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(models.UserTenant)
        .where(models.UserTenant.username == username)
        .order_by(models.UserTenant.tenant_id)
    ).scalars()
    return [
        {
            "tenant_id": row.tenant_id,
            "role": row.role,
            "granted_at": _iso(row.created_at),
            "granted_by": row.created_by,
        }
        for row in rows
    ]


def _security_keys(session: Session, username: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(models.WebAuthnCredential)
        .where(models.WebAuthnCredential.username == username)
        .order_by(models.WebAuthnCredential.created_at)
    ).scalars()
    return [
        {
            "name": row.name,
            "created_at": _iso(row.created_at),
            "last_used_at": _iso(row.last_used_at),
            "device_type": row.device_type,
            "backed_up": bool(row.backed_up),
            "transports": list(row.transports or []),
        }
        for row in rows
    ]


def _sessions(session: Session, username: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(models.SessionFamily)
        .where(models.SessionFamily.username == username)
        .order_by(models.SessionFamily.created_at)
    ).scalars()
    return [
        {
            "created_at": _iso(row.created_at),
            "last_used_at": _iso(row.last_used_at),
            "expires_at": _iso(row.expires_at),
            "mfa_method": row.mfa_method,
            "ended_at": _iso(row.revoked_at),
            "ended_because": row.revoked_reason,
        }
        for row in rows
    ]


def _sign_ins(session: Session, username: str) -> list[dict[str, Any]]:
    rows = session.execute(
        select(models.AuthEvent)
        .where(models.AuthEvent.username == username)
        .order_by(models.AuthEvent.occurred_at, models.AuthEvent.id)
    ).scalars()
    return [
        {
            "occurred_at": _iso(row.occurred_at),
            "client_ip": row.client_ip,
            "outcome": row.outcome,
            "reason": row.reason,
        }
        for row in rows
    ]


def _audit_rows(session: Session, *conditions) -> list[dict[str, Any]]:
    rows = session.execute(
        select(models.AuditEvent)
        .where(*conditions)
        .order_by(models.AuditEvent.occurred_at, models.AuditEvent.id)
    ).scalars()
    return [
        {
            "occurred_at": _iso(row.occurred_at),
            "tenant_id": row.tenant_id,
            "actor": row.actor,
            "action": row.action,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "client_ip": row.client_ip,
            "user_agent": row.user_agent,
            "request_id": row.request_id,
        }
        for row in rows
    ]


def _recipient_matches(entry: Any, email: str) -> bool:
    return (
        isinstance(entry, dict)
        and entry.get("transport") == "email"
        and str(entry.get("target") or "").strip().lower() == email
    )


def _report_schedules_listing(session: Session, email: str | None) -> list[dict[str, Any]]:
    if not email:
        return []
    address = email.strip().lower()
    return [
        {"tenant_id": row.tenant_id, "schedule_id": row.schedule_id, "name": row.name}
        for row in session.execute(select(models.ReportSchedule)).scalars()
        if any(_recipient_matches(entry, address) for entry in row.recipients or [])
    ]


def _email_channels_with(session: Session, address: str) -> list[models.NotificationChannel]:
    """Email notification channels whose ``config["to"]`` holds ``address``."""
    return [
        row
        for row in session.execute(
            select(models.NotificationChannel).where(models.NotificationChannel.kind == "email")
        ).scalars()
        if any(
            str(target or "").strip().lower() == address
            for target in (row.config or {}).get("to") or []
        )
    ]


def _channels_listing(session: Session, email: str | None) -> list[dict[str, Any]]:
    if not email:
        return []
    return [
        {"tenant_id": row.tenant_id, "channel_id": row.channel_id, "name": row.name}
        for row in _email_channels_with(session, email.strip().lower())
    ]


def _attributions(session: Session, username: str) -> list[dict[str, Any]]:
    counts = []
    for name, (table, columns) in _attribution_columns().items():
        # One scan per table, every column counted in it (review round 1): the
        # findings table alone names people in six columns, none indexed for it.
        row = session.execute(
            select(*[func.count().filter(column == username) for column in columns]).select_from(
                table
            )
        ).one()
        for column, count in zip(columns, row):
            if count:
                counts.append({"table": name, "column": column.name, "rows": int(count)})
    return counts


class ExportTooSlow(RuntimeError):
    """The export hit :data:`STATEMENT_TIMEOUT_MS`. Routes answer 503."""


def _bound(session: Session) -> None:
    """Cap every statement of this transaction at :data:`STATEMENT_TIMEOUT_MS`.

    The export and the erasure's hold check read the audit trail and the
    findings by columns nothing indexes for them, inside a request. A cap turns
    "the API held a connection for ten minutes" into a refusal that says so.
    """
    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            text("SELECT set_config('statement_timeout', :ms, true)"),
            {"ms": str(int(STATEMENT_TIMEOUT_MS))},
        )


def _timed_out(exc: OperationalError) -> bool:
    return getattr(exc.orig, "sqlstate", None) == "57014"


# -- erasure ---------------------------------------------------------------------


def _assert_not_last_admin(session: Session, row: models.User) -> None:
    """Refuse to erase the last usable platform admin.

    The same rule the delete and disable routes apply
    (``users.count_active_admins``: enabled, admin, with a password), taken
    under a lock on every admin row, so two admins erasing each other at once
    cannot both succeed and leave an installation nobody can administer.
    """
    if row.role != "admin":
        return
    admins = session.execute(
        select(models.User).where(models.User.role == "admin").with_for_update()
    ).scalars().all()
    remaining = [
        admin
        for admin in admins
        if admin.username != row.username
        and admin.disabled_at is None
        and admin.password_hash
    ]
    if not remaining:
        raise ErasureRefused(
            "cannot erase the last active admin — create another admin first"
        )


def _assert_no_hold(session: Session, username: str) -> None:
    """Refuse while a tenant this account belongs to, belonged to or acted in is on hold.

    Art. 17(3)(e): data needed for legal claims is exempt from erasure, and
    what erasure destroys is precisely the link from a username in the held
    tenant's records to the person behind it. The held tenant's trail answers
    the past tense as well as the membership table answers the present: a
    revoked membership takes neither the account's actions nor its grant out
    of that trail.
    """
    for tenant_id in sorted(legal_hold.held_tenants_naming(session, username)):
        legal_hold.assert_not_on_hold(session, tenant_id, action="user.erase")


def erase_user(
    settings: Settings,
    username: str,
    *,
    requested_by: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Erase one account's personal data, keeping its username as a pseudonym.

    Raises LookupError for an unknown account, :class:`ErasureRefused` for the
    requester's own account or the last admin, and
    :class:`~api.services.legal_hold.LegalHoldActive` while a tenant the
    account belongs to or acted in is on hold. Returns what was removed.

    Everything — the account, the rows that go, the report recipients, the
    membership revocations and the erasure's own audit row — commits together:
    an erasure that half-happened is one nobody can state the result of.
    """
    if username == requested_by:
        raise ErasureRefused("cannot erase the account you are signed in as")
    try:
        return _erase(settings, username, requested_by, audit)
    except OperationalError as exc:
        if _timed_out(exc):
            raise ExportTooSlow(
                f"the erasure of {username!r} stopped at its statement timeout "
                f"({STATEMENT_TIMEOUT_MS // 1000} s) and changed nothing. Retry off-peak."
            ) from exc
        raise


def _erase(
    settings: Settings,
    username: str,
    requested_by: str,
    audit: audit_service.AuditContext | None,
) -> dict[str, Any]:
    with get_session(settings.postgres_url) as session:
        _bound(session)
        row = session.execute(
            select(models.User).where(models.User.username == username).with_for_update()
        ).scalar_one_or_none()
        if row is None:
            raise LookupError(f"user '{username}' not found")
        if row.erased_at is not None:
            return {"username": username, "erased_at": _iso(row.erased_at), "already_erased": True}
        _assert_not_last_admin(session, row)
        _assert_no_hold(session, username)

        now = _now()
        address = (row.email or "").strip().lower()
        memberships = session.execute(
            select(models.UserTenant).where(models.UserTenant.username == username)
        ).scalars().all()
        removed: dict[str, Any] = {
            "email": bool(row.email),
            "sso_identity": bool(row.oidc_subject),
            "second_factor": row.mfa_enabled_at is not None,
            "memberships": sorted(m.tenant_id for m in memberships),
            "security_keys": _count(session, models.WebAuthnCredential, username),
            "sessions": _count(session, models.SessionFamily, username),
            "report_recipients": _strip_report_recipient(session, address) if address else 0,
            "notification_recipients": (
                _strip_channel_recipient(session, address, audit) if address else 0
            ),
            # Minted by the account for a tenant's automation. The docs promise
            # every credential the account holds is refused, and a token its
            # creator can no longer answer for is a leaver's key (review round 1).
            "service_tokens": service_tokens_service.revoke_created_by(
                session, username, audit=audit
            ),
        }

        for membership in memberships:
            # One row per tenant, in *that* tenant: its admin reads a trail
            # scoped to their tenant, where a platform-level erasure row would
            # leave a member vanishing with no explanation.
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_MEMBERSHIP_REVOKE,
                resource_type="membership",
                resource_id=username,
                tenant_id=membership.tenant_id,
                before={"role": membership.role},
                after={"erased": True},
            )
            session.delete(membership)
        for model in (
            models.WebAuthnCredential,
            models.WebAuthnChallenge,
            models.SessionFamily,
            models.RevokedToken,
        ):
            session.execute(delete(model).where(model.username == username))

        row.password_hash = ""
        row.email = None
        row.email_verified = False
        row.oidc_issuer = None
        row.oidc_subject = None
        row.mfa_secret = None
        row.mfa_enabled_at = None
        row.mfa_last_step = None
        row.mfa_recovery_codes = []
        row.password_changed_at = None
        row.role = "viewer"
        row.disabled_at = row.disabled_at or now
        row.erased_at = now
        row.updated_at = now
        # Every token the account holds is refused from here on; the deleted
        # session families already end the refresh tokens.
        row.token_version = int(row.token_version or 0) + 1
        session.flush()

        # Counts and flags only. Writing the erased address into an
        # append-only table at the moment of erasing it would make the trail
        # the one copy nobody can remove.
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_ERASE,
            resource_type="user",
            resource_id=username,
            before=removed,
            after={"erased": True},
        )
    LOG.warning("Account %s erased at the request of %s", username, requested_by)
    return {"username": username, "erased_at": _iso(now), "already_erased": False, "removed": removed}


def _count(session: Session, model, username: str) -> int:
    return int(
        session.execute(
            select(func.count()).select_from(model).where(model.username == username)
        ).scalar_one()
    )


def _strip_report_recipient(session: Session, address: str) -> int:
    """Take ``address`` off every report schedule. Returns how many entries went.

    Only schedules: a report already sent keeps its delivery log, which is the
    record of a disclosure that has happened, and ages out with the report.
    """
    removed = 0
    for schedule in session.execute(select(models.ReportSchedule)).scalars():
        entries = list(schedule.recipients or [])
        kept = [entry for entry in entries if not _recipient_matches(entry, address)]
        if len(kept) != len(entries):
            removed += len(entries) - len(kept)
            schedule.recipients = kept
    return removed


def _strip_channel_recipient(
    session: Session, address: str, audit: audit_service.AuditContext | None
) -> int:
    """Take ``address`` off every email notification channel (review round 1).

    A channel left with nobody to mail is switched off rather than left to fail
    every run with "no recipients". Each change is ``notification_channel.update``
    in the channel's tenant, as a tenant admin's own edit would be — counted, not
    quoted: the removed address must not reach the append-only trail.
    """
    removed = 0
    for channel in _email_channels_with(session, address):
        config = dict(channel.config or {})
        recipients = list(config.get("to") or [])
        kept = [target for target in recipients if str(target or "").strip().lower() != address]
        config["to"] = kept
        channel.config = config
        was_enabled = channel.enabled
        if not kept:
            channel.enabled = False
        removed += len(recipients) - len(kept)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_NOTIFICATION_CHANNEL_UPDATE,
            resource_type="notification_channel",
            resource_id=channel.channel_id,
            tenant_id=channel.tenant_id,
            before={"recipients": len(recipients), "enabled": was_enabled},
            after={
                "recipients": len(kept),
                "enabled": channel.enabled,
                "reason": "a recipient's account was erased",
            },
        )
    return removed
