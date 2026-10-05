"""Console accounts, Postgres-backed (#156).

Replaces ``OCTO_API_USERS`` as the source of truth. The env var survives as a
*bootstrap* input only: it is imported once, into an empty table, and after
that the table wins — the same shape as the one-time import of the legacy
``state/api_{jobs,agents}.json`` files in ROADMAP P1.2.

Two rules carry most of the security value here:

1. **Only hashes are stored.** ``hash_password``/``verify_password`` come from
   ``api.auth``, which is the same passlib context ``ProvisioningKey`` uses.
   The pre-#156 store compared plaintext whenever the configured value did not
   start with ``$2``; nothing here reproduces that.
2. **The built-in demo accounts are never written to the table.** Their
   passwords are published in this repository, so importing them would re-open
   through the database exactly the hole #155 closed at the environment level.
   They exist only when ``OCTO_ENV=dev`` explicitly seeds them.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, or_, select

from api.auth import hash_password, verify_password
from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import audit as audit_service
from api.services import metrics as metrics_service
from api.settings import ENV_PROD, InsecureConfigurationError, Settings

logger = logging.getLogger(__name__)

VALID_ROLES = ("viewer", "operator", "admin")

_settings: Settings | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "users_service.configure()/bootstrap() not called"
    return _settings


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _to_dict(row: models.User) -> dict[str, Any]:
    """Public shape. There is no code path that returns password material."""
    return {
        "username": row.username,
        "role": row.role,
        "disabled": row.disabled_at is not None,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "disabled_at": _iso(row.disabled_at),
        "password_changed_at": _iso(row.password_changed_at),
        "created_by": row.created_by,
        # An account backfilled by migration 0013, or one whose password was
        # never set. Surfaced so an admin can tell "disabled by someone" from
        # "never had a password" without exposing the hash itself.
        "has_password": bool(row.password_hash),
        "email": row.email,
        "email_verified": bool(row.email_verified),
        # Whether this account signs in through the identity provider. The
        # issuer and subject themselves stay out of the response: they identify
        # the customer's IdP and the user inside it, and no console screen has
        # a use for either.
        "sso_linked": bool(row.oidc_subject),
        # The global admin role *is* platform admin: it acts across every
        # tenant and bypasses the membership table entirely, which is why
        # ``tenants`` below is usually empty for one.
        "is_platform_admin": row.role == "admin",
        # A tombstone left by a data-subject erasure (#332): the username is
        # kept as a pseudonym and nothing else is.
        "erased_at": _iso(row.erased_at),
    }


def _tenant_ids(session, usernames: list[str]) -> dict[str, list[str]]:
    """``{username: [tenant_id, ...]}`` for the given accounts, in one query.

    One query for the whole page rather than one per row: the users list is
    the only place that needs memberships for more than one account, and a
    per-row lookup there would grow with the installation.
    """
    if not usernames:
        return {}
    rows = session.execute(
        select(models.UserTenant.username, models.UserTenant.tenant_id)
        .where(models.UserTenant.username.in_(usernames))
        .order_by(models.UserTenant.username, models.UserTenant.tenant_id)
    ).all()
    grouped: dict[str, list[str]] = {}
    for username, tenant_id in rows:
        grouped.setdefault(username, []).append(tenant_id)
    return grouped


def _with_tenants(session, row: models.User) -> dict[str, Any]:
    """Public shape plus this one account's memberships.

    Kept apart from :func:`_to_dict` so ``authenticate`` — the hot path, which
    only needs the username and the role — does not pay for the extra query.
    """
    result = _to_dict(row)
    result["tenants"] = _tenant_ids(session, [row.username]).get(row.username, [])
    return result


class AccountErased(ValueError):
    """A change to an account erased under a data-subject request (#332).

    The tombstone holds nothing but the username, and that name is the
    pseudonym the append-only audit trail still attributes history to. Giving
    it a password, a role, an address or a membership would hand that history
    to whoever holds the new credential; deleting it would free the name to be
    issued to somebody else. So every write refuses it. A ``ValueError``, so
    the routes that already answer one with 422 refuse this too.
    """


def _refuse_erased(row: models.User) -> None:
    if row.erased_at is not None:
        raise AccountErased(f"user '{row.username}' was erased and cannot be changed")


def _validate_role(role: str) -> str:
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {', '.join(VALID_ROLES)}")
    return role


def _validate_username(username: str) -> str:
    cleaned = (username or "").strip()
    if not cleaned:
        raise ValueError("username must not be empty")
    if len(cleaned) > 128:
        raise ValueError("username must be at most 128 characters")
    return cleaned


def _validate_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    # A floor, not a policy: bcrypt silently truncates beyond 72 bytes, so a
    # longer value would make part of what the operator typed decorative.
    if len(password.encode("utf-8")) > 72:
        raise ValueError("password must be at most 72 bytes")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return password


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Verify credentials against the table. Returns the user dict or None.

    Never distinguishes "no such user" from "wrong password" to the caller —
    that difference is the whole of a username-enumeration oracle, and #157
    will add the rate limit that makes the distinction expensive to probe.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        if row.disabled_at is not None:
            return None
        # Checked explicitly rather than trusting bcrypt to reject "": a
        # migration-backfilled placeholder must never authenticate, and that
        # should not depend on a library's behaviour with an empty digest.
        if not row.password_hash:
            return None
        try:
            if not verify_password(password, row.password_hash):
                return None
        except ValueError:
            # passlib raises (UnknownHashError, a ValueError) rather than
            # returning False when the stored value is not a recognisable
            # hash — which is exactly what a row left over from the pre-#156
            # plaintext era looks like. Uncaught, that surfaces as a 500 on the
            # login endpoint, so a malformed credential would be reported as a
            # server fault instead of a failed login. Refuse instead.
            logger.warning(
                "User %r has an unusable password hash and cannot authenticate; "
                "reset it with PUT /api/users/{username}/password.",
                username,
            )
            return None
        return _to_dict(row)


def list_users() -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(select(models.User).order_by(models.User.username)).scalars().all()
        tenants = _tenant_ids(session, [row.username for row in rows])
        return [
            {**_to_dict(row), "tenants": tenants.get(row.username, [])} for row in rows
        ]


def get_user(username: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        return _with_tenants(session, row) if row else None


def create_user(
    *,
    username: str,
    password: str,
    role: str,
    email: str | None = None,
    created_by: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Create one account, address included, in a single transaction.

    ``email`` is written here rather than by a follow-up call to
    :func:`set_email` on purpose: a second request that fails leaves an
    account whose address the operator believes they set. It is always stored
    **unverified** — the verified flag is what makes an account linkable to an
    SSO identity by address, and that assertion belongs to a deliberate
    ``PUT /users/{username}/email``, not to whoever filled the create form.
    """
    username = _validate_username(username)
    role = _validate_role(role)
    password = _validate_password(password)
    cleaned_email = _normalise_email(email)

    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        if session.get(models.User, username) is not None:
            raise ValueError(f"user '{username}' already exists")
        if cleaned_email is not None:
            clash = session.execute(
                select(models.User).where(models.User.email == cleaned_email)
            ).scalars().first()
            if clash is not None:
                raise ValueError("email is already used by another account")
        row = models.User(
            username=username,
            password_hash=hash_password(password),
            role=role,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
            created_by=created_by,
            email=cleaned_email,
            email_verified=False,
        )
        session.add(row)
        session.flush()
        created = _with_tenants(session, row)
        # In this transaction, so an account that exists and an account that was
        # recorded are the same set (#327). ``created`` carries no password
        # material by construction, and audit redacts by field name anyway.
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_CREATE,
            resource_type="user",
            resource_id=username,
            after=created,
        )
        return created


def _end_sessions(row: models.User) -> None:
    """Move the account to the next session generation (#314).

    Called from inside the transaction that makes the change, so "the password
    is new" and "the tokens issued under the old one are dead" commit together
    or not at all. Every console JWT carries the version it was minted at and
    ``api/services/sessions.py`` refuses one that no longer matches, so this
    single ``+= 1`` is the whole of "and sign them out".
    """
    row.token_version = int(row.token_version or 0) + 1


def set_password(
    username: str,
    password: str,
    *,
    audit: "audit_service.AuditContext | None" = None,
    action: str | None = None,
) -> dict[str, Any] | None:
    """Write a new password hash, end every session opened with the old one
    (#314), and record *that* it changed (#327).

    ``action`` names which of the two acts this is — an admin's reset or the
    owner's own rotation — because they are different facts to an auditor and
    :func:`change_own_password` delegates here. Neither the old nor the new
    password appears in the row: ``before``/``after`` carry the timestamp that
    moved, which is what "was this account's password changed at 03:00" needs
    and all it needs.
    """
    password = _validate_password(password)
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        _refuse_erased(row)
        previous_changed_at = _iso(row.password_changed_at)
        row.password_hash = hash_password(password)
        row.password_changed_at = _now()
        row.updated_at = _now()
        _end_sessions(row)
        session.flush()
        updated = _with_tenants(session, row)
        audit_service.record(
            session,
            audit,
            action=action or audit_service.ACTION_USER_PASSWORD_RESET,
            resource_type="user",
            resource_id=username,
            before={"password_changed_at": previous_changed_at},
            after={"password_changed_at": _iso(row.password_changed_at)},
        )
        return updated


def change_own_password(
    username: str,
    *,
    current: str,
    new: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Rotate one's own password, re-verifying the current one first.

    Separate from :func:`set_password` on purpose: an admin resetting someone
    else's password does not know the old one, while a user changing their own
    must prove they are still the one sitting at the session. Recorded under
    its own action for the same reason — a reset performed *on* an account is
    the interesting one to review, and folding it in with every user's routine
    rotation is how it stops being noticed.
    """
    if authenticate(username, current) is None:
        return None
    return set_password(
        username, new, audit=audit, action=audit_service.ACTION_USER_PASSWORD_CHANGE
    )


def set_role(
    username: str, role: str, *, audit: "audit_service.AuditContext | None" = None
) -> dict[str, Any] | None:
    role = _validate_role(role)
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        _refuse_erased(row)
        previous = row.role
        changed = row.role != role
        row.role = role
        row.updated_at = _now()
        # A demotion that leaves the old role live in an already-issued token
        # is not a demotion (#314). The decoder reads the role from this row
        # too, so the bump is belt-and-braces — it also ends the sessions of a
        # *promoted* account, which is the conservative reading of "their
        # authority changed".
        #
        # Only when the role actually moved: this endpoint is what an IaC run
        # or a directory sync calls on every reconcile, and bumping on a PUT
        # that asserts the role the account already has would sign everybody
        # out on a schedule for no change at all.
        if changed:
            _end_sessions(row)
        session.flush()
        updated = _with_tenants(session, row)
        # Only the field that moved: "admin -> viewer" is the fact a review
        # reads, and the rest of the account is noise around it.
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_ROLE,
            resource_type="user",
            resource_id=username,
            before={"role": previous},
            after={"role": role},
        )
        return updated


def set_disabled(
    username: str, disabled: bool, *, audit: "audit_service.AuditContext | None" = None
) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        _refuse_erased(row)
        was_disabled = row.disabled_at is not None
        changed = was_disabled != disabled
        row.disabled_at = _now() if disabled else None
        # A person's decision either way (#316): an account an administrator
        # disabled is not the IdP's to re-enable, and one they re-enabled is no
        # longer "disabled by the IdP" for a later resync to act on.
        row.disabled_source = None
        row.updated_at = _now()
        # Both directions, but only on a real transition. Disabling must end
        # the sessions — that is the whole point of the operation — and
        # re-enabling ends whatever was still in flight when the account was
        # locked, so "disabled and enabled again" is a clean start rather than
        # a resumed one. Re-asserting the state the account is already in
        # changes nothing and must not end anyone's session: the reconcile
        # loop that keeps accounts in step with a directory sends exactly that
        # PUT on every pass.
        if changed:
            _end_sessions(row)
        session.flush()
        updated = _with_tenants(session, row)
        # One action for both directions, with the values either side: an
        # account disabled and re-enabled an hour later is two rows that read as
        # the pair they are.
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_DISABLE,
            resource_type="user",
            resource_id=username,
            before={"disabled": was_disabled},
            after={"disabled": disabled},
        )
        return updated


class SsoLinkError(PermissionError):
    """An SSO login that resolved to no account this platform will sign in.

    A ``PermissionError`` because that is what the auth routes already turn
    into a refusal, and because every case it covers is a decision not to
    authenticate rather than a fault: no matching account with JIT off, an
    unverified email, a disabled account, or a local account whose address the
    provider will not vouch for.
    """


def _normalise_email(email: str | None) -> str | None:
    cleaned = (email or "").strip().lower()
    return cleaned[:320] or None


def _scim_link_candidate(
    session, *, subject: str, verified_email: str | None, lock: bool
) -> models.User | None:
    """The account a SCIM client created for this login's identity, if any.

    Matched by ``externalId == subject`` first, then by an address the
    provider verified — see :func:`link_or_provision_sso_user`. Every other
    condition here is what makes the account SCIM's and still unclaimed.
    """
    identity = [models.User.scim_external_id == subject]
    if verified_email:
        identity.append(models.User.email == verified_email)
    lookup = (
        select(models.User)
        .where(
            or_(*identity),
            models.User.oidc_subject.is_(None),
            models.User.password_hash == "",
            models.User.created_by.like("scim:%"),
            models.User.erased_at.is_(None),
        )
        # The subject before the address: it is the stronger assertion.
        .order_by(case((models.User.scim_external_id == subject, 0), else_=1))
    )
    if lock:
        lookup = lookup.with_for_update()
    for row in session.execute(lookup).scalars():
        token = session.get(models.ScimToken, row.created_by.removeprefix("scim:"))
        tenant_bound = token is None or not token.all_tenants
        if tenant_bound and not _holds_a_membership(session, row.username):
            # A tenant-bound directory's account with no grant yet: linking it
            # would put this person in an account that directory alone
            # controls, on the strength of nothing it has granted.
            continue
        return row
    return None


def _holds_a_membership(session, username: str) -> bool:
    return (
        session.execute(
            select(models.UserTenant.tenant_id).where(models.UserTenant.username == username)
        ).first()
        is not None
    )


def link_or_provision_sso_user(
    settings: Settings,
    *,
    issuer: str,
    subject: str,
    username: str,
    email: str | None,
    email_verified: bool,
    role: str,
    tenant_id: str,
    jit_enabled: bool,
    groups: list[str] | None = None,
) -> tuple[dict[str, Any], str]:
    """Resolve an OIDC identity to a console account.

    Returns ``(user, action)`` where ``action`` is ``signin``, ``link`` or
    ``provision`` — the caller records which one happened in the auth trail.

    Resolution order, and why it is this order:

    1. **The stored ``(issuer, subject)``.** Once linked, that pair is the
       identity. It survives a renamed account and a changed email address,
       neither of which should log a different person in.
    2. **A verified email match.** The provider must assert ``email_verified``
       *and* the local account must already carry the same address marked
       verified. An unverified address on either side is a string somebody
       typed, and linking on it hands the account to whoever can register that
       address at the identity provider. Refused, never silently provisioned
       under a new name.
    3. **Just-in-time provisioning**, only when enabled. The account is created
       with an empty password hash — it can never be used to log in with a
       password, only through the provider — and with the role the claim
       mapping produced, which defaults to the lowest privileged role.

    A disabled account is refused at every step: SSO is a way to prove who you
    are, not a way around a revocation.

    With ``OCTO_IDP_AUTHORITATIVE`` on (#316) the account found by any of the
    three is then brought in line with ``groups`` — role, IdP-sourced
    memberships, enabled state — by :func:`api.services.idp_sync.reconcile`,
    *before* the disabled check, in the same transaction. Before, because an
    account the IdP disabled for being in no group must come back when a group
    does; in the same transaction, because a reconcile that disables the
    account has to commit even though the login it ran for is then refused.
    JIT provisioning in that mode creates no account for an identity in no
    mapped group, and grants no ``tenant_id`` membership of its own: the group
    map is the only source of memberships. ``groups`` None means the ID token
    did not list them (the claim is missing, or Entra ID's overage replaced
    it): the login then changes nothing — "not listed" is not "in no group",
    and reading it as that would disable the account — and provisions nothing.

    Between 2 and 3, **an account a SCIM client created** (#316) is linked by
    an identifier the IdP asserts for this login: its ``externalId`` equal to
    ``subject``, or its address equal to one the provider marks verified (SCIM
    addresses are stored unverified, so step 2 never matches them). Never by
    the login's username, which can come from an ``email`` claim nobody
    verified — linking on it handed a SCIM-provisioned admin to whoever typed
    that address into their IdP profile. An account with a password, one
    already linked, an erased one, and one a tenant-bound SCIM token created
    and has granted nothing yet (a placeholder that directory alone controls)
    are never matched.
    """
    from api.services import idp_sync

    settings_local = settings
    email = _normalise_email(email)
    now = _now()
    authoritative = idp_sync.is_authoritative(settings_local)
    groups_listed = groups is not None
    groups = list(groups or [])
    context = audit_service.AuditContext(
        actor=f"oidc:{issuer}"[:128], actor_type=audit_service.ACTOR_SYSTEM
    )
    refusal: str | None = None
    outcome: tuple[dict[str, Any], str] | None = None

    with get_session(settings_local.postgres_url) as session:

        def _resync(row: models.User) -> None:
            if not groups_listed:
                metrics_service.IDP_RESYNC_SKIPPED_TOTAL.inc()
                logger.warning(
                    "IdP resync of %r skipped at SSO login: the ID token does not list "
                    "the groups (claim %r missing or replaced by an overage pointer)",
                    row.username,
                    settings_local.oidc_role_claim,
                )
                return
            result = idp_sync.reconcile(
                session, settings_local, row, groups, scope=idp_sync.LOGIN_SCOPE, audit=context
            )
            if result.reduced or result.granted or result.enabled:
                logger.info(
                    "IdP resync of %r at SSO login: %s", row.username, idp_sync.describe(result)
                )

        lookup = select(models.User).where(
            models.User.oidc_issuer == issuer,
            models.User.oidc_subject == subject,
        )
        if authoritative:
            # Two logins of one person at once would otherwise both compute
            # the same grants and race each other's inserts.
            lookup = lookup.with_for_update()
        linked = session.execute(lookup).scalar_one_or_none()
        if linked is not None:
            if authoritative:
                _resync(linked)
            if linked.disabled_at is not None:
                refusal = "account is disabled"
            else:
                # Keep the address current: it is what the console displays,
                # and a stale one would misidentify the person behind the
                # account.
                if email and email_verified:
                    linked.email = email
                    linked.email_verified = True
                linked.updated_at = now
                session.flush()
                outcome = (_to_dict(linked), "signin")

        if outcome is None and refusal is None:
            candidate = None
            if email and email_verified:
                candidate_lookup = select(models.User).where(
                    models.User.email == email,
                    models.User.email_verified.is_(True),
                    models.User.oidc_subject.is_(None),
                )
                if authoritative:
                    candidate_lookup = candidate_lookup.with_for_update()
                candidate = session.execute(candidate_lookup).scalars().first()
            if candidate is None:
                candidate = _scim_link_candidate(
                    session,
                    subject=subject,
                    verified_email=email if email_verified else None,
                    lock=authoritative,
                )
            if candidate is not None:
                if candidate.disabled_at is not None and not (
                    authoritative and candidate.disabled_source == idp_sync.DISABLED_BY_IDP
                ):
                    refusal = "account is disabled"
                else:
                    candidate.oidc_issuer = issuer
                    candidate.oidc_subject = subject
                    candidate.updated_at = now
                    if authoritative:
                        _resync(candidate)
                    if candidate.disabled_at is not None:
                        refusal = "account is disabled"
                    else:
                        session.flush()
                        outcome = (_to_dict(candidate), "link")

        if outcome is None and refusal is None:
            if not jit_enabled:
                refusal = (
                    "no console account is linked to this identity and just-in-time "
                    "provisioning is disabled"
                )
            elif authoritative and not groups_listed:
                refusal = (
                    "the ID token does not list this identity's groups; an account "
                    "cannot be provisioned from it"
                )
            elif authoritative and not idp_sync.mapped_groups(
                settings_local, groups, idp_sync.LOGIN_SCOPE
            ):
                # Provisioning it only for the resync to disable it at once
                # would leave an account behind for every person the IdP
                # authenticates and this installation was never meant to see.
                refusal = "this identity is in no group mapped to console access"

        if outcome is None and refusal is None:
            role = _validate_role(role)
            name = _validate_username(username)
            existing = session.get(models.User, name)
            if existing is not None:
                # The name is taken by a *local* account we were not allowed to
                # link to (unverified address, or a different address
                # entirely). Provisioning over it would be an account takeover
                # by whoever controls that name at the identity provider.
                refusal = (
                    "a local account already uses this username and cannot be linked "
                    "to this identity"
                )
            else:
                row = models.User(
                    username=name,
                    # No password, ever: this account authenticates through the
                    # provider only, and authenticate() refuses an empty hash.
                    password_hash="",
                    role=role,
                    created_at=now,
                    updated_at=now,
                    password_changed_at=None,
                    created_by=f"oidc:{issuer}",
                    email=email,
                    email_verified=bool(email and email_verified),
                    oidc_issuer=issuer,
                    oidc_subject=subject,
                )
                session.add(row)
                session.flush()
                if authoritative:
                    _resync(row)
                outcome = (_to_dict(row), "provision")

    # After the transaction: a reconcile that disabled the account committed
    # above, and the refusal is the answer to this login.
    if refusal is not None:
        raise SsoLinkError(refusal)
    assert outcome is not None
    provisioned, action = outcome
    if action != "provision" or authoritative:
        return provisioned, action

    # Outside the transaction above: the membership lives in another service
    # with its own session, and a failure to grant it must not roll back the
    # account it belongs to (the next login re-grants it).
    if tenant_id:
        from api.services import memberships as memberships_service

        try:
            memberships_service.grant(
                username=provisioned["username"],
                tenant_id=tenant_id,
                role=role,
                created_by=f"oidc:{issuer}",
                # The platform granting on the identity provider's word, which
                # the installation configured: there is no granter in the
                # tenant whose ceiling it could be held to.
                granted_by=None,
                # The IdP's grant, so a later authoritative resync owns it.
                source=idp_sync.SOURCE_IDP,
            )
        except ValueError:
            # An unknown tenant in the claim is a mapping mistake, not a reason
            # to refuse the login: the account exists with no membership, which
            # confines it to the default tenant exactly like any other.
            logger.warning(
                "OIDC tenant claim named an unknown tenant for a provisioned user; "
                "no membership was granted."
            )
    return provisioned, action


def set_email(username: str, email: str | None, *, verified: bool = False) -> dict[str, Any] | None:
    """Set an account's address and whether this platform treats it as verified.

    Admin-driven, and the only way an existing local account becomes eligible
    for SSO linking by email — which is the point: somebody with the authority
    to grant access decides that this address is this user's, rather than the
    identity provider asserting it into an account that never had one.
    """
    settings = _require_settings()
    cleaned = _normalise_email(email)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        _refuse_erased(row)
        if cleaned is not None:
            clash = session.execute(
                select(models.User).where(
                    models.User.email == cleaned, models.User.username != username
                )
            ).scalars().first()
            if clash is not None:
                raise ValueError("email is already used by another account")
        row.email = cleaned
        row.email_verified = bool(cleaned) and verified
        row.updated_at = _now()
        session.flush()
        return _with_tenants(session, row)


def count_active_admins(exclude: str | None = None) -> int:
    """Enabled accounts with the admin role, optionally ignoring one username.

    Used to refuse the last-admin lockout: disabling or demoting the only
    remaining admin leaves an installation whose user management can only be
    recovered by editing the database by hand.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.User).where(
            models.User.role == "admin",
            models.User.disabled_at.is_(None),
            models.User.password_hash != "",
        )
        if exclude:
            stmt = stmt.where(models.User.username != exclude)
        return len(session.execute(stmt).scalars().all())


def delete_user(username: str, *, audit: "audit_service.AuditContext | None" = None) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return False
        _refuse_erased(row)
        # Snapshot before the delete: this row is the only remaining answer to
        # "what did the account we deleted have", including the tenants whose
        # membership rows go with it.
        removed = _with_tenants(session, row)
        # Memberships cascade (FK from migration 0013), so no orphan grant
        # survives to be silently re-attached if the name is recreated later.
        session.delete(row)
        # The tokens it minted do not cascade — they belong to a tenant — but a
        # credential nobody can answer for any more is a leaver's key (#332).
        from api.services import service_tokens as service_tokens_service

        service_tokens_service.revoke_created_by(session, username, audit=audit)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_DELETE,
            resource_type="user",
            resource_id=username,
            before=removed,
        )
        return True


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.User).delete()


def _has_any_usable_account(session) -> bool:
    stmt = select(models.User).where(
        models.User.disabled_at.is_(None),
        models.User.password_hash != "",
    )
    return session.execute(stmt).scalars().first() is not None


def bootstrap(settings: Settings) -> None:
    """Configure the service, import legacy env users once, and check we can log in.

    Called from ``create_app()`` after the tenant store is up. Three outcomes:

    * ``OCTO_API_USERS`` is set and the table holds no usable account — the env
      users are imported (plaintext hashed on the way in) and the variable
      stops being consulted from then on. Import, not sync: a later edit to the
      variable is ignored, because two sources of truth is the state this
      change exists to leave.
    * ``OCTO_ENV=dev`` with nothing configured — the built-in demo accounts are
      seeded, so the kind overlay and the test suite keep working.
    * ``OCTO_ENV=prod`` with nothing configured — refuses to start, naming how
      to supply the first account. An install nobody can log into is a failure
      whether it is reported at startup or discovered at the login form, and
      the startup message is the one that says why.
    """
    configure(settings)

    with get_session(settings.postgres_url) as session:
        if _has_any_usable_account(session):
            return

    imported = _import_env_users(settings)
    if imported:
        logger.warning(
            "Imported %d account(s) from OCTO_API_USERS into the users table. "
            "The table is the source of truth from now on: later edits to the "
            "variable are ignored, and passwords rotate via POST /api/auth/password "
            "or PUT /api/users/{username}/password. Remove the variable once the "
            "import is confirmed.",
            imported,
        )
        return

    if settings.env != ENV_PROD:
        _seed_dev_users(settings)
        return

    raise InsecureConfigurationError(
        "Refusing to start: no console account exists and none was supplied.\n\n"
        "  Console users live in Postgres since #156. Seed the first account by\n"
        "  setting OCTO_API_USERS once (a JSON list of\n"
        '  {"username": ..., "password": ..., "role": "admin"}); it is imported\n'
        "  into the users table on the next start and then stops being consulted.\n\n"
        "  The built-in demo accounts are deliberately not seeded here: their\n"
        "  passwords are published in this repository. They exist only under\n"
        "  OCTO_ENV=dev."
    )


def _import_env_users(settings: Settings) -> int:
    """Import ``settings.users`` unless it is the built-in default list.

    Returns the number of accounts written. Passwords already stored as bcrypt
    (``$2``…) are carried across as-is; anything else is hashed here, which is
    the one and only place plaintext is still accepted — and it is accepted as
    *input to hashing*, never as a stored value.
    """
    from api.settings import DEFAULT_USERS

    configured = settings.users or []
    if not configured or configured == DEFAULT_USERS:
        return 0

    now = _now()
    written = 0
    with get_session(settings.postgres_url) as session:
        for entry in configured:
            username = str(entry.get("username", "")).strip()
            password = str(entry.get("password", ""))
            role = str(entry.get("role", "viewer"))
            if not username or not password:
                logger.warning(
                    "Skipping an OCTO_API_USERS entry with no username or no password."
                )
                continue
            if role not in VALID_ROLES:
                logger.warning(
                    "OCTO_API_USERS entry %r has an unknown role; importing as viewer.",
                    username,
                )
                role = "viewer"
            if session.get(models.User, username) is not None:
                continue
            session.add(
                models.User(
                    username=username,
                    password_hash=password if password.startswith("$2") else hash_password(password),
                    role=role,
                    created_at=now,
                    updated_at=now,
                    password_changed_at=now,
                    created_by="import:OCTO_API_USERS",
                )
            )
            written += 1
    return written


def _seed_dev_users(settings: Settings) -> None:
    """Seed the built-in demo accounts. Only reachable when OCTO_ENV != prod."""
    from api.settings import DEFAULT_USERS

    now = _now()
    with get_session(settings.postgres_url) as session:
        for entry in DEFAULT_USERS:
            username = str(entry["username"])
            # Not check-then-insert: nothing separates the lookup from the
            # insert, and this runs at startup in every replica at once (and,
            # in the suite, against a database a leftover worker thread is
            # still writing to). The row a racing writer inserted is the same
            # row, so losing the race is a no-op -- but only if the failure is
            # scoped to it, which is what insert_if_absent's SAVEPOINT buys.
            insert_if_absent(
                session,
                models.User(
                    username=username,
                    password_hash=hash_password(str(entry["password"])),
                    role=str(entry["role"]),
                    created_at=now,
                    updated_at=now,
                    password_changed_at=now,
                    created_by="seed:dev",
                ),
                username,
            )
    logger.warning(
        "OCTO_ENV=%s: seeded the built-in demo accounts, whose passwords are "
        "published in this repository. Never expose this installation.",
        settings.env,
    )
