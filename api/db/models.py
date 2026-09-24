"""SQLAlchemy 2.x declarative models for the Postgres PRIMARY_DB (Phase 7)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    ForeignKey,
    LargeBinary,
    ForeignKeyConstraint,
    Index,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ``jsonb`` on Postgres, plain ``json`` on the SQLite dev fallback, which has
# neither. Only the audit trail's before/after use it: they are stored and read
# whole, so what jsonb buys here is dropping the key order and whitespace of a
# document nobody edits.
_JSON_DOC = JSON().with_variant(JSONB(), "postgresql")

# The same document type, but with Python ``None`` stored as SQL NULL rather
# than as the JSON scalar ``null`` — which is what SQLAlchemy's JSON does by
# default, and which makes ``WHERE col IS NULL`` silently match nothing. Only
# ``IdempotencyRecord.response`` uses it, and it has to: "reserved, not yet
# answered" is expressed as NULL and is queried for by the release path.
_JSON_DOC_NULLABLE = JSON(none_as_null=True).with_variant(
    JSONB(none_as_null=True), "postgresql"
)


class Base(DeclarativeBase):
    pass


class ConfigOverride(Base):
    """Installation-wide scanner-config overrides (editable configurator).

    A single ``scope="global"`` row holds a JSON dict deep-merged onto the base
    scan config at job start, so operators can toggle stages / tune profiles
    without editing the (often read-only) config file. Kept in Postgres like
    the tenant/asset stores so it survives restarts and multi-replica APIs.
    """

    __tablename__ = "config_overrides"

    scope: Mapped[str] = mapped_column(primary_key=True, default="global")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime]
    updated_by: Mapped[str | None] = mapped_column(default=None)


class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    # active | suspended | pending_deletion | deleting (#325). Every gate
    # refuses anything but ``active``; see api/services/tenant_lifecycle.py for
    # what moves a tenant between them.
    status: Mapped[str] = mapped_column(default="active")
    created_at: Mapped[datetime]
    # Why the tenant is in its current status, since when and on whose word
    # (migration 0066, #325). Shown to platform admins only: the reason a
    # customer was suspended is the platform's business, not the customer's
    # members'.
    status_reason: Mapped[str | None] = mapped_column(default=None)
    status_changed_at: Mapped[datetime | None] = mapped_column(default=None)
    status_changed_by: Mapped[str | None] = mapped_column(default=None)
    # Change freeze (#352). Distinct from ``status``: a frozen tenant is fully
    # operational — its console works, its findings are readable — it has
    # simply declared that nothing may touch its estate right now, so scan
    # admission refuses. Deactivating the tenant instead would take the
    # customer's data away from them to stop a scan.
    change_freeze: Mapped[bool] = mapped_column(default=False)
    change_freeze_note: Mapped[str | None] = mapped_column(default=None)
    change_freeze_at: Mapped[datetime | None] = mapped_column(default=None)
    change_freeze_by: Mapped[str | None] = mapped_column(default=None)


class User(Base):
    """A console account (#156). Postgres-backed, replacing ``OCTO_API_USERS``.

    Passwords are stored **only** as bcrypt hashes, using the same
    ``passlib`` context as ``ProvisioningKey.key_hash`` — one hashing scheme in
    the codebase, not two. There is deliberately no plaintext column and no
    plaintext acceptance in ``authenticate_user``: the pre-#156 env-backed
    store compared plaintext whenever the configured value did not start with
    ``$2``.

    ``disabled_at`` rather than a row delete, so revoking access keeps the
    audit trail and the ``user_tenants`` memberships intact — re-enabling is
    then a decision, not a re-grant of every tenant. ``password_changed_at``
    records rotation for #157's auth audit; it is set on every password write.
    """

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(primary_key=True)
    # bcrypt only. Empty string means "cannot authenticate" and is what the
    # 0013 migration backfills for usernames that had memberships but no
    # account — see the migration for why those rows exist.
    password_hash: Mapped[str] = mapped_column(default="")
    role: Mapped[str] = mapped_column(default="viewer")  # viewer | operator | admin
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    disabled_at: Mapped[datetime | None] = mapped_column(default=None)
    password_changed_at: Mapped[datetime | None] = mapped_column(default=None)
    created_by: Mapped[str | None] = mapped_column(default=None)
    # Federated identity (migration 0026, ROADMAP Track E). ``email`` is the
    # only thing an existing local account can be auto-linked by, and only when
    # ``email_verified`` is true *and* the provider asserts the same address as
    # verified: an unverified address is a claim the user typed, so linking on
    # it would let anyone who can register that address at the IdP take over a
    # console account. ``oidc_issuer``/``oidc_subject`` are the durable
    # identifier once linked — an email can be reassigned, ``sub`` cannot.
    email: Mapped[str | None] = mapped_column(default=None, index=True)
    email_verified: Mapped[bool] = mapped_column(default=False)
    oidc_issuer: Mapped[str | None] = mapped_column(default=None)
    oidc_subject: Mapped[str | None] = mapped_column(default=None)
    # Session generation (migration 0038, #314). Every console JWT carries the
    # value this column held when it was issued, and a token whose ``ver`` no
    # longer matches is refused at decode. Bumped by every change that should
    # end the sessions issued before it -- password, role, disable/enable --
    # and by the explicit "sign me out everywhere". A row that predates the
    # migration starts at 0, which is also what a token minted before the
    # upgrade implicitly claims, so an upgrade does not sign the console out.
    token_version: Mapped[int] = mapped_column(default=0)
    # Multi-factor authentication (migration 0041, #315). ``mfa_secret`` is the
    # base32 TOTP shared secret, stored through ``api/services/crypto`` under
    # the context ``users.mfa_secret`` — a secret that authenticates its owner
    # belongs at rest under the same envelope as the integration credentials
    # #310 moved, and for the same threat: a dump, a backup or a read replica.
    # ``mfa_enabled_at`` is set only once a code has been confirmed, so an
    # abandoned setup leaves an account exactly as it was.
    mfa_secret: Mapped[str | None] = mapped_column(default=None)
    mfa_enabled_at: Mapped[datetime | None] = mapped_column(default=None)
    # The last RFC 6238 step this account spent. Refusing a step at or before
    # it is what makes a code single-use: without it a code observed on the
    # wire stays good for the rest of its thirty seconds. BigInteger because a
    # step is unix-seconds/30 — it fits an int32 for another two millennia, but
    # a column that silently overflows is not a thing to leave to arithmetic.
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger, default=None)
    # Recovery codes as ``[{"hash": <bcrypt>, "used_at": <iso|null>}, …]``.
    # Only hashes, using the same passlib context as ``password_hash``: a
    # recovery code is a password that bypasses the second factor, so storing
    # it in a form the database can hand over would make the second factor
    # optional for whoever reads a backup. Spent codes stay in the list with a
    # timestamp — "which of my codes are gone" is a question the console
    # answers, and deleting the row would delete the answer.
    mfa_recovery_codes: Mapped[list] = mapped_column(JSON, default=list)
    # Erased under a data-subject request (migration 0065, #332). The row is
    # kept as a tombstone holding nothing but the username: the append-only
    # audit trail names actors by username, so the name must stay a stable
    # pseudonym and can never be issued to somebody else. See
    # api/services/data_subject.py for what erasure removes.
    erased_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_users_oidc_identity"),
    )


class WebAuthnCredential(Base):
    """One registered security key or passkey (migration 0061, #315).

    Nothing here is secret: the private key never leaves the authenticator,
    and what the relying party keeps is the public key and the counter it
    checks the next assertion against. That is why, unlike ``mfa_secret``, none
    of these columns goes through the secret envelope.

    ``credential_id`` is the base64url ``rawId`` the browser reports, unique
    across the installation — the spec makes it so, and a second account
    presenting the same id is a replay of somebody else's registration.
    ``sign_count`` is advanced by every accepted assertion under a row lock; an
    assertion that does not move it past the stored value is refused as a
    possible clone (authenticators that always report ``0`` are exempt, per
    the spec, and the library applies that rule).
    """

    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE"), index=True
    )
    credential_id: Mapped[str] = mapped_column(unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    # What the owner called it ("YubiKey on the keyring"), for the inventory.
    name: Mapped[str] = mapped_column(default="")
    aaguid: Mapped[str] = mapped_column(default="")
    transports: Mapped[list] = mapped_column(JSON, default=list)
    # Whether the authenticator reported the credential as synced to a cloud
    # account (a passkey) rather than bound to one device (a security key).
    backed_up: Mapped[bool] = mapped_column(default=False)
    device_type: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)


class WebAuthnChallenge(Base):
    """The server half of a WebAuthn ceremony in flight (migration 0061, #315).

    Written by an options endpoint and **deleted** by the verification that
    spends it — before the response is checked, so a failed attempt burns it
    too. ``binding`` is the ``jti`` of the token that asked for the challenge:
    a challenge minted for one login or one session cannot be spent by another.
    """

    __tablename__ = "webauthn_challenges"

    id: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE"), index=True
    )
    purpose: Mapped[str]  # register | authenticate
    binding: Mapped[str]
    challenge: Mapped[bytes] = mapped_column(LargeBinary)
    # The address that asked: the options rate limit is per (account, address),
    # so somebody else holding the password cannot spend the owner's budget.
    client_ip: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime] = mapped_column(index=True)


class ServiceToken(Base):
    """A non-interactive API credential, scoped to one tenant (Track E).

    Issued by a platform admin for automation — a CI job pulling findings, a
    SIEM forwarder — so that integrations stop being run under a human's
    password. Three properties carry the security value:

    * **Only a hash is stored.** ``token_hash`` uses the same passlib context
      as :class:`User` and :class:`ProvisioningKey`; the plaintext exists once,
      in the creation response, and is never recoverable afterwards.
    * **``role`` is a ceiling, not a grant.** A token authenticates as a
      principal whose role inside ``tenant_id`` is exactly this value, and
      ``scopes`` narrows it further. Neither can exceed what the role allows,
      and no membership row can raise it.
    * **It expires.** ``expires_at`` is required — a credential that lives
      forever is one nobody rotates — and ``revoked_at`` is the immediate kill
      switch that does not wait for it.

    ``token_prefix`` is the non-secret, indexed public half of the credential
    (``octo_st_<16 hex>``): it identifies which row to bcrypt-verify against
    without turning authentication into a scan of every token, and it is what
    the UI shows so an admin can recognise a token they cannot read.
    """

    __tablename__ = "service_tokens"

    token_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(default="")
    token_prefix: Mapped[str] = mapped_column(unique=True, index=True)
    token_hash: Mapped[str]
    # Space-separated ``resource:action`` grants; see api/services/service_tokens.py.
    scopes: Mapped[str] = mapped_column(default="")
    # viewer | operator | admin — the role this token acts with in its tenant.
    role: Mapped[str] = mapped_column(default="viewer")
    created_by: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)


class UserTenant(Base):
    """Which tenants a console user may act in, and with what role (P0).

    Since #156 ``username`` is a real FK to :class:`User`; before that it was a
    plain string because users lived in ``OCTO_API_USERS`` and there was no
    table to point at. A user with *no* rows keeps pre-P0 behaviour: access to
    the ``default`` tenant with their configured global role.

    ``role`` is the role **inside** this tenant and is independent of the
    global role in the JWT; the global ``admin`` role means platform admin and
    bypasses this table entirely (see api/services/memberships.py).
    """

    __tablename__ = "user_tenants"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(default="viewer")  # viewer | operator | admin
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("username", "tenant_id", name="uq_user_tenant"),
    )


class Permission(Base):
    """The catalogue of named authorities a role can carry (migration 0049, #318).

    Reference data, not state: the rows are seeded by the migration from
    :data:`api.core.permissions.PERMISSIONS` and read by
    ``GET /api/rbac/permissions`` so an operator building a role can see what
    there is to grant. Enforcement does **not** read this table — a request
    that had to query for its own authority is a request that fails open when
    the database is slow — which is why the compiled dict is the source of
    truth and a test asserts the two still agree.
    """

    __tablename__ = "permissions"

    permission_key: Mapped[str] = mapped_column(primary_key=True)
    description: Mapped[str] = mapped_column(default="")


class RoleDefinition(Base):
    """One role, built-in or defined by a tenant (migration 0049, #318).

    ``tenant_id`` is ``""`` for a built-in role — every tenant's — and a real
    tenant id for one that tenant defined. Empty string rather than NULL
    because both halves are in the primary key: a composite PK cannot hold a
    NULL at all, and a unique constraint over a nullable column treats two
    NULLs as distinct, which would let the same built-in role be seeded twice.

    The class is not called ``Role``: that name is the console's own role enum
    (:class:`api.auth.Role`), and two things called Role in one import graph is
    a bug waiting for a tired reviewer.
    """

    __tablename__ = "roles"

    role_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(primary_key=True, default="")
    description: Mapped[str] = mapped_column(default="")
    builtin: Mapped[bool] = mapped_column(default=False)
    # 1 = read-only, 2 = operator-level writes, 3 = administers the tenant.
    # Mirrors RoleDefinition.rank in api/core/permissions.py.
    rank: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)


class RolePermission(Base):
    """One permission held by one role (migration 0049, #318)."""

    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(primary_key=True, default="")
    permission_key: Mapped[str] = mapped_column(
        ForeignKey("permissions.permission_key", ondelete="CASCADE"), primary_key=True
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["role_id", "tenant_id"],
            ["roles.role_id", "roles.tenant_id"],
            ondelete="CASCADE",
            name="fk_role_permissions_role",
        ),
    )


class RevokedToken(Base):
    """One console token refused before its own ``exp`` -- the logout denylist (#314).

    ``User.token_version`` ends *every* session of an account at once; this
    table ends exactly one, which is what a logout is: signing out on a laptop
    should not sign the same person out of the phone next to it.

    A row is never longer-lived than the token it refuses, so the table is
    bounded by "sessions logged out while still valid" rather than by history.
    ``api/services/sessions.py`` deletes the expired rows on every write, and
    the index on ``expires_at`` is what that sweep reads.

    ``username`` is a real FK with ``ON DELETE CASCADE``, unlike
    :class:`AuthEvent`'s: a deleted account's tokens are already refused for
    the missing user row, so there is nothing left for the denylist to guard.
    """

    __tablename__ = "revoked_tokens"

    # The token's own ``jti``. Primary key, so revoking twice is idempotent
    # rather than a second row.
    jti: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE"), index=True
    )
    revoked_at: Mapped[datetime]
    # The ``exp`` of the token this row refuses. Naive UTC like every other
    # timestamp in this schema.
    expires_at: Mapped[datetime] = mapped_column(index=True)


class SessionFamily(Base):
    """One console sign-in and every refresh token it has been rotated through (#314).

    A login, an SSO callback or the second leg of an MFA login opens one of
    these; ``POST /api/auth/refresh`` extends it; nothing else creates a row.
    The access tokens minted for it quote ``family_id`` as their ``sid`` claim,
    so ending the family ends them too, on the next request rather than at
    their own ``exp``.

    Three clocks, all naive UTC:

    * ``expires_at`` — the absolute end, ``OCTO_JWT_EXPIRE_MINUTES`` after the
      sign-in. Refreshing never moves it: a stolen refresh token rotated
      forever still stops here.
    * ``last_used_at`` — the last sign-in or refresh. A refresh further than
      ``OCTO_SESSION_IDLE_MINUTES`` from it is refused: the idle timeout.
    * ``revoked_at`` — set by logout, by a refresh token presented twice
      (``revoked_reason='reuse'``), and by the idle and absolute refusals, so
      the row says why the session ended rather than only that it did.

    ``token_version`` is the account's generation at sign-in. A refresh is
    refused once the account's has moved on, which is how disable, demote,
    password change and ``revoke-all`` reach the refresh token as well as the
    access token — none of them has to know this table exists.

    ``mfa_verified_at`` is carried from the session that proved the factor to
    every access token refreshed from it, so a refresh neither loses a step-up
    nor makes an old one look new.
    """

    __tablename__ = "session_families"

    family_id: Mapped[str] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE"), index=True
    )
    token_version: Mapped[int]
    created_at: Mapped[datetime]
    # The sweep in ``api/services/sessions.py`` reads this index.
    expires_at: Mapped[datetime] = mapped_column(index=True)
    last_used_at: Mapped[datetime]
    mfa_verified_at: Mapped[datetime | None] = mapped_column(default=None)
    # Which factor ``mfa_verified_at`` was proved with (``totp``, ``recovery``,
    # ``webauthn``; migration 0061, #315). Always written together with it —
    # a newer proof by a weaker factor must replace the label as well as the
    # time — and carried into every refreshed access token.
    mfa_method: Mapped[str | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)
    revoked_reason: Mapped[str | None] = mapped_column(default=None)


class RefreshToken(Base):
    """One refresh token of a :class:`SessionFamily`, stored as its digest (#314).

    The browser holds the plaintext in an httpOnly cookie; this row holds
    ``sha256`` of it. A plain digest rather than bcrypt, unlike a password or a
    service token: the value is 256 random bits the server chose, so there is
    nothing to brute-force, and the lookup has to be by the digest itself.

    ``used_at`` is set the moment the token is exchanged. A second presentation
    of a row that already has one is the reuse the rotation exists to detect —
    one of the two presenters is not the browser the session was issued to —
    and ends the whole family.
    """

    __tablename__ = "refresh_tokens"

    token_hash: Mapped[str] = mapped_column(primary_key=True)
    family_id: Mapped[str] = mapped_column(
        ForeignKey("session_families.family_id", ondelete="CASCADE"), index=True
    )
    issued_at: Mapped[datetime]
    used_at: Mapped[datetime | None] = mapped_column(default=None)


class AuthEvent(Base):
    """One console-authentication attempt: the audit trail *and* the rate limiter (#157).

    Two jobs in one table, because they are two readings of the same rows. The
    admin-facing audit answers "who signed in, from where, and what failed";
    the limiter counts the failures for one ``(username, client_ip)`` pair
    inside a window. A separate counter table would have to be kept consistent
    with the log it summarises, and the query the limiter needs is already the
    log's natural index.

    ``username`` is **not** a FK to :class:`User`: the interesting failures are
    exactly the attempts naming an account that does not exist, and a FK would
    make them unrecordable. It stores what was submitted, truncated by the
    route's own length bound.

    ``client_ip`` is the address the request is attributed to after the trusted
    -proxy resolution in ``api/core/client_ip.py`` — never a raw
    ``X-Forwarded-For``, which the client writes itself and could use to pick a
    fresh limiter key per attempt.
    """

    __tablename__ = "auth_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(index=True)
    username: Mapped[str] = mapped_column(default="")
    client_ip: Mapped[str] = mapped_column(default="")
    # success | failure | locked | denied | trust_change. "locked" is a refusal
    # the credentials were never checked against, so it is none of the others;
    # "denied" and "trust_change" are decisions about an already-authenticated
    # principal (a scan out of scope, an SSH host-key pin set or removed).
    outcome: Mapped[str] = mapped_column(default="failure")
    # Machine-readable cause; NULL on success. See AUTH_REASONS in
    # api/services/auth_audit.py.
    reason: Mapped[str | None] = mapped_column(default=None)
    # Free-text subject of a non-login decision — for a scan-scope refusal
    # (#226) the targets that were out of scope. NULL for login attempts,
    # whose subject is already the username/IP pair.
    detail: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        # The limiter's exact predicate: one pair's recent rows, newest first.
        Index("ix_auth_events_pair", "username", "client_ip", "occurred_at"),
        # The per-IP limiter and the "what is this address doing" audit query.
        Index("ix_auth_events_ip", "client_ip", "occurred_at"),
    )


class AuditEvent(Base):
    """One administrative change this platform made, and who made it (#327).

    :class:`AuthEvent` next door answers "who signed in and what was refused";
    this one answers "what was changed" — the accounts, memberships,
    credentials, scan scopes and configuration an operator altered, with the
    value before and the value after. They stay two tables because they are two
    lifetimes: the login trail is also the rate limiter's counter and is pruned
    on the login path, while these rows are append-only (#329) and outlive it.

    ``tenant_id`` is NULL for a platform-level act (creating a console account,
    changing the installation-wide scanner config) and set for anything done
    *inside* a tenant. It is deliberately **not** a foreign key: deleting a
    tenant must not delete the record of what was done in it, which is the one
    moment the record matters most.

    ``before``/``after`` are the resource's public shape, never its secrets —
    :func:`api.services.audit.redact` drops password hashes, token plaintexts,
    provisioning keys and webhook secrets by field name before either is
    stored, so a reader of this table cannot recover a credential from it.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime]
    # NULL for a platform-level act; see the class docstring.
    tenant_id: Mapped[str | None] = mapped_column(default=None)
    # Console username, service-token name, agent id, or "system" — whatever
    # ``actor_type`` says this is. Not a FK, for the reason auth_events.username
    # is not one: the actor may be gone by the time the row is read.
    actor: Mapped[str] = mapped_column(default="")
    # user | service_token | agent | system
    actor_type: Mapped[str] = mapped_column(default="user")
    # Dotted verb, e.g. "user.create", "membership.revoke". See ACTIONS in
    # api/services/audit.py.
    action: Mapped[str] = mapped_column(default="")
    resource_type: Mapped[str] = mapped_column(default="")
    resource_id: Mapped[str] = mapped_column(default="")
    # Redacted snapshots. NULL rather than {} where the action has no such
    # side: a creation has no "before", a deletion has no "after".
    before: Mapped[dict | None] = mapped_column(_JSON_DOC, default=None)
    after: Mapped[dict | None] = mapped_column(_JSON_DOC, default=None)
    # Resolved through api/core/client_ip.py, like auth_events.client_ip — never
    # a raw X-Forwarded-For, which the client writes itself.
    client_ip: Mapped[str] = mapped_column(default="")
    user_agent: Mapped[str] = mapped_column(default="")
    # The X-Request-Id of the request that made the change, when it carried
    # one, so a row here can be joined to the API log line that produced it.
    request_id: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        # The list endpoint's default query: one tenant's rows, newest first.
        Index("ix_audit_events_tenant_time", "tenant_id", "occurred_at"),
        Index("ix_audit_events_action", "action"),
        # "everything that happened to this object", the question an incident
        # asks about one account, token or scope.
        Index("ix_audit_events_resource", "resource_type", "resource_id"),
        # The platform-admin listing and the export, which are not filtered by
        # tenant at all.
        Index("ix_audit_events_time", "occurred_at"),
    )


class AuditForwardCursor(Base):
    """How far a SIEM forwarder has read into :class:`AuditEvent` (#328).

    Only the ``db`` source of ``api.services.audit_syslog_forwarder`` uses this:
    the ``nats`` source keeps its position in a JetStream durable consumer,
    where it belongs. An installation with no broker has neither, and a cursor
    in a file would have meant a PersistentVolume for one integer and a
    forwarder that re-sent everything whenever a pod moved.

    One row per forwarder name, so a second destination added later gets its
    own place rather than fighting over this one. The position is the *pair*
    ``(last_occurred_at, last_id)``, and the next pass reads everything after
    it in that order: a cursor on ``id`` alone would skip a row whose
    transaction committed after a higher-id one, permanently.

    Deliberately **not** in ``audit_events``' immutability regime (#329): this
    is bookkeeping about the trail, not part of it, and it must be updatable by
    the API's own role.
    """

    __tablename__ = "audit_forward_cursors"

    forwarder: Mapped[str] = mapped_column(primary_key=True)
    # The id half of the position: the id of the last row written to the
    # destination's socket. Breaks the tie between two rows sharing a timestamp.
    last_id: Mapped[int] = mapped_column(default=0)
    # The timestamp half, and the one the ordering leads with. NULL on a
    # forwarder that has sent nothing yet, which reads as "before every row".
    last_occurred_at: Mapped[datetime | None] = mapped_column(default=None)
    updated_at: Mapped[datetime]


class OidcPendingState(Base):
    """One in-flight SSO authorization request, between the redirect and the callback (#321).

    This used to be a dict in the API process, which made an SSO login work
    only if the callback happened to land on the replica that issued it —
    every ``k8s/`` manifest may run more than one, and which one serves a
    request is the load balancer's choice. Session affinity for
    ``/api/auth/oidc/*`` was the documented workaround; it is not one, because
    a rollout moves the browser to a replica that never held the record.

    Keyed on ``sha256`` of the state's ``jti``, never the ``jti`` itself. The
    signed state is a bearer value for the remainder of the flow, so a reader
    of a dump of this table must not come away with the one thing that, with
    the platform secret, completes somebody else's login — the same reasoning
    as ``provisioning_keys.key_lookup``.

    ``nonce`` and ``code_verifier`` are the halves the browser never carries.
    Rows are single-use (``DELETE … RETURNING`` in
    ``api/services/oidc.py::consume_state``) and expire on ``expires_at``;
    nothing here outlives ``OCTO_OIDC_STATE_TTL_SECONDS``.
    """

    __tablename__ = "oidc_pending_states"

    state_hash: Mapped[str] = mapped_column(primary_key=True)
    nonce: Mapped[str]
    code_verifier: Mapped[str]
    # Sent again on the token exchange, where the provider compares it against
    # the one the authorization request carried. Stored rather than recomputed
    # so a redirect URI an operator changes mid-flight cannot fail the exchange
    # of a login that started under the old one.
    redirect_uri: Mapped[str]
    next_url: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime] = mapped_column(index=True)


class ProvisioningKey(Base):
    __tablename__ = "provisioning_keys"

    key_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    label: Mapped[str] = mapped_column(default="")
    key_hash: Mapped[str]
    # Non-secret sha256(plaintext)[:16] prefix, indexed, so resolve_provisioning_key
    # can look up the candidate row directly instead of bcrypt-verifying every key.
    key_lookup: Mapped[str] = mapped_column(index=True)
    created_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)
    # When the key stops being exchangeable, from OCTO_PROVISIONING_KEY_TTL_DAYS
    # at mint time (#308). NULL means "never", which is what every key minted
    # before this column has and what a TTL of 0 mints — the column adds an
    # expiry to new keys, it does not retroactively expire old ones.
    expires_at: Mapped[datetime | None] = mapped_column(default=None)


class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    status: Mapped[str] = mapped_column(default="active")  # active | stale | decommissioned
    first_seen: Mapped[datetime]
    # Moved by *anything* that observes the host, an endpoint agent's inventory
    # check-in included. It is not a coverage signal, which is what the three
    # columns below are for: they are written only by the scan-ingest path in
    # api/services/assets.py, so "scanned recently" cannot be satisfied by an
    # agent phoning home. Nullable with no backfill — nothing records which
    # past run covered which asset, so coverage reads as unknown until real
    # runs fill them.
    last_seen: Mapped[datetime]
    last_scanned_at: Mapped[datetime | None] = mapped_column(default=None)
    last_scan_run_id: Mapped[str | None] = mapped_column(default=None)
    # A discovery run covers the asset for inventory but says nothing about its
    # vulnerabilities. Set only when the run actually assessed them — findings
    # in vulnerabilities.json, or a vulnerability stage recorded as run in
    # stage_timings.json. The file's *existence* means nothing: report.py writes
    # it on every run (see api/services/assets.py::_assessed_vulnerabilities).
    last_vuln_scan_at: Mapped[datetime | None] = mapped_column(default=None)
    # "Ownership" (roadmap Phase 7.1) as plain nullable columns rather than a
    # join table — nothing in the scan pipeline produces multi-owner data yet;
    # a real ownership graph is Phase 11 territory.
    owner_email: Mapped[str | None] = mapped_column(default=None)
    business_unit: Mapped[str | None] = mapped_column(default=None)
    # Forward-compat for Phase 9 (exposure fingerprinting); unused this phase.
    asset_criticality: Mapped[int | None] = mapped_column(default=None)
    # Business context (#146). Operator- or CMDB-set; never inferred from a
    # scan. ``exposure_level`` is a *decision* ("we treat this as internet-
    # facing"), not a measurement — network exposure is still #171.
    business_service: Mapped[str | None] = mapped_column(default=None)
    environment: Mapped[str | None] = mapped_column(default=None)
    data_classification: Mapped[str | None] = mapped_column(default=None)
    exposure_level: Mapped[str | None] = mapped_column(default=None)
    # Who last wrote the context: operator | cmdb | ad | other.
    context_source: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (Index("ix_assets_tenant_status", "tenant_id", "status"),)


class AssetContextEvent(Base):
    """One audited change to an asset's business context (#146).

    Same contract as ``vulnerability_events``: written in the same transaction
    as the PATCH. ``actor`` is a username or null (platform / import).
    """

    __tablename__ = "asset_context_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(index=True)
    occurred_at: Mapped[datetime]
    field: Mapped[str]
    old_value: Mapped[str | None] = mapped_column(default=None)
    new_value: Mapped[str | None] = mapped_column(default=None)
    actor: Mapped[str | None] = mapped_column(default=None)
    source: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (Index("ix_asset_context_events_asset_time", "asset_id", "occurred_at"),)


class AssetIdentifier(Base):
    __tablename__ = "asset_identifiers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    # Denormalized (also on Asset) so the uniqueness constraint below can be
    # tenant-scoped without a join.
    tenant_id: Mapped[str] = mapped_column(index=True)
    identifier_type: Mapped[str]  # "ip" | "fqdn" | "cert_sha256"
    identifier_value: Mapped[str]

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "identifier_type", "identifier_value", name="uq_asset_identifier"
        ),
    )


class AssetIdentityLink(Base):
    """IP↔FQDN correlation evidence (P4.2).

    Written every run that can see the pair. ``merged`` is true only when
    both ``forward-dns`` and ``certificate`` agreed and the IP was not
    shared. A wrong merge is worse than two assets, so shared hosting
    stays two rows and this trail says why.
    """

    __tablename__ = "asset_identity_links"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    ip: Mapped[str]
    fqdn: Mapped[str]
    sources: Mapped[str]
    confidence: Mapped[str]
    shared: Mapped[bool] = mapped_column(default=False)
    merged: Mapped[bool] = mapped_column(default=False)
    survivor_id: Mapped[str | None] = mapped_column(default=None)
    run_id: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint("tenant_id", "ip", "fqdn", name="uq_asset_identity_link"),
        Index("ix_asset_identity_links_survivor", "survivor_id"),
    )


class ScanSchedule(Base):
    """Per-tenant recurring scan schedule (Phase 8.5).

    Dispatched by ``api.services.schedule_dispatcher`` in-process (same pod as
    the API, alongside the ClickHouse ingest worker) rather than one K8s
    CronJob per tenant. ``cron`` and ``interval_seconds`` are mutually
    exclusive; enforced in ``api/services/scan_schedules.py``, not here.
    """

    __tablename__ = "scan_schedules"

    schedule_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    name: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    cron: Mapped[str | None] = mapped_column(default=None)
    interval_seconds: Mapped[int | None] = mapped_column(default=None)
    scan_options: Mapped[dict] = mapped_column(JSON, default=dict)
    targets: Mapped[dict] = mapped_column(JSON, default=dict)
    next_run_at: Mapped[datetime | None] = mapped_column(default=None)
    last_run_at: Mapped[datetime | None] = mapped_column(default=None)
    last_job_id: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (Index("ix_scan_schedules_tenant_enabled", "tenant_id", "enabled"),)


class MaintenanceWindow(Base):
    """One recurring period in which scanning is forbidden, or the only one in
    which it is allowed (#352).

    The platform could express *when* a scan repeats (``scan_schedules``) but
    nothing about when it must not happen. A customer's change calendar —
    quarter close, a payment window, the night of a migration — lived in an
    email, and the only way to honour it was for somebody to remember to
    disable the schedules and remember to enable them again.

    ``kind`` is the polarity of the entry:

    * ``blackout`` — no scan may start while the window is open.
    * ``allowed`` — the tenant's scans may start **only** while one of its
      allowed windows is open. One such window turns the whole tenant into
      opt-in, which is why it is a separate kind rather than an inverted
      blackout: the two read differently in the calendar and are written by
      different customers.

    Recurrence is an RFC 5545 ``RRULE`` (the supported subset is documented in
    ``api/services/maintenance.py``), and it is evaluated in ``timezone`` —
    the tenant's, not the server's. ``dtstart_local`` is therefore a *wall
    clock* naive timestamp interpreted in that zone, so "every Saturday at
    22:00 local" stays at 22:00 local across a DST change instead of drifting
    by an hour. The absolute duration is ``duration_minutes``, which is what
    makes a window that crosses a spring-forward end when the operator said it
    would rather than an hour early.

    ``scope_kind`` is ``tenant`` (every scan of the tenant) or ``asset_group``.
    The platform has no first-class asset-group entity, so a group is named by
    ``asset_group`` and *defined* by ``scope_targets`` — the CIDRs and domain
    suffixes it covers, matched against a scan's targets by overlap with the
    same rules the approved scan scope uses. A scan whose targets are the
    installation defaults matches every window of its tenant: the control
    plane cannot tell what such a run will touch, and a blackout that could be
    dodged by omitting targets is not a blackout.
    """

    __tablename__ = "maintenance_windows"

    window_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    kind: Mapped[str] = mapped_column(default="blackout")  # blackout | allowed
    enabled: Mapped[bool] = mapped_column(default=True)
    timezone: Mapped[str] = mapped_column(default="UTC")
    rrule: Mapped[str]
    # Naive on purpose: wall clock in ``timezone``. See the class docstring.
    dtstart_local: Mapped[datetime]
    duration_minutes: Mapped[int] = mapped_column(default=60)
    scope_kind: Mapped[str] = mapped_column(default="tenant")  # tenant | asset_group
    asset_group: Mapped[str | None] = mapped_column(default=None)
    scope_targets: Mapped[list] = mapped_column(JSON, default=list)
    note: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime | None] = mapped_column(default=None)
    updated_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_maintenance_windows_tenant_enabled", "tenant_id", "enabled"),
    )


class EndpointDevice(Base):
    """A Lariska-managed endpoint (Endpoint Inventory Integration, Agent_plan.md).

    Separate identity from the network-scanner ``Asset``/``AssetIdentifier``
    tables — an endpoint may or may not link to an ``Asset`` (``asset_id``).
    Business-rule validation (reconciliation, bounds) lives in
    ``api/services/endpoint_inventory.py``.
    """

    __tablename__ = "endpoint_devices"

    device_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str]
    # SET NULL, not CASCADE: unlinking an asset must not delete the endpoint.
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="SET NULL"), default=None
    )
    hostname: Mapped[str]
    os_family: Mapped[str | None] = mapped_column(default=None)
    os_name: Mapped[str | None] = mapped_column(default=None)
    os_version: Mapped[str | None] = mapped_column(default=None)
    os_arch: Mapped[str | None] = mapped_column(default=None)
    agent_version: Mapped[str]
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    reconciliation_status: Mapped[str] = mapped_column(default="linked")  # linked | conflict | unlinked
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    last_inventory_at: Mapped[datetime | None] = mapped_column(default=None)
    latest_snapshot_id: Mapped[str | None] = mapped_column(default=None)
    # The software→CVE matcher's queue marker (migration 0033). The queue used
    # to be "``latest_snapshot_id`` differs from the ``snapshot_id`` on this
    # device's ``software_cve_matches`` rows", which cannot tell "matched, and
    # there was nothing to report" from "never matched": a host with no
    # matches has no rows. Those devices were due forever and, at
    # ``batch_size`` a tick with no ordering, crowded out the ones that had
    # actually changed. This column records the snapshot the fold last ran
    # over, whatever the fold's verdict was.
    last_matched_snapshot_id: Mapped[str | None] = mapped_column(default=None)
    # Consecutive failures folding this device, and when it may be tried
    # again. One device that raises must not be re-read at the head of every
    # batch for the rest of the installation's life.
    match_failure_count: Mapped[int] = mapped_column(default=0, server_default="0")
    match_retry_after: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_id", name="uq_endpoint_device_tenant_agent"),
        # The worker's due-devices read, which is a tenant-scoped comparison of
        # the two snapshot columns.
        Index("ix_endpoint_devices_match_queue", "tenant_id", "last_matched_snapshot_id"),
    )


class EndpointIdentifier(Base):
    """Agent-hashed platform identifier (MAC/serial/BIOS-UUID/TPM-EK). Only
    hashes are ever stored — never the raw machine identifier."""

    __tablename__ = "endpoint_identifiers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_devices.device_id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(index=True)
    identifier_type: Mapped[str]
    value_hash: Mapped[str]
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "identifier_type", "value_hash", name="uq_endpoint_identifier"
        ),
    )


class EndpointInventorySnapshot(Base):
    """One accepted inventory submission for a device. ``snapshot_id`` is
    agent-supplied (idempotency key); ``payload_digest`` is the canonical
    sha256 used to detect exact-replay vs. conflicting-content resubmits."""

    __tablename__ = "endpoint_inventory_snapshots"

    snapshot_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_devices.device_id", ondelete="CASCADE"), index=True
    )
    schema_version: Mapped[int]
    collected_at: Mapped[datetime]
    received_at: Mapped[datetime]
    payload_digest: Mapped[str]
    software_count: Mapped[int]
    collector_warnings: Mapped[dict] = mapped_column(JSON, default=dict)
    response: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        UniqueConstraint("tenant_id", "snapshot_id", name="uq_endpoint_snapshot"),
    )


class EndpointSoftwareItem(Base):
    """A single software row within one snapshot. ``comparison_key`` is the
    stable sha256(name|publisher|architecture|source) used for diffing
    against the device's previous accepted snapshot."""

    __tablename__ = "endpoint_software_items"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_inventory_snapshots.snapshot_id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(index=True)
    device_id: Mapped[str] = mapped_column(index=True)
    comparison_key: Mapped[str]
    name: Mapped[str]
    version: Mapped[str | None] = mapped_column(default=None)
    publisher: Mapped[str | None] = mapped_column(default=None)
    architecture: Mapped[str | None] = mapped_column(default=None)
    source: Mapped[str]
    install_location: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint(
            "snapshot_id", "comparison_key", name="uq_software_item_snapshot_key"
        ),
    )


class EndpointSoftwareChange(Base):
    """installed/removed/updated event computed by diffing two consecutive
    accepted snapshots for a device. Suppressed for a device's first
    snapshot. No upgrade/downgrade ordering is claimed for ``updated``."""

    __tablename__ = "endpoint_software_changes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_devices.device_id", ondelete="CASCADE"), index=True
    )
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_inventory_snapshots.snapshot_id", ondelete="CASCADE")
    )
    comparison_key: Mapped[str]
    event_type: Mapped[str]  # installed | removed | updated
    old_version: Mapped[str | None] = mapped_column(default=None)
    new_version: Mapped[str | None] = mapped_column(default=None)
    display_name: Mapped[str]
    observed_at: Mapped[datetime]

    __table_args__ = (
        Index("ix_endpoint_software_changes_device_time", "device_id", "observed_at"),
        Index("ix_endpoint_software_changes_tenant_time", "tenant_id", "observed_at"),
    )


class WebhookSubscription(Base):
    """Outbound webhook for asset events (ROADMAP P2 / Phase 10.3).

    The routing policy is the row itself: ``event_kinds`` (empty = every kind)
    and ``min_severity`` (applied only to the kinds that carry a severity, i.e.
    ``new_cve``) decide whether an event on ``events.asset.{tenant}.{kind}``
    becomes a delivery. Keeping the policy in Postgres rather than in a NATS
    consumer's filter subject is what lets an operator change it through the
    API without touching the broker, and what makes the per-tenant scoping the
    same scoping every other table here uses.

    ``secret`` is the HMAC key the receiver verifies with — for a ticket
    transport, the tracker's API token. It cannot be hashed: a signature is
    *computed*, not compared, and a token has to be replayed to Jira as issued.
    So since #310 it is encrypted at rest instead, as are the ``headers``
    values, which is where an ``Authorization`` header for the same tracker
    lives. ``api/services/crypto`` holds the envelope; redaction on the read
    paths (``secure_webhooks.py``) is unchanged and still the answer to a
    different question — what an API *caller* may see, rather than what a dump
    of this table yields.
    """

    __tablename__ = "webhook_subscriptions"

    subscription_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    url: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    # [] means "every asset kind" — the administrative trail (audit.*, #328) is
    # opt-in, so an upgrade does not start posting it to receivers configured
    # before it could leave the platform. Validated on write against
    # asset_events.EVENT_KINDS plus the audit forms.
    event_kinds: Mapped[list] = mapped_column(JSON, default=list)
    min_severity: Mapped[str | None] = mapped_column(default=None)
    secret: Mapped[str | None] = mapped_column(default=None)
    # Static headers merged into every request (e.g. an API gateway token).
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    # webhook (HMAC POST, default) | jira | servicenow | defectdojo.
    # Ticket transports reuse this queue; they do not HMAC-sign a foreign API.
    transport: Mapped[str] = mapped_column(default="webhook")
    # Adapter knobs that are not credentials: Jira project_key / issue_type,
    # ServiceNow table, DefectDojo test_id. Tokens stay in secret/headers.
    transport_config: Mapped[dict] = mapped_column(JSON, default=dict)
    # KEK id every encrypted value in this row is wrapped with; NULL means the
    # row holds nothing secret, or predates #310 and is still plaintext. Each
    # ciphertext already names its own key, so this is a queryable mirror
    # rather than the authority — the two readers that want the question
    # answered in SQL rather than by parsing every column: the startup check
    # (api/services/crypto/startup.py), which asks whether this installation
    # stores integration secrets at all, and the operator confirming a rotation
    # is finished (docs/operations.md § Secrets at rest, GROUP BY key_id).
    # `reencrypt_secrets` deliberately does not trust it: it derives the label
    # from the values it just wrote. Keeping it true is why a write re-encrypts
    # all of the row's secret material, not only the fields the request touched
    # (api/services/integrations/webhooks.py).
    key_id: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime | None] = mapped_column(default=None)
    last_delivery_at: Mapped[datetime | None] = mapped_column(default=None)
    last_status: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_webhook_subscriptions_tenant_enabled", "tenant_id", "enabled"),
    )


class NotificationChannel(Base):
    """Where one tenant's finished-run notifications go (#351).

    Alerts used to be an installation-wide affair: ``OCTO_SLACK_WEBHOOK``,
    ``OCTO_SMTP_TO`` and ``OCTO_DEFECTDOJO_*`` were read by the scanner, so in
    an MSSP every tenant's scan announced itself in one Slack channel and every
    tenant's findings landed in one DefectDojo product. This table is the
    per-tenant answer, deliberately shaped like ``webhook_subscriptions`` next
    door: a tenant-scoped row, a ``kind`` that selects an adapter, non-secret
    adapter knobs in JSON, and the credential encrypted at rest under #310.

    Where the credential lives depends on the kind, and the split is the
    interesting part:

    * ``slack`` / ``msteams`` / ``mattermost`` — the incoming-webhook URL *is*
      the credential (anyone holding it can post to the channel), so it lives
      in ``secret`` and ``endpoint`` stays NULL. That is a deliberate
      difference from ``webhook_subscriptions.url``, which is a receiver the
      tenant also authenticates by signature.
    * ``defectdojo`` — ``endpoint`` is the instance URL (not a credential) and
      ``secret`` is the API token, exactly as for the ticket transports.
    * ``email`` — neither. The recipients are in ``config["to"]``; the relay
      itself is installation infrastructure (``OCTO_REPORT_SMTP_*``), the same
      way Postgres is, and it was never the part that crossed tenants.

    ``min_severity`` is the floor this channel cares about: the severity above
    which new findings are listed in a chat/email alert, and the DefectDojo
    import's ``minimum_severity``. It is not a mute switch — a run summary is
    sent even when nothing new crossed the floor, because "nothing new" is a
    result an operations channel wants.
    """

    __tablename__ = "notification_channels"

    channel_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    # slack | msteams | mattermost | email | defectdojo. Validated on write
    # against api/services/integrations/channel_transports.py::KINDS.
    kind: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    min_severity: Mapped[str] = mapped_column(default="high")
    # The target system's non-secret base URL: the DefectDojo instance, and
    # nothing else so far. NULL for the kinds whose URL is a credential.
    endpoint: Mapped[str | None] = mapped_column(default=None)
    # Adapter knobs that are not credentials: the mail recipients, the
    # DefectDojo product/engagement names, a Mattermost channel override.
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    secret: Mapped[str | None] = mapped_column(default=None)
    # The KEK this row's ciphertext is wrapped with, mirroring
    # ``webhook_subscriptions.key_id`` — same meaning, same non-authority, and
    # read by the same two callers (the startup check and the rotation
    # runbook's GROUP BY).
    key_id: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime | None] = mapped_column(default=None)
    # Last attempt and its outcome. There is no delivery queue behind a
    # channel: a run summary is only interesting while it is fresh, so an
    # unreachable Slack is reported here and on the job log rather than
    # retried for fifteen minutes into a channel that has moved on.
    last_send_at: Mapped[datetime | None] = mapped_column(default=None)
    last_status: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_notification_channels_tenant_enabled", "tenant_id", "enabled"),
    )


class WebhookDelivery(Base):
    """One attempt-carrying delivery of one event to one subscription (10.3).

    This single table is the retry queue, the dead-letter queue and the audit
    trail at once, because they are the same rows seen through different
    predicates: ``status="pending"`` with a due ``next_attempt_at`` is the
    queue, ``status="dead"`` is the DLQ, and every row that ever existed is the
    trail of what this installation sent where. Splitting them would mean
    copying a row between tables on every state change and losing the history
    of the attempts that led there.

    ``(subscription_id, event_id)`` is unique: JetStream is at-least-once, so
    the fan-out consumer can legitimately see the same event twice, and a
    redelivery must not turn into a second webhook call.
    """

    __tablename__ = "webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    subscription_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_subscriptions.subscription_id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[str]
    event_kind: Mapped[str]
    # The exact body that was (or will be) POSTed, so a redelivery from the DLQ
    # sends what the event said at the time and not a re-derived approximation.
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(default="pending")  # pending|delivered|dead
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    next_attempt_at: Mapped[datetime | None] = mapped_column(default=None)
    last_status_code: Mapped[int | None] = mapped_column(default=None)
    last_error: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    delivered_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("subscription_id", "event_id", name="uq_webhook_delivery_event"),
        # The dispatcher's predicate: due pending rows, oldest first. It runs on
        # every replica on a short timer, so it must not scan the table.
        Index("ix_webhook_deliveries_due", "status", "next_attempt_at"),
        Index("ix_webhook_deliveries_tenant_status", "tenant_id", "status", "created_at"),
    )


class SlaPolicy(Base):
    """Remediation deadline for one (asset criticality, severity) pair (#145).

    The SLA an organisation actually has is "critical findings on
    business-critical systems in 7 days, everything else in 90" — two axes, so
    the policy is a small table rather than a column on the tenant. A row with
    ``asset_criticality = NULL`` is the tenant's fallback for that severity,
    which is what makes the table usable before anyone has set criticality on a
    single asset. When no row matches at all, the built-in defaults in
    ``api/services/vulnerabilities.py`` apply; they are code and not seeded rows
    so that an installation which never opens this API still gets deadlines,
    and so that "the default changed" is a release note rather than a data
    migration on every tenant.

    ``remediation_days`` is days and not hours: an SLA measured in hours would
    be a promise about scan cadence (``OCTO_*`` schedules are daily by default)
    that nothing in this platform can keep.
    """

    __tablename__ = "sla_policies"

    policy_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    # NULL = the tenant's fallback for this severity. 0–4, same scale as
    # Asset.asset_criticality.
    asset_criticality: Mapped[int | None] = mapped_column(default=None)
    # critical | high | medium | low | unknown — scanner.pipeline.report.SEVERITY_ORDER.
    severity: Mapped[str]
    remediation_days: Mapped[int]
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        # One deadline per (criticality, severity). Two rows would mean the
        # answer depended on row order, i.e. on nothing.
        UniqueConstraint(
            "tenant_id", "asset_criticality", "severity", name="uq_sla_policy_scope"
        ),
    )


class Vulnerability(Base):
    """One finding tracked across runs, with its lifecycle state (#145).

    Until this table the platform had no *vulnerability* — only per-run rows.
    ``vulnerabilities.json`` is rewritten by every scan, the ClickHouse
    ``shapoclyack_vulnerabilities`` table is a ``ReplacingMergeTree`` whose
    whole job is to keep the latest observation, and both are therefore
    unable to hold anything a human wrote: an owner, a decision, a deadline. A
    ``ReplacingMergeTree`` merge would silently drop them. So the state that
    people produce lives here, in Postgres, next to the assets and jobs, and
    the analytics store keeps doing what it is good at.

    **Identity.** ``finding_key`` is ``sha256(asset_id|cve-or-script_id|port)``
    — deliberately the same triple the report pipeline already de-duplicates on
    (``_dedupe_vulnerabilities``: host:port:CVE), so "the same finding" means
    the same thing to the tracker as it does to the report. It is scoped by
    tenant, not global. The key is over ``asset_id`` rather than the observed
    IP because an asset is what survives a DHCP lease: correlating a finding to
    the asset registry (Phase 7) is what lets a host keep its remediation
    history when its address changes.

    **Two sources, one identity space.** ``source="endpoint_software"`` rows
    are keyed by ``api/services/software_findings.py``'s own hash, which
    includes ``device_id`` and its own namespace element. The scan path's
    ``finding_key`` is deliberately untouched: adding anything to that hash
    would rename every existing finding and reopen the whole backlog.

    **Denormalised finding fields** (``severity``, ``contextual_score``,
    ``risk_level``, …) are the values from the *latest* observation. They are
    copied here rather than joined from the run artifacts because the queries
    this table exists to serve — "what breaches SLA, sorted by risk" — must not
    depend on a run directory still being on disk, and because the run that
    first found something may long since have been pruned.

    ``due_at`` is stored, while SLA *breach* is derived on read. Storing the
    deadline is what makes "what is overdue" an indexed query instead of a
    scan; deriving the breach keeps a clock comparison out of the table, where
    it would otherwise need a sweeper to stay true and could be frozen wrong by
    whichever replica wrote last (the same reasoning as ``Agent.status`` never
    storing "stale").
    """

    __tablename__ = "vulnerabilities"

    vuln_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    # CASCADE: a finding is a statement about an asset. If the asset row is
    # gone, the finding is not a record of anything addressable.
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"), index=True
    )
    finding_key: Mapped[str]
    # Which observer produced this row: "scan" (a run's vulnerabilities.json,
    # register_findings_from_run) or "endpoint_software" (a software→CVE match
    # folded in by api/services/software_findings.py). The two share the table
    # because they share everything an operator does with a finding — an owner,
    # a deadline, a ticket, an audit trail — and differ only in who is allowed
    # to say it is gone. "retro_match" (api/services/retro_findings.py) is a
    # stored service fingerprint re-matched against the NVD range dataset; it
    # shares the *scan* key, and a scan that observes it takes the row over.
    source: Mapped[str] = mapped_column(default="scan", server_default="scan")
    # The endpoint the software finding was observed on. NULL for every scan
    # finding. SET NULL rather than CASCADE, exactly as EndpointDevice.asset_id
    # is: retiring a device must not delete the remediation history of what was
    # found on it, which stays attached to the asset.
    device_id: Mapped[str | None] = mapped_column(
        ForeignKey("endpoint_devices.device_id", ondelete="SET NULL"), default=None
    )
    # What was found. `cve` is NULL for exposure/nuclei findings, which is why
    # `script_id` is part of the identity too.
    cve: Mapped[str | None] = mapped_column(default=None)
    # NVD/nuclei CWE ids from the latest observation. Empty when the overlay
    # has none — never inferred from the CVE id.
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    script_id: Mapped[str | None] = mapped_column(default=None)
    port: Mapped[str | None] = mapped_column(default=None)
    title: Mapped[str] = mapped_column(default="")
    # Latest observation's assessment (api/services/risk_scoring.py, nist-1).
    severity: Mapped[str] = mapped_column(default="unknown")
    risk_level: Mapped[str | None] = mapped_column(default=None)
    contextual_score: Mapped[float | None] = mapped_column(default=None)
    cvss: Mapped[float | None] = mapped_column(default=None)
    # Latest observation's exploit overlay (#139). Copied here so Threat Intel
    # does not depend on the run directory still being on disk.
    in_kev: Mapped[bool] = mapped_column(default=False, server_default="false")
    exploit_maturity: Mapped[str | None] = mapped_column(default=None)
    # Latest observation's network exposure (#171). external | internal | unknown.
    # ``unknown`` is the default so a missing observation is not "not exposed".
    network_exposure: Mapped[str | None] = mapped_column(default=None)
    network_exposure_source: Mapped[str | None] = mapped_column(default=None)
    # Lifecycle. Legal moves live in api/services/vuln_states.py; the column
    # stays a plain string so adding a state does not need a migration.
    state: Mapped[str] = mapped_column(default="OPEN")
    state_changed_at: Mapped[datetime]
    state_changed_by: Mapped[str | None] = mapped_column(default=None)
    # Ownership of *remediation*, which is not the same as Asset.owner_email
    # (who runs the box). Defaulted from the asset on creation and then
    # independent — reassigning a fix must not rewrite the asset registry.
    assignee: Mapped[str | None] = mapped_column(default=None)
    # Free-form team/queue name. A FK would require a teams table that nothing
    # else in the platform has yet (#146 territory).
    owner_team: Mapped[str | None] = mapped_column(default=None)
    # SLA. `sla_days` records the policy that produced `due_at`, so a later
    # policy edit is visibly not what the finding was judged against until it
    # is re-observed.
    due_at: Mapped[datetime | None] = mapped_column(default=None)
    sla_days: Mapped[int | None] = mapped_column(default=None)
    # "default" (built-in table) | "policy" (a sla_policies row) | "exception".
    sla_source: Mapped[str | None] = mapped_column(default=None)
    # Accepted risk, expiring. See the vuln_states docstring for why this is an
    # attribute and not a seventh state. ``exception_until`` and
    # ``exception_by`` describe the acceptance that is *in force*: written when
    # it is approved, cleared when it is withdrawn. So ``exception_until is not
    # NULL and in the future`` still means exactly what it meant before #348 —
    # the clock is suspended until then — while ``exception_by`` is now the
    # approver rather than whoever asked for it.
    exception_until: Mapped[datetime | None] = mapped_column(default=None)
    # The justification. Written when the acceptance is *requested* and kept
    # through the decision, including a rejected or lapsed one: the risk
    # register has to be able to show what was argued, not only what was
    # granted.
    # The justification *of the acceptance in force*. A later request for an
    # extension writes its own text to ``exception_requested_reason`` instead:
    # this column is what somebody signed, and an unapproved ask overwriting it
    # would put unapproved words in the risk register.
    exception_reason: Mapped[str | None] = mapped_column(default=None)
    exception_by: Mapped[str | None] = mapped_column(default=None)
    # The rest of the acceptance in force, written at approval and untouched by
    # whatever the workflow does next. ``exception_decided_*`` below describe
    # the *latest* decision, which after a refused extension is a rejection —
    # reading the register off them named the person who said no as the
    # approver.
    exception_approved_at: Mapped[datetime | None] = mapped_column(default=None)
    exception_approved_requested_by: Mapped[str | None] = mapped_column(default=None)
    # When the sweep recorded that the window ran out. It is the once-only
    # marker for that sweep, which is why it is a column and not an inference
    # from ``exception_state``: a finding whose extension is pending (or was
    # refused) still has an acceptance that lapses, and its workflow state has
    # moved on from ``exception_approved``.
    exception_expired_at: Mapped[datetime | None] = mapped_column(default=None)
    # The approval workflow around it (#348). ``exception_state`` is the
    # machine in api/services/vuln_states.py; the request fields are what was
    # asked for and by whom, the decision fields are the second person's
    # answer. The requester is kept after the decision on purpose — a register
    # that could not say who asked cannot show that two people were involved,
    # which is the entire control.
    exception_state: Mapped[str] = mapped_column(default="none", server_default="none")
    exception_requested_by: Mapped[str | None] = mapped_column(default=None)
    exception_requested_at: Mapped[datetime | None] = mapped_column(default=None)
    # The expiry that was asked for. Copied to ``exception_until`` on approval
    # and left here afterwards, so a rejected or lapsed request still says what
    # window it wanted.
    exception_requested_until: Mapped[datetime | None] = mapped_column(default=None)
    # The justification of the request that is waiting. Promoted to
    # ``exception_reason`` when it is approved, kept here when it is refused.
    exception_requested_reason: Mapped[str | None] = mapped_column(default=None)
    exception_decided_by: Mapped[str | None] = mapped_column(default=None)
    exception_decided_at: Mapped[datetime | None] = mapped_column(default=None)
    exception_decision_note: Mapped[str | None] = mapped_column(default=None)
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    # The run the SLA clock is counted from: first discovery, or the
    # re-observation that reopened it. Not necessarily first_seen_run_id.
    sla_started_at: Mapped[datetime]
    first_seen_run_id: Mapped[str | None] = mapped_column(default=None)
    last_seen_run_id: Mapped[str | None] = mapped_column(default=None)
    observation_count: Mapped[int] = mapped_column(default=1, server_default="1")
    reopen_count: Mapped[int] = mapped_column(default=0, server_default="0")
    closed_at: Mapped[datetime | None] = mapped_column(default=None)
    # Operator-set pointer to work in an external tracker (#138). Creating the
    # ticket itself is a 10.3/P2 transport; this is only the link.
    ticket_system: Mapped[str | None] = mapped_column(default=None)
    ticket_key: Mapped[str | None] = mapped_column(default=None)
    ticket_url: Mapped[str | None] = mapped_column(default=None)
    # The inbound sync worker's cursor (#347): when this finding's ticket was
    # last *read*, whether or not the read succeeded. It is the attempt and not
    # the success on purpose — a tracker answering 404 for one key must not put
    # that finding at the head of every batch forever, starving the rest. Which
    # of the two it was is in ``ticket_sync_error``, and the worker's `lag`
    # metric is the age of the oldest cursor still due.
    ticket_synced_at: Mapped[datetime | None] = mapped_column(default=None)
    # The tracker's own status string as of that read ("Done", "6", "Active").
    # The poller applies a suggestion only when this *changes*, which is what
    # keeps it from re-imposing a state an operator has just overruled: if a
    # human reopens a finding whose Jira issue is still Done — and the outbound
    # reflection could not move it, because the workflow offers no Reopen —
    # then without this the next tick would close it again, every interval,
    # forever. The manual button is not subject to it: a person clicking Sync
    # is asking for the tracker's current word regardless.
    ticket_remote_status: Mapped[str | None] = mapped_column(default=None)
    # The last read's failure, or NULL after one that worked. Kept on the row
    # rather than only in the log because "the ticket link is broken" is a
    # property of this finding that an operator has to be able to see.
    ticket_sync_error: Mapped[str | None] = mapped_column(default=None)
    # Closed-loop remediation (#183). ``machine_verified`` is only ever set by
    # the ingest path in api/services/vulnerabilities.py, never from a request
    # body: the whole value of the metric is that it cannot be self-attested.
    machine_verified: Mapped[bool] = mapped_column(default=False, server_default="false")
    # The job dispatched to re-check this finding. The closure is gated on the
    # run that job produced, so an unrelated scan touching the same asset can
    # never close a finding as verified.
    verification_job_id: Mapped[str | None] = mapped_column(default=None)
    last_verified_at: Mapped[datetime | None] = mapped_column(default=None)
    # verified_remediated | manual | ticket_resolved | patched |
    # false_positive. See CLOSURE_REASONS in
    # api/services/vulnerabilities.py. ``patched`` is the software path's
    # own: the next accepted inventory snapshot no longer matches the CVE,
    # which is a machine observation but not a re-scan.
    closure_reason: Mapped[str | None] = mapped_column(default=None)
    # False-positive verdict, expiring — an attribute for the same reason
    # accepted risk is one (see the vuln_states docstring). `fp_suppress_until`
    # is mandatory whenever the verdict is set: a suppression with no end date
    # is a finding nobody looks at again. `fp_observations` counts how often the
    # scanner still saw it while suppressed, which is the number that says
    # whether the verdict was wrong.
    fp_reason: Mapped[str | None] = mapped_column(default=None)
    fp_marked_by: Mapped[str | None] = mapped_column(default=None)
    fp_marked_at: Mapped[datetime | None] = mapped_column(default=None)
    fp_evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    fp_suppress_until: Mapped[datetime | None] = mapped_column(default=None)
    fp_observations: Mapped[int] = mapped_column(default=0, server_default="0")
    # How sure the observer is, for a finding nobody observed directly: a
    # ``retro_match`` row says "the NVD range dataset covers the version this
    # service disclosed" (``version_range``) or "the distribution's advisory
    # says this build is unfixed" (``vendor_advisory``). NULL for every scan
    # and endpoint-software finding, and cleared when a scan observes the
    # finding itself (docs/retro-cve-matching.md).
    match_confidence: Mapped[str | None] = mapped_column(default=None)
    # What the retro matcher saw: product, version, CPE, the range, the feed
    # date, the advisory. Kept after a scan takes the row over, because it is
    # the record of why the finding existed before the scan confirmed it.
    match_evidence: Mapped[dict | None] = mapped_column(JSON, default=None)
    # When the retro matcher announced this finding as a ``new_cve`` event.
    # NULL on a retro finding means "committed, not yet announced" — the
    # durable half of at-least-once delivery (retro_findings.announce_pending).
    # NULL and meaningless for every other source.
    match_announced_at: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]

    __table_args__ = (
        # Identity: re-observing a finding must find this row, and two API
        # replicas ingesting the same run must not create it twice.
        UniqueConstraint("tenant_id", "finding_key", name="uq_vulnerability_finding"),
        # Ingest asks "which findings were waiting on this run?".
        Index("ix_vulnerabilities_verification_job", "verification_job_id"),
        # The SLA queries: one tenant's still-open findings by deadline.
        Index("ix_vulnerabilities_due", "tenant_id", "state", "due_at"),
        # The Vulnerability Center's default view: worst first within a tenant.
        Index("ix_vulnerabilities_risk", "tenant_id", "state", "contextual_score"),
        Index("ix_vulnerabilities_asset", "tenant_id", "asset_id"),
        Index("ix_vulnerabilities_assignee", "tenant_id", "assignee"),
        # The source filter, and the software worker's "what is still open from
        # the endpoint inventory" read.
        Index("ix_vulnerabilities_source", "tenant_id", "source", "state"),
        # Adoption: one tenant's closures inside a window, by reason.
        Index("ix_vulnerabilities_fp", "tenant_id", "closure_reason", "closed_at"),
        Index("ix_vulnerabilities_closed", "tenant_id", "state", "closed_at"),
        # The retro announcer's read: findings committed but not yet announced
        # (migration 0064). Partial, so it holds only those.
        Index(
            "ix_vulnerabilities_retro_unannounced",
            "tenant_id",
            postgresql_where=text("source = 'retro_match' AND match_announced_at IS NULL"),
            sqlite_where=text("source = 'retro_match' AND match_announced_at IS NULL"),
        ),
        # The ticket-sync worker's due read: one tenant's findings on one
        # tracker, oldest cursor first (#347).
        Index(
            "ix_vulnerabilities_ticket_sync",
            "tenant_id",
            "ticket_system",
            "ticket_synced_at",
        ),
    )


class VulnerabilityEvent(Base):
    """One auditable thing that happened to one finding (#145).

    #145's acceptance criterion is that *all* transitions are auditable, so the
    row is written in the same transaction as the change it records — an audit
    trail assembled afterwards from logs is an approximation of what happened,
    and one that a crash between the two writes makes wrong.

    Observations are events too (``kind="observed"``), which is what makes the
    trail answer "when did this stop being seen" without a separate scan
    history. They are the high-volume kind: one per finding per scan. Retention
    is deliberately not implemented here — the endpoint-inventory retention
    worker is the pattern to follow when the volume justifies it, and until
    then losing the trail is worse than keeping it.
    """

    __tablename__ = "vulnerability_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    vuln_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.vuln_id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[str] = mapped_column(index=True)
    occurred_at: Mapped[datetime]
    # observed | state_change | reopened | assigned | exception_set |
    # exception_cleared | comment | ticket_set | ticket_cleared —
    # see VULN_EVENT_KINDS in api/services/vulnerabilities.py.
    kind: Mapped[str]
    from_state: Mapped[str | None] = mapped_column(default=None)
    to_state: Mapped[str | None] = mapped_column(default=None)
    # The username, or NULL when the scanner did it. NULL is meaningful: it is
    # the difference between "the platform observed this" and "a person said
    # so", and no FK to users, because the trail must outlive the account.
    actor: Mapped[str | None] = mapped_column(default=None)
    note: Mapped[str | None] = mapped_column(default=None)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        # The per-finding timeline, newest first, and the tenant-wide activity
        # feed the remediation view (#138) reads.
        Index("ix_vulnerability_events_vuln_time", "vuln_id", "occurred_at"),
        Index("ix_vulnerability_events_tenant_time", "tenant_id", "occurred_at"),
    )


class AssetTag(Base):
    __tablename__ = "asset_tags"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    key: Mapped[str]
    value: Mapped[str]

    __table_args__ = (UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),)


class Wordlist(Base):
    """A tenant-uploaded wordlist for subdomain/bucket brute force (Phase 8.2).

    ``ct.brute_force.wordlist_file`` and ``cloud.wordlist_file`` in the scanner
    config point at a path on disk, which forces operators to bake custom
    wordlists into the image or a mounted volume. This stores the list itself
    in Postgres, like the config overrides and tenant stores, so it survives
    restarts and reaches every replica; at local scan start the selected row is
    materialized to a file under the state dir and that path is injected into
    the job's effective config.

    ``content`` is the already-normalized newline-joined body (lowercased,
    de-duplicated, comments/blank lines stripped — the same shape
    ``hostnames._load_wordlist`` would have produced), so the scanner reads it
    verbatim. ``sha256`` is over that normalized body, for dedupe and display.
    """

    __tablename__ = "wordlists"

    wordlist_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    # subdomain | bucket — which brute-force stage the list feeds. Kept as a
    # plain string so a new kind does not need a migration.
    kind: Mapped[str] = mapped_column(default="subdomain")
    content: Mapped[str]
    line_count: Mapped[int] = mapped_column(default=0)
    sha256: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        # One name per tenant, so a scan can select a wordlist by a stable
        # human name and re-uploading under the same name is an update.
        UniqueConstraint("tenant_id", "name", name="uq_wordlist_tenant_name"),
    )


class AgentGroup(Base):
    """A named set of a tenant's agents, and the unit a job can be addressed to (#361).

    Before this table an agent job was claimable by any agent of the tenant, so
    a provider running one agent inside a customer's card-data segment and
    another in their office network could not say which of the two a scan of
    the card-data segment had to come from. The queue was flat and the first
    worker to poll won.

    A group is identified by its ``name`` inside the tenant, not by
    ``group_id``: ``agents.agent_group``, ``jobs.agent_group`` and
    ``tenant_scan_scopes.agent_groups`` all refer to it by that name, because
    the name is also what the API body, the console and the operator use. The
    name is therefore immutable — there is no rename endpoint — and deleting a
    group is refused by ``api/services/agent_groups.py`` while anything still
    names it, since the alternative is a scope entry whose restriction quietly
    evaporates.

    Membership is written only by an operator holding ``agent.group.manage``.
    An agent's own ``labels`` are not consulted: a worker that could declare
    its way into a group would be granting itself the jobs of a segment it does
    not sit in, which is the control this table exists to provide.
    """

    __tablename__ = "agent_groups"

    group_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    description: Mapped[str] = mapped_column(default="")
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_agent_groups_tenant_name"),
    )


class Agent(Base):
    """Registered remote scanning agent (ROADMAP P1.1).

    Was a module-level dict in ``api/services/agents.py`` mirrored to
    ``state/api_agents.json``: a second API replica saw its own registry, and
    concurrent writers raced on a whole-file rewrite. The row is the registry
    now; the JSON file is imported once at startup and then retired.

    ``status`` here is the last *reported* state (idle | busy | error).
    "stale" is never stored — it is derived on read from ``last_seen_at``
    against ``OCTO_AGENT_STALE_SECONDS``, so staleness cannot get frozen into
    the table by whichever replica happened to write last.
    """

    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    hostname: Mapped[str] = mapped_column(default="")
    version: Mapped[str] = mapped_column(default="")
    # ``scanner`` or ``endpoint`` (#358). Two different programs register here:
    # the scanning agent that claims jobs, and the Lariska endpoint agent that
    # only submits inventory. Without the distinction the fleet view compared
    # an endpoint agent's version against the *scanner's* and declared it
    # permanently outdated, and the ``agent_offline`` escalation treated a
    # sleeping laptop as a scanner that had gone missing.
    agent_kind: Mapped[str] = mapped_column(default="scanner", server_default="scanner")
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(default="idle")
    # What an *operator* decided about this agent (active | disabled |
    # quarantined), as distinct from ``status`` above, which is what the agent
    # last said about itself. Two columns rather than one because the two
    # answer different questions and are written by different parties: an
    # agent reporting "busy" must not overwrite an operator's "quarantined",
    # and the fleet view needs both at once (#308).
    lifecycle_status: Mapped[str] = mapped_column(default="active", server_default="active")
    # Free text from the operator who moved it out of ``active`` — it is what
    # the refused agent is told and what the next operator reads.
    lifecycle_reason: Mapped[str | None] = mapped_column(default=None)
    # The provisioning key this agent registered with, so deleting the agent
    # can also revoke the credential that would let the same host register
    # itself straight back (#308). Nullable: legacy shared-token agents were
    # never minted from a key, and rows that predate this column have no
    # record of which key they used.
    provisioning_key_id: Mapped[str | None] = mapped_column(
        ForeignKey("provisioning_keys.key_id"), default=None, index=True
    )
    # Which agent group an *operator* put this agent in (#361), by name — the
    # vocabulary ``jobs.agent_group`` and the scope entries share. NULL is the
    # pre-#361 agent: it claims only jobs addressed to no group. Never written
    # from the agent's own registration: a worker that could name its own group
    # would be a worker that grants itself the jobs of a segment it is not in.
    agent_group: Mapped[str | None] = mapped_column(default=None)
    current_job_id: Mapped[str | None] = mapped_column(default=None)
    detail: Mapped[str | None] = mapped_column(default=None)
    registered_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    # When this agent's current unbroken run of heartbeats began — not when it
    # was last heard from. The two differ exactly where it matters: an agent
    # whose link drops every other beat has a fresh ``last_seen_at`` half the
    # time and a run that never grows past the gap. ``agent_offline`` is
    # claimed once per silence and given back on recovery
    # (``api/services/sla_escalation.py``), and this is what lets the worker
    # refuse to call a flapping agent recovered. Restarted only by a gap longer
    # than ``OCTO_AGENT_STALE_SECONDS``; NULL on rows that predate 0056 and are
    # read as a run starting at ``last_seen_at``.
    healthy_since: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_agents_tenant_last_seen", "tenant_id", "last_seen_at"),
        Index("ix_agents_group", "tenant_id", "agent_group"),
    )


class AgentSshHostKey(Base):
    """Pinned SSH host key for one deployment target, per tenant (#232).

    The SSH push carries the operator's credentials for the target host and a
    freshly minted tenant provisioning key. Both used to go to whatever host
    key answered, because the deployer accepted any key it was offered. The
    pinned row is what a subsequent deployment is checked against, and a
    mismatch is a refusal rather than a re-add.

    The full public key is stored, not only its fingerprint: the OpenSSH
    fallback path needs a ``known_hosts`` line, which a fingerprint cannot
    produce. ``fingerprint`` is the ``SHA256:...`` form, kept alongside so the
    value an operator compares out-of-band is the value that was stored rather
    than one recomputed at display time.

    Scoped per tenant on purpose: two tenants naming the same host are not
    making a claim about each other's infrastructure, and one tenant must not
    be able to pre-pin a key another tenant then trusts.
    """

    __tablename__ = "agent_ssh_host_keys"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    host: Mapped[str]
    port: Mapped[int] = mapped_column(default=22)
    key_type: Mapped[str]
    public_key: Mapped[str]
    fingerprint: Mapped[str]
    created_at: Mapped[datetime]
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("tenant_id", "host", "port", name="uq_agent_ssh_host_keys_target"),
    )


class AgentDeployment(Base):
    """One SSH push deployment run (#223).

    Was a module-level dict bounded to the last 100 runs. Under more than one
    API replica the status poll reached whichever replica the load balancer
    picked, so a completed deployment answered 404 more often than not, and a
    restart erased the log the operator was reading. The row also carries the
    tenant, which is what makes the status route scopeable at all.

    ``logs`` is the rendered log line list; it is trimmed on write, since an
    installer that talks for an hour must not turn one row into an unbounded
    document.
    """

    __tablename__ = "agent_deployments"

    deploy_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    host: Mapped[str] = mapped_column(default="")
    port: Mapped[int] = mapped_column(default=22)
    username: Mapped[str] = mapped_column(default="")
    status: Mapped[str] = mapped_column(default="queued")
    stage: Mapped[str] = mapped_column(default="")
    progress_percent: Mapped[int] = mapped_column(default=0)
    agent_id: Mapped[str | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(default=None)
    logs: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime]
    completed_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_agent_deployments_tenant_started", "tenant_id", "started_at"),
    )


class Job(Base):
    """Scan job — the control plane's unit of work (ROADMAP P1.1).

    Replaces the ``_JOBS`` dict + ``state/api_jobs.json`` dump, which lost
    every unflushed update on restart and gave each API replica a private
    queue. With the queue in Postgres, ``claim_job`` can serialise agent
    claims with ``SELECT … FOR UPDATE SKIP LOCKED`` instead of a per-process
    ``threading.Lock`` that a second replica never sees.

    ``execution`` splits the two lifecycles: ``local`` jobs run in a thread
    inside the API process, ``agent`` jobs on a remote worker. ``owner_id``
    records which API instance started a local job, so a restart only
    reconciles its *own* orphans (see ``api/services/jobs.py``).

    Timestamps are naive UTC, matching the other tables here; the API
    serialises them back to ISO-8601 with a ``Z`` suffix.
    """

    __tablename__ = "jobs"

    job_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    # Lifecycle and legal transitions live in api/services/job_states.py; the
    # column stays a plain string so adding a state does not need a migration.
    status: Mapped[str] = mapped_column(default="queued")
    execution: Mapped[str] = mapped_column(default="local")  # local | agent
    mode: Mapped[str] = mapped_column(default="balanced")
    run_id: Mapped[str | None] = mapped_column(default=None, index=True)
    command: Mapped[list] = mapped_column(JSON, default=list)
    scan_options: Mapped[dict] = mapped_column(JSON, default=dict)
    target_counts: Mapped[dict | None] = mapped_column(JSON, default=None)
    requested_by: Mapped[str] = mapped_column(default="")
    assigned_agent_id: Mapped[str | None] = mapped_column(default=None, index=True)
    # The agent group this job is addressed to (#361), by name. NULL is the
    # pre-#361 meaning and still the default: any agent of the tenant may claim
    # it. A named group is a claim-time filter, not a preference — see
    # ``api/services/jobs.py::claim_job``.
    agent_group: Mapped[str | None] = mapped_column(default=None)
    owner_id: Mapped[str | None] = mapped_column(default=None)
    # Idempotency (ROADMAP P1.5). `idempotency_key` is the client's name for
    # the scan request, unique per tenant; `results_idempotency_key` records
    # which completion produced the terminal state, so a replayed upload is
    # recognisable as a replay rather than a conflicting second result.
    idempotency_key: Mapped[str | None] = mapped_column(default=None)
    results_idempotency_key: Mapped[str | None] = mapped_column(default=None)
    # Lease (ROADMAP P1.4): the deadline the job's executor keeps pushing
    # forward while it is alive. NULL whenever the job is not out with one.
    claimed_until: Mapped[datetime | None] = mapped_column(default=None)
    # Incremented every time the job is handed to an executor, so the reaper
    # can stop requeueing one that kills whatever picks it up.
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    # Ingest lease: which upload is being processed right now, and on whose
    # behalf. ``complete_job`` checks the claim's fencing token in its first
    # transaction and then spends minutes outside any transaction extracting
    # the archive and writing artifacts, so these are what its *terminal*
    # write is conditional on — an attempt the reaper replaced meanwhile no
    # longer matches and its result is refused instead of overwriting the
    # attempt that took over. ``ingest_started_at`` is for the operator reading
    # a row that is mid-ingest; the deadline itself is ``claimed_until``, which
    # the reservation pushes forward because an upload in flight is proof of
    # life. All NULL whenever no upload is being processed.
    ingest_token: Mapped[str | None] = mapped_column(default=None)
    ingest_attempt: Mapped[int | None] = mapped_column(default=None)
    ingest_agent_id: Mapped[str | None] = mapped_column(default=None)
    ingest_started_at: Mapped[datetime | None] = mapped_column(default=None)
    # When an operator asked a *running* scan to stop (#360). The request
    # travels to the agent on its next heartbeat; this column is the deadline
    # clock for the answer, so a job whose agent is too old to understand the
    # request — or died with the signal in flight — is finished as `cancelled`
    # by ``jobs.reap_stale_cancellations`` instead of sitting in `cancelling`
    # forever. NULL for every job nobody has asked to stop.
    cancel_requested_at: Mapped[datetime | None] = mapped_column(default=None)
    queued_at: Mapped[datetime]
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    exit_code: Mapped[int | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(default=None)
    asset_upsert_error: Mapped[str | None] = mapped_column(default=None)
    # Excluded from the tenant's monthly scan quota (Track E). Set by the
    # caller that dispatches the scan, never inferred from who asked for it: a
    # verification re-scan is exempt because it is the platform closing its own
    # loop, and that is a property of the dispatch, not of the analyst whose
    # name is on it.
    quota_exempt: Mapped[bool] = mapped_column(default=False, server_default="false")

    __table_args__ = (
        Index("ix_jobs_tenant_status", "tenant_id", "status"),
        # The claim query's exact predicate: queued agent jobs of one tenant,
        # oldest first.
        Index("ix_jobs_claim", "execution", "status", "tenant_id", "queued_at"),
        # The same predicate once the claim also filters by group (#361).
        Index(
            "ix_jobs_claim_group",
            "execution",
            "status",
            "tenant_id",
            "agent_group",
            "queued_at",
        ),
        # The reaper's predicate: in-flight jobs whose lease has lapsed. It
        # runs on every replica on a timer, so it must not scan the table.
        Index("ix_jobs_lease", "status", "claimed_until"),
        # Uniqueness is the point, not the lookup: two replicas serving the
        # same retry would both read "no such key" and both insert.
        Index("uq_jobs_tenant_idempotency_key", "tenant_id", "idempotency_key", unique=True),
    )


class RunPublication(Base):
    """One accepted upload that still owes the installation its visible copy.

    The row is written in the *same transaction* as the job's terminal write,
    which is what makes the publication of a run a decision rather than a race
    (``api/services/run_publisher.py``). Before that transaction an upload is
    a staging tree nobody can see; after it, everything that makes the run
    visible — the object store, the run directory, ``latest_run.json``,
    ``ingest.results.{tenant}`` — is redone from this row until it is done.

    ``publication_id`` *is* the ingest lease token that authorised the
    outcome, so there is exactly one row per accepted upload without a second
    unique constraint, and a straggler refused by the fence cannot have one at
    all: it never reached the write that inserts it.

    ``staging_path`` and ``archive_path`` are paths on ``replica``'s disk. A
    remote backend caches per pod and a local backend need not share a volume,
    so a peer that claims the row and cannot see the tree gives it back rather
    than declaring it lost — see the reconciler.
    """

    __tablename__ = "run_publications"

    publication_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    job_id: Mapped[str] = mapped_column(index=True)
    run_id: Mapped[str] = mapped_column(index=True)
    agent_id: Mapped[str | None] = mapped_column(default=None)
    # The outcome that was committed beside this row. The projections a
    # published run feeds are gated on it (a partial sweep read as a complete
    # one reports hosts as gone), so it travels with the publication rather
    # than being re-read from a job row that may since have been retried.
    job_status: Mapped[str] = mapped_column(default="succeeded")
    exit_code: Mapped[int | None] = mapped_column(default=None)
    # The scanner's error string, for the bus payload only. Not the job's
    # ``error``: that one also carries who asked for a cancellation.
    scan_error: Mapped[str | None] = mapped_column(default=None)
    surface: Mapped[str | None] = mapped_column(default=None)
    staging_path: Mapped[str] = mapped_column(default="")
    archive_path: Mapped[str | None] = mapped_column(default=None)
    replica: Mapped[str | None] = mapped_column(default=None)
    status: Mapped[str] = mapped_column(default="pending")  # pending | dead
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    # Claims that never reached an outcome. ``attempts`` counts refusals the
    # store or the broker gave; this counts the publications that killed the
    # replica before it could record one, which is the only way an accepted
    # run could otherwise be retried forever in silence.
    claims: Mapped[int] = mapped_column(default=0, server_default="0")
    # When the run's whole tree reached the store, stamped before the staging
    # tree is promoted and long before the row is closed out. It is the fence
    # a losing attempt reads before taking its own keys back: the row outlives
    # the upload by the length of an archive publish to the broker, so "the row
    # is still here" is not the same question as "is this run already
    # published" (see the reconciler).
    stored_at: Mapped[datetime | None] = mapped_column(default=None)
    next_attempt_at: Mapped[datetime | None] = mapped_column(default=None)
    last_error: Mapped[str | None] = mapped_column(default=None)
    # Proof of life, stamped by every renewal of a running attempt whatever
    # the row's status (migration 0062). ``next_attempt_at`` cannot say it: a
    # ``dead`` row has none, and a row goes ``dead`` when *one* attempt gives
    # up, not when every attempt has stopped. Operator actions wait it out.
    leased_until: Mapped[datetime | None] = mapped_column(default=None)
    # A generation that only moves forward: bumped by every claim and by a
    # requeue. ``claims`` is reset on every recorded outcome, so it alone
    # cannot tell a rollback whether the row is still the one it claimed.
    fence: Mapped[int] = mapped_column(default=0, server_default="0")
    # ``claims`` at the last outcome, requeue or unworked hand-back: the claim
    # budget is ``claims - claims_base``, and ``claims`` itself only grows, so
    # a replica on the release before 0062 — which fences on ``claims`` alone
    # — never sees its own number come back.
    claims_base: Mapped[int] = mapped_column(default=0, server_default="0")
    # Renewals of this row that failed or came after the hold had lapsed
    # (#426): which publication ran unprotected, after the fact.
    lease_lapses: Mapped[int] = mapped_column(default=0, server_default="0")
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]

    __table_args__ = (
        # The reconciler's predicate: due pending rows, oldest first. It runs
        # on every replica on a timer, so it must not scan the table.
        Index("ix_run_publications_due", "status", "next_attempt_at"),
        Index("ix_run_publications_tenant_status", "tenant_id", "status", "created_at"),
    )


class RiskScoreSnapshot(Base):
    """Historical snapshot of a tenant's risk posture (#144, Track C).

    Recorded on run completion, scheduled ticks, or manual triggers so
    the security dashboard can render accurate risk trend charts over time.
    """

    __tablename__ = "risk_score_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(index=True, unique=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    recorded_at: Mapped[datetime]
    estate_risk: Mapped[str | None] = mapped_column(default=None)
    open_total: Mapped[int] = mapped_column(default=0)
    total: Mapped[int] = mapped_column(default=0)
    untriaged: Mapped[int] = mapped_column(default=0)
    unassigned: Mapped[int] = mapped_column(default=0)
    breached: Mapped[int] = mapped_column(default=0)
    worst_breached_severity: Mapped[str | None] = mapped_column(default=None)
    by_severity_open: Mapped[dict] = mapped_column(JSON, default=dict)
    by_risk_level_open: Mapped[dict] = mapped_column(JSON, default=dict)
    by_state: Mapped[dict] = mapped_column(JSON, default=dict)
    by_sla: Mapped[dict] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(default="run")

    __table_args__ = (
        Index("ix_risk_snapshots_tenant_time", "tenant_id", "recorded_at"),
    )


class TenantScanScope(Base):
    """One allow or deny entry in a tenant's approved scanning scope (#226).

    Until this table existed the platform validated only the *syntax* of a
    scan target: any well-formed CIDR or FQDN was accepted, so a tenant
    operator could point the platform's own IP at a link-local address, at the
    provider's cluster range, or at a third party's network, and afterwards
    nobody could answer whether that tenant had been allowed to.

    One row is one entry, so approval provenance is per entry: an operator who
    widens a scope later cannot make the earlier, narrower approval look like
    it had always included the addition. ``approved_by`` is the console
    username that stored the row — or ``migration-0025`` for the grandfathered
    allow-all entries that revision created for tenants predating this table
    (see docs/operations.md).

    ``value`` holds a CIDR (``kind="cidr"``, normalised by ``ip_network``) or a
    domain suffix (``kind="domain"``, lowercased, no leading dot). The literal
    ``*`` is the explicit any-value wildcard and is the only non-literal form.

    Evaluation lives in ``api/services/scan_scopes.py``; two properties belong
    to the data model rather than to that module: deny beats allow, and a
    tenant with no rows at all scans nothing.
    """

    __tablename__ = "tenant_scan_scopes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    # allow | deny. Deny always wins — see scan_scopes.ScanScope.
    effect: Mapped[str]
    # cidr | domain.
    kind: Mapped[str]
    value: Mapped[str]
    note: Mapped[str] = mapped_column(default="")
    # On an allow entry: the agent groups entitled to scan what it approves
    # (#361), by name. ``[]`` — what every entry written before this column had
    # — means any agent of the tenant, so an installation with no groups is
    # unchanged. Meaningless on a deny entry, which refuses everybody, and
    # refused there by ``api/services/scan_scopes.py``.
    agent_groups: Mapped[list] = mapped_column(JSON, default=list, server_default="[]")
    approved_by: Mapped[str] = mapped_column(default="")
    approved_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "effect", "kind", "value", name="uq_tenant_scan_scopes_entry"
        ),
    )


class TenantScanPolicy(Base):
    """How hard this tenant may be scanned, decided by the platform (#362).

    The scope table above says *what* a tenant may be pointed at; this one says
    at what pace. Before it existed the API sent an agent ``--mode`` and
    nothing else, and every rate the packets actually ran at came from the
    ``scanner/config/default.yaml`` on the agent's own host — so the operator
    who answers for the traffic could not set it, and two agents of the same
    tenant could legitimately scan at different speeds with nothing recording
    which had.

    One row per tenant, and **no row is the pre-#362 behaviour**: no ceilings,
    every mode allowed, the agent's local config left alone. Every existing
    tenant has no row.

    The NULL ceilings mean "nothing of this tenant's own"; they are not the
    whole answer, because ``profile`` carries a floor of its own.
    ``fragile`` is the OT/ICS profile, and what it forces — the avoid-list of
    fieldbus ports, the minimum pace, service probing off — lives in
    ``api/services/scan_policy.py`` rather than in these columns, so that a row
    can only ever be *stricter* than its profile and an operator cannot raise
    their way out of one by editing it.

    ``avoid_ports`` is a list of TCP/UDP port numbers this tenant's scans must
    never send a packet to. It is unioned with the profile's list, never
    replaced by it, and a scan naming one of them in its own port list is
    refused rather than quietly filtered — an operator who asked to scan 502
    should be told no, not handed results that omit it without saying so.
    """

    __tablename__ = "tenant_scan_policies"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    # standard | fragile. See scan_policy.PROFILE_FLOORS.
    profile: Mapped[str] = mapped_column(default="standard", server_default="standard")
    # Refuse every speed profile but ``safe``. Implied by ``fragile``; storable
    # on its own for a tenant that is merely noise-sensitive.
    safe_only: Mapped[bool] = mapped_column(default=False, server_default="false")
    max_discover_rate: Mapped[int | None] = mapped_column(default=None)
    max_port_rate: Mapped[int | None] = mapped_column(default=None)
    max_host_concurrency: Mapped[int | None] = mapped_column(default=None)
    # Packets per second aimed at any single host, which is what a fragile
    # device notices — the two rates above are budgets for a whole batch.
    per_host_rate: Mapped[int | None] = mapped_column(default=None)
    avoid_ports: Mapped[list] = mapped_column(JSON, default=list, server_default="[]")
    note: Mapped[str] = mapped_column(default="")
    updated_at: Mapped[datetime]
    updated_by: Mapped[str | None] = mapped_column(default=None)


class SoftwareCveMatch(Base):
    """One statement about one CVE on one endpoint (ROADMAP Track E, M1).

    Produced by ``api/services/software_cve_match.py`` from the endpoint's
    latest accepted inventory snapshot and a vendor advisory dataset. Rows are
    replaced wholesale per device on every run, so the table always describes
    the current snapshot rather than accumulating history — the snapshot the
    statement came from is recorded in ``snapshot_id``.

    Two columns exist because a match must be able to say "I do not know".
    ``status`` carries ``unknown`` alongside vulnerable/fixed/not_applicable,
    and ``unknown_reason`` names what was missing (an unresolved distribution, a
    package from a non-distribution source). An ``unknown`` row has no CVE, so
    ``cve_id`` is the empty string rather than NULL and ``match_key`` — a
    sha256 over ``(cve_id, source_package, unknown_reason)`` — carries the row's
    identity, because a unique constraint over a nullable column constrains
    nothing in Postgres.
    """

    __tablename__ = "software_cve_matches"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_devices.device_id", ondelete="CASCADE"), index=True
    )
    snapshot_id: Mapped[str | None] = mapped_column(default=None)
    match_key: Mapped[str]
    # "" for an unknown row — see the class docstring.
    cve_id: Mapped[str] = mapped_column(default="")
    # vulnerable | fixed | not_applicable | unknown
    status: Mapped[str] = mapped_column(default="unknown")
    # The vendor's own word, never a CVSS score re-derived here.
    severity: Mapped[str] = mapped_column(default="unknown")
    source_package: Mapped[str] = mapped_column(default="")
    installed_package: Mapped[str] = mapped_column(default="")
    installed_version: Mapped[str | None] = mapped_column(default=None)
    fixed_version: Mapped[str | None] = mapped_column(default=None)
    advisory_id: Mapped[str | None] = mapped_column(default=None)
    advisory_url: Mapped[str | None] = mapped_column(default=None)
    provider: Mapped[str] = mapped_column(default="")
    distro: Mapped[str | None] = mapped_column(default=None)
    distro_release: Mapped[str | None] = mapped_column(default=None)
    purl: Mapped[str | None] = mapped_column(default=None)
    cpe23: Mapped[str | None] = mapped_column(default=None)
    unknown_reason: Mapped[str | None] = mapped_column(default=None)
    # The date the advisory feed stamped on itself, not the file's mtime.
    feed_date: Mapped[str | None] = mapped_column(default=None)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    matched_at: Mapped[datetime]

    __table_args__ = (
        Index(
            "ix_software_cve_matches_tenant_device_cve",
            "tenant_id",
            "device_id",
            "cve_id",
        ),
        UniqueConstraint(
            "tenant_id", "device_id", "match_key", name="uq_software_cve_match_row"
        ),
    )


class TenantBranding(Base):
    """Per-tenant report identity (Sprint 4, "No report factory").

    An MSSP sells the report, and a report that carries this platform's name to
    its customer is one the MSSP cannot send. One row per tenant, all columns
    optional: an unbranded report is the product's own look, not an error.

    ``logo_png`` is a base64 PNG rather than a path or a URL. A path means the
    file has to exist on whichever replica renders — which is the bug that
    makes a scheduled report fail once a month and never in testing — and a URL
    means the renderer fetches from the network at render time, which is an
    SSRF sink reached by editing a settings field. Bytes in the row render
    identically everywhere and fetch nothing.
    """

    __tablename__ = "tenant_branding"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    org_name: Mapped[str | None] = mapped_column(default=None)
    # "#1e3a8a" style hex. Validated in the service, since a malformed colour
    # must fail the PATCH rather than the monthly render.
    primary_color: Mapped[str | None] = mapped_column(default=None)
    accent_color: Mapped[str | None] = mapped_column(default=None)
    logo_png: Mapped[str | None] = mapped_column(default=None)
    footer_text: Mapped[str | None] = mapped_column(default=None)
    contact_email: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime]
    updated_by: Mapped[str | None] = mapped_column(default=None)


class ReportTemplate(Base):
    """What a report contains, separate from when it is sent (Sprint 4).

    ``kind`` selects the builder — ``executive``, ``technical`` or
    ``compliance`` — and ``sections`` turns individual blocks off. Templates are
    rows rather than files because an MSSP configures them per customer through
    the console, and a per-tenant file would have to live on a volume every
    replica mounts.
    """

    __tablename__ = "report_templates"

    template_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    kind: Mapped[str] = mapped_column(default="executive")
    # For kind="compliance": which catalogue to assess against.
    framework_id: Mapped[str | None] = mapped_column(default=None)
    # {"section_key": bool}. Absent keys default to on, so a template written
    # before a new section existed keeps rendering the whole report.
    sections: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_report_template_name"),
        Index("ix_report_templates_tenant", "tenant_id"),
    )


class ReportSchedule(Base):
    """When a template is rendered and where the result goes (Sprint 4).

    Deliberately the same shape as ``ScanSchedule`` — cron, ``next_run_at``,
    ``last_run_at`` — and dispatched by the same kind of leader-locked worker,
    because a second scheduling model in one product is a second set of
    timezone and overlap bugs.

    ``recipients`` is a list of ``{"transport": "email"|"webhook", "target": …}``.
    A webhook target goes through ``integrations.delivery``'s SSRF validation
    at delivery time, not only at write time: a hostname that resolved publicly
    when the schedule was created can resolve to link-local a month later.
    """

    __tablename__ = "report_schedules"

    schedule_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    template_id: Mapped[str] = mapped_column(
        ForeignKey("report_templates.template_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    cron: Mapped[str]
    fmt: Mapped[str] = mapped_column(default="pdf")
    recipients: Mapped[list] = mapped_column(JSON, default=list)
    next_run_at: Mapped[datetime | None] = mapped_column(default=None)
    last_run_at: Mapped[datetime | None] = mapped_column(default=None)
    last_report_id: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (Index("ix_report_schedules_tenant_enabled", "tenant_id", "enabled"),)


class GeneratedReport(Base):
    """One rendered report, and what happened to it (Sprint 4).

    The bytes live on disk under ``output_dir/reports/`` and this row carries
    the pointer, the same split the scan runs already use: a 2 MB PDF in a
    Postgres row is a backup nobody can restore quickly, and a per-tenant
    quarterly report is worth keeping long after the run that produced its
    numbers has been pruned.

    ``delivery`` records one entry per recipient — transport, target, status,
    error — rather than a single ``delivered`` boolean. "The report was sent"
    is not true when three of four recipients bounced, and an operator asked to
    debug that needs to know which one.
    """

    __tablename__ = "generated_reports"

    report_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    template_id: Mapped[str | None] = mapped_column(default=None)
    schedule_id: Mapped[str | None] = mapped_column(default=None)
    kind: Mapped[str] = mapped_column(default="executive")
    fmt: Mapped[str] = mapped_column(default="pdf")
    # pending | ready | failed
    status: Mapped[str] = mapped_column(default="pending")
    title: Mapped[str] = mapped_column(default="")
    # Relative to output_dir, never absolute: an absolute path in a row is a
    # path traversal waiting for a different deployment layout.
    storage_path: Mapped[str | None] = mapped_column(default=None)
    size_bytes: Mapped[int] = mapped_column(default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(default=None)
    delivery: Mapped[list] = mapped_column(JSON, default=list)
    generated_at: Mapped[datetime]
    generated_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_generated_reports_tenant_time", "tenant_id", "generated_at"),
    )


class TenantPromotedDomain(Base):
    """A related domain an operator promoted into the tenant's scan scope
    (org_profile M4, EPIC #182).

    The org-profile stage proposes domains that *probably* belong to the
    organisation (shared certificates, CT organisation matches, same NS/MX),
    and never scans them on its own: attribution is probabilistic and a wrong
    guess is a scan of somebody else's infrastructure. Promotion is the
    operator saying "yes, ours" — and that decision belongs to the tenant, not
    to the run that happened to make the proposal, which is why it is a row
    here rather than a file in the run directory that retention deletes.

    Every scan the tenant starts afterwards (``jobs.start_scan``) carries these
    domains in addition to its own targets, after the approved scan scope
    (#226) has been applied to them; a verification re-scan (#183) does not,
    because widening a targeted re-check is how "not observed" stops meaning
    "fixed". Deleting the row withdraws the promotion.
    """

    __tablename__ = "tenant_promoted_domains"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    domain: Mapped[str] = mapped_column(primary_key=True)
    # The run whose related_domains.json proposed it — the evidence trail.
    source_run_id: Mapped[str] = mapped_column(default="", server_default="")
    promoted_by: Mapped[str] = mapped_column(default="", server_default="")
    promoted_at: Mapped[datetime]


class TenantQuota(Base):
    """What one tenant is allowed to consume (ROADMAP Track E, MSSP operations).

    An MSSP sells capacity, and until this table existed the platform had no
    expression of it: any tenant could register an unbounded number of assets
    and start an unbounded number of scans, so the only limit was the hardware
    the provider had bought. "How much is this customer using, and how much did
    they buy?" could be answered by neither the operator nor the customer.

    One row per tenant, and **the absence of a row is not zero** — it is the
    platform default from ``Settings`` (unlimited unless the operator set one).
    A quota is a commercial boundary, not a security one, so unlike the scan
    scope of migration 0025 it fails *open*: an install that upgrades into this
    table keeps running exactly as before until somebody sells a limit.

    ``NULL`` in a limit column means "unlimited for this tenant" and is
    distinct from the missing row: it overrides a platform default that would
    otherwise apply, which is how one customer is exempted without disabling
    metering for everyone.
    """

    __tablename__ = "tenant_quotas"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    # NULL = unlimited for this tenant (an override, not an absence).
    max_assets: Mapped[int | None] = mapped_column(default=None)
    max_scans_per_month: Mapped[int | None] = mapped_column(default=None)
    # Free-text contract reference, so the limit can be traced to what was
    # sold rather than to whoever happened to type it.
    note: Mapped[str] = mapped_column(default="", server_default="")
    updated_at: Mapped[datetime]
    updated_by: Mapped[str] = mapped_column(default="", server_default="")


class TenantRetentionPolicy(Base):
    """How long one tenant's data is kept, category by category (#332).

    Every reaper used to read one window from ``Settings`` for the whole
    installation. A row here overrides it per category for one tenant; ``NULL``
    in a column is "inherit the platform default", and a tenant with no row at
    all is swept exactly as before this table existed.

    The bounds a value has to sit within are deliberately **not** columns: they
    are platform configuration (``OCTO_RETENTION_BOUNDS`` over the defaults in
    ``api/services/retention_policy.py``). A floor stored on the tenant's row
    would be a floor the tenant's admin could edit — and the audit floor exists
    precisely so that they cannot shorten their own trail.
    """

    __tablename__ = "tenant_retention_policies"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    # Days, NULL = inherit. One per category in retention_policy.CATEGORIES.
    run_days: Mapped[int | None] = mapped_column(default=None)
    screenshot_days: Mapped[int | None] = mapped_column(default=None)
    report_days: Mapped[int | None] = mapped_column(default=None)
    endpoint_snapshot_days: Mapped[int | None] = mapped_column(default=None)
    endpoint_change_days: Mapped[int | None] = mapped_column(default=None)
    risk_snapshot_days: Mapped[int | None] = mapped_column(default=None)
    webhook_delivery_days: Mapped[int | None] = mapped_column(default=None)
    workflow_marker_days: Mapped[int | None] = mapped_column(default=None)
    audit_event_days: Mapped[int | None] = mapped_column(default=None)
    # Why this tenant keeps what it keeps — a contract clause, a DPA annex.
    note: Mapped[str] = mapped_column(default="", server_default="")
    updated_at: Mapped[datetime]
    updated_by: Mapped[str] = mapped_column(default="", server_default="")


class TenantLegalHold(Base):
    """A tenant whose data nothing may delete until the hold is released (#332).

    One row per tenant on hold, and the row's existence is the whole state: no
    reaper deletes the tenant's data while it is here, and ``audit_events_prune``
    skips the tenant in the database itself (migration 0065). A hold covers
    every category at once — the platform cannot know which of a tenant's data
    a claim will turn on, and a hold that lets some of it age out is one that
    fails exactly when it is tested.

    The foreign key is **RESTRICT**: a tenant on hold cannot be deleted, by any
    code path, until the hold is released. Releasing deletes the row; who placed
    it, when and why stays in the audit trail.
    """

    __tablename__ = "tenant_legal_holds"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"), primary_key=True
    )
    # Required: a hold nobody can explain is one nobody dares release.
    reason: Mapped[str]
    set_by: Mapped[str]
    set_at: Mapped[datetime]


class TenantDeletion(Base):
    """One request to delete a tenant, and what became of it (#325).

    The journal the purge worker drives (``api/services/tenant_purge``) and the
    record that outlives the tenant: ``tenant_id`` is deliberately **not** a
    foreign key, because the row that proves a deletion happened has to survive
    the ``DELETE FROM tenants`` it describes. A completed row's ``outcome`` is
    the tombstone — how much was removed from each store, counts only — and the
    list of completed rows is what an operator re-applies after restoring a
    backup taken before them (``docs/tenant-lifecycle.md``).

    ``state``: ``pending`` through the grace period (``purge_after``), then
    ``purging`` once a platform admin approves; ``blocked`` when a legal hold
    appeared mid-purge, until somebody retries after it is released;
    ``completed`` or ``cancelled`` at the end. One open row per tenant, by a
    partial unique index (migration 0066).
    """

    __tablename__ = "tenant_deletions"

    deletion_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str]
    state: Mapped[str]
    reason: Mapped[str]
    requested_by: Mapped[str]
    requested_at: Mapped[datetime]
    purge_after: Mapped[datetime]
    approved_by: Mapped[str | None] = mapped_column(default=None)
    approved_at: Mapped[datetime | None] = mapped_column(default=None)
    cancelled_by: Mapped[str | None] = mapped_column(default=None)
    cancelled_at: Mapped[datetime | None] = mapped_column(default=None)
    completed_at: Mapped[datetime | None] = mapped_column(default=None)
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    last_error: Mapped[str | None] = mapped_column(default=None)
    next_attempt_at: Mapped[datetime | None] = mapped_column(default=None)
    # The worker's claim, renewed between batches; a replica that finds it in
    # the past may take the row over (steps are idempotent).
    lease_owner: Mapped[str | None] = mapped_column(default=None)
    lease_until: Mapped[datetime | None] = mapped_column(default=None)
    outcome: Mapped[dict | None] = mapped_column(JSON, default=None)

    __table_args__ = (
        Index("ix_tenant_deletions_tenant", "tenant_id"),
        Index("ix_tenant_deletions_due", "state", "next_attempt_at"),
        Index(
            "uq_tenant_deletions_open",
            "tenant_id",
            unique=True,
            postgresql_where=text("state IN ('pending', 'purging', 'blocked')"),
            sqlite_where=text("state IN ('pending', 'purging', 'blocked')"),
        ),
    )


class TenantDeletionStep(Base):
    """One store a tenant's purge walks, with its own outcome (#325).

    Separate rows rather than a JSON document on the journal so that each step
    records its progress in the same transaction as the batch it describes —
    the Postgres step counts the rows it deleted in the transaction that
    deleted them — and so that "which store failed, how often and why" is a
    query, not a parse.
    """

    __tablename__ = "tenant_deletion_steps"

    deletion_id: Mapped[str] = mapped_column(
        ForeignKey("tenant_deletions.deletion_id", ondelete="CASCADE"), primary_key=True
    )
    step: Mapped[str] = mapped_column(primary_key=True)
    position: Mapped[int]
    # pending | waiting | failed | done | skipped
    state: Mapped[str] = mapped_column(default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    last_error: Mapped[str | None] = mapped_column(default=None)
    counts: Mapped[dict | None] = mapped_column(JSON, default=None)


class SlaEscalationPolicy(Base):
    """What a tenant wants done when a remediation deadline is missed (#349).

    The SLA itself is ``sla_policies`` — how long the tenant gets. This is the
    other half nobody had written down: what happens *after* the deadline
    passes. Until #349 the answer was nothing at all. ``sla_state`` was derived
    on read, so a breach existed only for as long as somebody was looking at
    the list it appeared in.

    One row per tenant, and **the absence of a row does not disable the
    events** — ``sla_due_soon``/``sla_breached`` are notifications and are
    emitted for every tenant. What the row enables is the part that *writes*:
    reassigning a finding and raising its severity. Escalation edits somebody's
    work queue, so it stays off until a tenant admin asks for it, the same way
    ``TenantQuota`` leaves metering fail-open until a limit is sold.

    ``bump_severity`` is honestly weaker than it looks, and the class docstring
    is the place to say so: ``Vulnerability.severity`` is denormalised from the
    latest observation, so the next scan that re-observes the finding puts the
    scanner's severity back. The bump is a signal to whoever is looking at the
    queue now, not a durable reclassification — the durable record is the
    ``escalated`` entry in the finding's event trail.
    """

    __tablename__ = "sla_escalation_policies"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    # Gates the *actions* only — the reassignment, the severity bump and the
    # digest alike, so it is the one off switch. With this false the tenant
    # still gets the breach and due-soon events on its webhooks.
    enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Grace period past ``due_at`` before a finding is escalated, in days. 0 is
    # "at the breach", which is the default because a deadline the platform
    # then waits past is two deadlines.
    escalate_after_days: Mapped[int] = mapped_column(default=0, server_default="0")
    # Who the breach is reassigned to, and which queue it lands in. NULL leaves
    # the current owner alone — a tenant may want the severity bump and the
    # notification without having its assignments rewritten.
    escalate_to: Mapped[str | None] = mapped_column(default=None)
    escalate_owner_team: Mapped[str | None] = mapped_column(default=None)
    # Raise the finding one severity step on escalation, up to critical. See
    # the class docstring for what this does and does not survive.
    bump_severity: Mapped[bool] = mapped_column(default=False, server_default="false")
    # Daily digest of the tenant's breached and due-soon findings, sent to each
    # asset's ``owner_email``. Off by default: it is outbound mail about
    # somebody's vulnerabilities, which is not a thing to start sending because
    # a version was bumped.
    digest_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    updated_at: Mapped[datetime]
    updated_by: Mapped[str] = mapped_column(default="", server_default="")


class WorkflowEventMarker(Base):
    """Proof that one workflow event has already been emitted once (#349).

    Every event the discovery bus carries is a *transition* somebody observed:
    a port that was not open before, a row an operator wrote. The workflow
    events of #349 are not — ``sla_breached`` is a predicate over ``due_at``
    and the clock, which is true again on every tick of the escalation worker.
    Emitting on truth rather than on change would page the tenant's on-call
    every minute for the rest of the finding's life.

    So the fact is recorded here, once, and the worker's tick skips what this
    table already holds. Two properties make the row the right shape for that:

    ``marker`` **is the discriminator, not a timestamp.** It carries whatever
    makes one occurrence distinct from the next — the deadline for an SLA
    event, the deadline plus the threshold for an expiring exception. A finding
    whose clock restarts (a reopen recomputes ``due_at``) therefore gets a new
    marker and is announced once more, while the same deadline is announced
    once however many times the worker looks at it.

    For ``agent_offline`` the discriminator is the *episode* rather than any
    timestamp: the marker is the constant ``"offline"`` (0056), claimed when
    the agent goes quiet and released by the escalation worker when it comes
    back for a run of heartbeats long enough to count. Keyed on ``last_seen_at``
    — as it was until 0056 — an agent whose link dropped every other beat
    presented a different-but-still-stale timestamp on every tick and was
    announced on every one of them. The beat it fell silent after still keys
    the *envelope*, so two episodes are two events on the bus.

    **The insert is the claim.** The unique constraint decides, so two replicas
    that both believe they lead — the advisory lock is not fenced — send one
    notification between them rather than one each.

    Rows are pruned by age (``OCTO_WORKFLOW_MARKER_RETENTION_DAYS``), which is
    a deliberate re-announcement and not only housekeeping: a breach still open
    a year later is worth raising a second time.
    """

    __tablename__ = "workflow_event_markers"

    marker_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    # An event kind from ``workflow_events.WORKFLOW_EVENT_KINDS``, or one of the
    # worker's internal bookkeeping keys (the daily digest). A plain string, so
    # a new kind needs no migration.
    kind: Mapped[str]
    # What the event is about: a vuln_id, an agent_id, a digest recipient.
    subject_id: Mapped[str]
    marker: Mapped[str] = mapped_column(default="", server_default="")
    created_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "kind", "subject_id", "marker", name="uq_workflow_event_marker"
        ),
    )


class IdempotencyRecord(Base):
    """One write request a client gave a name to, and what it answered (#346).

    ``Job.idempotency_key`` already does this for scan starts, and it can do it
    because a start *creates a row* — the unique index on
    ``(tenant_id, idempotency_key)`` lives on the thing the request produced, so
    the replay is the row itself. A bulk action produces no such row: it edits
    findings that already exist, and its answer is a per-id report. There is
    nowhere on the tenant's findings to hang the key, so the key gets a table.

    ``endpoint`` namespaces the key, so ``Idempotency-Key: nightly`` on
    ``/vulnerabilities/bulk`` and on ``/assets/bulk`` are two different
    promises rather than one collision. ``actor`` namespaces it the other way
    (#346 debt): a key is the *caller's* name for their own request, not a
    tenant-wide reservation, or one member taking ``nightly-triage`` would take
    it from every pipeline in the tenant. ``request_digest`` is what makes a
    replay checkable: a key on its own only says "the client called this
    request X", and reusing it for a *different* batch is a 409
    (:class:`~api.services.idempotency.IdempotencyMismatch`), never a replay of
    somebody else's answer.

    ``response`` is NULL while the request is in flight — the row is inserted
    before the work starts, so two concurrent sends of one key cannot both do
    it, and the second is told the first is still running. A request that
    *failed* deletes its own row, so a key is never burned by an answer the
    caller never got.

    Rows are disposable: they are the memory of a retry window, not a record of
    anything, and :func:`api.services.idempotency.purge_expired` drops them
    once past their TTL.
    """

    __tablename__ = "idempotency_records"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # No FK to tenants: a key outliving its tenant is harmless, and a cascade
    # delete on this table buys nothing worth the constraint.
    tenant_id: Mapped[str]
    # Which endpoint the key was presented to, e.g. "vulnerabilities.bulk".
    endpoint: Mapped[str]
    key: Mapped[str]
    # Who reserved the key: the principal string the audit trail uses, so an
    # integration is ``service-token:<name>`` and a person is their username.
    # NULL means the row predates 0055_idempotency_actor and was reserved when
    # a key was a tenant-wide namespace — see ``idempotency.reserve``, which
    # still honours those rows until they age out.
    actor: Mapped[str | None] = mapped_column(default=None)
    request_digest: Mapped[str] = mapped_column(default="", server_default="")
    # NULL = still in flight. See the class docstring, and ``_JSON_DOC_NULLABLE``
    # for why this one column does not share ``_JSON_DOC``.
    response: Mapped[dict | None] = mapped_column(_JSON_DOC_NULLABLE, default=None)
    created_at: Mapped[datetime]

    __table_args__ = (
        # The whole point of the table: one key means one execution per caller
        # per endpoint, enforced by the database rather than by a lookup that
        # two replicas can both pass.
        Index(
            "uq_idempotency_tenant_endpoint_actor_key",
            "tenant_id",
            "endpoint",
            "actor",
            "key",
            unique=True,
        ),
        # The index this replaced, kept for the rows it still governs: a
        # replica on the previous release writes no ``actor``, and for the
        # length of a rolling deploy those rows need the uniqueness that
        # decides which of two racing replicas holds the key. Empty of new
        # rows the moment every replica is current, and gone for good once the
        # last legacy row is swept.
        Index(
            "uq_idempotency_legacy_tenant_endpoint_key",
            "tenant_id",
            "endpoint",
            "key",
            unique=True,
            postgresql_where=text("actor IS NULL"),
            sqlite_where=text("actor IS NULL"),
        ),
        # The purge's only query.
        Index("ix_idempotency_created_at", "created_at"),
    )


class EndpointAgentRelease(Base):
    """One build of the Lariska endpoint agent the platform can hand out (#358).

    Identified by ``(version, platform)``, where platform is the target triple
    the agent reports for itself (``x86_64-pc-windows-msvc``). Two builds of
    one version for two platforms are two rows; a rebuilt binary for a version
    that already exists replaces the row, because a version that means two
    different binaries is a version that means nothing.

    **The bytes are in the row.** The alternative is a file on a volume, and
    the API already cannot run more than one replica because run artifacts sit
    on an RWO PVC (#336) — putting a path an endpoint fleet polls behind the
    same constraint would deepen exactly the problem that issue is about.
    ``sha256`` is what the agent verifies the download against before it runs
    anything, and it is computed here, from the stored bytes, rather than
    accepted from whoever uploaded them.
    """

    __tablename__ = "endpoint_agent_releases"

    version: Mapped[str] = mapped_column(primary_key=True)
    platform: Mapped[str] = mapped_column(primary_key=True)
    sha256: Mapped[str]
    size_bytes: Mapped[int]
    content: Mapped[bytes] = mapped_column(LargeBinary)
    notes: Mapped[str | None] = mapped_column(default=None)
    uploaded_at: Mapped[datetime]
    uploaded_by: Mapped[str | None] = mapped_column(default=None)


class EndpointAgentPolicy(Base):
    """What an operator wants an endpoint agent doing, without visiting it (#358).

    ``agent_id IS NULL`` is the tenant-wide default; a row naming an agent
    overrides it, field by field. ``settings`` holds only the knobs that are
    safe to decide centrally — intervals and log level — and deliberately not
    ``server_url`` or the provisioning key: an agent that can be told where to
    report is an agent that can be told to report somewhere else.

    ``revision`` increments on every write. The agent echoes the revision it
    has applied, so a heartbeat carries a decision only when there is a new
    one to carry, and an agent that restarts does not re-apply and re-log a
    policy it was already running.
    """

    __tablename__ = "endpoint_agent_policies"

    policy_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    agent_id: Mapped[str | None] = mapped_column(default=None)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    desired_version: Mapped[str | None] = mapped_column(default=None)
    revision: Mapped[int] = mapped_column(default=1, server_default="1")
    updated_at: Mapped[datetime]
    updated_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index(
            "uq_endpoint_agent_policy_default",
            "tenant_id",
            unique=True,
            postgresql_where=text("agent_id IS NULL"),
            sqlite_where=text("agent_id IS NULL"),
        ),
        Index(
            "uq_endpoint_agent_policy_agent",
            "tenant_id",
            "agent_id",
            unique=True,
            postgresql_where=text("agent_id IS NOT NULL"),
            sqlite_where=text("agent_id IS NOT NULL"),
        ),
    )


class NatsOutboxEntry(Base):
    """One publication the broker refused, kept until it is on the stream.

    From the P2 finding of ``docs/architecture-review-2026-09-18.ru.md``.

    The gap this closes: ``results_ingest.publish_raw_results`` returns
    ``published=false`` when NATS is unreachable and its caller did not look at
    the flag, so the upload is answered 200 while the analytics projection never
    hears about the run. With the broker out of ``BLOCKING_CHECKS`` the replica
    also stays in its Service, which would make that silence the *normal* way a
    broker outage looks. A row here is the record that makes the silence
    temporary and visible instead.

    Written by ``run_publisher._publish_to_bus`` — the last step of an accepted
    run's publication (``run_publications``) — and by nothing else. The two
    tables are one pipeline, not two queues for the same work: the publication
    owns the store, the run directory, the pointer and the projections, and
    hands this table the one hop it ends on, so a broker outage delays the
    analytics without holding the run itself open.

    ``payload`` is the exact body that was to be published, not a reference to
    rebuild it from: an ingest body carries the run archive inline (bounded by
    ``results_ingest``'s 4 MB cap — a larger archive travels as
    ``archive_inline: false`` and the stored body says so too, exactly like the
    one that would have gone to the broker). Re-deriving it later would mean
    re-tarring a run whose files may already have been retained away.

    ``(subject, msg_id)`` is unique, which is the same key JetStream dedupes
    on: two replicas that fail to publish the same message record it once, and
    a republish of a message the broker did in fact accept is dropped by the
    stream rather than doubled in ClickHouse. That second half holds only
    within the stream's ``duplicate_window``, which ``nats_bus`` sets on
    ``INGEST`` (24h by default) precisely to cover the reconciler's retry
    schedule — JetStream's own default is two minutes, shorter than one backoff.

    A row is deleted once it is published — unlike ``webhook_deliveries``,
    which keeps its history, because that history is an audit trail and this
    one is megabytes of base64. ``status="dead"`` rows stay: they are the
    backlog an operator has to decide about.
    """

    __tablename__ = "nats_outbox"

    outbox_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    # What kind of message this is, which decides how it is republished:
    # "ingest" goes back through the ingest publisher (tenant subject plus the
    # legacy one), anything else is a plain publish on ``subject``.
    kind: Mapped[str]
    subject: Mapped[str]
    msg_id: Mapped[str]
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    # Carried for the operator view and for log lines; the payload holds them
    # too, and reading a 5 MB document to answer "which run is stuck" is not a
    # query worth running.
    job_id: Mapped[str | None] = mapped_column(default=None)
    run_id: Mapped[str | None] = mapped_column(default=None)
    status: Mapped[str] = mapped_column(default="pending")  # pending|dead
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    next_attempt_at: Mapped[datetime | None] = mapped_column(default=None)
    last_error: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint("subject", "msg_id", name="uq_nats_outbox_message"),
        # The reconciler's predicate: due pending rows, oldest first. It runs on
        # every replica on a timer, so it must not scan the table.
        Index("ix_nats_outbox_due", "status", "next_attempt_at"),
        # The reserved ingest claim window filters by kind before ordering.
        Index(
            "ix_nats_outbox_kind_due", "status", "kind", "next_attempt_at"
        ),
        # The health probe's predicate: pending rows older than the alert
        # window. ``/readyz`` asks for it on every replica on the kubelet's
        # period, and without this index that is a scan of every pending row —
        # growing precisely during the outage it is there to measure.
        Index("ix_nats_outbox_stale", "status", "created_at"),
    )


class AssetService(Base):
    """One listener a scan fingerprinted on an asset (docs/retro-cve-matching.md).

    Until this table the platform kept no service inventory: the product and
    version a scan disclosed lived in the run's ``services.json`` / nmap XML and
    left with the run directory at ``run_retention_days``. That is enough for
    the scan's own CVE checks, which run while the socket is open, and useless
    for the question a new CVE asks — *which of our hosts run the affected
    version?* — which has to be answerable without re-scanning.

    Keyed ``(tenant, asset, port, protocol)``: the same listener on the next
    scan is the same row, updated. A newer observation replaces the fingerprint;
    an older one (a backfill walking runs out of order) only widens
    ``first_seen_at``. A port that stops being observed is not deleted —
    ``last_seen_at`` says how old the statement is, exactly as a finding's does.

    ``matched_dataset_version`` is the retro matcher's durable queue, the same
    device as ``EndpointDevice.last_matched_snapshot_id``: a row is due when it
    differs from the NVD dataset's current marker, which a new fingerprint (the
    column is cleared) and a new dataset (the marker moves) both cause.
    """

    __tablename__ = "asset_services"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    # CASCADE like a finding: a fingerprint is a statement about an asset.
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"), index=True
    )
    # The address the scan reached it on — what a retro ``new_cve`` event names
    # as ``host``, as a scan's own event would.
    host: Mapped[str] = mapped_column(default="")
    port: Mapped[int]
    protocol: Mapped[str] = mapped_column(default="tcp")
    service: Mapped[str] = mapped_column(default="")
    product: Mapped[str] = mapped_column(default="")
    version: Mapped[str] = mapped_column(default="")
    # Truncated raw banner, or nmap's extrainfo — where "Ubuntu Linux" or
    # "Debian-2+deb12u3" lives when the version field does not carry it.
    banner: Mapped[str] = mapped_column(default="")
    cpe: Mapped[list] = mapped_column(JSON, default=list)
    # pulse | nmap
    source: Mapped[str] = mapped_column(default="")
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    last_run_id: Mapped[str | None] = mapped_column(default=None)
    # When product/version/banner/cpe last changed, as opposed to when the
    # listener was last seen.
    fingerprint_changed_at: Mapped[datetime]
    matched_dataset_version: Mapped[str | None] = mapped_column(default=None)
    matched_at: Mapped[datetime | None] = mapped_column(default=None)
    # Verdict tallies and the "possible, unconfirmed" CVEs of the last match —
    # the statements that are deliberately not tracked findings.
    match_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    match_failure_count: Mapped[int] = mapped_column(default=0, server_default="0")
    match_retry_after: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "asset_id", "port", "protocol", name="uq_asset_service_listener"
        ),
        # The worker's due read: one tenant's rows not yet matched against the
        # current dataset.
        Index("ix_asset_services_match_due", "tenant_id", "matched_dataset_version"),
    )


class AssetOs(Base):
    """The operating system a scan guessed for an asset (retro matching).

    One row per asset, the best guess of the newest scan: nmap's top
    ``osmatch`` or Pulse's ``os.json``. The retro matcher reads it for a
    listener whose own banner names no distribution — "Linux 5.x" or "Ubuntu
    20.04" is what separates Exim 4.92 from a distribution build nobody can
    see into (docs/retro-cve-matching.md). A guess, and treated as one: it can
    only make a match *less* certain or send it to the vendor, never create a
    finding by itself.
    """

    __tablename__ = "asset_os"

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    os_name: Mapped[str] = mapped_column(default="")
    accuracy: Mapped[int | None] = mapped_column(default=None)
    source: Mapped[str] = mapped_column(default="")
    last_seen_at: Mapped[datetime]
    last_run_id: Mapped[str | None] = mapped_column(default=None)


class RetroMatchState(Base):
    """Per-tenant bookkeeping of the retro matcher, for the status route.

    Not the queue — that is ``asset_services.matched_dataset_version`` — and
    nothing reads it to decide what to do. It exists so "when did this last
    run, against which dataset, and what did it find" has an answer that
    survives a restart and is the same in every replica.
    """

    __tablename__ = "retro_match_state"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    dataset_version: Mapped[str | None] = mapped_column(default=None)
    last_run_at: Mapped[datetime | None] = mapped_column(default=None)
    # Cumulative since the tenant's first sweep.
    findings_created: Mapped[int] = mapped_column(default=0, server_default="0")
    events_published: Mapped[int] = mapped_column(default=0, server_default="0")
    events_suppressed: Mapped[int] = mapped_column(default=0, server_default="0")
    # The one-by-one event budget is per dataset version, not per tick: the
    # wave a new dataset causes spans many ticks. Which version the count is
    # for, and how much of it is spent.
    events_marker: Mapped[str | None] = mapped_column(default=None)
    events_marker_individual: Mapped[int] = mapped_column(default=0, server_default="0")
    last_stats: Mapped[dict] = mapped_column(JSON, default=dict)
    refresh_requested_at: Mapped[datetime | None] = mapped_column(default=None)
    refresh_requested_by: Mapped[str | None] = mapped_column(default=None)
