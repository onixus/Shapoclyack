"""SQLAlchemy 2.x declarative models for the Postgres PRIMARY_DB (Phase 7)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


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
    status: Mapped[str] = mapped_column(default="active")
    created_at: Mapped[datetime]


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


class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    status: Mapped[str] = mapped_column(default="active")  # active | stale | decommissioned
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
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

    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_id", name="uq_endpoint_device_tenant_agent"),
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


class EndpointSoftwareAdvisory(Base):
    """CVE / OSV security advisory matching an installed endpoint software item (Sprint 3)."""

    __tablename__ = "endpoint_software_advisories"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(index=True)
    device_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_devices.device_id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="SET NULL"), index=True, default=None
    )
    software_name: Mapped[str]
    installed_version: Mapped[str | None] = mapped_column(default=None)
    fixed_version: Mapped[str | None] = mapped_column(default=None)
    purl: Mapped[str | None] = mapped_column(default=None)
    cpe: Mapped[str | None] = mapped_column(default=None)
    cve: Mapped[str] = mapped_column(index=True)
    advisory_id: Mapped[str | None] = mapped_column(default=None)
    severity: Mapped[str] = mapped_column(default="medium")  # low | medium | high | critical
    cvss: Mapped[float | None] = mapped_column(default=None)
    title: Mapped[str | None] = mapped_column(default=None)
    vuln_id: Mapped[str | None] = mapped_column(default=None)
    matched_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint(
            "device_id", "software_name", "cve", name="uq_endpoint_software_advisory"
        ),
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

    ``secret`` is the HMAC key the receiver verifies with; it is stored in
    plaintext because a signature has to be *computed*, not compared — a hash
    would make it unusable — and it is redacted on every read path (see
    ``api/services/integrations/webhooks.py``). It is a shared secret for a
    URL the operator controls, not a credential for this system.
    """

    __tablename__ = "webhook_subscriptions"

    subscription_id: Mapped[str] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    url: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    # [] means "every kind"; validated against asset_events.EVENT_KINDS on write.
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
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    updated_at: Mapped[datetime | None] = mapped_column(default=None)
    last_delivery_at: Mapped[datetime | None] = mapped_column(default=None)
    last_status: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_webhook_subscriptions_tenant_enabled", "tenant_id", "enabled"),
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
    # attribute and not a seventh state.
    exception_until: Mapped[datetime | None] = mapped_column(default=None)
    exception_reason: Mapped[str | None] = mapped_column(default=None)
    exception_by: Mapped[str | None] = mapped_column(default=None)
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
    # Verification & Closure reason (Sprint 2 Remediation Loop)
    machine_verified: Mapped[bool] = mapped_column(default=False, server_default="false")
    verification_job_id: Mapped[str | None] = mapped_column(default=None)
    last_verified_at: Mapped[datetime | None] = mapped_column(default=None)
    closure_reason: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]

    __table_args__ = (
        # Identity: re-observing a finding must find this row, and two API
        # replicas ingesting the same run must not create it twice.
        UniqueConstraint("tenant_id", "finding_key", name="uq_vulnerability_finding"),
        # The SLA queries: one tenant's still-open findings by deadline.
        Index("ix_vulnerabilities_due", "tenant_id", "state", "due_at"),
        # The Vulnerability Center's default view: worst first within a tenant.
        Index("ix_vulnerabilities_risk", "tenant_id", "state", "contextual_score"),
        Index("ix_vulnerabilities_asset", "tenant_id", "asset_id"),
        Index("ix_vulnerabilities_assignee", "tenant_id", "assignee"),
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
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(default="idle")
    current_job_id: Mapped[str | None] = mapped_column(default=None)
    detail: Mapped[str | None] = mapped_column(default=None)
    registered_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]

    __table_args__ = (Index("ix_agents_tenant_last_seen", "tenant_id", "last_seen_at"),)


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
    queued_at: Mapped[datetime]
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    exit_code: Mapped[int | None] = mapped_column(default=None)
    error: Mapped[str | None] = mapped_column(default=None)
    asset_upsert_error: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        Index("ix_jobs_tenant_status", "tenant_id", "status"),
        # The claim query's exact predicate: queued agent jobs of one tenant,
        # oldest first.
        Index("ix_jobs_claim", "execution", "status", "tenant_id", "queued_at"),
        # The reaper's predicate: in-flight jobs whose lease has lapsed. It
        # runs on every replica on a timer, so it must not scan the table.
        Index("ix_jobs_lease", "status", "claimed_until"),
        # Uniqueness is the point, not the lookup: two replicas serving the
        # same retry would both read "no such key" and both insert.
        Index("uq_jobs_tenant_idempotency_key", "tenant_id", "idempotency_key", unique=True),
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
    approved_by: Mapped[str] = mapped_column(default="")
    approved_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "effect", "kind", "value", name="uq_tenant_scan_scopes_entry"
        ),
    )


class ServiceToken(Base):
    """Scoped API keys for non-interactive integrations and CI/CD (Sprint 1 IAM)."""

    __tablename__ = "service_tokens"

    id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    key_prefix: Mapped[str] = mapped_column(index=True)
    key_hash: Mapped[str]
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(default="viewer")
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)
    expires_at: Mapped[datetime | None] = mapped_column(default=None)
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)


class OIDCIdentity(Base):
    """External OpenID Connect identity linked to a local console user (Sprint 1 IAM)."""

    __tablename__ = "oidc_identities"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE"), index=True
    )
    issuer: Mapped[str]
    subject: Mapped[str]
    email: Mapped[str | None] = mapped_column(default=None)
    claims: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]
    last_login_at: Mapped[datetime | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_oidc_issuer_subject"),
    )

