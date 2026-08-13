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


class UserTenant(Base):
    """Which tenants a console user may act in, and with what role (P0).

    Users themselves still come from ``OCTO_API_USERS`` (env/config) — this
    table only binds an existing username to a tenant, so no credential
    material lives here. A user with *no* rows keeps pre-P0 behaviour: access
    to the ``default`` tenant with their configured global role.

    ``role`` is the role **inside** this tenant and is independent of the
    global role in the JWT; the global ``admin`` role means platform admin and
    bypasses this table entirely (see api/services/memberships.py).
    """

    __tablename__ = "user_tenants"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(index=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(default="viewer")  # viewer | operator | admin
    created_at: Mapped[datetime]
    created_by: Mapped[str | None] = mapped_column(default=None)

    __table_args__ = (
        UniqueConstraint("username", "tenant_id", name="uq_user_tenant"),
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

    __table_args__ = (Index("ix_assets_tenant_status", "tenant_id", "status"),)


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
