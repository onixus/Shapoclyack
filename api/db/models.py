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
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.tenant_id"), index=True)
    agent_id: Mapped[str]
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.asset_id"), default=None)
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
    device_id: Mapped[str] = mapped_column(ForeignKey("endpoint_devices.device_id"), index=True)
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
    device_id: Mapped[str] = mapped_column(ForeignKey("endpoint_devices.device_id"), index=True)
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
        ForeignKey("endpoint_inventory_snapshots.snapshot_id"), index=True
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
    device_id: Mapped[str] = mapped_column(ForeignKey("endpoint_devices.device_id"), index=True)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("endpoint_inventory_snapshots.snapshot_id"))
    comparison_key: Mapped[str]
    event_type: Mapped[str]  # installed | removed | updated
    old_version: Mapped[str | None] = mapped_column(default=None)
    new_version: Mapped[str | None] = mapped_column(default=None)
    display_name: Mapped[str]
    observed_at: Mapped[datetime]

    __table_args__ = (
        Index("ix_endpoint_software_changes_device_time", "device_id", "observed_at"),
    )


class AssetTag(Base):
    __tablename__ = "asset_tags"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    key: Mapped[str]
    value: Mapped[str]

    __table_args__ = (UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),)
