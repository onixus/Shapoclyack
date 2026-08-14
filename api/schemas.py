from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Uniform envelope for every paginated list endpoint (ROADMAP P3.2).

    ``offset``/``limit`` echo the request so a client never has to track what
    it asked for, ``total`` is the count *after* filtering, and ``has_more``
    saves the caller the ``offset + len(items) < total`` arithmetic.
    """

    items: list[T]
    total: int
    offset: int
    limit: int
    has_more: bool


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    service: str = "shapoclyack-api"
    nats: bool | None = None
    clickhouse: bool | None = None
    ch_ingest: dict[str, int] | None = None


class RunSummary(BaseModel):
    run_id: str
    # Owning tenant (ROADMAP P0). Reads back as "default" for runs written
    # before runs were tagged.
    tenant_id: str = "default"
    profile: str | None = None
    started_at: str | None = None
    config: str | None = None
    alive_hosts: int | None = None
    open_host_port_pairs: int | None = None
    potential_vulnerabilities: int | None = None
    vulnerable_hosts: int | None = None
    has_diff: bool = False
    has_summary: bool = False
    path: str


class RunDetail(BaseModel):
    run_id: str
    tenant_id: str = "default"
    meta: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] | None = None
    diff: dict[str, Any] | None = None
    artifacts: list[str] = Field(default_factory=list)


class VulnerabilityItem(BaseModel):
    host: str | None = None
    port: str | None = None
    cve: str | None = None
    cvss: float | None = None
    cvss4: float | None = None
    cvss4_vector: str | None = None
    cvss4_severity: str | None = None
    severity: str | None = None
    script_id: str | None = None
    country: str | None = None
    city: str | None = None
    country_iso: str | None = None
    # Scanner-supplied finding taxonomy: "version_cve" (confirmed banner/version
    # match), "keyword_cve" (unverified NVD keyword hit), "exposure" (reachable
    # service, no CVE), "tls". Absent for nuclei/NSE findings.
    finding_class: str | None = None
    confidence: int | None = None
    requires_confirmation: bool = False
    epss: float | None = None
    in_kev: bool = False
    # Prioritisation, computed per request by api.services.risk_scoring.
    contextual_score: float | None = None
    cisa_decision: str | None = None
    risk_explanation: str | None = None
    # NIST SP 800-30 assessment (scoring model nist-1). `risk_level` is the
    # verdict from Table I-2; `contextual_score` above stays a continuous 0-10
    # sort key so a table can order rows within a level.
    risk_level: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    # Does exploit code exist, or is this only theoretical: attacked /
    # weaponized / proof_of_concept / unproven / theoretical / unknown.
    # "unknown" means no exploit-intelligence source is configured — which is
    # deliberately not the same answer as "theoretical".
    exploit_maturity: str | None = None
    # Named sources behind the maturity call, e.g. ["cisa-kev", "nuclei-match"],
    # so a reader can check the claim instead of trusting it.
    exploit_evidence: list[str] = Field(default_factory=list)
    # True when a working check fired against this host, rather than the level
    # being inferred from a list keyed by CVE.
    exploit_verified_on_host: bool = False


class AliveHostItem(BaseModel):
    host: str
    hostname: str | None = None
    names: list[str] = Field(default_factory=list)
    country: str | None = None
    city: str | None = None
    country_iso: str | None = None
    # GeoIP coordinates, when the City database carried a location. This is the
    # *registered* position of the network — typically a city or country
    # centre, never the machine — and the Geo Map labels it as such. Null for a
    # Country-only database, a private address, or a run scanned before the
    # scanner recorded them; such hosts are plotted from `country_iso` if they
    # have one and listed as unlocated otherwise.
    latitude: float | None = None
    longitude: float | None = None
    os_name: str | None = None
    os_accuracy: int | None = None
    asn: str | None = None
    asn_org: str | None = None
    vulnerability_count: int = 0


class PortAggregateItem(BaseModel):
    port: str
    protocol: str | None = None
    host_count: int = 0
    vulnerability_count: int = 0
    hosts: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)


class AssetIdentifier(BaseModel):
    identifier_type: str
    identifier_value: str


class AssetSummary(BaseModel):
    asset_id: str
    status: str
    first_seen: datetime
    last_seen: datetime
    primary_identifier: str | None = None
    identifier_count: int = 0
    asset_criticality: int | None = None


class AssetDetail(BaseModel):
    asset_id: str
    tenant_id: str
    status: str
    first_seen: datetime
    last_seen: datetime
    owner_email: str | None = None
    business_unit: str | None = None
    asset_criticality: int | None = None
    identifiers: list[AssetIdentifier] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class UpdateAssetRequest(BaseModel):
    owner_email: str | None = None
    business_unit: str | None = None
    asset_criticality: int | None = Field(default=None, ge=0, le=4)
    # Manual decommission only — "active"/"stale" stay system-managed
    # (upsert_assets_from_run / mark_stale_assets), never operator-set.
    status: Literal["decommissioned"] | None = None


class StartScanRequest(BaseModel):
    mode: Literal["safe", "balanced", "fast", "test"] = "balanced"
    # Product-level work selection (see api.services.scan_intents). When set,
    # owns skip_nse / nuclei floor; speed profile stays in ``mode``.
    intent: Literal["inventory", "vuln", "full", "delta"] | None = None
    delta: bool = False
    skip_nse: bool = False
    notify: bool = False
    export_defectdojo: bool = False
    run_id: str | None = None
    # MSSP tenant (Phase 2). Defaults to "default" when omitted.
    tenant_id: str | None = None
    # Newline-separated targets. Empty / omitted → server default input files.
    ranges: str | None = None
    domains: str | None = None
    ports: str | None = None
    ports_udp: str | None = None
    # A tenant-uploaded brute-force wordlist to run this scan with (Phase 8.2).
    # Local execution only: it enables ct.brute_force with the uploaded list.
    # Rejected in agent mode, where the scanner runs its own mounted config.
    wordlist_id: str | None = None


class JobInfo(BaseModel):
    job_id: str
    # `claimed` (an agent holds the job but has not reported starting) and
    # `cancelled` are ROADMAP P1.3 additions — see api/services/job_states.py.
    status: Literal["queued", "claimed", "running", "succeeded", "failed", "cancelled"]
    run_id: str | None = None
    mode: str
    command: list[str]
    started_at: str | None = None
    finished_at: str | None = None
    exit_code: int | None = None
    error: str | None = None
    requested_by: str
    target_counts: dict[str, int] | None = None
    execution: Literal["local", "agent"] = "local"
    assigned_agent_id: str | None = None
    tenant_id: str = "default"
    # Why the Phase 7 asset-registry upsert did not run for this job's run. The
    # upsert is best-effort and deliberately never fails the scan, so without
    # this the job reads as a clean success while the asset list stays empty --
    # with the reason only ever in the pod log, gone with the pod.
    asset_upsert_error: str | None = None
    # How many times this job has been handed to an executor (ROADMAP P1.4).
    # Above 1 means an earlier attempt's lease expired and the reaper put the
    # job back on the queue.
    attempts: int = 0
    # Persisted start options (intent, mode, delta, wordlist provenance, …).
    scan_options: dict[str, Any] | None = None


class AgentRegisterRequest(BaseModel):
    agent_id: str | None = None
    hostname: str = ""
    version: str = ""
    labels: dict[str, str] = Field(default_factory=dict)


class AgentHeartbeatRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    status: Literal["idle", "busy", "error"] = "idle"
    current_job_id: str | None = None
    detail: str | None = None


class AgentInfo(BaseModel):
    agent_id: str
    hostname: str = ""
    version: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    status: Literal["idle", "busy", "error", "stale"] = "idle"
    current_job_id: str | None = None
    detail: str | None = None
    registered_at: str | None = None
    last_seen_at: str | None = None
    online: bool = False
    tenant_id: str = "default"


class AgentClaimResponse(BaseModel):
    job_id: str
    run_id: str
    mode: str
    delta: bool = False
    skip_nse: bool = False
    notify: bool = False
    export_defectdojo: bool = False
    inputs: dict[str, str] = Field(default_factory=dict)
    tenant_id: str = "default"
    # Fencing token for this hand-out (ROADMAP P1.4/P1.5). Echo it back on the
    # results upload; the API rejects an upload carrying a stale attempt, which
    # is how a late result from a lease that already expired is kept from
    # overwriting the run of the attempt that replaced it.
    attempt: int = 1


class CreateScheduleRequest(BaseModel):
    tenant_id: str | None = None
    name: str = Field(min_length=1, max_length=128)
    cron: str | None = None
    interval_seconds: int | None = None
    mode: Literal["safe", "balanced", "fast", "test"] = "balanced"
    intent: Literal["inventory", "vuln", "full", "delta"] | None = None
    delta: bool = True
    skip_nse: bool = False
    notify: bool = False
    export_defectdojo: bool = False
    ranges: str | None = None
    domains: str | None = None
    ports: str | None = None
    ports_udp: str | None = None


class UpdateScheduleRequest(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    cron: str | None = None
    interval_seconds: int | None = None
    mode: Literal["safe", "balanced", "fast", "test"] | None = None
    intent: Literal["inventory", "vuln", "full", "delta"] | None = None
    delta: bool | None = None
    skip_nse: bool | None = None
    notify: bool | None = None
    export_defectdojo: bool | None = None
    ranges: str | None = None
    domains: str | None = None
    ports: str | None = None
    ports_udp: str | None = None


class ScheduleInfo(BaseModel):
    schedule_id: str
    tenant_id: str
    name: str
    enabled: bool
    cron: str | None = None
    interval_seconds: int | None = None
    scan_options: dict[str, Any]
    targets: dict[str, Any]
    next_run_at: str | None = None
    last_run_at: str | None = None
    last_job_id: str | None = None
    created_at: str | None = None
    created_by: str | None = None


class CreateWebhookRequest(BaseModel):
    """New outbound webhook subscription (ROADMAP Phase 10.3)."""

    tenant_id: str | None = None
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=2048)
    # Empty/omitted = every asset event kind.
    event_kinds: list[str] | None = None
    # Applies to the kinds that carry a severity (new_cve); others are
    # delivered regardless.
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    # Omitted = a signing secret is generated and returned once.
    secret: str | None = Field(default=None, max_length=512)
    headers: dict[str, str] | None = None
    enabled: bool = True


class UpdateWebhookRequest(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None
    event_kinds: list[str] | None = None
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    headers: dict[str, str] | None = None


class WebhookInfo(BaseModel):
    subscription_id: str
    tenant_id: str
    name: str
    url: str
    enabled: bool
    event_kinds: list[str]
    min_severity: str | None = None
    has_secret: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    created_at: str | None = None
    created_by: str | None = None
    updated_at: str | None = None
    last_delivery_at: str | None = None
    last_status: str | None = None
    # Present only in the response that created or rotated it — the value is
    # write-only afterwards.
    secret: str | None = None


class WebhookDeliveryInfo(BaseModel):
    """One delivery attempt chain: queue entry, DLQ row and audit record."""

    delivery_id: str
    tenant_id: str
    subscription_id: str
    event_id: str
    event_kind: str
    status: str
    attempts: int
    next_attempt_at: str | None = None
    last_status_code: int | None = None
    last_error: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    delivered_at: str | None = None


class WordlistInfo(BaseModel):
    """A tenant-uploaded brute-force wordlist — metadata only, never the body."""

    wordlist_id: str
    tenant_id: str
    name: str
    kind: str
    line_count: int
    sha256: str
    created_at: str | None = None
    created_by: str | None = None


class AgentCompleteRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    exit_code: int = 0
    run_id: str | None = None
    error: str | None = None


class MembershipInfo(BaseModel):
    """One user's access to one tenant (ROADMAP P0)."""

    username: str
    tenant_id: str
    role: Literal["viewer", "operator", "admin"]
    created_at: str | None = None
    created_by: str | None = None


class GrantMembershipRequest(BaseModel):
    role: Literal["viewer", "operator", "admin"] = "viewer"


class AuthEventInfo(BaseModel):
    """One recorded login attempt (#157).

    ``outcome`` is ``success``, ``failure`` (credentials checked and rejected)
    or ``locked`` (refused by the rate limiter before they were checked).
    ``reason`` is NULL on success.
    """

    id: int
    occurred_at: str | None = None
    username: str
    client_ip: str
    outcome: Literal["success", "failure", "locked"]
    reason: str | None = None


class UserInfo(BaseModel):
    """A console account (#156). Carries no password material by construction."""

    username: str
    role: Literal["viewer", "operator", "admin"]
    disabled: bool = False
    # False for an account backfilled by migration 0013 from an orphan
    # membership: it exists and can be granted tenants, but cannot log in until
    # an admin sets a password.
    has_password: bool = True
    created_at: str | None = None
    updated_at: str | None = None
    disabled_at: str | None = None
    password_changed_at: str | None = None
    created_by: str | None = None


# 12 characters is a floor rather than a policy, and 72 bytes is bcrypt's own
# limit — beyond it the tail of what the operator typed is silently ignored,
# which would make a longer password decorative rather than stronger.
_PASSWORD = Field(min_length=12, max_length=72)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = _PASSWORD
    role: Literal["viewer", "operator", "admin"] = "viewer"


class SetUserPasswordRequest(BaseModel):
    password: str = _PASSWORD


class SetUserRoleRequest(BaseModel):
    role: Literal["viewer", "operator", "admin"]


class SetUserDisabledRequest(BaseModel):
    disabled: bool


class ChangeOwnPasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = _PASSWORD


class TenantInfo(BaseModel):
    tenant_id: str
    name: str
    status: Literal["active", "disabled"] = "active"
    created_at: str | None = None


class CreateTenantRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    tenant_id: str | None = Field(default=None, max_length=64)


class CreateProvisioningKeyRequest(BaseModel):
    label: str = Field(default="", max_length=128)


class ProvisioningKeyInfo(BaseModel):
    key_id: str
    tenant_id: str
    label: str = ""
    created_at: str | None = None
    revoked_at: str | None = None
    last_used_at: str | None = None
    # Present only on create (one-time plaintext).
    key: str | None = None


class AgentTokenRequest(BaseModel):
    provisioning_key: str = Field(min_length=8, max_length=256)
    agent_id: str | None = Field(default=None, max_length=128)


class AgentTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    key_id: str
    agent_id: str | None = None
    expires_in: int


class AuthExchangeRequest(BaseModel):
    """Body for ``POST /api/v1/auth/exchange``."""

    provisioning_key: str = Field(min_length=8, max_length=256)
    agent_id: str | None = Field(default=None, max_length=128)


class AuthExchangeResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str
    agent_id: str
    key_id: str | None = None
    expires_in: int


class ToolVersion(BaseModel):
    name: str
    version: str | None = None
    error: str | None = None
    # Phase 5: tools not required for default Pulse path (e.g. nmap).
    optional: bool = False


class EnrichmentDb(BaseModel):
    name: str
    present: bool
    path: str
    size_bytes: int | None = None
    modified_at: datetime | None = None
    age_days: float | None = None


class ScanConfigSummary(BaseModel):
    profiles: list[str]
    nse_profiles: list[str]
    # service_probe.backend (pulse | nmap | hybrid); optional for older responses.
    service_backend: str | None = None
    stages: dict[str, bool]


class RuntimeInfo(BaseModel):
    allow_scan_start: bool
    job_execution_mode: str
    nats_enabled: bool
    clickhouse_enabled: bool
    postgres_enabled: bool
    ch_ingest_enabled: bool
    asset_stale_days: int
    endpoint_inventory_enabled: bool = True
    endpoint_stale_hours: int = 48
    # Job leases (ROADMAP P1.4): how long an unattended job survives before the
    # reaper acts, and how many hand-outs it gets first.
    job_lease_seconds: int = 300
    job_max_attempts: int = 3
    job_reaper_enabled: bool = True
    # Login brute-force protection (#157). Without a trusted proxy configured
    # behind an ingress, every attempt is attributed to the ingress address and
    # the whole installation shares one limiter key.
    login_rate_limit_enabled: bool = True
    login_rate_limit_max_failures: int = 5
    login_rate_limit_window_seconds: int = 900
    trusted_proxies_configured: bool = False


class InventoryCounts(BaseModel):
    tenants: int | None = None
    agents_total: int | None = None
    agents_online: int | None = None


class EndpointInventoryStatus(BaseModel):
    """Endpoint-inventory footprint and retention posture (Agent_plan.md S9)."""

    enabled: bool
    devices_total: int | None = None
    devices_stale: int | None = None
    stale_hours: int
    retention_enabled: bool
    snapshot_retention_days: int
    change_retention_days: int
    retention_interval_seconds: int
    retention_last_run_at: str | None = None


class SystemStatus(BaseModel):
    """Read-only snapshot of the running installation (Web UI System page).
    Contains no secrets — only booleans/counts derived from settings."""

    app_version: str
    tools: list[ToolVersion]
    enrichment: list[EnrichmentDb]
    scan_config: ScanConfigSummary
    runtime: RuntimeInfo
    inventory: InventoryCounts
    endpoint_inventory: EndpointInventoryStatus


class ConfigResponse(BaseModel):
    """Editable scanner-config settings for the configurator (dot-path keyed)."""

    editable_paths: list[str]
    defaults: dict[str, Any]
    effective: dict[str, Any]
    overrides: dict[str, Any]


class ConfigUpdateRequest(BaseModel):
    """Flat dot-path → value overrides (only whitelisted paths are accepted)."""

    overrides: dict[str, Any] = Field(default_factory=dict)


class EndpointSoftwareItem(BaseModel):
    """One installed-software record within an inventory snapshot (Lariska agent)."""

    name: str = Field(min_length=1, max_length=512)
    version: str | None = Field(default=None, max_length=128)
    publisher: str | None = Field(default=None, max_length=256)
    architecture: str | None = Field(default=None, max_length=32)
    source: Literal["apt", "dpkg", "rpm", "winreg", "msi", "brew", "other"] = "other"
    install_location: str | None = Field(default=None, max_length=1024)


class EndpointIdentifierIn(BaseModel):
    """Agent-hashed platform identifier. The API never sees or stores a raw
    machine identifier (MAC/serial/etc.) — only the hash the agent computed."""

    identifier_type: Literal["mac_hash", "serial_hash", "bios_uuid_hash", "tpm_ek_hash"]
    value_hash: str = Field(min_length=8, max_length=128)


class EndpointInventorySnapshotRequest(BaseModel):
    """Body for ``POST /api/endpoint/inventory`` (schema v1)."""

    schema_version: Literal[1]
    snapshot_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    collected_at: str
    hostname: str = Field(min_length=1, max_length=255)
    os_family: str | None = Field(default=None, max_length=64)
    os_name: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    os_arch: str | None = Field(default=None, max_length=32)
    agent_version: str = Field(min_length=1, max_length=64)
    labels: dict[str, str] = Field(default_factory=dict)
    identifiers: list[EndpointIdentifierIn] = Field(default_factory=list)
    software: list[EndpointSoftwareItem] = Field(default_factory=list)
    collector_warnings: list[str] = Field(default_factory=list)


class EndpointInventoryResponse(BaseModel):
    snapshot_id: str
    status: Literal["accepted"] = "accepted"
    device_id: str
    asset_id: str | None = None
    reconciliation_status: str = "linked"
    software_count: int
    changes: dict[str, int] = Field(default_factory=lambda: {"installed": 0, "removed": 0, "updated": 0})


class EndpointDeviceInfo(BaseModel):
    device_id: str
    tenant_id: str
    agent_id: str
    asset_id: str | None = None
    hostname: str
    os_family: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_arch: str | None = None
    agent_version: str
    labels: dict[str, str] = Field(default_factory=dict)
    reconciliation_status: str
    # Derived from last_inventory_at against OCTO_ENDPOINT_STALE_HOURS (S9) —
    # "active" | "stale". Never stored, so a threshold change applies at once.
    status: str = "stale"
    first_seen: str | None = None
    last_seen: str | None = None
    last_inventory_at: str | None = None
    latest_snapshot_id: str | None = None


class EndpointSnapshotSummary(BaseModel):
    snapshot_id: str
    device_id: str
    schema_version: int
    collected_at: str | None = None
    received_at: str | None = None
    software_count: int
    collector_warnings: list[str] = Field(default_factory=list)


class EndpointSoftwareChangeInfo(BaseModel):
    device_id: str
    snapshot_id: str
    event_type: Literal["installed", "removed", "updated"]
    display_name: str
    old_version: str | None = None
    new_version: str | None = None
    observed_at: str | None = None


class EndpointSoftwareChangeFeedItem(EndpointSoftwareChangeInfo):
    """A software-change event annotated with the device it happened on, for
    the cross-device recent-changes feed (``GET /endpoint/changes``)."""

    hostname: str
    asset_id: str | None = None


class EndpointSoftwareItemInfo(BaseModel):
    name: str
    version: str | None = None
    publisher: str | None = None
    architecture: str | None = None
    source: str
    install_location: str | None = None
