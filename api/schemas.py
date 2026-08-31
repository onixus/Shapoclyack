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


class SsoStatus(BaseModel):
    """Whether this installation offers single sign-on. Unauthenticated.

    Deliberately not the issuer: the login form is reachable by anyone, and the
    provider's URL names the customer's identity vendor.
    """

    enabled: bool = False
    login_url: str = "/api/auth/oidc/login"


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    service: str = "shapoclyack-api"
    nats: bool | None = None
    clickhouse: bool | None = None
    ch_ingest: dict[str, int] | None = None
    # Whether single sign-on is configured (Track E). Here rather than on
    # /api/system because the login form has to know before anyone is signed
    # in, and this is the endpoint that is already public.
    sso: SsoStatus | None = None


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
    # Subset of `potential_vulnerabilities` the scanner itself could not
    # confirm — `exposure` observations and unverified `keyword_cve` hits (see
    # VulnerabilityItem.finding_class). Carried alongside the total so a reader
    # can tell a run with 40 confirmed CVEs from one with 40 keyword guesses;
    # None for runs written before the scanner recorded it.
    unconfirmed_findings: int | None = None
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
    # Host reachability for likelihood (#171). Not inferred from a public IP.
    network_exposure: str | None = None
    network_exposure_source: str | None = None
    # On-path CDN/WAF names from fingerprint.json on the same host:port (#173).
    # Empty means we did not observe one, not that the service is unprotected.
    cdn_waf: list[str] = Field(default_factory=list)
    compensating_control_source: str | None = None


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
    # P4.3: operator-set ownership from the asset registry. Never inferred
    # from a public IP or an ASN. ``ownership_source`` is operator | domain | none.
    owner_email: str | None = None
    business_unit: str | None = None
    asset_id: str | None = None
    registrable_domain: str | None = None
    ownership_source: str | None = None


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


class AssetIdentityLink(BaseModel):
    ip: str
    fqdn: str
    sources: list[str] = Field(default_factory=list)
    confidence: str
    shared: bool = False
    merged: bool = False


class AssetSummary(BaseModel):
    asset_id: str
    status: str
    first_seen: datetime
    last_seen: datetime
    primary_identifier: str | None = None
    identifier_count: int = 0
    asset_criticality: int | None = None
    owner_email: str | None = None
    business_service: str | None = None
    environment: str | None = None
    exposure_level: str | None = None
    # Page-scoped rollup (#136): one query for the page, not one per row.
    open_findings: int = 0
    unassigned_findings: int = 0
    estate_risk: str | None = None


class AssetDetail(BaseModel):
    asset_id: str
    tenant_id: str
    status: str
    first_seen: datetime
    last_seen: datetime
    owner_email: str | None = None
    business_unit: str | None = None
    asset_criticality: int | None = None
    business_service: str | None = None
    environment: str | None = None
    data_classification: str | None = None
    exposure_level: str | None = None
    context_source: str | None = None
    identifiers: list[AssetIdentifier] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    # P4.2: named IP↔FQDN evidence. ``merged`` is false when shared hosting
    # forbade a collapse — two assets on purpose.
    identity_links: list[AssetIdentityLink] = Field(default_factory=list)
    # Open-finding rollup from the tracker — why this asset is risky (#146).
    risk: VulnerabilitySummary | None = None


class AssetContextEventInfo(BaseModel):
    id: int
    asset_id: str
    tenant_id: str
    occurred_at: str | None = None
    field: str
    old_value: str | None = None
    new_value: str | None = None
    actor: str | None = None
    source: str | None = None


class UpdateAssetRequest(BaseModel):
    owner_email: str | None = None
    business_unit: str | None = None
    asset_criticality: int | None = Field(default=None, ge=0, le=4)
    business_service: str | None = Field(default=None, max_length=200)
    environment: Literal["production", "staging", "development", "lab", "other"] | None = None
    data_classification: Literal["public", "internal", "confidential", "restricted"] | None = None
    # Operator-set posture, not a scan measurement (#171 is the network fact).
    exposure_level: Literal["internet", "partner", "internal", "unknown"] | None = None
    context_source: Literal["operator", "cmdb", "ad", "other"] | None = None
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
    metrics: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)


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
    metrics: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[str] = Field(default_factory=list)
    is_outdated: bool = False
    latest_version: str = ""
    upgrade_requested: bool = False


class AgentFleetSummary(BaseModel):
    total_agents: int = 0
    online_agents: int = 0
    busy_agents: int = 0
    stale_agents: int = 0
    error_agents: int = 0
    outdated_agents: int = 0
    latest_version: str = ""
    by_tenant: dict[str, int] = Field(default_factory=dict)


# A hostname, an IPv4 literal, or a bracketed IPv6 literal — never a value
# that starts with ``-``, which ``ssh`` would take for an option.
_SSH_HOST_PATTERN = r"^[A-Za-z0-9\[][A-Za-z0-9._:\[\]-]*$"
# POSIX-portable account names, again never leading with ``-``.
_SSH_USERNAME_PATTERN = r"^[A-Za-z0-9_][A-Za-z0-9._-]*$"


class AgentDeploySSHRequest(BaseModel):
    # ``host`` and ``username`` are concatenated into the ``user@host``
    # argument of ``ssh``/``ssh-keyscan``. A value beginning with ``-`` is read
    # by both as an option rather than a destination, and ``-oProxyCommand=…``
    # is then executed by ``/bin/sh`` inside the API process — before the host
    # key is ever compared, so a refused target is no obstacle. The character
    # sets below are what a destination can legitimately be made of; the argv
    # builders additionally pass ``--`` so neither barrier is the only one.
    host: str = Field(min_length=1, max_length=255, pattern=_SSH_HOST_PATTERN)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(
        min_length=1, max_length=64, default="root", pattern=_SSH_USERNAME_PATTERN
    )
    password: str | None = None
    private_key: str | None = None
    tenant_id: str = "default"
    agent_id: str | None = None
    install_dir: str = "/opt/shapoclyack-agent"
    use_docker: bool = False
    # The target's SSH host key fingerprint (SHA256:…), as the operator read it
    # off the target itself. Required the first time this tenant deploys to a
    # host and pinned on success; afterwards the pin is what is checked and
    # this field is ignored. Without it the deployment is refused rather than
    # trusting whatever key answers (#232).
    expected_host_key: str | None = Field(default=None, max_length=200)


class AgentSSHHostKeyProbeRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255, pattern=_SSH_HOST_PATTERN)
    port: int = Field(default=22, ge=1, le=65535)


class AgentSSHHostKeyInfo(BaseModel):
    """A target's SSH host key as the API currently sees it.

    ``pinned`` says whether this is the tenant's stored key or one just read
    off the wire — an unpinned fingerprint is a claim by whoever answered, and
    the operator is expected to check it against the host before trusting it.
    """

    host: str
    port: int
    key_type: str
    fingerprint: str
    pinned: bool = False
    pinned_at: str | None = None


class AgentDeployStatusResponse(BaseModel):
    deploy_id: str
    status: Literal["queued", "connecting", "installing", "verifying", "completed", "failed"] = "queued"
    stage: str = "Initializing"
    progress_percent: int = 0
    logs: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None


class AgentDeploymentSnippetResponse(BaseModel):
    tenant_id: str
    # Null on the read-only GET: the snippets then carry a placeholder the
    # caller must replace. Only the minting POST returns plaintext, once.
    provisioning_key: str | None = None
    key_minted: bool = False
    server_url: str
    systemd_oneliner: str
    docker_run: str
    docker_compose: str
    kubernetes_yaml: str


class CreateAgentDeploymentKeyRequest(BaseModel):
    label: str = Field(default="", max_length=200)


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
    # webhook (default HMAC POST) | jira | servicenow | defectdojo
    transport: Literal["webhook", "jira", "servicenow", "defectdojo"] | None = None
    transport_config: dict[str, Any] | None = None


class UpdateWebhookRequest(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None
    event_kinds: list[str] | None = None
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    headers: dict[str, str] | None = None
    transport: Literal["webhook", "jira", "servicenow", "defectdojo"] | None = None
    transport_config: dict[str, Any] | None = None


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
    transport: str = "webhook"
    transport_config: dict[str, Any] = Field(default_factory=dict)
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
    """One recorded access decision (#157, #226, #241).

    ``outcome`` is ``success``, ``failure`` (credentials checked and
    rejected), ``locked`` (refused by the rate limiter before they were
    checked), ``denied`` (an authenticated principal refused an action, e.g. a
    scan outside the tenant's approved scope, or a deployment target outside
    it) or ``trust_change`` (an admin set or removed an SSH host-key pin, which
    is neither an attempt nor a refusal). ``reason`` is NULL on success.
    ``detail`` names the subject of a non-login decision and is NULL for login
    attempts, whose subject is the username/IP pair; ``client_ip`` is empty for
    the decisions taken in the service layer, which have no request to read it
    from.
    """

    id: int
    occurred_at: str | None = None
    username: str
    client_ip: str
    outcome: Literal["success", "failure", "locked", "denied", "trust_change"]
    reason: str | None = None
    detail: str | None = None


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
    # Federated identity (Track E). The issuer and subject themselves are never
    # returned: they name the customer's IdP and the person inside it, and no
    # console screen has a use for either.
    email: str | None = None
    email_verified: bool = False
    sso_linked: bool = False


class SetUserEmailRequest(BaseModel):
    """Set an account's address, and whether this platform treats it as verified.

    ``verified`` is an administrative assertion, which is the point: it is what
    makes the account eligible to be linked to an SSO identity by address, so
    the decision belongs to someone with the authority to grant access rather
    than to the identity provider alone.
    """

    email: str | None = Field(default=None, max_length=320)
    verified: bool = False


class OidcLoginResponse(BaseModel):
    """The provider URL to send the browser to, for a client that redirects itself."""

    authorization_url: str
    state: str
    expires_in: int


class ServiceTokenInfo(BaseModel):
    """An issued service token. ``token`` is present only in the create response."""

    token_id: str
    tenant_id: str
    name: str
    token_prefix: str
    scopes: list[str] = Field(default_factory=list)
    role: Literal["viewer", "operator", "admin"] = "viewer"
    status: Literal["active", "expired", "revoked"] = "active"
    created_by: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None
    # One-time plaintext, exactly like ProvisioningKeyInfo.key: set on create
    # and never again, because only a hash is stored.
    token: str | None = None


class CreateServiceTokenRequest(BaseModel):
    """Issue a service token for one tenant.

    ``scopes`` is required and has no default: a token created with none by
    accident would otherwise be the most powerful credential in the
    installation. ``role`` is the ceiling the scopes narrow, and defaults to
    the lowest one.
    """

    name: str = Field(min_length=1, max_length=128)
    scopes: list[str] = Field(min_length=1, max_length=64)
    role: Literal["viewer", "operator", "admin"] = "viewer"
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


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


class ScanScopeEntry(BaseModel):
    """One allow/deny entry of a tenant's approved scanning scope (#226).

    ``value`` is a CIDR (``kind="cidr"``), a domain suffix covering itself and
    its subdomains (``kind="domain"``), or the literal ``*`` for either kind,
    which is the explicit any-value wildcard.
    """

    effect: Literal["allow", "deny"]
    kind: Literal["cidr", "domain"]
    value: str = Field(min_length=1, max_length=255)
    note: str = Field(default="", max_length=500)


class ScanScopeEntryInfo(ScanScopeEntry):
    """A stored entry, with the approval it was written under."""

    id: int
    tenant_id: str
    approved_by: str = ""
    approved_at: str | None = None


class ReplaceScanScopeRequest(BaseModel):
    """The scope a tenant should have after this request — the whole of it.

    A replacement rather than a patch: a scope is evaluated as a set (deny
    beats allow), so applying a narrowing entry by entry would leave a window
    in which a half-applied set is the one being enforced. An empty list is
    accepted and means "this tenant scans nothing".
    """

    entries: list[ScanScopeEntry] = Field(default_factory=list, max_length=1000)


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
    stale: bool = False
    # Provenance recorded when the data was fetched (#246). Age alone cannot
    # tell a freshly-pulled corpus from a committed baseline that no fetch has
    # ever managed to replace. All optional: an image built before the manifest
    # existed, or a volume with no manifest on it, reports None for each.
    source: str | None = None
    # "fetch" (this dataset was refreshed), "seed" (whatever the image shipped),
    # "stale" (a refresh was attempted and failed), or "missing".
    origin: str | None = None
    # The date the feed itself stamped on the data, not the file's mtime.
    updated: str | None = None
    entries: int | None = None


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


SoftwareCveMatchStatus = Literal["vulnerable", "fixed", "not_applicable", "unknown"]


class SoftwareCveMatchInfo(BaseModel):
    """One vendor-advisory statement about one CVE on one endpoint (Track E M1).

    ``status`` is four-valued on purpose. ``unknown`` is a first-class answer —
    an endpoint whose distribution could not be resolved carries an ``unknown``
    row with ``unknown_reason`` set and an empty ``cve_id``, rather than
    silently reading as clean. See docs/software-cve-matching.md.
    """

    device_id: str
    hostname: str | None = None
    snapshot_id: str | None = None
    # "" on an ``unknown`` row, which is about a package set rather than a CVE.
    cve_id: str = ""
    status: SoftwareCveMatchStatus = "unknown"
    # The distribution's own word (critical/high/medium/low/negligible/unknown),
    # never a CVSS score re-derived here.
    severity: str = "unknown"
    source_package: str = ""
    installed_package: str = ""
    installed_version: str | None = None
    fixed_version: str | None = None
    advisory_id: str | None = None
    advisory_url: str | None = None
    provider: str = ""
    distro: str | None = None
    distro_release: str | None = None
    purl: str | None = None
    cpe23: str | None = None
    unknown_reason: str | None = None
    feed_date: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    matched_at: str | None = None


class SoftwareCveMatchRunSummary(BaseModel):
    """Result of a matcher run over one device."""

    device_id: str
    snapshot_id: str | None = None
    distro: str | None = None
    distro_release: str | None = None
    packages_total: int = 0
    packages_assessed: int = 0
    # Packages the matcher could not put the question for at all — a non-distro
    # source, an unparsable version, an unresolved release.
    packages_unassessed: int = 0
    matches: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)


class SoftwareCveMatchTenantRunSummary(BaseModel):
    """Result of a matcher run over every device in a tenant."""

    tenant_id: str
    devices: int = 0
    matches: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    results: list[SoftwareCveMatchRunSummary] = Field(default_factory=list)


class AdvisoryProviderStatus(BaseModel):
    """Provenance of one vendor-advisory dataset, mirroring ``EnrichmentDb``."""

    name: str
    distro: str
    path: str
    present: bool = False
    source: str | None = None
    updated: str | None = None
    entries: int = 0
    releases: list[str] = Field(default_factory=list)
    error: str | None = None


class SoftwareCveMatchSummary(BaseModel):
    """Tenant-wide tallies, plus which advisory data produced them."""

    total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    vulnerable_by_severity: dict[str, int] = Field(default_factory=dict)
    last_matched_at: str | None = None
    providers: list[AdvisoryProviderStatus] = Field(default_factory=list)


class VulnerabilityInfo(BaseModel):
    """One tracked finding with its lifecycle and SLA state (#145).

    Distinct from ``VulnerabilityItem`` above, which is a *run's* finding read
    off disk and scored per request. This is the persistent entity: the same
    finding across runs, plus everything a person decided about it. ``sla_state``
    and nothing else is derived per response — see the model docstring for why
    breach is not a column.
    """

    vuln_id: str
    tenant_id: str
    asset_id: str
    finding_key: str
    cve: str | None = None
    cwe: list[str] = Field(default_factory=list)
    script_id: str | None = None
    port: str | None = None
    title: str = ""
    severity: str = "unknown"
    risk_level: str | None = None
    contextual_score: float | None = None
    cvss: float | None = None
    in_kev: bool = False
    exploit_maturity: str | None = None
    network_exposure: str | None = None
    network_exposure_source: str | None = None
    state: str
    state_changed_at: str | None = None
    state_changed_by: str | None = None
    assignee: str | None = None
    owner_team: str | None = None
    due_at: str | None = None
    sla_days: int | None = None
    sla_source: str | None = None
    sla_state: str
    exception_until: str | None = None
    exception_reason: str | None = None
    exception_by: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    sla_started_at: str | None = None
    first_seen_run_id: str | None = None
    last_seen_run_id: str | None = None
    observation_count: int = 1
    reopen_count: int = 0
    closed_at: str | None = None
    ticket_system: str | None = None
    ticket_key: str | None = None
    ticket_url: str | None = None
    # Closed-loop remediation (#183). Read-only: ``machine_verified`` is set by
    # the ingest path when a dispatched verification run failed to re-observe
    # the finding, never by a request body.
    machine_verified: bool = False
    verification_job_id: str | None = None
    last_verified_at: str | None = None
    closure_reason: str | None = None


class VulnerabilityEventInfo(BaseModel):
    """One audit entry. ``actor`` is null when the platform, not a person, did it."""

    id: int
    vuln_id: str
    tenant_id: str
    occurred_at: str | None = None
    kind: str
    from_state: str | None = None
    to_state: str | None = None
    actor: str | None = None
    note: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityTransitionRequest(BaseModel):
    """Body for ``POST /vulnerabilities/{id}/transition``.

    ``note`` is optional in general but is the only way to record *why* a
    finding was closed, which is the transition anyone auditing this will ask
    about first.
    """

    state: Literal["OPEN", "ACKNOWLEDGED", "PLANNED", "FIXING", "VERIFYING", "CLOSED"]
    note: str | None = Field(default=None, max_length=2000)


class VulnerabilityAssignRequest(BaseModel):
    """Body for ``POST /vulnerabilities/{id}/assign``. An explicit ``null``
    clears the field; an omitted key leaves it untouched."""

    assignee: str | None = Field(default=None, max_length=320)
    owner_team: str | None = Field(default=None, max_length=200)
    note: str | None = Field(default=None, max_length=2000)


class VulnerabilityExceptionRequest(BaseModel):
    """Body for ``POST /vulnerabilities/{id}/exception`` — accepted risk.

    Both fields are required: an acceptance with no expiry is a decision nobody
    revisits, and one with no reason cannot be reviewed by whoever inherits it.
    """

    until: datetime
    reason: str = Field(min_length=1, max_length=2000)


class VulnerabilityCommentRequest(BaseModel):
    """Body for ``POST /vulnerabilities/{id}/comment`` (#138)."""

    note: str = Field(min_length=1, max_length=2000)


class VulnerabilityTicketRequest(BaseModel):
    """Body for ``POST /vulnerabilities/{id}/ticket`` — link, not create.

    Native Jira/ServiceNow/SMAX/DefectDojo creation is the 10.3/P2 transport
    over the existing delivery queue. This only records where the work lives.
    """

    system: Literal["jira", "servicenow", "smax", "defectdojo", "other"]
    key: str | None = Field(default=None, max_length=200)
    url: str | None = Field(default=None, max_length=2000)
    note: str | None = Field(default=None, max_length=2000)


class SlaPolicyInfo(BaseModel):
    policy_id: str
    tenant_id: str
    # null = this severity's tenant-wide fallback.
    asset_criticality: int | None = None
    severity: str
    remediation_days: int
    created_at: str | None = None
    created_by: str | None = None
    updated_at: str | None = None


class SlaPolicyRequest(BaseModel):
    """Body for ``PUT /vulnerabilities/sla-policies`` — upsert by scope."""

    severity: Literal["critical", "high", "medium", "low", "unknown"]
    remediation_days: int = Field(ge=1, le=3650)
    asset_criticality: int | None = Field(default=None, ge=0, le=4)


class VulnerabilitySummary(BaseModel):
    """Aggregates for the Vulnerability Center header and the Risk Dashboard
    (#135, #137). ``estate_risk`` is the worst open NIST ``risk_level``."""

    total: int
    open_total: int
    untriaged: int
    unassigned: int = 0
    estate_risk: str | None = None
    by_state: dict[str, int] = Field(default_factory=dict)
    by_severity_open: dict[str, int] = Field(default_factory=dict)
    by_risk_level_open: dict[str, int] = Field(default_factory=dict)
    by_sla: dict[str, int] = Field(default_factory=dict)
    breached: int
    worst_breached_severity: str | None = None
    closed_total: int = 0
    machine_verified_closed: int = 0
    manual_closed: int = 0
    # Percentage of closures a scan confirmed, 0-100.
    machine_verification_rate: float = 0.0
    generated_at: str | None = None


class RiskScoreSnapshotInfo(BaseModel):
    """Historical risk snapshot schema (#144, Track C)."""

    snapshot_id: str
    tenant_id: str
    recorded_at: str | None = None
    estate_risk: str | None = None
    open_total: int = 0
    total: int = 0
    untriaged: int = 0
    unassigned: int = 0
    breached: int = 0
    worst_breached_severity: str | None = None
    by_severity_open: dict[str, int] = Field(default_factory=dict)
    by_risk_level_open: dict[str, int] = Field(default_factory=dict)
    by_state: dict[str, int] = Field(default_factory=dict)
    by_sla: dict[str, int] = Field(default_factory=dict)
    source: str = "run"



class TenantPosture(BaseModel):
    """One customer's risk posture for the MSSP comparison (#139).

    ``declared_internet_assets`` is operator-set ``exposure_level='internet'``,
    not a scan measurement (#171).
    """

    tenant_id: str
    name: str
    status: str
    estate_risk: str | None = None
    open_total: int = 0
    unassigned: int = 0
    breached: int = 0
    in_kev_open: int = 0
    unowned_assets: int = 0
    declared_internet_assets: int = 0


class AssetInventorySummary(BaseModel):
    """Tenant asset posture for the Risk Dashboard (#135).

    ``unowned`` is active+stale assets with no ``owner_email`` — decommissioned
    boxes are out of the working set, so they do not inflate the number.
    Internet-facing exposure is **not** counted: that input does not exist yet
    ([#171](https://github.com/onixus/Shapoclyack/issues/171) / #146).
    """

    total: int
    unowned: int
    by_status: dict[str, int] = Field(default_factory=dict)
    by_criticality: dict[str, int] = Field(default_factory=dict)
    generated_at: str | None = None


class ControlFinding(BaseModel):
    id: str
    domain: str | None = None
    severity: str = "medium"
    detail: str | None = None


class ControlCoverage(BaseModel):
    checked: int = 0
    total: int = 0


class ControlItem(BaseModel):
    control: str
    title: str
    status: Literal["ok", "weak", "fail", "not_checked", "error"]
    impact: str
    coverage: ControlCoverage = Field(default_factory=ControlCoverage)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    top_findings: list[ControlFinding] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    why: str = ""
    risk_level: str = "unassessed"


class OrgProfileControlsSummary(BaseModel):
    overall_verdict: Literal["ok", "weak", "fail", "not_checked", "error"]
    overall_risk: str = "unassessed"
    controls: list[ControlItem] = Field(default_factory=list)
    evaluated_at: str | None = None


class RelatedDomainEvidence(BaseModel):
    source: str
    indicator: str | None = None
    detail: str | None = None


class RelatedDomainCandidate(BaseModel):
    domain: str
    status: Literal["confirmed", "candidate"]
    confidence: float
    sources: list[str] = Field(default_factory=list)
    evidence: list[RelatedDomainEvidence] = Field(default_factory=list)


class RelatedDomainsSummary(BaseModel):
    status: str = "ok"
    seed_domains: list[str] = Field(default_factory=list)
    confirmed_count: int = 0
    candidate_count: int = 0
    total_candidates: int = 0
    truncated: bool = False
    auto_merged: bool = False
    merge_into_scope: bool = False
    merged_domains: list[str] = Field(default_factory=list)
    disclaimer: str = ""
    candidates: list[RelatedDomainCandidate] = Field(default_factory=list)
    evaluated_at: str | None = None


class OrgProfileDetail(BaseModel):
    run_id: str
    seed_domains: list[str] = Field(default_factory=list)
    ownership: dict[str, Any] | None = None
    #: True when ``ownership`` was withheld because the caller is a viewer.
    ownership_restricted: bool = False
    related_domains: RelatedDomainsSummary | None = None
    controls: OrgProfileControlsSummary | None = None
    promoted_domains: list[str] = Field(default_factory=list)
    generated_at: str | None = None


class PromoteDomainResponse(BaseModel):
    domain: str
    promoted: bool = True
    message: str
    promoted_at: str | None = None


class BreachSummary(BaseModel):
    name: str
    title: str | None = None
    domain: str | None = None
    breach_date: str | None = None
    pwn_count: int = 0
    description: str | None = None
    data_classes: list[str] = Field(default_factory=list)
    has_passwords: bool = False
    is_verified: bool = True
    is_sensitive: bool = False
    masked_identifiers: list[str] = Field(default_factory=list)


class DomainBreachDetail(BaseModel):
    status: str
    reason: str | None = None
    breaches_count: int = 0
    accounts_count: int = 0
    breaches: list[BreachSummary] = Field(default_factory=list)


class CredentialLeaksSummary(BaseModel):
    status: str
    skipped_reason: str | None = None
    provider: str = "hibp"
    checked_domains: int = 0
    attempted_domains: int = 0
    total_domains: int = 0
    breaches_count: int = 0
    accounts_count: int = 0
    seed_domains: list[str] = Field(default_factory=list)
    domains: dict[str, DomainBreachDetail] = Field(default_factory=dict)
    truncated: bool = False
    evaluated_at: str | None = None


class LeakIdentifiersResponse(BaseModel):
    run_id: str
    total_identifiers: int = 0
    domains: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    #: False when ``credential_leaks.reveal_identifiers`` was left off, in which
    #: case ``domains`` is empty by design rather than for lack of data.
    revealed: bool = True
    withheld_reason: str | None = None
    withheld_identifiers: int = 0
    generated_at: str | None = None



