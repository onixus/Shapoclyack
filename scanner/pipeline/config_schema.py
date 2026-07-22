from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class RuntimeConfig(BaseModel):
    mode: Literal["safe", "balanced", "fast"] = "balanced"
    output_dir: str = "scanner/output"
    state_dir: str = "scanner/state"
    logs_dir: str = ""
    retries: int = Field(default=2, ge=0, le=10)
    timeout_seconds: int = Field(default=1800, ge=30, le=86400)
    nse_timeout_seconds: int = Field(default=600, ge=30, le=600)
    nse_concurrency: int = Field(default=4, ge=1, le=64)
    nse_max_rate: int = Field(default=0, ge=0)
    nse_hosts_per_scan: int = Field(default=1, ge=1, le=256)
    discover_concurrency: int = Field(default=1, ge=1, le=32)
    ports_concurrency: int = Field(default=1, ge=1, le=32)
    # Skip NSE stage (L1 scan: discover + ports + reports only). Re-run with --resume to enrich.
    skip_nse: bool = False
    keep_intermediate: bool = True
    per_run_output: bool = True
    log_max_bytes: int = Field(default=10_485_760, ge=1024)  # 10 MiB
    log_backup_count: int = Field(default=5, ge=1, le=100)

    @model_validator(mode="after")
    def default_logs_dir(self) -> RuntimeConfig:
        if not self.logs_dir:
            self.logs_dir = f"{self.output_dir}/logs"
        return self


class ProfileConfig(BaseModel):
    discover_rate: int = Field(ge=1, le=100_000)
    port_rate: int = Field(ge=1, le=100_000)
    top_ports: int = Field(ge=1, le=65535)
    nmap_timing: Literal["T0", "T1", "T2", "T3", "T4", "T5"] = "T4"
    nse_profile: str
    nse_concurrency: int | None = Field(default=None, ge=1, le=64)
    nse_max_rate: int | None = Field(default=None, ge=0)


class BatchingConfig(BaseModel):
    enabled: bool = True
    ipv4_prefix: int = Field(default=20, ge=8, le=30)
    max_targets_per_batch: int = Field(default=4096, ge=1, le=1_000_000)


class AdaptiveDiscoveryConfig(BaseModel):
    enabled: bool = False
    wave2_rate: int | None = Field(default=None, ge=1, le=100_000)
    min_gap: int = Field(default=1, ge=0, le=1_000_000)
    max_gap_hosts: int = Field(default=65536, ge=1, le=1_000_000)
    # Skip wave-2 when coverage already meets this percent (fast profile).
    min_coverage_pct: float | None = Field(default=None, ge=0.0, le=100.0)


class VerifyDiscoveryConfig(BaseModel):
    enabled: bool = False
    rate: int | None = Field(default=None, ge=1, le=100_000)


class IcmpDiscoveryConfig(BaseModel):
    enabled: bool = False
    tool: Literal["fping"] = "fping"
    timeout_ms: int = Field(default=500, ge=50, le=30_000)
    retries: int = Field(default=1, ge=0, le=10)
    period_ms: int | None = Field(default=None, ge=0, le=10_000)


class TcpProbeDiscoveryConfig(BaseModel):
    enabled: bool = False
    ports: list[int] = Field(default_factory=lambda: [80, 443, 22])
    rate: int | None = Field(default=None, ge=1, le=100_000)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if port < 1 or port > 65535:
                raise ValueError(f"invalid TCP probe port: {port}")
        if not ports:
            raise ValueError("tcp_probe.ports must not be empty when tcp probe is used")
        return ports


ProbeMethod = Literal["icmp", "tcp", "naabu"]
DiscoveryProfileSetting = Literal["auto", "fast", "balanced", "thorough", "custom"]
_DEFAULT_PROBE_ORDER: list[ProbeMethod] = ["icmp", "tcp", "naabu"]


class HostnameResolveConfig(BaseModel):
    # Map alive IPs to input FQDNs from dns_resolution.json (resolve stage).
    forward: bool = True
    # PTR lookup via dnsx for alive IPs after discovery.
    reverse: bool = True


class CloudflareDiscoveryConfig(BaseModel):
    """Import DNS records from Cloudflare zones (Phase 5.1). Opt-in; token via env preferred."""

    enabled: bool = False
    # Prefer env OCTO_CLOUDFLARE_API_TOKEN over YAML secrets.
    api_token: str = ""
    # Zone names (example.com) and/or zone IDs. Empty = all zones the token can list.
    zones: list[str] = Field(default_factory=list)
    include_proxied: bool = True
    include_unproxied: bool = True
    # Flag A/AAAA records with proxied=false as potential misconfigurations.
    flag_unproxied_a: bool = True
    timeout_seconds: int = Field(default=30, ge=5, le=300)


class BruteForceSubdomainConfig(BaseModel):
    """Wordlist-based subdomain brute force (Phase 8.2). Opt-in, nested under ct.

    Candidates are generated as ``{word}.{domain}`` and kept only if they
    resolve. Concurrency/candidate caps exist so this stays a good citizen
    against target DNS resolvers rather than a query flood.
    """

    enabled: bool = False
    # Empty = built-in scanner/data/wordlists/subdomains-small.txt.
    wordlist_file: str = ""
    concurrency: int = Field(default=20, ge=1, le=200)
    max_candidates: int = Field(default=2000, ge=1, le=50_000)
    timeout_seconds: int = Field(default=5, ge=1, le=60)


class CertificateTransparencyConfig(BaseModel):
    """Async subdomain discovery: CT logs (Phase 5.2) + passive DNS + brute force (Phase 8.2). Opt-in."""

    enabled: bool = False
    # crtsh/certspotter = CT log APIs; otx = AlienVault OTX passive DNS (keyless).
    providers: list[Literal["crtsh", "certspotter", "otx"]] = Field(
        default_factory=lambda: ["crtsh"]
    )
    # Empty domains = use validated FQDN inputs (base domains / registered names).
    domains: list[str] = Field(default_factory=list)
    max_subdomains: int = Field(default=5000, ge=1, le=100_000)
    timeout_seconds: int = Field(default=45, ge=5, le=300)
    brute_force: BruteForceSubdomainConfig = Field(default_factory=BruteForceSubdomainConfig)

    @field_validator("providers")
    @classmethod
    def validate_providers(cls, providers: list[str]) -> list[str]:
        if not providers:
            raise ValueError("ct.providers must not be empty when CT is configured")
        return providers


class AsnDiscoveryConfig(BaseModel):
    """ASN / BGP org mapping (Phase 8.1): seed domain -> resolved IP -> ASN ->
    announced prefixes, via RIPEstat's free keyless API. Opt-in.

    SAFETY: an ASN can cover far more than one organization's infrastructure
    (shared hosting, CDNs). max_total_ips hard-caps how many IPs from
    announced prefixes get merged into scan scope; results past the cap are
    dropped and the run is flagged "truncated" rather than silently scoped up.
    """

    enabled: bool = False
    # Empty domains = use validated FQDN inputs (base domains / registered names).
    domains: list[str] = Field(default_factory=list)
    max_total_ips: int = Field(default=4096, ge=1, le=1_000_000)
    timeout_seconds: int = Field(default=15, ge=5, le=120)


class CloudDiscoveryConfig(BaseModel):
    """Cloud storage bucket enumeration (Phase 8.3). Opt-in.

    SAFETY: hits live third-party cloud infrastructure (AWS/Google/Microsoft
    endpoints, not the target's own hosts) once per generated candidate x
    provider. max_candidates and concurrency are deliberately more
    conservative than ct.brute_force's DNS-query defaults, since shared
    cloud-provider endpoints may rate-limit or flag abuse. Findings are
    reported only -- never merged into scan scope (a discovered bucket is a
    finding, not a port-scan target).
    """

    enabled: bool = False
    # Empty domains = use validated FQDN inputs (base domains / registered names).
    domains: list[str] = Field(default_factory=list)
    # azure is best-effort (two-level namespace, GET-only list API) -- opt-in-within-opt-in.
    providers: list[Literal["s3", "gcs", "azure"]] = Field(default_factory=lambda: ["s3", "gcs"])
    # Empty = built-in scanner/data/wordlists/bucket-names-small.txt.
    wordlist_file: str = ""
    concurrency: int = Field(default=10, ge=1, le=50)
    max_candidates: int = Field(default=500, ge=1, le=5_000)
    timeout_seconds: int = Field(default=8, ge=1, le=30)
    # Azure only: container-name guesses per resolved storage account (kept
    # small -- account x container is a compounding candidate space).
    azure_container_probes: int = Field(default=10, ge=1, le=50)

    @field_validator("providers")
    @classmethod
    def validate_providers(cls, providers: list[str]) -> list[str]:
        if not providers:
            raise ValueError("cloud.providers must not be empty when cloud discovery is configured")
        return providers


class DomainMonitorConfig(BaseModel):
    """Typosquat / domain monitoring (Phase 8.4). Opt-in.

    Two independent sub-checks, each individually toggleable:

    - typosquat_enabled: generate look-alike candidates of the seed domains
      (omission, transposition, keyboard-adjacent substitution, doubling,
      homoglyph substitution, TLD swap) and DNS-resolve them (A/AAAA only,
      passive -- same risk class as ct.brute_force). A candidate that
      resolves is reported as a finding; it is never merged into scan scope.
    - dangling_cname_enabled: for the org's own in-scope FQDNs, resolve the
      CNAME chain and flag targets matching a known vulnerable-service
      suffix with no A/AAAA record of their own. This is a heuristic
      pattern + non-resolution signal only -- it never confirms an actual
      takeover is possible.

    max_candidates caps typosquat candidates generated per seed domain
    (round-robin across generator classes, like cloud_discovery's
    max_candidates).
    """

    enabled: bool = False
    # Empty domains = use validated FQDN inputs (base domains / registered names).
    domains: list[str] = Field(default_factory=list)
    typosquat_enabled: bool = True
    dangling_cname_enabled: bool = True
    max_candidates: int = Field(default=150, ge=1, le=2_000)
    concurrency: int = Field(default=10, ge=1, le=50)
    timeout_seconds: int = Field(default=15, ge=5, le=120)
    retries: int = Field(default=1, ge=0, le=5)


class DeltaDiscoveryConfig(BaseModel):
    enabled: bool = False
    previous_run_dir: str = ""
    refresh_rate: float = Field(default=0.1, ge=0.0, le=1.0)
    refresh_seed: int = Field(default=0, ge=0)


class DiscoveryConfig(BaseModel):
    source: Literal["naabu"] = "naabu"
    # auto: derive from runtime.mode (safe→thorough, balanced→balanced, fast→fast)
    profile: DiscoveryProfileSetting = "auto"
    skip_discovery: bool = False
    # Skip hosts already found alive in earlier discover batches (overlapping batches only).
    skip_known_alive: bool = True
    # Parallel discover when batches do not share IPs (e.g. /22 split into /24).
    disjoint_batches: bool = True
    adaptive: AdaptiveDiscoveryConfig = Field(default_factory=AdaptiveDiscoveryConfig)
    exclude_alive: list[str] = Field(default_factory=list)
    exclude_last_octets: list[int] = Field(default_factory=list)
    verify: VerifyDiscoveryConfig = Field(default_factory=VerifyDiscoveryConfig)
    icmp: IcmpDiscoveryConfig = Field(default_factory=IcmpDiscoveryConfig)
    tcp_probe: TcpProbeDiscoveryConfig = Field(default_factory=TcpProbeDiscoveryConfig)
    probe_order: list[ProbeMethod] = Field(default_factory=lambda: list(_DEFAULT_PROBE_ORDER))
    hostnames: HostnameResolveConfig = Field(default_factory=HostnameResolveConfig)
    cloudflare: CloudflareDiscoveryConfig = Field(default_factory=CloudflareDiscoveryConfig)
    ct: CertificateTransparencyConfig = Field(default_factory=CertificateTransparencyConfig)
    asn: AsnDiscoveryConfig = Field(default_factory=AsnDiscoveryConfig)
    cloud: CloudDiscoveryConfig = Field(default_factory=CloudDiscoveryConfig)
    domain_monitor: DomainMonitorConfig = Field(default_factory=DomainMonitorConfig)
    seed_alive_file: str = ""
    delta: DeltaDiscoveryConfig = Field(default_factory=DeltaDiscoveryConfig)

    @field_validator("probe_order")
    @classmethod
    def validate_probe_order(cls, order: list[str]) -> list[str]:
        if not order:
            raise ValueError("probe_order must not be empty")
        allowed = set(_DEFAULT_PROBE_ORDER)
        for step in order:
            if step not in allowed:
                raise ValueError(f"unsupported probe_order step: {step}")
        return order


class PortsConfig(BaseModel):
    source: Literal["naabu"] = "naabu"
    protocol: Literal["tcp", "udp", "tcp_udp"] = "tcp"
    custom_ports_file: str = "scanner/inputs/ports.txt"
    custom_udp_ports_file: str = "scanner/inputs/ports_udp.txt"
    top_udp_ports: int = Field(default=100, ge=1, le=65535)
    udp_probes: bool = True


class NseProfileConfig(BaseModel):
    scripts: str = Field(min_length=1)
    version_detection: bool = True
    os_detection: bool = False


class DiffReportingConfig(BaseModel):
    # Compare current run artifacts against the previous run (hosts/ports/CVEs).
    enabled: bool = True
    previous_run_dir: str = ""
    markdown: bool = True


class ReportingConfig(BaseModel):
    markdown_summary: bool = True
    html_summary: bool = True
    csv_export: bool = True
    json_export: bool = True
    # Business PDF (summary.pdf) for leadership / ticket attachments.
    pdf_summary: bool = True
    pdf_title: str = "Octo-man Security Scan Report"
    pdf_org_name: str = ""
    pdf_max_vulnerabilities: int = Field(default=40, ge=1, le=500)
    diff: DiffReportingConfig = Field(default_factory=DiffReportingConfig)


class Cvss4Config(BaseModel):
    enabled: bool = True
    # Local CVE → CVSS v4 JSON map. Refresh with scripts/fetch-cvss4-db.py
    database: str = "scanner/data/cvss4/cvss4.json"


class GeoIpConfig(BaseModel):
    enabled: bool = True
    # MaxMind GeoLite2-City.mmdb or JSON overlay (labs/tests).
    # Fetch MMDB with scripts/fetch-geoip-db.sh (requires MAXMIND_LICENSE_KEY).
    database: str = "scanner/data/geoip/geoip-overlay.json"


class EnrichmentConfig(BaseModel):
    cvss4: Cvss4Config = Field(default_factory=Cvss4Config)
    geoip: GeoIpConfig = Field(default_factory=GeoIpConfig)


class FingerprintConfig(BaseModel):
    """Tech stack fingerprinting (Phase 9.1). Opt-in.

    Runs against already-discovered open TCP ports (``open_ports.txt``) that
    look like web ports -- no new port scan happens here. One GET per
    candidate endpoint is issued and classified against a small built-in
    CDN/WAF and CMS/framework signature set (see ``fingerprint.py`` module
    docstring for the honesty note on scope). ``body_max_bytes`` caps how
    much of each response is read (streamed, not buffered fully) and
    ``max_targets`` caps how many endpoints get probed per run -- past the
    cap, remaining endpoints are skipped and the run is flagged "truncated".
    Findings are reported only (``fingerprint.json``) -- never merged into
    scan scope or asset identity.
    """

    enabled: bool = False
    concurrency: int = Field(default=10, ge=1, le=50)
    max_targets: int = Field(default=1000, ge=1, le=50_000)
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    body_max_bytes: int = Field(default=65_536, ge=1024, le=1_048_576)
    http_ports: list[int] = Field(default_factory=lambda: [80, 8080, 8000, 8008, 8888])
    https_ports: list[int] = Field(default_factory=lambda: [443, 8443])
    # Self-signed/internal certs are common on scanned hosts; TLS posture
    # itself is Phase 9.2's job, not this module's.
    verify_tls: bool = False

    @field_validator("http_ports", "https_ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        for port in ports:
            if port < 1 or port > 65535:
                raise ValueError(f"invalid fingerprint port: {port}")
        return ports


class TlsPostureConfig(BaseModel):
    """TLS / certificate posture (Phase 9.2). Opt-in.

    Parses the free-text ``output`` of nmap's own ``ssl-cert`` /
    ``ssl-enum-ciphers`` NSE scripts, already written to ``nmap/tcp/*.xml`` by
    the ``nse`` stage -- no new scan or TLS-handshake dependency is added
    here (see ``tls_posture.py`` module docstring for the honesty note on
    parsing free text, not a stable schema). ``ssl-enum-ciphers`` must be
    present in the active NSE profile's ``scripts`` for weak-cipher/protocol
    findings to populate; cert expiry/self-signed detection works off
    ``ssl-cert`` alone. ``max_targets`` caps how many host:port endpoints get
    inspected per run -- past the cap, remaining endpoints are skipped and
    the run is flagged "truncated". ``expiring_soon_days`` is the lookahead
    window for the ``cert_expiring_soon`` finding. Findings are reported only
    (``tls_posture.json``) -- never merged into scan scope or asset identity.
    Hostname/SAN-CN mismatch checking is out of scope for this module.
    """

    enabled: bool = False
    max_targets: int = Field(default=2000, ge=1, le=50_000)
    expiring_soon_days: int = Field(default=30, ge=1, le=365)


class SlackAlertConfig(BaseModel):
    enabled: bool = False
    # Prefer env OCTO_SLACK_WEBHOOK over committing secrets to YAML.
    webhook_url: str = ""


class TelegramAlertConfig(BaseModel):
    enabled: bool = False
    # Prefer env OCTO_TELEGRAM_BOT_TOKEN / OCTO_TELEGRAM_CHAT_ID.
    bot_token: str = ""
    chat_id: str = ""


class SmtpAlertConfig(BaseModel):
    """Outbound SMTP via local Maddy (or any relay). Phase 5.3."""

    enabled: bool = False
    # Prefer env OCTO_SMTP_HOST / OCTO_SMTP_PORT / OCTO_SMTP_FROM / OCTO_SMTP_TO.
    host: str = "127.0.0.1"
    port: int = Field(default=25, ge=1, le=65535)
    from_addr: str = ""
    # Comma-separated or list; env OCTO_SMTP_TO overrides as comma-separated.
    to_addrs: list[str] = Field(default_factory=list)
    username: str = ""
    password: str = ""
    use_starttls: bool = False
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    # Deliverability hygiene before send (DKIM TXT + PTR).
    dkim_selector: str = ""
    require_dkim: bool = False
    require_ptr: bool = False
    # Host/IP whose PTR is checked; empty = SMTP host.
    ptr_hostname: str = ""


class AlertsConfig(BaseModel):
    enabled: bool = False
    min_severity: Literal["critical", "high", "medium", "low", "unknown"] = "high"
    # When true, skip notifications unless a report diff found changes.
    on_diff_only: bool = False
    slack: SlackAlertConfig = Field(default_factory=SlackAlertConfig)
    telegram: TelegramAlertConfig = Field(default_factory=TelegramAlertConfig)
    smtp: SmtpAlertConfig = Field(default_factory=SmtpAlertConfig)


class DefectDojoConfig(BaseModel):
    """Push Generic Findings Import JSON to DefectDojo API v2 (reimport-scan)."""

    enabled: bool = False
    # Prefer env OCTO_DEFECTDOJO_URL / OCTO_DEFECTDOJO_API_KEY over YAML secrets.
    url: str = ""
    api_key: str = ""
    product_name: str = "Octo-man"
    product_type_name: str = "Network"
    # Stable engagement name so reimport closes mitigated findings across runs.
    engagement_name: str = "Octo-man"
    test_title: str = "Octo-man NSE"
    min_severity: Literal["critical", "high", "medium", "low", "unknown"] = "high"
    include_without_cve: bool = True
    close_old_findings: bool = True
    active: bool = True
    verified: bool = False
    auto_create_context: bool = True
    verify_ssl: bool = True
    timeout_seconds: int = Field(default=60, ge=5, le=600)


class SchedulerConfig(BaseModel):
    # In-process / compose scheduler (python -m scanner.scheduler). Disabled by default.
    enabled: bool = False
    # 5-field cron (UTC): minute hour day-of-month month day-of-week (0=Sunday).
    cron: str = "0 2 * * *"
    # If > 0, use a fixed interval instead of cron.
    interval_seconds: int = Field(default=0, ge=0, le=31_536_000)
    mode: Literal["safe", "balanced", "fast"] | None = None
    delta: bool = False
    skip_nse: bool = False
    notify: bool = False
    export_defectdojo: bool = False
    # 0 = run forever; >0 stops after N successful schedule ticks (useful for tests).
    max_runs: int = Field(default=0, ge=0, le=1_000_000)

    @field_validator("cron")
    @classmethod
    def validate_cron(cls, expr: str) -> str:
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError("cron must have 5 fields: minute hour dom month dow")
        return expr


class AppConfig(BaseModel):
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    profiles: dict[str, ProfileConfig]
    batching: BatchingConfig = Field(default_factory=BatchingConfig)
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    ports: PortsConfig = Field(default_factory=PortsConfig)
    nse_profiles: dict[str, NseProfileConfig]
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    fingerprint: FingerprintConfig = Field(default_factory=FingerprintConfig)
    tls_posture: TlsPostureConfig = Field(default_factory=TlsPostureConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    defectdojo: DefectDojoConfig = Field(default_factory=DefectDojoConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)

    @field_validator("profiles")
    @classmethod
    def require_standard_profiles(cls, profiles: dict[str, ProfileConfig]) -> dict[str, ProfileConfig]:
        for name in ("safe", "balanced", "fast"):
            if name not in profiles:
                raise ValueError(f"missing required profile '{name}'")
        return profiles

    @model_validator(mode="after")
    def profile_nse_refs_exist(self) -> AppConfig:
        for name, profile in self.profiles.items():
            if profile.nse_profile not in self.nse_profiles:
                raise ValueError(
                    f"profile '{name}' references unknown nse_profile '{profile.nse_profile}'"
                )
        if self.runtime.mode not in self.profiles:
            raise ValueError(f"runtime.mode '{self.runtime.mode}' is not defined in profiles")
        return self


def load_config(raw: dict[str, Any]) -> AppConfig:
    """Parse and validate a raw YAML dict. Raises pydantic.ValidationError on failure."""
    return AppConfig.model_validate(raw)


def format_validation_error(exc: ValidationError) -> str:
    lines = ["configuration validation failed:"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"])
        lines.append(f"  - {loc}: {err['msg']}")
    return "\n".join(lines)
