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


class SlackAlertConfig(BaseModel):
    enabled: bool = False
    # Prefer env OCTO_SLACK_WEBHOOK over committing secrets to YAML.
    webhook_url: str = ""


class TelegramAlertConfig(BaseModel):
    enabled: bool = False
    # Prefer env OCTO_TELEGRAM_BOT_TOKEN / OCTO_TELEGRAM_CHAT_ID.
    bot_token: str = ""
    chat_id: str = ""


class AlertsConfig(BaseModel):
    enabled: bool = False
    min_severity: Literal["critical", "high", "medium", "low", "unknown"] = "high"
    # When true, skip notifications unless a report diff found changes.
    on_diff_only: bool = False
    slack: SlackAlertConfig = Field(default_factory=SlackAlertConfig)
    telegram: TelegramAlertConfig = Field(default_factory=TelegramAlertConfig)


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
