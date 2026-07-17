from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    service: str = "octo-man-api"


class RunSummary(BaseModel):
    run_id: str
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


class AliveHostItem(BaseModel):
    host: str
    hostname: str | None = None
    names: list[str] = Field(default_factory=list)
    country: str | None = None
    city: str | None = None
    country_iso: str | None = None
    vulnerability_count: int = 0


class PortAggregateItem(BaseModel):
    port: str
    protocol: str | None = None
    host_count: int = 0
    vulnerability_count: int = 0
    hosts: list[str] = Field(default_factory=list)


class StartScanRequest(BaseModel):
    mode: Literal["safe", "balanced", "fast"] = "balanced"
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


class JobInfo(BaseModel):
    job_id: str
    status: Literal["queued", "running", "succeeded", "failed"]
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


class AgentCompleteRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    exit_code: int = 0
    run_id: str | None = None
    error: str | None = None


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
