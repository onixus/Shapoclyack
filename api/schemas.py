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
    severity: str | None = None
    script_id: str | None = None


class StartScanRequest(BaseModel):
    mode: Literal["safe", "balanced", "fast"] = "balanced"
    delta: bool = False
    skip_nse: bool = False
    notify: bool = False
    export_defectdojo: bool = False
    run_id: str | None = None
    # Newline-separated targets. Empty / omitted → server default input files.
    ranges: str | None = None
    domains: str | None = None
    ports: str | None = None


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
