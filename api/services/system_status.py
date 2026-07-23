"""Read-only introspection of the running installation for the Web UI's
System page. Everything here is best-effort and fail-soft — a missing tool,
unreadable config, or unconfigured Postgres degrades to ``None``/empty rather
than raising, and **no secrets** (URLs, tokens, JWT secret, passwords) are
ever included in the payload."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from api import __version__
from api.settings import Settings

LOG = logging.getLogger(__name__)

# `<binary>: <version-probe args>` for the external scanner toolchain.
_TOOL_COMMANDS: dict[str, list[str]] = {
    "nmap": ["nmap", "--version"],
    "naabu": ["naabu", "-version"],
    "nuclei": ["nuclei", "-version"],
    "dnsx": ["dnsx", "-version"],
}
_VERSION_RE = re.compile(r"v?\d+\.\d+(?:\.\d+)?")

# Probing four subprocesses on every page poll is wasteful and the answer only
# changes on a rebuild, so cache the result for a few minutes.
_TOOL_TTL_SECONDS = 300.0
_tool_cache: dict[str, dict[str, str | None]] | None = None
_tool_cache_at = 0.0


def _probe_tool(command: list[str]) -> dict[str, str | None]:
    binary = command[0]
    if shutil.which(binary) is None:
        return {"version": None, "error": "not installed"}
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"version": None, "error": str(exc)}
    combined = f"{proc.stdout}\n{proc.stderr}"
    match = _VERSION_RE.search(combined)
    if match:
        return {"version": match.group(0), "error": None}
    first_line = next((line.strip() for line in combined.splitlines() if line.strip()), "")
    return {"version": first_line or None, "error": None if first_line else "no version output"}


def tool_versions(*, force: bool = False) -> list[dict[str, str | None]]:
    """Versions of nmap/naabu/nuclei/dnsx, cached for ``_TOOL_TTL_SECONDS``."""
    global _tool_cache, _tool_cache_at
    now = time.monotonic()
    if force or _tool_cache is None or (now - _tool_cache_at) > _TOOL_TTL_SECONDS:
        _tool_cache = {name: _probe_tool(cmd) for name, cmd in _TOOL_COMMANDS.items()}
        _tool_cache_at = now
    return [{"name": name, **info} for name, info in _tool_cache.items()]


def _load_config(settings: Settings) -> dict[str, Any]:
    try:
        data = yaml.safe_load(settings.config_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, yaml.YAMLError):
        LOG.warning("system_status: could not read scan config at %s", settings.config_path)
        return {}


def _stat_db(name: str, path_str: str) -> dict[str, Any]:
    path = Path(path_str)
    try:
        stat = path.stat()
    except OSError:
        return {"name": name, "present": False, "path": path_str, "size_bytes": None,
                "modified_at": None, "age_days": None}
    modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    age_days = round((datetime.now(tz=timezone.utc) - modified).total_seconds() / 86400, 1)
    return {
        "name": name,
        "present": True,
        "path": path_str,
        "size_bytes": stat.st_size,
        "modified_at": modified,
        "age_days": age_days,
    }


def enrichment_status(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Freshness of the four enrichment databases at their effective paths
    (env override → scan-config default → hardcoded fallback)."""
    enrichment = config.get("enrichment", {}) if isinstance(config, dict) else {}
    geoip_default = (enrichment.get("geoip", {}) or {}).get("database", "scanner/data/geoip/geoip.mmdb")
    cvss4_default = (enrichment.get("cvss4", {}) or {}).get("database", "scanner/data/cvss4/cvss4.json")
    paths = {
        "epss": os.environ.get("OCTO_EPSS_DATABASE") or "scanner/data/epss/epss-overlay.json",
        "kev": os.environ.get("OCTO_KEV_DATABASE") or "scanner/data/kev/kev-overlay.json",
        "geoip": os.environ.get("OCTO_GEOIP_DATABASE") or geoip_default,
        "cvss4": os.environ.get("OCTO_CVSS4_DATABASE") or cvss4_default,
    }
    return [_stat_db(name, path) for name, path in paths.items()]


def _stage_enabled(config: dict[str, Any], section: str, key: str = "enabled") -> bool:
    node = config.get(section)
    return bool(isinstance(node, dict) and node.get(key))


def scan_config_summary(config: dict[str, Any]) -> dict[str, Any]:
    profiles = config.get("profiles", {})
    nse = config.get("nse_profiles", {})
    return {
        "profiles": sorted(profiles.keys()) if isinstance(profiles, dict) else [],
        "nse_profiles": sorted(nse.keys()) if isinstance(nse, dict) else [],
        "stages": {
            "fingerprint": _stage_enabled(config, "fingerprint"),
            "tls_posture": _stage_enabled(config, "tls_posture"),
            "nuclei": _stage_enabled(config, "nuclei"),
            "pdf_summary": _stage_enabled(config, "reporting", "pdf_summary"),
            "alerts": _stage_enabled(config, "alerts"),
            "defectdojo": _stage_enabled(config, "defectdojo"),
            "scheduler": _stage_enabled(config, "scheduler"),
        },
    }


def runtime_info(settings: Settings) -> dict[str, Any]:
    # bool(url) only — the URLs/secrets themselves are never exposed.
    return {
        "allow_scan_start": settings.allow_scan_start,
        "job_execution_mode": settings.job_execution_mode,
        "nats_enabled": bool(settings.nats_url.strip()),
        "clickhouse_enabled": bool(settings.clickhouse_url.strip()),
        "postgres_enabled": bool(settings.postgres_url.strip()),
        "ch_ingest_enabled": settings.ch_ingest_enabled,
        "asset_stale_days": settings.asset_stale_days,
    }


def inventory_counts() -> dict[str, int | None]:
    tenants: int | None
    agents_total: int | None
    agents_online: int | None
    try:
        from api.services import tenants as tenants_service

        tenants = len(tenants_service.list_tenants())
    except Exception:  # noqa: BLE001 - fail-soft status view
        tenants = None
    try:
        from api.services import agents as agents_service

        agent_rows = agents_service.list_agents()
        agents_total = len(agent_rows)
        agents_online = sum(1 for a in agent_rows if getattr(a, "online", False))
    except Exception:  # noqa: BLE001 - fail-soft status view
        agents_total = None
        agents_online = None
    return {"tenants": tenants, "agents_total": agents_total, "agents_online": agents_online}


def build_status(settings: Settings) -> dict[str, Any]:
    config = _load_config(settings)
    return {
        "app_version": __version__,
        "tools": tool_versions(),
        "enrichment": enrichment_status(config),
        "scan_config": scan_config_summary(config),
        "runtime": runtime_info(settings),
        "inventory": inventory_counts(),
    }
