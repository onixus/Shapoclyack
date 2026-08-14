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
from api.services import config_override
from api.services import pagination
from api.settings import Settings

LOG = logging.getLogger(__name__)

# `<binary>: <version-probe args>` for the external scanner toolchain.
# Phase 5: nmap is optional (default path is Pulse); pulse/nuclei/naabu/dnsx
# cover the default stack. ``optional`` tools may report "not installed".
_TOOL_COMMANDS: dict[str, list[str]] = {
    "pulse": ["pulse", "--version"],
    "naabu": ["naabu", "-version"],
    "nuclei": ["nuclei", "-version"],
    "dnsx": ["dnsx", "-version"],
    # Optional: only required for service_probe.backend nmap|hybrid.
    "nmap": ["nmap", "--version"],
}
# Tools that are not required for the default Pulse path (Phase 5).
_OPTIONAL_TOOLS: frozenset[str] = frozenset({"nmap"})
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


def tool_versions(*, force: bool = False) -> list[dict[str, Any]]:
    """Versions of pulse/naabu/nuclei/dnsx/nmap, cached for ``_TOOL_TTL_SECONDS``.

    Each entry includes ``optional: true`` for tools not needed on the default
    Pulse path (currently ``nmap``).
    """
    global _tool_cache, _tool_cache_at
    now = time.monotonic()
    if force or _tool_cache is None or (now - _tool_cache_at) > _TOOL_TTL_SECONDS:
        _tool_cache = {name: _probe_tool(cmd) for name, cmd in _TOOL_COMMANDS.items()}
        _tool_cache_at = now
    return [
        {
            "name": name,
            "optional": name in _OPTIONAL_TOOLS,
            **info,
        }
        for name, info in _tool_cache.items()
    ]


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
    """Freshness of the enrichment databases at their effective paths
    (env override → scan-config default → hardcoded fallback)."""
    enrichment = config.get("enrichment", {}) if isinstance(config, dict) else {}
    geoip_default = (enrichment.get("geoip", {}) or {}).get("database", "scanner/data/geoip/geoip.mmdb")
    cvss4_default = (enrichment.get("cvss4", {}) or {}).get("database", "scanner/data/cvss4/cvss4.json")
    asn_default = (enrichment.get("asn", {}) or {}).get("database", "scanner/data/asn/asn.mmdb")
    paths = {
        "epss": os.environ.get("OCTO_EPSS_DATABASE") or "scanner/data/epss/epss-overlay.json",
        "kev": os.environ.get("OCTO_KEV_DATABASE") or "scanner/data/kev/kev-overlay.json",
        "geoip": os.environ.get("OCTO_GEOIP_DATABASE") or geoip_default,
        "cvss4": os.environ.get("OCTO_CVSS4_DATABASE") or cvss4_default,
        "asn": os.environ.get("OCTO_ASN_DATABASE") or asn_default,
    }
    return [_stat_db(name, path) for name, path in paths.items()]


def _stage_enabled(config: dict[str, Any], section: str, key: str = "enabled") -> bool:
    node = config.get(section)
    return bool(isinstance(node, dict) and node.get(key))


def _effective_overrides(settings: Settings) -> dict[str, Any]:
    """Whitelisted config paths as actually applied (base file + stored
    overrides). Fail-soft to ``{}`` on any error (matches editable_snapshot /
    get_overrides) so a Postgres hiccup degrades to base-file values below,
    never a 500."""
    try:
        return config_override.editable_snapshot(settings).get("effective", {})
    except Exception:  # noqa: BLE001 - fail-soft status view
        LOG.warning("system_status: could not load config overrides", exc_info=True)
        return {}


def scan_config_summary(config: dict[str, Any], effective: dict[str, Any] | None = None) -> dict[str, Any]:
    effective = effective or {}
    profiles = config.get("profiles", {})
    nse = config.get("nse_profiles", {})
    service_probe = config.get("service_probe") if isinstance(config.get("service_probe"), dict) else {}
    backend = str(service_probe.get("backend") or "pulse")
    return {
        "profiles": sorted(profiles.keys()) if isinstance(profiles, dict) else [],
        # Legacy nmap NSE profiles (used only when backend is nmap|hybrid).
        "nse_profiles": sorted(nse.keys()) if isinstance(nse, dict) else [],
        "service_backend": backend,
        "stages": {
            # fingerprint/tls_posture/nuclei/pdf_summary are editable via the
            # Web UI's config overrides (Postgres-backed, see config_override.py)
            # -- prefer the effective (overridden) value over the base file so
            # this panel doesn't lag behind what an admin actually saved.
            "fingerprint": bool(effective.get("fingerprint.enabled", _stage_enabled(config, "fingerprint"))),
            "tls_posture": bool(effective.get("tls_posture.enabled", _stage_enabled(config, "tls_posture"))),
            "nuclei": bool(effective.get("nuclei.enabled", _stage_enabled(config, "nuclei"))),
            "pdf_summary": bool(
                effective.get("reporting.pdf_summary", _stage_enabled(config, "reporting", "pdf_summary"))
            ),
            # Not overridable (no whitelist entry in config_override.py) -- base file only.
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
        "endpoint_inventory_enabled": settings.endpoint_inventory_enabled,
        "endpoint_stale_hours": settings.endpoint_stale_hours,
        "job_lease_seconds": settings.job_lease_seconds,
        "job_max_attempts": settings.job_max_attempts,
        "job_reaper_enabled": settings.job_reaper_enabled,
        "login_rate_limit_enabled": settings.login_rate_limit_enabled,
        "login_rate_limit_max_failures": settings.login_rate_limit_max_failures,
        "login_rate_limit_window_seconds": settings.login_rate_limit_window_seconds,
        # Whether *any* proxy is trusted, never which — the addresses are
        # infrastructure detail, and the operator question this answers is
        # "is X-Forwarded-For being honoured at all" (#157).
        "trusted_proxies_configured": bool(settings.trusted_proxies),
    }


def endpoint_inventory_status(settings: Settings) -> dict[str, Any]:
    """Endpoint-inventory footprint, staleness, and retention posture (S9).

    Fail-soft like every other panel here: an unconfigured Postgres or a
    disabled feature degrades to ``None`` counts rather than raising. Also
    refreshes the ``octo_endpoint_devices`` gauge, which otherwise only moves
    on a retention sweep.
    """
    counts: dict[str, int | None] = {"devices_total": None, "devices_stale": None}
    if settings.endpoint_inventory_enabled:
        try:
            from api.services import endpoint_inventory as endpoint_inventory_service
            from api.services import metrics as metrics_service

            tallied = endpoint_inventory_service.device_counts()
            counts = {"devices_total": tallied["total"], "devices_stale": tallied["stale"]}
            metrics_service.ENDPOINT_DEVICES.labels("active").set(tallied["active"])
            metrics_service.ENDPOINT_DEVICES.labels("stale").set(tallied["stale"])
        except Exception:  # noqa: BLE001 - fail-soft status view
            LOG.warning("system_status: could not count endpoint devices", exc_info=True)

    from api.services import endpoint_retention

    return {
        "enabled": settings.endpoint_inventory_enabled,
        **counts,
        "stale_hours": settings.endpoint_stale_hours,
        "retention_enabled": settings.endpoint_retention_enabled,
        "snapshot_retention_days": settings.endpoint_snapshot_retention_days,
        "change_retention_days": settings.endpoint_change_retention_days,
        "retention_interval_seconds": settings.endpoint_retention_interval_seconds,
        "retention_last_run_at": (endpoint_retention.worker_stats() or {}).get("last_run_at"),
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

        # Status counts are installation-wide, so ask for everything rather
        # than the paginated default (ROADMAP P3.2).
        agent_rows, agents_total = agents_service.list_agents(limit=pagination.MAX_LIMIT)
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
        "scan_config": scan_config_summary(config, _effective_overrides(settings)),
        "runtime": runtime_info(settings),
        "inventory": inventory_counts(),
        "endpoint_inventory": endpoint_inventory_status(settings),
    }
