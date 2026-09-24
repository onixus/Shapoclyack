"""The per-job config overlay an agent is handed with its job (#338 review).

A local scan runs on a config file the API writes for it: the installation's
base config, the console's overrides (``api/services/config_override.py``) and
the scan intent's own settings (``api/services/scan_intents.py``), merged in
that order. A remote executor runs on the config mounted on its own host, so
until this existed it ran none of the latter two — an ``inventory`` job ran
nuclei, and a console port rate of 50 pps ran at the executor's 2000.

The API now sends the overrides and the intent as this document, and the
scanner merges it onto its own config before the schema is validated, i.e. at
the same point the local path does. The tenant scan policy is applied *after*
it (see ``scanner/main.py``), so an overlay can shape a scan but never lift it
above the tenant's ceilings (#362).

The overlay crosses a trust boundary: the executor sits in a network the
platform scans on somebody's behalf, and its own config holds things that are
that host's business — where alerts go and with which credentials, output
paths, tool arguments. So the scanner accepts only :data:`OVERLAY_PATHS`, the
scan-shaping settings the console and the intents can set, and refuses the
whole run on anything else rather than applying the part it recognises.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

#: The claim input name, and the file the worker writes it to.
INPUT_NAME = "config_overlay.json"

#: The document version this build applies. A later API that sends a shape this
#: build does not know is refused by the capability check on claim; this is the
#: second line for a document that arrives some other way.
OVERLAY_VERSION = 1

_PROFILES = ("safe", "balanced", "fast", "test")
_PROFILE_LEAVES = ("discover_rate", "port_rate", "top_ports", "nmap_timing")
_ORG_PROFILE_STAGES = (
    "ownership",
    "related_domains",
    "dns_hygiene",
    "mail_posture",
    "credential_leaks",
    "controls",
)

#: Every dot-path an overlay may set. The console's editable settings minus the
#: one secret among them (``enrichment.cvss4.nvd_api_key`` never leaves the
#: API), plus what the scan intents set. ``tests/test_agent_config_overlay.py``
#: holds the API's two lists to this one.
OVERLAY_PATHS: frozenset[str] = frozenset(
    {
        "fingerprint.enabled",
        "screenshots.enabled",
        "tls_posture.enabled",
        "tls_posture.hostname_mismatch",
        "nuclei.enabled",
        "nuclei.severities",
        "nuclei.exclude_tags",
        "nuclei.templates_dir",
        "nuclei.concurrency",
        "nuclei.rate_limit",
        "nuclei.timeout_seconds",
        "nuclei.retries",
        "reporting.pdf_summary",
        "service_probe.backend",
        "service_probe.shadow",
        "runtime.skip_nse",
        *(f"profiles.{p}.{leaf}" for p in _PROFILES for leaf in _PROFILE_LEAVES),
        *(f"org_profile.{stage}.enabled" for stage in _ORG_PROFILE_STAGES),
    }
)


class ConfigOverlayError(ValueError):
    """An overlay this build cannot apply as sent. The run does not start."""


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


def to_document(config: dict[str, Any]) -> dict[str, Any]:
    """The document the API writes. Checked here so a path the scanner would
    refuse is refused where the job is created, not on the executor later."""
    check_config(config)
    return {"overlay_version": OVERLAY_VERSION, "config": config}


def check_config(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigOverlayError("config overlay: 'config' must be an object")
    refused = sorted(path for path in _flatten(config) if path not in OVERLAY_PATHS)
    if refused:
        raise ConfigOverlayError(
            "config overlay sets settings an executor does not take from the "
            f"platform: {', '.join(refused)}"
        )
    return config


def load_overlay(path: Path) -> dict[str, Any]:
    """Read and check the document; return the nested config to merge."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigOverlayError(f"config overlay {path} is unreadable: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigOverlayError("config overlay must be a JSON object")
    version = document.get("overlay_version")
    if version != OVERLAY_VERSION:
        raise ConfigOverlayError(
            f"config overlay version {version!r} is not one this build applies "
            f"(expected {OVERLAY_VERSION}); upgrade the agent"
        )
    return check_config(document.get("config"))


def apply_overlay(raw: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """``raw`` with ``overlay`` deep-merged onto it; neither is modified."""
    out = copy.deepcopy(raw) if isinstance(raw, dict) else {}
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = apply_overlay(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out
