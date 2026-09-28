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

And one installation-wide console override now reaches every tenant's
sensors, so for the settings that decide how hard a sensor hits its network
the host's own file stays the limit (review round 2): rates, concurrency and
nmap timing take the lower of the two, nuclei's excluded tags are the union,
and screenshots run only where the host enabled them. An overlay can make a
sensor gentler, never rougher; a tenant scan policy (#362) lowers it further.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from scanner.pipeline.config_schema import AppConfig

#: The claim input name, and the file the worker writes it to.
INPUT_NAME = "config_overlay.json"

#: The document version this build applies — and the set of settings it
#: accepts: a release that adds or removes a path in :data:`OVERLAY_PATHS`
#: bumps this (tests/test_agent_config_overlay.py pins a digest per version),
#: so a sensor that knows an older set is refused the job on claim, by
#: :data:`CAPABILITY`, instead of refusing the run on the host.
OVERLAY_VERSION = 1

#: What a sensor built from this tree declares, and what the API requires of a
#: job's claimant. Versioned for the reason above.
CAPABILITY = f"config_overlay.v{OVERLAY_VERSION}"

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

#: Every dot-path an overlay may set. The console's editable settings minus
#: the ones that belong to the API's host — the NVD key, a secret, and
#: ``nuclei.templates_dir``, a directory on the API's filesystem that a sensor
#: does not have, where nuclei then skipped without a word — plus what the scan
#: intents set. ``tests/test_agent_config_overlay.py`` holds the API's lists to
#: this one.
OVERLAY_PATHS: frozenset[str] = frozenset(
    {
        "fingerprint.enabled",
        "screenshots.enabled",
        "tls_posture.enabled",
        "tls_posture.hostname_mismatch",
        "nuclei.enabled",
        "nuclei.severities",
        "nuclei.exclude_tags",
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


#: Settings where the host's value is a ceiling: the overlay may lower them.
_CEILINGS_PROFILE = ("discover_rate", "port_rate")
_CEILINGS_NUCLEI = ("rate_limit", "concurrency")


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
    # Older versions are subsets of this one's settings; a newer one may carry
    # a setting this build does not know.
    if not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= OVERLAY_VERSION:
        raise ConfigOverlayError(
            f"config overlay version {version!r} is not one this build applies "
            f"(1 to {OVERLAY_VERSION}); upgrade the agent"
        )
    return check_config(document.get("config"))


def _merge(raw: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(raw) if isinstance(raw, dict) else {}
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _timing_level(value: str) -> int:
    return int(str(value)[1:])


def apply_overlay(
    raw: dict[str, Any], overlay: dict[str, Any], host: AppConfig | None = None
) -> dict[str, Any]:
    """``raw`` with ``overlay`` deep-merged onto it; neither is modified.

    ``host`` is ``raw`` as the schema reads it — defaults filled in — and makes
    the host's file the limit for the settings above. ``None`` is a plain merge.
    """
    out = _merge(raw, overlay)
    if host is None:
        return out
    for profile, settings in (overlay.get("profiles") or {}).items():
        own = host.profiles.get(profile)
        target = out["profiles"][profile]
        if own is None:
            continue
        for leaf in _CEILINGS_PROFILE:
            if leaf in settings:
                target[leaf] = min(settings[leaf], getattr(own, leaf))
        if "nmap_timing" in settings:
            target["nmap_timing"] = min(
                settings["nmap_timing"], own.nmap_timing, key=_timing_level
            )
    nuclei = overlay.get("nuclei") or {}
    for leaf in _CEILINGS_NUCLEI:
        if leaf in nuclei:
            out["nuclei"][leaf] = min(nuclei[leaf], getattr(host.nuclei, leaf))
    if "exclude_tags" in nuclei:
        own_tags = list(host.nuclei.exclude_tags or [])
        out["nuclei"]["exclude_tags"] = own_tags + [
            tag for tag in nuclei["exclude_tags"] if tag not in own_tags
        ]
    if "enabled" in (overlay.get("screenshots") or {}):
        out["screenshots"]["enabled"] = bool(overlay["screenshots"]["enabled"]) and host.screenshots.enabled
    return out
