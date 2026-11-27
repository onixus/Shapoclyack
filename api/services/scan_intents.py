"""Scan intents — product-level "what work to do" for a job/schedule.

Speed profile (``mode``: safe/balanced/fast) stays orthogonal: how hard to
hit the network. Intent chooses *which pipeline stages and nuclei floor* run
so operators can schedule inventory often and full assessments rarely without
hand-editing YAML (see ``docs/scan-performance.md``, ADR 0009 / ADR 0013).

| Intent              | Effect                                                              |
|---------------------|---------------------------------------------------------------------|
| inventory           | Ports-only L1 (``--skip-nse``), nuclei off, top_ports 100;          |
|                     | plugins + cipher-enum forced OFF                                    |
| inventory_services  | Mid-tier: Pulse banners/services/OS/CVE, no plugins/tls-enum/nuclei;|
|                     | S3 chunk overlap                                                    |
| enrichment          | Stage2: Pulse plugins + tls-enum + nuclei on known hosts (S4)       |
| vuln                | Full probe + nuclei critical/high only (no medium); heavy Pulse     |
| full                | Assessment-grade pipeline; heavy Pulse                              |
| delta               | Same as full + ``--delta`` discovery refresh                        |
| org_profile         | Full + the organization-profile stages (see docs/configuration.md)  |

When ``intent`` is omitted, legacy ``skip_nse`` / ``delta`` flags apply as
before (shipped YAML keeps plugins/tls-enum on). When ``intent`` is set, it
owns those flags (and nuclei/top_ports/plugins/cipher-enum config); explicit
``skip_nse``/``delta`` on the request are ignored so the product control is
unambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ScanIntent = Literal[
    "inventory",
    "inventory_services",
    "enrichment",
    "vuln",
    "full",
    "delta",
    "org_profile",
]

INTENTS: tuple[ScanIntent, ...] = (
    "inventory",
    "inventory_services",
    "enrichment",
    "vuln",
    "full",
    "delta",
    "org_profile",
)

#: Intents that must not inherit assessment-grade plugins / cipher enum.
SPEED_INTENTS: frozenset[ScanIntent] = frozenset({"inventory", "inventory_services"})

#: Intents that keep (or restore) plugins + cipher enumeration.
HEAVY_INTENTS: frozenset[ScanIntent] = frozenset(
    {"enrichment", "vuln", "full", "delta", "org_profile"}
)

# Scanner CLI --mode only accepts these (not "test").
_CLI_MODES = frozenset({"safe", "balanced", "fast"})


@dataclass(frozen=True)
class ResolvedIntent:
    """Flags + per-job config overlay produced from an intent (or legacy flags)."""

    intent: ScanIntent | None
    mode: str
    delta: bool
    skip_nse: bool
    config_extra: dict[str, Any]
    # Human-readable summary for UI / scan_options audit.
    summary: str


def _cli_mode(mode: str) -> str:
    if mode in _CLI_MODES:
        return mode
    # API historically allowed "test"; map to balanced + leave intent overlays
    # to cut coverage (inventory-like knobs if intent also set).
    return "balanced"


def _speed_pulse_overlay() -> dict[str, Any]:
    """ADR 0013: speed paths never pay tls-enum / Rhai plugin wall-clock."""
    return {
        "tls_posture": {"enumerate_ciphers": False},
        "service_probe": {"pulse": {"plugins": False}},
    }


def _heavy_pulse_overlay() -> dict[str, Any]:
    """ADR 0013: assessment paths keep plugins + cipher grades."""
    return {
        "tls_posture": {"enabled": True, "enumerate_ciphers": True},
        "service_probe": {"pulse": {"plugins": True, "banner": True}},
    }


def resolve_scan_options(
    *,
    intent: str | None,
    mode: str,
    delta: bool,
    skip_nse: bool,
) -> ResolvedIntent:
    """Expand optional ``intent`` into CLI flags and a nested config override."""
    cli_mode = _cli_mode(mode)
    if not intent:
        return ResolvedIntent(
            intent=None,
            mode=cli_mode,
            delta=bool(delta),
            skip_nse=bool(skip_nse),
            config_extra={},
            summary="legacy flags (no intent)",
        )

    if intent not in INTENTS:
        raise ValueError(f"intent must be one of {list(INTENTS)}")

    profile_key = cli_mode

    if intent == "inventory":
        # L1: discover + ports + report. No Pulse/NSE/Nuclei wall-clock.
        # Still force plugins/tls-enum OFF so a resume without skip_nse cannot
        # inherit assessment defaults (FTT-056 / ADR 0013).
        return ResolvedIntent(
            intent="inventory",
            mode=cli_mode,
            delta=bool(delta),  # still allow incremental inventory
            skip_nse=True,
            config_extra={
                "nuclei": {"enabled": False},
                "profiles": {profile_key: {"top_ports": 100}},
                "runtime": {"skip_nse": True},
                **_speed_pulse_overlay(),
            },
            summary="inventory: ports-only, nuclei/plugins/tls-enum off, top 100 ports",
        )

    if intent == "inventory_services":
        # Mid-tier (FTT-PULSE-2026-052 S3): L4 + Pulse banners/services without
        # the TLS-enum / plugin / nuclei wall that bounds full assessment.
        return ResolvedIntent(
            intent="inventory_services",
            mode=cli_mode,
            delta=bool(delta),
            skip_nse=False,
            config_extra={
                "nuclei": {"enabled": False},
                "profiles": {profile_key: {"top_ports": 100}},
                "tls_posture": {"enabled": False, "enumerate_ciphers": False},
                "service_probe": {
                    "pulse": {
                        "banner": True,
                        "plugins": False,
                        "cve": True,
                        "cve_online": False,
                        # S3: overlap the mid-tier chunks. Serial (1) is the
                        # historical adapter; this intent exists to leave it.
                        "chunk_concurrency": 4,
                        "enrich_concurrency": 8,
                    }
                },
            },
            summary=(
                "inventory_services: Pulse banners/services, "
                "no plugins/tls-enum/nuclei"
            ),
        )

    if intent == "enrichment":
        # Stage2 assessment (FTT-PULSE-2026-054): TLS posture + Pulse plugins
        # + nuclei on hosts already observed by Stage1. Overlap knobs match
        # the mid-tier intent so a single Stage2 pod is not serial by default.
        return ResolvedIntent(
            intent="enrichment",
            mode=cli_mode,
            delta=False,
            skip_nse=False,
            config_extra={
                "nuclei": {
                    "enabled": True,
                    "severities": ["critical", "high", "medium"],
                },
                "tls_posture": {"enabled": True, "enumerate_ciphers": True},
                "service_probe": {
                    "pulse": {
                        "banner": True,
                        "plugins": True,
                        "cve": True,
                        "cve_online": False,
                        "chunk_concurrency": 2,
                        "enrich_concurrency": 8,
                    }
                },
            },
            summary=(
                "enrichment: Stage2 TLS/plugins/nuclei on known hosts"
            ),
        )

    if intent == "vuln":
        return ResolvedIntent(
            intent="vuln",
            mode=cli_mode,
            delta=bool(delta),
            skip_nse=False,
            config_extra={
                "nuclei": {
                    "enabled": True,
                    "severities": ["critical", "high"],
                },
                **_heavy_pulse_overlay(),
            },
            summary="vuln: full probe, nuclei critical+high only, heavy Pulse",
        )

    if intent == "delta":
        return ResolvedIntent(
            intent="delta",
            mode=cli_mode,
            delta=True,
            skip_nse=False,
            config_extra={
                "nuclei": {
                    "enabled": True,
                    "severities": ["critical", "high", "medium"],
                },
                **_heavy_pulse_overlay(),
            },
            summary="delta: full pipeline with incremental discovery, heavy Pulse",
        )

    if intent == "org_profile":
        return ResolvedIntent(
            intent="org_profile",
            mode=cli_mode,
            delta=bool(delta),
            skip_nse=False,
            config_extra={
                "nuclei": {
                    "enabled": True,
                    "severities": ["critical", "high", "medium"],
                },
                "org_profile": {
                    "ownership": {"enabled": True},
                    "related_domains": {"enabled": True},
                    "dns_hygiene": {"enabled": True},
                    "mail_posture": {"enabled": True},
                    "credential_leaks": {"enabled": True},
                    "controls": {"enabled": True},
                },
                "fingerprint": {"enabled": True},
                **_heavy_pulse_overlay(),
            },
            summary="org_profile: full assessment with complete org_profile & security controls evaluation",
        )

    # full
    return ResolvedIntent(
        intent="full",
        mode=cli_mode,
        delta=bool(delta),
        skip_nse=False,
        config_extra={
            "nuclei": {
                "enabled": True,
                "severities": ["critical", "high", "medium"],
            },
            **_heavy_pulse_overlay(),
        },
        summary="full: assessment-grade pipeline, heavy Pulse",
    )


def merge_config_extras(*parts: dict[str, Any] | None) -> dict[str, Any] | None:
    """Deep-merge nested override dicts left-to-right. Empty → None."""
    from api.services.config_override import _deep_merge

    out: dict[str, Any] = {}
    for part in parts:
        if part:
            out = _deep_merge(out, part)
    return out or None
