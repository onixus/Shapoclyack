"""Scan intents — product-level "what work to do" for a job/schedule.

Speed profile (``mode``: safe/balanced/fast) stays orthogonal: how hard to
hit the network. Intent chooses *which pipeline stages and nuclei floor* run
so operators can schedule inventory often and full assessments rarely without
hand-editing YAML (see ``docs/scan-performance.md``, ADR 0009 / ADR 0014).

| Intent     | Effect                                                              |
|------------|---------------------------------------------------------------------|
| inventory  | Ports-only L1 (``--skip-nse``), nuclei off, top_ports 100;          |
|            | historical∪top-N ports; JARM/tls-enum OFF; short connect timeouts   |
| vuln       | Full probe + nuclei critical/high only; JARM/tls-enum ON            |
| full       | Assessment-grade pipeline; JARM/tls-enum ON                         |
| delta      | Same as full + ``--delta`` discovery refresh; JARM/tls-enum ON      |
| org_profile| Full + the organization-profile stages; JARM/tls-enum ON            |

When ``intent`` is omitted, legacy ``skip_nse`` / ``delta`` flags apply as
before. When ``intent`` is set, it owns those flags (and nuclei/top_ports /
heuristic / JARM / tls-enum / timeout config); explicit ``skip_nse``/``delta``
on the request are ignored so the product control is unambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ScanIntent = Literal["inventory", "vuln", "full", "delta", "org_profile"]

INTENTS: tuple[ScanIntent, ...] = ("inventory", "vuln", "full", "delta", "org_profile")

#: Inventory-class speed path (S5 heuristics apply).
SPEED_INTENTS: frozenset[ScanIntent] = frozenset({"inventory"})

#: Assessment paths that keep (or restore) JARM + cipher enumeration.
HEAVY_INTENTS: frozenset[ScanIntent] = frozenset(
    {"vuln", "full", "delta", "org_profile"}
)

# Scanner CLI --mode only accepts these (not "test").
_CLI_MODES = frozenset({"safe", "balanced", "fast"})

#: Connect / silence wait on speed paths (Pulse ``-t``). RST closes return
#: immediately; this only bounds filtered/silent targets (FTT-057).
SPEED_CONNECT_TIMEOUT_MS = 300
#: Shorter settle before contradicting naabu opens on speed paths.
SPEED_RETRY_SETTLE_SECONDS = 3


def _cli_mode(mode: str) -> str:
    if mode in _CLI_MODES:
        return mode
    # API historically allowed "test"; map to balanced + leave intent overlays
    # to cut coverage (inventory-like knobs if intent also set).
    return "balanced"


def _speed_heuristic_overlay() -> dict[str, Any]:
    """S5 / ADR 0014: historical∪top-N, no JARM/tls-enum, short silence waits."""
    return {
        "ports": {"heuristic_union": True},
        "tls_posture": {"enumerate_ciphers": False, "jarm": False},
        "service_probe": {
            "pulse": {
                "jarm": False,
                "timeout_ms": SPEED_CONNECT_TIMEOUT_MS,
                "retry_settle_seconds": SPEED_RETRY_SETTLE_SECONDS,
            }
        },
    }


def _heavy_tls_overlay() -> dict[str, Any]:
    """S5: assessment paths keep JARM + cipher grades (explicit ON)."""
    return {
        "tls_posture": {
            "enabled": True,
            "enumerate_ciphers": True,
            "jarm": True,
        },
        "service_probe": {"pulse": {"jarm": True}},
    }


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
        # S5: historical∪top-N, JARM/tls-enum off, short connect timeouts.
        return ResolvedIntent(
            intent="inventory",
            mode=cli_mode,
            delta=bool(delta),  # still allow incremental inventory
            skip_nse=True,
            config_extra={
                "nuclei": {"enabled": False},
                "profiles": {profile_key: {"top_ports": 100}},
                "runtime": {"skip_nse": True},
                **_speed_heuristic_overlay(),
            },
            summary=(
                "inventory: ports-only, nuclei/JARM/tls-enum off, "
                "top 100 ∪ historical, short connect timeouts"
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
                **_heavy_tls_overlay(),
            },
            summary="vuln: full probe, nuclei critical+high only, JARM/tls-enum on",
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
                **_heavy_tls_overlay(),
            },
            summary="delta: full pipeline with incremental discovery, JARM/tls-enum on",
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
                **_heavy_tls_overlay(),
            },
            summary=(
                "org_profile: full assessment with complete org_profile "
                "& security controls evaluation, JARM/tls-enum on"
            ),
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
            **_heavy_tls_overlay(),
        },
        summary="full: assessment-grade pipeline, JARM/tls-enum on",
    )


def merge_config_extras(*parts: dict[str, Any] | None) -> dict[str, Any] | None:
    """Deep-merge nested override dicts left-to-right. Empty → None."""
    from api.services.config_override import _deep_merge

    out: dict[str, Any] = {}
    for part in parts:
        if part:
            out = _deep_merge(out, part)
    return out or None
