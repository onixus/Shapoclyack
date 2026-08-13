"""Scan intents — product-level "what work to do" for a job/schedule.

Speed profile (``mode``: safe/balanced/fast) stays orthogonal: how hard to
hit the network. Intent chooses *which pipeline stages and nuclei floor* run
so operators can schedule inventory often and full assessments rarely without
hand-editing YAML (see ``docs/scan-performance.md``).

| Intent     | Effect                                                              |
|------------|---------------------------------------------------------------------|
| inventory  | Ports-only L1 (``--skip-nse``), nuclei off, top_ports 100           |
| vuln       | Full probe + nuclei critical/high only (no medium)                  |
| full       | Default pipeline (nuclei critical/high/medium)                      |
| delta      | Same as full + ``--delta`` discovery refresh                        |

When ``intent`` is omitted, legacy ``skip_nse`` / ``delta`` flags apply as
before. When ``intent`` is set, it owns those flags (and nuclei/top_ports
config); explicit ``skip_nse``/``delta`` on the request are ignored so the
product control is unambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ScanIntent = Literal["inventory", "vuln", "full", "delta"]

INTENTS: tuple[ScanIntent, ...] = ("inventory", "vuln", "full", "delta")

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
        return ResolvedIntent(
            intent="inventory",
            mode=cli_mode,
            delta=bool(delta),  # still allow incremental inventory
            skip_nse=True,
            config_extra={
                "nuclei": {"enabled": False},
                "profiles": {profile_key: {"top_ports": 100}},
                "runtime": {"skip_nse": True},
            },
            summary="inventory: ports-only, nuclei off, top 100 ports",
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
            },
            summary="vuln: full probe, nuclei critical+high only",
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
            },
            summary="delta: full pipeline with incremental discovery",
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
        },
        summary="full: assessment-grade pipeline",
    )


def merge_config_extras(*parts: dict[str, Any] | None) -> dict[str, Any] | None:
    """Deep-merge nested override dicts left-to-right. Empty → None."""
    from api.services.config_override import _deep_merge

    out: dict[str, Any] = {}
    for part in parts:
        if part:
            out = _deep_merge(out, part)
    return out or None
