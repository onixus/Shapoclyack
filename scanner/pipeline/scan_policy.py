"""Apply the tenant scan policy the API pushed onto this run (#362).

The pace a scan runs at used to be decided entirely by the config file on the
host executing it — ``scanner/config/default.yaml``, or whatever an agent's
operator had edited it to. The platform sent ``--mode`` and hoped. This module
is the other half: the API writes the tenant's policy next to the run's target
files (``scan_policy.json``) and the pipeline is handed it as
``--scan-policy``, exactly like the approved scope of #244.

**Every knob here can only ever go down.** The policy is a set of ceilings, not
a set of values: a rate is applied as ``min(config, policy)``, the avoid-list
is unioned with whatever the config already excludes, and ``skip_service_probe``
can turn the service-probe stage off but never on. That is what makes the local
file the fallback it is documented to be — an installation that has hardened
its own config keeps the hardening, and the policy only ever tightens it.

An unknown ``policy_version`` is a hard error rather than a best-effort
application: a ceiling half-understood is a ceiling that reads as enforced and
is not, and the scan that would have run under it is on somebody's plant
network.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .config_schema import AppConfig

#: The shape this build understands. Mirrors
#: ``api.services.scan_policy.POLICY_VERSION``; the two move together and a
#: mismatch stops the run (see :func:`load_policy`).
SUPPORTED_POLICY_VERSION = 1


class ScanPolicyError(ValueError):
    """The policy file is missing, malformed, or of a version this build cannot apply."""


def load_policy(path: Path) -> dict[str, Any]:
    """Read and sanity-check one policy document written by the API."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScanPolicyError(f"could not read scan policy {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScanPolicyError(f"scan policy {path} is not an object")
    version = raw.get("policy_version")
    if version != SUPPORTED_POLICY_VERSION:
        raise ScanPolicyError(
            f"scan policy {path} is version {version!r}, and this scanner applies "
            f"version {SUPPORTED_POLICY_VERSION}: upgrade the scanner rather than "
            "running the scan without the policy"
        )
    return raw


def _ceiling(current: int | None, limit: int | None, *, zero_is_unlimited: bool = False) -> int | None:
    """``min`` over two ceilings, where None — and sometimes 0 — mean "no limit".

    ``zero_is_unlimited`` is for the config fields that spell "unlimited" as 0
    (``runtime.nse_max_rate``, ``pulse.rate``). Without it a policy of 50 pps
    would compute ``min(0, 50) == 0`` and read as *unlimited*, which is the one
    mistake in this file that would be silent and catastrophic.
    """
    if limit is None:
        return current
    if current is None:
        return limit
    if zero_is_unlimited and current == 0:
        return limit
    return min(current, limit)


def apply_policy(config: AppConfig, policy: dict[str, Any]) -> AppConfig:
    """Return ``config`` tightened by ``policy``. Never loosens anything."""
    max_discover = policy.get("max_discover_rate")
    max_port = policy.get("max_port_rate")
    max_concurrency = policy.get("max_host_concurrency")
    per_host_rate = policy.get("per_host_rate")
    avoid_ports = sorted({int(p) for p in (policy.get("avoid_ports") or [])})

    profiles = {}
    for name, profile in config.profiles.items():
        updates: dict[str, Any] = {}
        if max_discover is not None:
            updates["discover_rate"] = _ceiling(profile.discover_rate, max_discover)
        if max_port is not None:
            updates["port_rate"] = _ceiling(profile.port_rate, max_port)
        if max_concurrency is not None:
            updates["nse_concurrency"] = _ceiling(profile.nse_concurrency, max_concurrency)
        if per_host_rate is not None:
            # The NSE budget is shared by every parallel nmap, so holding the
            # whole stage to the per-host ceiling is stricter than the policy
            # asks for and never looser — which is the direction this file is
            # allowed to be wrong in.
            updates["nse_max_rate"] = _ceiling(
                profile.nse_max_rate, per_host_rate, zero_is_unlimited=True
            )
        pulse_updates: dict[str, Any] = {}
        if per_host_rate is not None:
            pulse_updates["rate"] = _ceiling(
                profile.pulse.rate, per_host_rate, zero_is_unlimited=True
            )
        if max_concurrency is not None:
            pulse_updates["host_parallel"] = _ceiling(profile.pulse.host_parallel, max_concurrency)
            pulse_updates["concurrency"] = _ceiling(profile.pulse.concurrency, max_concurrency)
        if pulse_updates:
            updates["pulse"] = profile.pulse.model_copy(update=pulse_updates)
        profiles[name] = profile.model_copy(update=updates) if updates else profile

    runtime_updates: dict[str, Any] = {}
    if max_concurrency is not None:
        runtime_updates["discover_concurrency"] = _ceiling(
            config.runtime.discover_concurrency, max_concurrency
        )
        runtime_updates["ports_concurrency"] = _ceiling(
            config.runtime.ports_concurrency, max_concurrency
        )
        runtime_updates["nse_concurrency"] = _ceiling(
            config.runtime.nse_concurrency, max_concurrency
        )
    if per_host_rate is not None:
        runtime_updates["nse_max_rate"] = _ceiling(
            config.runtime.nse_max_rate, per_host_rate, zero_is_unlimited=True
        )
    if policy.get("skip_service_probe"):
        # One direction only: a policy can turn the stage that sends
        # protocol-specific payloads off, and nothing here turns it back on.
        runtime_updates["skip_nse"] = True

    updates: dict[str, Any] = {"profiles": profiles}
    if runtime_updates:
        updates["runtime"] = config.runtime.model_copy(update=runtime_updates)
    if avoid_ports:
        updates["ports"] = config.ports.model_copy(
            update={"exclude_ports": sorted(set(config.ports.exclude_ports) | set(avoid_ports))}
        )

    tightened = config.model_copy(update=updates)
    logging.info(
        "Scan policy applied (profile=%s, version=%s): discover<=%s pps, ports<=%s pps, "
        "concurrency<=%s, per-host<=%s pps, %d avoided port(s), service probe %s",
        policy.get("profile", "standard"),
        policy.get("policy_version"),
        max_discover if max_discover is not None else "config",
        max_port if max_port is not None else "config",
        max_concurrency if max_concurrency is not None else "config",
        per_host_rate if per_host_rate is not None else "config",
        len(avoid_ports),
        "off" if tightened.runtime.skip_nse else "on",
    )
    return tightened
