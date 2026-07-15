from __future__ import annotations

import logging
import re
from pathlib import Path

from .config_schema import IcmpDiscoveryConfig
from .discovery_targets import filter_hosts_in_scope
from .utils import run_command, write_lines

_ALIVE_LINE = re.compile(r"^(?P<host>\S+)\s+is\s+alive\b", re.IGNORECASE)


def parse_fping_output(stdout: str) -> list[str]:
    """Parse fping stdout (`-a` IP lines or `IP is alive` format)."""
    alive: list[str] = []
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        match = _ALIVE_LINE.match(text)
        if match:
            alive.append(match.group("host"))
            continue
        if " " not in text and "unreachable" not in text.lower():
            alive.append(text)
    return sorted(set(alive))


def icmp_ping_filter(
    targets: list[str],
    output_dir: Path,
    icmp: IcmpDiscoveryConfig,
    *,
    timeout: int,
    retries: int,
    tag: str,
) -> tuple[list[str], list[str]]:
    """ICMP pre-filter: return (alive, pending_for_naabu)."""
    if not targets or not icmp.enabled:
        return [], list(targets)

    batch_dir = output_dir / "discover"
    batch_dir.mkdir(parents=True, exist_ok=True)
    input_file = batch_dir / f"{tag}.icmp.targets.txt"
    alive_file = batch_dir / f"{tag}.icmp.alive.txt"
    pending_file = batch_dir / f"{tag}.icmp.pending.txt"
    write_lines(input_file, targets)

    if icmp.tool != "fping":
        raise ValueError(f"unsupported ICMP tool: {icmp.tool}")

    cmd = [
        "fping",
        "-f",
        str(input_file),
        "-a",
        "-q",
        "-t",
        str(icmp.timeout_ms),
        "-r",
        str(icmp.retries),
    ]
    if icmp.period_ms is not None:
        cmd.extend(["-p", str(icmp.period_ms)])

    result = run_command(cmd, timeout=timeout, retries=retries, check=False)
    alive = parse_fping_output(result.stdout or "")
    alive = filter_hosts_in_scope(alive, targets)
    alive_set = set(alive)
    pending = sorted({host for host in targets if host not in alive_set})
    write_lines(alive_file, alive)
    write_lines(pending_file, pending)
    logging.info(
        "ICMP batch %s: %s alive, %s pending for naabu (of %s)",
        tag,
        len(alive),
        len(pending),
        len(targets),
    )
    return alive, pending
