from __future__ import annotations

import ipaddress
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


def _family(value: str) -> int | None:
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        try:
            return ipaddress.ip_network(value, strict=False).version
        except ValueError:
            return None


def _fping_command(
    input_file: Path,
    icmp: IcmpDiscoveryConfig,
    *,
    family: int,
) -> list[str]:
    command = [
        "fping",
        "-6" if family == 6 else "-4",
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
        # ``-i``, not ``-p``. See IcmpDiscoveryConfig for why this is the
        # process-wide packet gap rather than a loop-mode-only no-op.
        command.extend(["-i", str(icmp.period_ms)])
    return command


def icmp_ping_filter(
    targets: list[str],
    output_dir: Path,
    icmp: IcmpDiscoveryConfig,
    *,
    timeout: int,
    retries: int,
    tag: str,
) -> tuple[list[str], list[str]]:
    """ICMP pre-filter for IPv4 and IPv6, returning ``(alive, pending)``.

    fping chooses one address family per invocation. Mixing both in one input
    silently left the IPv6 half unprobed on common builds, so each family gets
    its own file and explicit ``-4``/``-6`` command (#364).
    """
    if not targets or not icmp.enabled:
        return [], list(targets)
    if icmp.tool != "fping":
        raise ValueError(f"unsupported ICMP tool: {icmp.tool}")

    batch_dir = output_dir / "discover"
    batch_dir.mkdir(parents=True, exist_ok=True)
    input_file = batch_dir / f"{tag}.icmp.targets.txt"
    alive_file = batch_dir / f"{tag}.icmp.alive.txt"
    pending_file = batch_dir / f"{tag}.icmp.pending.txt"
    write_lines(input_file, targets)

    by_family = {
        family: sorted({target for target in targets if _family(target) == family})
        for family in (4, 6)
    }
    alive_accum: set[str] = set()
    for family, family_targets in by_family.items():
        if not family_targets:
            continue
        family_file = batch_dir / f"{tag}.icmp{family}.targets.txt"
        write_lines(family_file, family_targets)
        result = run_command(
            _fping_command(family_file, icmp, family=family),
            timeout=timeout,
            retries=retries,
            check=False,
        )
        alive_accum.update(parse_fping_output(result.stdout or ""))

    alive = filter_hosts_in_scope(sorted(alive_accum), targets)
    alive_set = set(alive)
    pending = sorted({host for host in targets if host not in alive_set})
    write_lines(alive_file, alive)
    write_lines(pending_file, pending)
    logging.info(
        "ICMP batch %s: %s alive, %s pending for naabu (of %s; v4=%s v6=%s)",
        tag,
        len(alive),
        len(pending),
        len(targets),
        len(by_family[4]),
        len(by_family[6]),
    )
    return alive, pending
