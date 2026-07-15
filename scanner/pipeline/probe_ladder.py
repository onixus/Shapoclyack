from __future__ import annotations

import logging
from pathlib import Path

from .config_schema import DiscoveryConfig
from .discovery_targets import filter_hosts_in_scope
from .icmp_discover import icmp_ping_filter
from .utils import run_command, save_json, write_lines

PROBE_METHODS = ("icmp", "tcp", "naabu")


def parse_naabu_host_lines(stdout: str) -> list[str]:
    """Extract unique hosts from naabu stdout (host-only or host:port lines)."""
    hosts: set[str] = set()
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        hosts.add(text.split(":", 1)[0])
    return sorted(hosts)


def tcp_port_probe(
    targets: list[str],
    output_dir: Path,
    *,
    ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> tuple[list[str], list[str]]:
    """TCP SYN probe on common ports; return (alive, pending)."""
    if not targets or not ports:
        return [], list(targets)

    batch_dir = output_dir / "discover"
    batch_dir.mkdir(parents=True, exist_ok=True)
    input_file = batch_dir / f"{tag}.tcp.targets.txt"
    alive_file = batch_dir / f"{tag}.tcp.alive.txt"
    pending_file = batch_dir / f"{tag}.tcp.pending.txt"
    write_lines(input_file, targets)

    port_arg = ",".join(str(port) for port in sorted(set(ports)))
    result = run_command(
        [
            "naabu",
            "-list",
            str(input_file),
            "-p",
            port_arg,
            "-silent",
            "-rate",
            str(rate),
            "-retries",
            str(max(1, retries)),
        ],
        timeout=timeout,
        retries=retries,
    )
    alive = parse_naabu_host_lines(result.stdout or "")
    alive = filter_hosts_in_scope(alive, scope_members)
    alive_set = set(alive)
    pending = sorted({host for host in targets if host not in alive_set})
    write_lines(alive_file, alive)
    write_lines(pending_file, pending)
    logging.info(
        "TCP probe batch %s: %s alive on ports %s, %s pending (of %s)",
        tag,
        len(alive),
        port_arg,
        len(pending),
        len(targets),
    )
    return alive, pending


def naabu_host_discovery(
    targets: list[str],
    output_dir: Path,
    *,
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> list[str]:
    """naabu -sn host discovery for pending targets."""
    if not targets:
        return []

    batch_dir = output_dir / "discover"
    input_file = batch_dir / f"{tag}.naabu.targets.txt"
    alive_file = batch_dir / f"{tag}.naabu.alive.txt"
    write_lines(input_file, targets)

    result = run_command(
        [
            "naabu",
            "-list",
            str(input_file),
            "-sn",
            "-silent",
            "-rate",
            str(rate),
            "-retries",
            str(max(1, retries)),
        ],
        timeout=timeout,
        retries=retries,
    )
    alive = parse_naabu_host_lines(result.stdout or "")
    alive = filter_hosts_in_scope(alive, scope_members)
    write_lines(alive_file, alive)
    logging.info("naabu -sn batch %s: %s alive (of %s)", tag, len(alive), len(targets))
    return alive


def run_probe_ladder(
    targets: list[str],
    output_dir: Path,
    discovery: DiscoveryConfig,
    *,
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> tuple[list[str], dict[str, int]]:
    """Run configured probe steps in order; return merged alive hosts and per-method counts."""
    pending = list(targets)
    alive_accum: set[str] = set()
    stats = {method: 0 for method in PROBE_METHODS}
    tcp_rate = discovery.tcp_probe.rate if discovery.tcp_probe.rate is not None else rate

    for step in discovery.probe_order:
        if not pending:
            break
        if step == "icmp":
            if not discovery.icmp.enabled:
                continue
            icmp_alive, pending = icmp_ping_filter(
                pending,
                output_dir,
                discovery.icmp,
                timeout=timeout,
                retries=retries,
                tag=tag,
            )
            stats["icmp"] = len(icmp_alive)
            alive_accum.update(icmp_alive)
        elif step == "tcp":
            if not discovery.tcp_probe.enabled:
                continue
            tcp_alive, pending = tcp_port_probe(
                pending,
                output_dir,
                ports=discovery.tcp_probe.ports,
                rate=tcp_rate,
                timeout=timeout,
                retries=retries,
                tag=tag,
                scope_members=scope_members,
            )
            stats["tcp"] = len(tcp_alive)
            alive_accum.update(tcp_alive)
        elif step == "naabu":
            naabu_alive = naabu_host_discovery(
                pending,
                output_dir,
                rate=rate,
                timeout=timeout,
                retries=retries,
                tag=tag,
                scope_members=scope_members,
            )
            stats["naabu"] = len(naabu_alive)
            alive_accum.update(naabu_alive)
            pending = []
        else:
            raise ValueError(f"unsupported probe step: {step}")

    alive = filter_hosts_in_scope(sorted(alive_accum), scope_members)
    save_json(output_dir / "discover" / f"{tag}.probe_stats.json", stats)
    return alive, stats


def merge_discovery_stats(output_dir: Path) -> dict[str, int]:
    """Aggregate per-batch probe stats into ``discovery_stats.json``."""
    from .utils import load_json, save_json as write_stats

    discover_dir = output_dir / "discover"
    merged = {method: 0 for method in PROBE_METHODS}
    merged["batches"] = 0
    if discover_dir.exists():
        for path in sorted(discover_dir.glob("*.probe_stats.json")):
            data = load_json(path, fallback={})
            merged["batches"] += 1
            for method in PROBE_METHODS:
                merged[method] += int(data.get(method, 0))
    write_stats(output_dir / "discovery_stats.json", merged)
    return merged
