from __future__ import annotations

import logging
from pathlib import Path

from .config_schema import DiscoveryConfig
from .discovery_targets import filter_hosts_in_scope
from .icmp_discover import icmp_ping_filter
from .utils import run_command, save_json, write_lines

PROBE_METHODS = ("icmp", "tcp", "naabu")

#: The TCP ports ``naabu -sn`` pings when it is given no probe flags of its
#: own. Not a guess: ``configureHostDiscovery`` in naabu v2.6.1 — the version
#: ``Dockerfile`` pins — sets ICMP echo, ICMP timestamp, and SYN *and* ACK
#: pings to 80 and 443 whenever ``!options.hasProbes()``. Naming them here is
#: what lets this stage honour the avoid-list: ``-exclude-ports`` belongs to
#: the port scan and does not reach host discovery.
NAABU_SN_PROBE_PORTS: tuple[int, ...] = (80, 443)


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
    exclude_ports: list[int] | None = None,
) -> tuple[list[str], list[str]]:
    """TCP SYN probe on common ports; return (alive, pending).

    ``exclude_ports`` is ``ports.exclude_ports`` — the ports this run must not
    touch (#362), a tenant's OT avoid-list or a local exclusion. This probe
    decides whether a host is alive, not what is open, but it is still a SYN
    aimed at a port of a device: the avoid-list means *no* stage may send one,
    and ``default.yaml`` says so in as many words ("ports no scan started from
    this config may touch"). The excluded ports are dropped from the selection
    here rather than only handed to naabu, so a probe whose whole port list is
    excluded sends nothing at all instead of a bare ``-p`` with everything
    filtered out; ``-exclude-ports`` goes along for the same reason the port
    stage passes it, so the guarantee does not rest on this arithmetic alone.
    """
    if not targets:
        return [], list(targets)
    excluded = sorted({int(p) for p in (exclude_ports or [])})
    ports = [port for port in ports if port not in set(excluded)]
    if not ports:
        if excluded:
            logging.info(
                "TCP probe batch %s: skipped — every configured port is excluded (#362)", tag
            )
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
            *(["-exclude-ports", ",".join(str(port) for port in excluded)] if excluded else []),
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
    exclude_ports: list[int] | None = None,
) -> list[str]:
    """naabu -sn host discovery for pending targets.

    ``exclude_ports`` is the run's avoid-list, and this step needs it for the
    same reason :func:`tcp_port_probe` does: left to itself ``-sn`` SYNs and
    ACKs 80 and 443 (:data:`NAABU_SN_PROBE_PORTS`), so a tenant who put an
    HMI's web port on the list was still receiving a SYN to it from the stage
    that decides who is alive. The probes are spelled out rather than left to
    naabu's defaults — naming any probe suppresses the defaults — and the
    avoided ports are dropped from the pair. With both gone the step still
    runs, on ICMP alone: losing the TCP half of host discovery is a few
    missed hosts, and sending the SYN is the thing the list forbids.
    """
    if not targets:
        return []

    excluded = {int(p) for p in (exclude_ports or [])}
    probe_ports = [port for port in NAABU_SN_PROBE_PORTS if port not in excluded]
    if len(probe_ports) != len(NAABU_SN_PROBE_PORTS):
        logging.info(
            "naabu -sn batch %s: host-discovery TCP pings narrowed to %s by the avoid-list (#362)",
            tag,
            probe_ports or "none (ICMP only)",
        )

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
            "-pe",
            "-pp",
            *(
                ["-ps", ",".join(str(port) for port in probe_ports)]
                + ["-pa", ",".join(str(port) for port in probe_ports)]
                if probe_ports
                else []
            ),
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
    exclude_ports: list[int] | None = None,
) -> tuple[list[str], dict[str, int]]:
    """Run configured probe steps in order; return merged alive hosts and per-method counts.

    ``exclude_ports`` is the run's avoid-list, and it reaches both steps that
    put a port on the wire: the TCP probe, which picks its port list from the
    config (see :func:`tcp_port_probe`), and ``naabu -sn``, which picks one
    from its own defaults (see :func:`naabu_host_discovery`).
    """
    pending = list(targets)
    alive_accum: set[str] = set()
    stats = {method: 0 for method in PROBE_METHODS}
    # ``rate`` is the batch rate the caller worked out, and it already carries
    # the policy's per-host correction for a batch of one device
    # (``scan_policy.single_host_rate``). ``tcp_probe.rate`` is a second
    # ceiling, not a replacement for the first: reading it as "a value that
    # wins when it is set" threw that correction away, and a policy promising
    # 25 pps at any single host sent that host 100 (#397 review).
    tcp_rate = (
        min(discovery.tcp_probe.rate, rate) if discovery.tcp_probe.rate is not None else rate
    )

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
                exclude_ports=exclude_ports,
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
                exclude_ports=exclude_ports,
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
    from .utils import load_json

    discover_dir = output_dir / "discover"
    merged = {method: 0 for method in PROBE_METHODS}
    merged["batches"] = 0
    if discover_dir.exists():
        for path in sorted(discover_dir.glob("*.probe_stats.json")):
            data = load_json(path, fallback={})
            merged["batches"] += 1
            for method in PROBE_METHODS:
                merged[method] += int(data.get(method, 0))
    save_json(output_dir / "discovery_stats.json", merged)
    return merged
