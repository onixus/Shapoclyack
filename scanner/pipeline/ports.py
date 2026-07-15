from __future__ import annotations

from pathlib import Path

from .protocol import ScanProtocol, format_endpoint, naabu_udp_port_spec, parse_endpoint, top_udp_port_list
from .utils import read_lines, run_command, write_lines


def _flatten_custom_ports(custom_file: Path) -> list[str] | None:
    if not custom_file.exists():
        return None
    lines = read_lines(custom_file)
    if not lines:
        return None
    expanded: list[str] = []
    for line in lines:
        for part in line.split(","):
            part = part.strip()
            if part.startswith("u:"):
                expanded.append(part[2:])
            elif part:
                expanded.append(part)
    return expanded or None


def _naabu_entries(stdout: str, protocol: ScanProtocol) -> list[str]:
    entries: list[str] = []
    for line in (stdout or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        parsed = parse_endpoint(raw if "/" in raw else f"{raw}/{protocol}")
        if parsed is None:
            continue
        entries.append(format_endpoint(parsed.host, parsed.port, protocol))
    return sorted(set(entries))


def _run_naabu(
    *,
    alive_hosts: list[str],
    batch_dir: Path,
    tag: str,
    rate: int,
    timeout: int,
    retries: int,
    port_args: list[str],
    protocol: ScanProtocol,
    udp_probes: bool,
) -> list[str]:
    input_file = batch_dir / f"{tag}.hosts.txt"
    output_file = batch_dir / f"{tag}.open.txt"
    write_lines(input_file, alive_hosts)
    if not alive_hosts:
        write_lines(output_file, [])
        return []

    command = [
        "naabu",
        "-list",
        str(input_file),
        "-silent",
        "-rate",
        str(rate),
        "-retries",
        "1",
        *port_args,
    ]
    if protocol == "udp" and udp_probes:
        command.append("-uP")

    result = run_command(command, timeout=timeout, retries=retries)
    entries = _naabu_entries(result.stdout or "", protocol)
    write_lines(output_file, entries)
    return entries


def fast_port_scan(
    alive_hosts: list[str],
    output_dir: Path,
    rate: int,
    top_ports: int,
    top_udp_ports: int,
    timeout: int,
    retries: int,
    protocol_mode: str,
    custom_ports_file: Path,
    custom_udp_ports_file: Path,
    udp_probes: bool,
    tag: str = "all",
) -> list[str]:
    """Run naabu port scan(s) for a batch of alive hosts.

    ``protocol_mode`` is one of ``tcp``, ``udp``, or ``tcp_udp``. Results use
    ``host:port/tcp`` or ``host:port/udp`` (plain ``host:port`` from naabu is
    normalized with the active protocol suffix).
    """
    batch_dir = output_dir / "ports"
    results: list[str] = []

    if protocol_mode in ("tcp", "tcp_udp"):
        suffix = tag if protocol_mode == "tcp" else f"{tag}-tcp"
        custom = _flatten_custom_ports(custom_ports_file)
        if custom:
            port_args = ["-p", ",".join(custom)]
        else:
            port_args = ["-top-ports", str(top_ports)]
        results.extend(
            _run_naabu(
                alive_hosts=alive_hosts,
                batch_dir=batch_dir,
                tag=suffix,
                rate=rate,
                timeout=timeout,
                retries=retries,
                port_args=port_args,
                protocol="tcp",
                udp_probes=False,
            )
        )

    if protocol_mode in ("udp", "tcp_udp"):
        suffix = tag if protocol_mode == "udp" else f"{tag}-udp"
        custom_udp = _flatten_custom_ports(custom_udp_ports_file)
        if custom_udp:
            port_spec = naabu_udp_port_spec(custom_udp)
        else:
            port_spec = naabu_udp_port_spec([str(p) for p in top_udp_port_list(top_udp_ports)])
        results.extend(
            _run_naabu(
                alive_hosts=alive_hosts,
                batch_dir=batch_dir,
                tag=suffix,
                rate=rate,
                timeout=timeout,
                retries=retries,
                port_args=["-p", port_spec],
                protocol="udp",
                udp_probes=udp_probes,
            )
        )

    return sorted(set(results))
