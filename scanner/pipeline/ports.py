from __future__ import annotations

import logging
import threading
from pathlib import Path

from .config_schema import NaabuScanType
from .protocol import ScanProtocol, format_endpoint, naabu_udp_port_spec, parse_endpoint, top_udp_port_list
from .utils import read_lines, run_command, write_lines

# Set once a SYN batch fails so the remaining batches go straight to CONNECT
# instead of each paying for the same failed attempt. Batches run concurrently
# (runtime.ports_concurrency), hence the lock.
_syn_lock = threading.Lock()
_syn_unavailable = False


def _syn_ruled_out() -> bool:
    with _syn_lock:
        return _syn_unavailable


def _rule_out_syn() -> None:
    global _syn_unavailable
    with _syn_lock:
        _syn_unavailable = True


def _scan_techniques(scan_type: NaabuScanType, protocol: ScanProtocol) -> list[str | None]:
    """naabu ``-s`` values to try, in order, for one batch.

    ``-s`` selects the TCP technique only, so UDP batches omit it entirely.
    """
    if protocol != "tcp":
        return [None]
    if scan_type == "syn":
        return ["s"]
    if scan_type == "connect":
        return ["c"]
    return ["c"] if _syn_ruled_out() else ["s", "c"]


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
    scan_type: NaabuScanType = "auto",
) -> list[str]:
    input_file = batch_dir / f"{tag}.hosts.txt"
    output_file = batch_dir / f"{tag}.open.txt"
    write_lines(input_file, alive_hosts)
    if not alive_hosts:
        write_lines(output_file, [])
        return []

    # -Pn: same reasoning as the nmap path in nse.py -- these hosts were already
    # proven alive by the discovery phase, so naabu's own host discovery is pure
    # duplication. Worse, when it fails it drops the host silently and the batch
    # reports zero open ports: inside a container naabu falls back to a CONNECT
    # scan ("non root privileges") whose discovery probes do not get through,
    # which turned a scan of hosts with known-open 80/443/25/465/587 into an
    # empty result with no error anywhere in the log.
    command = [
        "naabu",
        "-list",
        str(input_file),
        "-silent",
        "-Pn",
        "-rate",
        str(rate),
        "-retries",
        "1",
        *port_args,
    ]
    if protocol == "udp" and udp_probes:
        command.append("-uP")

    # Whether naabu can raise CAP_NET_RAW cannot be read off this process: the
    # capability reaches naabu through file capabilities, so the scanner's own
    # CapEff is empty even where SYN works. Attempting it is the only honest test.
    techniques = _scan_techniques(scan_type, protocol)
    for index, technique in enumerate(techniques):
        attempt = command if technique is None else [*command, "-s", technique]
        try:
            result = run_command(attempt, timeout=timeout, retries=retries)
            break
        except Exception:  # noqa: BLE001 -- fall back to the next technique
            if index == len(techniques) - 1:
                raise
            _rule_out_syn()
            logging.warning(
                "naabu SYN scan failed for batch %s; falling back to CONNECT for the rest of the run", tag
            )

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
    scan_type: NaabuScanType = "auto",
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
                scan_type=scan_type,
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
                scan_type=scan_type,
            )
        )

    return sorted(set(results))
