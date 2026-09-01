from __future__ import annotations

import logging
import threading
from pathlib import Path

from .config_schema import NaabuScanType
from .protocol import ScanProtocol, format_endpoint, naabu_udp_port_spec, parse_endpoint, top_udp_port_list
from .utils import read_lines, run_command, write_lines

# Whether naabu's SYN mode actually works here, decided once per run:
# "untested" until a batch has shown one way or the other, then "ok" or
# "unavailable". Batches run concurrently (runtime.ports_concurrency), so the
# state is guarded and the deciding batch holds _decision_lock while it settles
# the question -- otherwise every batch in flight launches its own probe.
_state_lock = threading.Lock()
_decision_lock = threading.Lock()
_syn_state = "untested"


def _get_syn_state() -> str:
    with _state_lock:
        return _syn_state


def _set_syn_state(value: str) -> None:
    global _syn_state
    with _state_lock:
        _syn_state = value


def _reset_syn_state() -> None:
    """Test seam: forget what this process learned about SYN."""
    _set_syn_state("untested")


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


def custom_tcp_ports(custom_file: Path) -> set[int]:
    """Individual TCP ports named by a custom ports file (ranges expanded).

    The custom TCP ports file feeds naabu's ``-p`` (comma/newline separated,
    ``N`` or ``N-M`` ranges). The web-scanning stages (nuclei, fingerprint,
    screenshots) need to know which non-default ports were explicitly scanned
    so they can be probed as web endpoints too -- otherwise a scan of, say,
    ``9000,7443`` finds the ports open but never runs nuclei against them
    because they are not in the built-in ``http_ports``/``https_ports`` lists.

    ``u:``-prefixed tokens mark UDP and are ignored here. Unparseable or
    out-of-range tokens are skipped rather than raising.
    """
    ports: set[int] = set()
    for line in read_lines(custom_file):
        for part in line.split(","):
            part = part.strip()
            if not part or part.startswith("u:"):
                continue
            if "-" in part:
                lo, _, hi = part.partition("-")
                try:
                    start, end = int(lo), int(hi)
                except ValueError:
                    continue
                if start > end:
                    start, end = end, start
                start, end = max(1, start), min(65535, end)
                if start <= end:
                    ports.update(range(start, end + 1))
            else:
                try:
                    port = int(part)
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    ports.add(port)
    return ports


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


def _exec(command: list[str], *, technique: str | None, protocol: ScanProtocol, timeout: int, retries: int) -> list[str]:
    attempt = command if technique is None else [*command, "-s", technique]
    result = run_command(attempt, timeout=timeout, retries=retries)
    return _naabu_entries(result.stdout or "", protocol)


def _decide_syn(command: list[str], *, protocol: ScanProtocol, timeout: int, retries: int, tag: str) -> list[str]:
    """Run one batch as SYN and settle whether SYN works here.

    A SYN scan fails two ways. It exits non-zero when naabu cannot raise
    CAP_NET_RAW, which is loud. It also exits 0 having seen nothing -- the CI
    image does exactly this -- which is silent and reads identically to a batch
    of genuinely closed ports. So an empty SYN batch is cross-checked against
    CONNECT: if CONNECT finds ports, SYN is broken here and the rest of the run
    uses CONNECT; if CONNECT agrees, the ports really are closed and SYN is
    trusted from then on. Only the first batch pays for this.
    """
    try:
        entries = _exec(command, technique="s", protocol=protocol, timeout=timeout, retries=retries)
    except Exception:  # noqa: BLE001 -- no CAP_NET_RAW; CONNECT is the answer
        _set_syn_state("unavailable")
        logging.warning("naabu SYN scan failed for batch %s; using CONNECT for the rest of the run", tag)
        return _exec(command, technique="c", protocol=protocol, timeout=timeout, retries=retries)

    if entries:
        _set_syn_state("ok")
        return entries

    cross = _exec(command, technique="c", protocol=protocol, timeout=timeout, retries=retries)
    if cross:
        _set_syn_state("unavailable")
        logging.warning(
            "naabu SYN scan returned nothing for batch %s while CONNECT found %s open port(s); "
            "using CONNECT for the rest of the run",
            tag,
            len(cross),
        )
        return cross

    _set_syn_state("ok")
    return entries


def _scan_batch(
    command: list[str],
    *,
    protocol: ScanProtocol,
    scan_type: NaabuScanType,
    timeout: int,
    retries: int,
    tag: str,
) -> list[str]:
    # -s picks the TCP technique; UDP batches have no use for it.
    if protocol != "tcp":
        return _exec(command, technique=None, protocol=protocol, timeout=timeout, retries=retries)
    if scan_type in ("syn", "connect"):
        return _exec(
            command, technique=scan_type[0], protocol=protocol, timeout=timeout, retries=retries
        )

    while True:
        state = _get_syn_state()
        if state == "unavailable":
            return _exec(command, technique="c", protocol=protocol, timeout=timeout, retries=retries)
        if state == "ok":
            try:
                return _exec(command, technique="s", protocol=protocol, timeout=timeout, retries=retries)
            except Exception:  # noqa: BLE001 -- capability lost mid-run; keep scanning
                _set_syn_state("unavailable")
                logging.warning("naabu SYN scan failed for batch %s; using CONNECT for the rest of the run", tag)
                return _exec(command, technique="c", protocol=protocol, timeout=timeout, retries=retries)
        # Untested: exactly one batch settles it while the others wait for the
        # answer, rather than each launching the same probe concurrently.
        with _decision_lock:
            if _get_syn_state() != "untested":
                continue
            return _decide_syn(command, protocol=protocol, timeout=timeout, retries=retries, tag=tag)


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

    entries = _scan_batch(
        command, protocol=protocol, scan_type=scan_type, timeout=timeout, retries=retries, tag=tag
    )
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
