from __future__ import annotations

import hashlib
import logging
import os
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .protocol import (
    ScanProtocol,
    endpoint_checkpoint_key,
    format_endpoint,
    parse_endpoint,
)
from .utils import run_command, write_lines


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _format_nmap_host(host: str) -> str:
    from .protocol import is_ipv6

    if is_ipv6(host):
        return f"[{host}]"
    return host


def _safe_filename(value: str) -> str:
    return value.replace(":", "_").replace("/", "_")


def _per_process_rate(max_rate: int, workers: int) -> int:
    if max_rate <= 0:
        return 0
    return max(1, max_rate // max(1, workers))


def _group_output_basename(hosts: list[str], protocol: ScanProtocol) -> str:
    if len(hosts) == 1:
        return f"{protocol}_{_safe_filename(hosts[0])}"
    digest = hashlib.sha1(",".join(sorted(hosts)).encode("utf-8")).hexdigest()[:12]
    return f"{protocol}_group_{digest}"


def _chunk_host_ports(host_ports: dict[str, list[str]], hosts_per_scan: int) -> list[dict[str, list[str]]]:
    size = max(1, hosts_per_scan)
    items = sorted(host_ports.items())
    if size == 1:
        return [{host: ports} for host, ports in items]
    return [dict(items[i : i + size]) for i in range(0, len(items), size)]


def _build_nmap_command(
    host_ports: dict[str, list[str]],
    base: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    per_process_rate: int,
    scan_protocol: ScanProtocol,
) -> list[str]:
    # -Pn: hosts are already selected as alive by discovery; ICMP/ACK ping
    # often fails on firewalled VPN/enterprise ranges and would drop them all.
    command = ["nmap", "-n", "-Pn", f"-{nmap_timing}"]
    if scan_protocol == "udp":
        command.append("-sU")
    if version_detection:
        command.append("-sV")
    if os_detection and scan_protocol == "tcp":
        if _running_as_root():
            command += ["-O", "--osscan-guess"]
        else:
            # nmap hard-requires euid 0 for -O regardless of capabilities
            # (cap_net_raw/cap_net_admin aren't enough) and refuses to run the
            # WHOLE command -- not just skip OS detection -- when unprivileged,
            # which would silently kill -sV and every NSE script too. The
            # all-in-one image runs as a non-root user by design (Dockerfile.allinone),
            # so drop it here rather than losing the entire scan.
            logging.warning(
                "os_detection is enabled but the process is not root; skipping -O/--osscan-guess "
                "(nmap requires root for OS fingerprinting -- version detection and NSE scripts still run)"
            )
    if per_process_rate > 0:
        command += ["--max-rate", str(per_process_rate)]
    command += ["--script", scripts]
    all_ports = sorted({port for ports in host_ports.values() for port in ports}, key=int)
    command += ["-p", ",".join(all_ports)]
    command += [_format_nmap_host(host) for host in sorted(host_ports)]
    command += ["-oA", str(base)]
    return command


def _group_ports_by_host(entries: list[str], protocol: ScanProtocol) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        parsed = parse_endpoint(entry)
        if parsed is None or parsed.protocol != protocol:
            continue
        grouped[parsed.host].append(parsed.port)
    return {host: sorted(set(ports), key=int) for host, ports in grouped.items()}


def _scan_host_group(
    host_ports: dict[str, list[str]],
    nmap_output_dir: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    per_process_rate: int,
    timeout: int,
    retries: int,
    scan_protocol: ScanProtocol,
) -> list[str]:
    hosts = sorted(host_ports)
    base = nmap_output_dir / _group_output_basename(hosts, scan_protocol)
    command = _build_nmap_command(
        host_ports,
        base,
        scripts,
        version_detection,
        os_detection,
        nmap_timing,
        per_process_rate,
        scan_protocol,
    )
    completed = run_command(command, timeout=timeout, retries=retries, check=False, capture_output=True)
    if completed.returncode != 0:
        logging.warning(
            "nmap exited %s for host group [%s]: %s",
            completed.returncode,
            ", ".join(hosts),
            (completed.stderr or completed.stdout or "").strip()[:500],
        )
    return hosts


def _run_nse_for_protocol(
    entries: list[str],
    *,
    output_dir: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    timeout: int,
    retries: int,
    concurrency: int,
    max_rate: int,
    hosts_per_scan: int,
    scan_protocol: ScanProtocol,
    done_keys: set[str],
    on_host_done: Callable[[str], None] | None,
) -> None:
    grouped = _group_ports_by_host(entries, scan_protocol)
    if not grouped:
        return

    pending = {
        host: ports
        for host, ports in grouped.items()
        if endpoint_checkpoint_key(host, scan_protocol) not in done_keys
    }
    skipped = len(grouped) - len(pending)
    if skipped:
        logging.info("Resuming NSE (%s): skipping %s already-scanned hosts", scan_protocol, skipped)
    if not pending:
        return

    nmap_output_dir = output_dir / "nmap" / scan_protocol
    nmap_output_dir.mkdir(parents=True, exist_ok=True)

    scan_groups = _chunk_host_ports(pending, hosts_per_scan)
    workers = max(1, concurrency)
    per_process_rate = _per_process_rate(max_rate, workers)
    logging.info(
        "Running %s NSE scans for %s hosts in %s group(s) "
        "(hosts_per_scan=%s, concurrency=%s, per_process_rate=%s pps)",
        scan_protocol.upper(),
        len(pending),
        len(scan_groups),
        max(1, hosts_per_scan),
        workers,
        per_process_rate if per_process_rate > 0 else "unlimited",
    )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _scan_host_group,
                group,
                nmap_output_dir,
                scripts,
                version_detection,
                os_detection,
                nmap_timing,
                per_process_rate,
                timeout,
                retries,
                scan_protocol,
            ): group
            for group in scan_groups
        }
        for future in as_completed(futures):
            group = futures[future]
            try:
                completed_hosts = future.result()
            except Exception as exc:  # noqa: BLE001
                label = ",".join(sorted(group))
                logging.warning(
                    "NSE (%s) scan failed for group (%s hosts): %s",
                    scan_protocol,
                    len(group),
                    label[:120],
                )
                logging.debug("NSE group failure detail: %s", exc)
                continue
            if on_host_done is not None:
                for host in completed_hosts:
                    on_host_done(endpoint_checkpoint_key(host, scan_protocol))


def run_nse(
    host_port_list: list[str],
    output_dir: Path,
    scripts: str,
    version_detection: bool,
    os_detection: bool,
    nmap_timing: str,
    timeout: int,
    retries: int,
    concurrency: int,
    max_rate: int = 0,
    hosts_per_scan: int = 1,
    done_hosts: Iterable[str] | None = None,
    on_host_done: Callable[[str], None] | None = None,
) -> Path:
    normalized: list[str] = []
    for entry in host_port_list:
        parsed = parse_endpoint(entry)
        if parsed is None:
            continue
        normalized.append(format_endpoint(parsed.host, parsed.port, parsed.protocol))

    targets_file = output_dir / "nse_targets.txt"
    write_lines(targets_file, normalized)

    nmap_root = output_dir / "nmap"
    nmap_root.mkdir(parents=True, exist_ok=True)
    if not normalized:
        return nmap_root

    done_keys = set(done_hosts or ())
    for key in list(done_keys):
        if "/" not in key:
            done_keys.add(endpoint_checkpoint_key(key, "tcp"))
    tcp_entries = [entry for entry in normalized if entry.endswith("/tcp")]
    udp_entries = [entry for entry in normalized if entry.endswith("/udp")]

    for scan_protocol, entries in (("tcp", tcp_entries), ("udp", udp_entries)):
        _run_nse_for_protocol(
            entries,
            output_dir=output_dir,
            scripts=scripts,
            version_detection=version_detection,
            os_detection=os_detection,
            nmap_timing=nmap_timing,
            timeout=timeout,
            retries=retries,
            concurrency=concurrency,
            max_rate=max_rate,
            hosts_per_scan=hosts_per_scan,
            scan_protocol=scan_protocol,
            done_keys=done_keys,
            on_host_done=on_host_done,
        )

    return nmap_root
