from __future__ import annotations

import ipaddress
import logging
import threading
from pathlib import Path

from .config_schema import DiscoveryConfig
from .discovery_targets import filter_hosts_in_scope
from .icmp_discover import icmp_ping_filter
from .protocol import parse_endpoint
from .utils import run_command, save_json, write_lines

PROBE_METHODS = ("icmp", "tcp", "naabu")

#: The TCP ports ``naabu -sn`` pings when it is given no probe flags of its
#: own. Not a guess: ``configureHostDiscovery`` in naabu v2.6.1 — the version
#: ``Dockerfile`` pins — sets ICMP echo, ICMP timestamp, and SYN *and* ACK
#: pings to 80 and 443 whenever ``!options.hasProbes()``. Naming them here is
#: what lets this stage honour the avoid-list: ``-exclude-ports`` belongs to
#: the port scan and does not reach host discovery.
NAABU_SN_PROBE_PORTS: tuple[int, ...] = (80, 443)

# Whether ``naabu -sn`` actually returns hosts here, decided once per process
# the same way the port scan decides SYN: "untested" until one batch shows it,
# then "ok" or "unavailable". Discovery batches run concurrently, so the
# deciding batch holds the lock — otherwise every batch launches CONNECT.
_host_syn_lock = threading.Lock()
_host_decision_lock = threading.Lock()
_host_syn_state = "untested"


def _get_host_syn_state() -> str:
    with _host_syn_lock:
        return _host_syn_state


def _set_host_syn_state(value: str) -> None:
    global _host_syn_state
    with _host_syn_lock:
        _host_syn_state = value


def _reset_host_syn_state() -> None:
    """Test seam: forget what this process learned about ``naabu -sn``."""
    _set_host_syn_state("untested")


def sn_probe_ports(exclude_ports: list[int] | None = None) -> list[int]:
    """:data:`NAABU_SN_PROBE_PORTS` minus the run's avoid-list."""
    excluded = {int(port) for port in (exclude_ports or [])}
    return [port for port in NAABU_SN_PROBE_PORTS if port not in excluded]


def build_naabu_sn_command(
    input_file: str | Path,
    *,
    rate: int,
    retries: int,
    exclude_ports: list[int] | None = None,
) -> list[str]:
    """Build the argv of the ``naabu -sn`` host-discovery step.

    Split out of :func:`naabu_host_discovery` so the flag set has one source
    of truth that a test — and the image smoke stage, which runs it against a
    real binary — can read without a scan. The previous round of this fix was
    reviewed by reading naabu's source and shipped a command that the binary
    refuses to start on, which no amount of reading caught.

    ``-wn`` is why. Spelling the probes out is only legal in naabu v2.6.1 when
    ``WithHostDiscovery`` is set: ``ValidateOptions`` rejects
    ``options.hasProbes() && !options.WithHostDiscovery`` outright ("discovery
    probes were provided but host discovery is disabled", exit 1) and does
    *not* accept ``OnlyHostDiscovery`` in its place, though
    ``shouldDiscoverHosts()`` two files over takes either. So ``-sn`` alone is
    fine and ``-sn -pe …`` is fatal. ``-wn`` alongside ``-sn`` changes nothing
    else about the run — ``OnlyHostDiscovery`` still returns the discovery
    results and skips the port scan (``runner.go``) — and the resulting command
    finds the same hosts as bare ``-sn`` did.
    """
    probe_ports = sn_probe_ports(exclude_ports)
    return [
        "naabu",
        "-list",
        str(input_file),
        "-sn",
        # Not redundant with -sn. See the docstring: without it naabu refuses
        # to start as soon as any probe flag is named.
        "-wn",
        "-silent",
        "-disable-update-check",  # no phone-home from an air-gapped scan (#339)
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
    ]


def build_naabu_connect_command(
    input_file: str | Path,
    *,
    probe_ports: list[int],
    rate: int,
    retries: int,
) -> list[str]:
    return [
        "naabu",
        "-list",
        str(input_file),
        "-Pn",
        "-s",
        "c",
        "-p",
        ",".join(str(port) for port in probe_ports),
        "-silent",
        "-disable-update-check",
        "-rate",
        str(rate),
        "-retries",
        str(max(1, retries)),
    ]


def parse_naabu_host_lines(stdout: str) -> list[str]:
    """Extract hosts from naabu output without truncating IPv6 at its first colon."""
    hosts: set[str] = set()
    for line in stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            hosts.add(str(ipaddress.ip_address(text)))
            continue
        except ValueError:
            pass
        endpoint = parse_endpoint(text)
        if endpoint is not None:
            hosts.add(endpoint.host)
            continue
        # Legacy naabu IPv4 output can be host:port without /tcp. The parser
        # above handles it, so anything left is malformed rather than a host.
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
                "TCP probe batch %s: skipped — every configured port is excluded (#362)", tag,
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
            "-disable-update-check",  # no phone-home from an air-gapped scan (#339)
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


def _run_recorded_naabu(
    targets: list[str],
    *,
    input_file: Path,
    command: list[str],
    scope_members: list[str],
    timeout: int,
    retries: int,
) -> list[str]:
    write_lines(input_file, targets)
    result = run_command(command, timeout=timeout, retries=retries)
    return filter_hosts_in_scope(
        parse_naabu_host_lines(result.stdout or ""), scope_members
    )


def _connect_host_discovery(
    targets: list[str],
    output_dir: Path,
    *,
    probe_ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> list[str]:
    batch_dir = output_dir / "discover"
    input_file = batch_dir / f"{tag}.naabu.connect.targets.txt"
    alive = _run_recorded_naabu(
        targets,
        input_file=input_file,
        command=build_naabu_connect_command(
            input_file, probe_ports=probe_ports, rate=rate, retries=retries
        ),
        scope_members=scope_members,
        timeout=timeout,
        retries=retries,
    )
    write_lines(batch_dir / f"{tag}.naabu.connect.alive.txt", alive)
    return alive


def _syn_host_discovery(
    targets: list[str],
    output_dir: Path,
    *,
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
    exclude_ports: list[int] | None,
) -> list[str]:
    input_file = output_dir / "discover" / f"{tag}.naabu.targets.txt"
    return _run_recorded_naabu(
        targets,
        input_file=input_file,
        command=build_naabu_sn_command(
            input_file, rate=rate, retries=retries, exclude_ports=exclude_ports
        ),
        scope_members=scope_members,
        timeout=timeout,
        retries=retries,
    )


def _connect_cross_check(
    targets: list[str],
    output_dir: Path,
    *,
    probe_ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> list[str] | None:
    """CONNECT hosts, or None when the cross-check command itself failed.

    An empty list is a real answer (nothing answered). None is not: the
    caller must not treat a crashed cross-check as "these hosts are dead".
    """
    try:
        return _connect_host_discovery(
            targets,
            output_dir,
            probe_ports=probe_ports,
            rate=rate,
            timeout=timeout,
            retries=retries,
            tag=tag,
            scope_members=scope_members,
        )
    except Exception:  # noqa: BLE001 -- the caller decides whether SYN still stands
        logging.warning("naabu CONNECT cross-check failed for batch %s", tag)
        return None


def _host_key(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _uncovered_targets(
    targets: list[str], alive: list[str], scope_members: list[str]
) -> list[str]:
    """In-scope targets whose normalized address SYN did not return.

    naabu prints ``2001:db8::1`` for an input of ``2001:db8:0:0:0:0:0:1``.
    A raw string difference would send CONNECT at a host SYN already found.
    """
    found = {_host_key(host) for host in alive}
    pending = [host for host in targets if _host_key(host) not in found]
    return filter_hosts_in_scope(pending, scope_members)


def _union_missed_hosts(
    alive: list[str],
    targets: list[str],
    output_dir: Path,
    *,
    probe_ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> list[str]:
    """CONNECT hosts a successful SYN probe missed, and union them.

    One alive host used to suppress the fallback for the rest of the batch.
    The cross-check covers only that miss. A failed or empty CONNECT keeps
    the SYN hosts and does not take the run off SYN: ICMP-reachable hosts
    would disappear if later batches became CONNECT-only. Both probe ports
    avoided leaves nothing legal to connect to.
    """
    if not alive or not probe_ports:
        return alive
    pending = _uncovered_targets(targets, alive, scope_members)
    if not pending:
        return alive
    found = _connect_cross_check(
        pending,
        output_dir,
        probe_ports=probe_ports,
        rate=rate,
        timeout=timeout,
        retries=retries,
        tag=tag,
        scope_members=scope_members,
    )
    if not found:
        return alive
    logging.warning(
        "naabu SYN/ACK host discovery missed %s host(s) in batch %s; CONNECT found %s",
        len(pending),
        tag,
        len(found),
    )
    return sorted(set(alive) | set(found))


def _accept_connect_recovery(tag: str, found: list[str]) -> list[str]:
    _set_host_syn_state("unavailable")
    logging.warning(
        "naabu SYN/ACK host discovery returned no hosts for batch %s while CONNECT found %s",
        tag,
        len(found),
    )
    return found


def _recover_failed_syn(
    exc: Exception,
    targets: list[str],
    output_dir: Path,
    *,
    probe_ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
) -> list[str]:
    """Replace a failed SYN probe only when CONNECT actually finds hosts.

    Returning ``[]`` here is what a delta refresh reads as "these known hosts
    are dead". CONNECT that finds nobody, or fails itself, leaves the SYN
    error in place so the batch is not checkpointed.
    """
    if not probe_ports:
        raise exc
    logging.warning("naabu host discovery failed for batch %s; trying CONNECT", tag)
    found = _connect_cross_check(
        targets,
        output_dir,
        probe_ports=probe_ports,
        rate=rate,
        timeout=timeout,
        retries=retries,
        tag=tag,
        scope_members=scope_members,
    )
    if found:
        return _accept_connect_recovery(tag, found)
    raise exc


def _decide_host_syn(
    targets: list[str],
    output_dir: Path,
    *,
    probe_ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
    exclude_ports: list[int] | None,
) -> list[str]:
    """Settle, from one batch, whether ``naabu -sn`` can be trusted here."""
    try:
        alive = _syn_host_discovery(
            targets,
            output_dir,
            rate=rate,
            timeout=timeout,
            retries=retries,
            tag=tag,
            scope_members=scope_members,
            exclude_ports=exclude_ports,
        )
    except Exception as exc:  # noqa: BLE001 -- no raw sockets; CONNECT may still answer
        return _recover_failed_syn(
            exc,
            targets,
            output_dir,
            probe_ports=probe_ports,
            rate=rate,
            timeout=timeout,
            retries=retries,
            tag=tag,
            scope_members=scope_members,
        )
    if not alive:
        if not probe_ports:
            return []
        found = _connect_cross_check(
            targets,
            output_dir,
            probe_ports=probe_ports,
            rate=rate,
            timeout=timeout,
            retries=retries,
            tag=tag,
            scope_members=scope_members,
        )
        if found is None:
            return []
        if found:
            return _accept_connect_recovery(tag, found)
        _set_host_syn_state("ok")
        return []

    # SYN reached something, so later batches keep using it, but this
    # batch's misses are still CONNECT-probed.
    alive = _union_missed_hosts(
        alive,
        targets,
        output_dir,
        probe_ports=probe_ports,
        rate=rate,
        timeout=timeout,
        retries=retries,
        tag=tag,
        scope_members=scope_members,
    )
    _set_host_syn_state("ok")
    return alive


def _resolve_host_discovery(
    targets: list[str],
    output_dir: Path,
    *,
    probe_ports: list[int],
    rate: int,
    timeout: int,
    retries: int,
    tag: str,
    scope_members: list[str],
    exclude_ports: list[int] | None,
) -> list[str]:
    while True:
        state = _get_host_syn_state()
        if state == "unavailable":
            if not probe_ports:
                raise RuntimeError(
                    f"naabu SYN host discovery is unavailable for batch {tag} "
                    "and the avoid-list leaves no CONNECT probe port"
                )
            return _connect_host_discovery(
                targets,
                output_dir,
                probe_ports=probe_ports,
                rate=rate,
                timeout=timeout,
                retries=retries,
                tag=tag,
                scope_members=scope_members,
            )
        if state == "ok":
            try:
                alive = _syn_host_discovery(
                    targets,
                    output_dir,
                    rate=rate,
                    timeout=timeout,
                    retries=retries,
                    tag=tag,
                    scope_members=scope_members,
                    exclude_ports=exclude_ports,
                )
            except Exception as exc:  # noqa: BLE001 -- capability lost after SYN had worked
                return _recover_failed_syn(
                    exc,
                    targets,
                    output_dir,
                    probe_ports=probe_ports,
                    rate=rate,
                    timeout=timeout,
                    retries=retries,
                    tag=tag,
                    scope_members=scope_members,
                )
            return _union_missed_hosts(
                alive,
                targets,
                output_dir,
                probe_ports=probe_ports,
                rate=rate,
                timeout=timeout,
                retries=retries,
                tag=tag,
                scope_members=scope_members,
            )
        with _host_decision_lock:
            if _get_host_syn_state() != "untested":
                continue
            return _decide_host_syn(
                targets,
                output_dir,
                probe_ports=probe_ports,
                rate=rate,
                timeout=timeout,
                retries=retries,
                tag=tag,
                scope_members=scope_members,
                exclude_ports=exclude_ports,
            )


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

    The command itself is :func:`build_naabu_sn_command`, which is also where
    the ``-wn`` that has to travel with a spelled-out probe set is explained.
    An exit-0 empty SYN/ACK probe is cross-checked once with CONNECT on the
    same ports: containers can exit 0 without delivering raw-socket results.
    A non-empty probe can still miss hosts when raw sockets work for only
    part of the batch. Those pending hosts are CONNECT-probed and unioned,
    on this batch and on later ones; one alive host does not stand in for
    the rest. A failed probe is not an empty result. CONNECT replaces it
    only when that cross-check finds hosts; otherwise the error still fails
    the batch, so a delta refresh cannot drop known hosts. Both probe ports
    excluded means there is nothing legal to CONNECT to, and the SYN error
    propagates.
    """
    if not targets:
        return []

    probe_ports = sn_probe_ports(exclude_ports)
    if len(probe_ports) != len(NAABU_SN_PROBE_PORTS):
        logging.info(
            "naabu -sn batch %s: host-discovery TCP pings narrowed to %s by the avoid-list (#362)",
            tag,
            probe_ports or "none (ICMP only)",
        )

    alive = _resolve_host_discovery(
        targets,
        output_dir,
        probe_ports=probe_ports,
        rate=rate,
        timeout=timeout,
        retries=retries,
        tag=tag,
        scope_members=scope_members,
        exclude_ports=exclude_ports,
    )
    write_lines(output_dir / "discover" / f"{tag}.naabu.alive.txt", alive)
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
