"""Directly attached IPv4 discovery for internal sensor deployments (#364, #542).

The ordinary discovery ladder is routed IP discovery. This stage is deliberately
separate: ARP, mDNS and NetBIOS are link-local protocols, so pretending that an
RFC1918 target is automatically on the sensor's Ethernet would be a scope and
operational lie. The stage is opt-in, never widens the run's target set, and
caps the number of addresses before invoking Pulse.

Pulse has no ARP mode of its own: ``-D --discover-method arp`` sends a 1-byte
UDP datagram to port 9 of every candidate and lets the kernel resolve the
neighbour, so the MAC is read back from ``/proc/net/arp`` and the packet rate
is ``--rate`` divided by the kernel's ARP retry count. See
docs/pulse-backend.md#l2-discovery for the measurements behind that.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .config_schema import L2DiscoveryConfig
from .discovery_targets import host_in_batch_scope
from .hostnames import merge_name_lists
from .pulse_probe import _pulse_available, pulse_env, resolve_pulse_bin, resolve_services_db
from .utils import run_command, save_json, write_lines

LOG = logging.getLogger("shapoclyack.l2-discovery")

#: Kernel files the stage reads. Module-level so tests can point them at a tmp dir.
NEIGH_SYSCTL_DIR = Path("/proc/sys/net/ipv4/neigh")
PROC_NET_ARP = Path("/proc/net/arp")
PROC_NET_ROUTE = Path("/proc/net/route")

#: ``mcast_solicit`` default of Linux: ARP requests sent for an unanswered address.
DEFAULT_MCAST_SOLICIT = 3
NETBIOS_PORT = 137
MDNS_PORT = 5353
#: Port Pulse's ARP trigger datagram always goes to (the discard service).
ARP_TRIGGER_PORT = 9

_NBSTAT_ANCHOR = re.compile(r"CKA{30}")
#: Bytes between the echoed wildcard name and the first table entry: name
#: terminator, type, class, TTL, RDLENGTH and the name count.
_NBSTAT_HEADER_LEN = 12
_NBSTAT_ENTRY_LEN = 18
_NBSTAT_NAME_LEN = 15
_GROUP_FLAG = "\ufffd"  # the group bit (0x80) is a high-bit byte: Pulse prints U+FFFD
#: Only this much of a banner is parsed for mDNS names: Pulse cuts banners at
#: about 150 characters anyway, and the scan below must stay linear.
MDNS_PARSE_LIMIT = 1024
_NETBIOS_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-]{0,14}")
_HOST_RUN_RE = re.compile(r"[A-Za-z0-9_.-]+")
_HOST_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


def _host_count(network: ipaddress.IPv4Network) -> int:
    if network.prefixlen >= 31:
        return network.num_addresses
    return max(0, network.num_addresses - 2)


def _target_networks(targets: list[str]) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for raw in targets:
        try:
            parsed = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if isinstance(parsed, ipaddress.IPv4Network):
            networks.append(parsed)
    return list(ipaddress.collapse_addresses(networks))


def select_l2_networks(
    targets: list[str], config: L2DiscoveryConfig
) -> tuple[list[ipaddress.IPv4Network], list[dict[str, str]]]:
    """Return in-scope local networks and explicit reasons for everything skipped."""
    target_networks = _target_networks(targets)
    requested = (
        [ipaddress.ip_network(value, strict=False) for value in config.networks]
        if config.networks
        else target_networks
    )
    selected: list[ipaddress.IPv4Network] = []
    skipped: list[dict[str, str]] = []
    total_hosts = 0

    for network in requested:
        assert isinstance(network, ipaddress.IPv4Network)
        if not any(network.subnet_of(scope) for scope in target_networks):
            skipped.append({"network": str(network), "reason": "outside_scan_scope"})
            continue
        if not config.networks and not (network.is_private or network.is_link_local):
            skipped.append({"network": str(network), "reason": "not_local_address_space"})
            continue
        count = _host_count(network)
        if count == 0:
            skipped.append({"network": str(network), "reason": "no_host_addresses"})
            continue
        if total_hosts + count > config.max_hosts:
            skipped.append(
                {
                    "network": str(network),
                    "reason": f"host_cap_exceeded:{config.max_hosts}",
                }
            )
            continue
        selected.append(network)
        total_hosts += count

    return list(ipaddress.collapse_addresses(selected)), skipped


def mcast_solicit(interface: str) -> int:
    """ARP requests the kernel sends per unanswered address (sysctl ``mcast_solicit``).

    Pulse's rate limit counts candidates, not packets, and every dead candidate
    costs this many requests plus the datagram that triggers them. Unreadable
    (or no interface at all) falls back to the Linux default: the stage is opt-in enrichment and must not
    fail on a kernel without the file (a non-Linux dev machine).
    """
    if interface:
        names = [interface] if Path(interface).name == interface else []
    else:
        # Pulse cannot be pinned to an interface, so any of them may carry the
        # sweep: take the largest retry count (loopback never ARPs).
        try:
            names = [d.name for d in NEIGH_SYSCTL_DIR.iterdir() if d.name != "lo"]
        except OSError:
            names = []
    values: list[int] = []
    for name in names:
        try:
            value = int((NEIGH_SYSCTL_DIR / name / "mcast_solicit").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            continue
        if value >= 0:
            values.append(value)
    return max(values) if values else DEFAULT_MCAST_SOLICIT


def _hex_ipv4(value: str) -> ipaddress.IPv4Address:
    """``/proc/net/route`` prints addresses as host-order hex of little-endian bytes."""
    return ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(value), "little"))


def interface_networks(interface: str) -> list[ipaddress.IPv4Network] | None:
    """Networks the kernel really sends out of ``interface`` without a gateway.

    The kernel picks the longest prefix and, at equal prefix, the lowest
    metric. So from the interface's on-link routes (gateway-less, UP, not the
    default) this removes every part that another route would win: a more
    specific route of any interface, or an equal route with a metric that is
    not strictly worse than ours. ``None`` means the route table could not be
    read, which is different from "no routes": the caller cannot then prove
    where Pulse's datagrams will go.
    """
    try:
        lines = PROC_NET_ROUTE.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return None
    routes: list[tuple[str, ipaddress.IPv4Network, bool, int]] = []  # iface, net, on-link, metric
    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            flags = int(fields[3], 16)
            gateway = _hex_ipv4(fields[2])
            metric = int(fields[6])
            network = ipaddress.IPv4Network((int(_hex_ipv4(fields[1])), str(_hex_ipv4(fields[7]))), strict=False)
        except ValueError:
            continue
        if flags & 0x1 and network.prefixlen > 0:
            routes.append((fields[0], network, int(gateway) == 0, metric))
    result: list[ipaddress.IPv4Network] = []
    for index, (iface, network, on_link, metric) in enumerate(routes):
        if iface != interface or not on_link:
            continue
        remaining = [network]
        for other, (_iface, rival, _on_link, rival_metric) in enumerate(routes):
            if other == index:
                continue
            wins = rival.prefixlen > network.prefixlen and rival.subnet_of(network)
            wins = wins or (rival == network and not metric < rival_metric)
            if wins:
                remaining = [part for q in remaining for part in _exclude(q, rival)]
        result.extend(remaining)
    return list(ipaddress.collapse_addresses(result))


def _exclude(network: ipaddress.IPv4Network, cut: ipaddress.IPv4Network) -> list[ipaddress.IPv4Network]:
    if network.subnet_of(cut):
        return []
    return list(network.address_exclude(cut)) if cut.subnet_of(network) else [network]


def split_by_routes(
    networks: list[ipaddress.IPv4Network], routes: list[ipaddress.IPv4Network]
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv4Network]]:
    """Split ``networks`` into the parts inside ``routes`` and the parts outside.

    ``select_l2_networks`` collapses neighbours (``10.0.0.0/24`` + ``10.0.1.0/24``
    becomes a /23), so a selected network can be only partly on the link.
    """
    inside: list[ipaddress.IPv4Network] = []
    outside: list[ipaddress.IPv4Network] = []
    for network in networks:
        pieces = [
            network if network.subnet_of(route) else route
            for route in routes
            if network.subnet_of(route) or route.subnet_of(network)
        ]
        pieces = list(ipaddress.collapse_addresses(pieces))
        rest = [network]
        for piece in pieces:
            remaining: list[ipaddress.IPv4Network] = []
            for part in rest:
                if part.subnet_of(piece):
                    continue
                remaining.extend(part.address_exclude(piece) if piece.subnet_of(part) else [part])
            rest = remaining
        inside.extend(pieces)
        outside.extend(rest)
    return sorted(inside), sorted(ipaddress.collapse_addresses(outside))


def neighbour_macs(interface: str = "") -> dict[str, str]:
    """IP -> MAC of complete ``/proc/net/arp`` entries (flag 0x2), optionally on one device.

    Incomplete entries (a dead address the kernel gave up on) carry the zero
    MAC and are not evidence of anything.
    """
    try:
        lines = PROC_NET_ARP.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        LOG.warning("%s is unreadable; L2 hosts will carry no MAC", PROC_NET_ARP)
        return {}
    macs: dict[str, str] = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        ip, _hw, flags, mac, _mask, device = fields[:6]
        try:
            complete = int(flags, 16) & 0x2
        except ValueError:
            continue
        if not complete or set(mac.replace(":", "")) <= {"0"}:
            continue
        if interface and device != interface:
            continue
        macs[ip] = mac.upper()
    return macs


def _pulse_rows(payload: Any, scope: list[str]) -> list[dict[str, Any]]:
    """Result rows of in-scope IPv4 hosts; every live host appears with ``--all``."""
    raw = payload.get("results") if isinstance(payload, dict) else None
    rows: list[dict[str, Any]] = []
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if host_in_batch_scope(ip, scope):
            rows.append(row)
    return rows


def nbstat_names(banner: str) -> list[str]:
    """Unique (non-group) names from the NBSTAT table in a UDP/137 banner.

    Pulse prints the answer one character per byte (non-printable as ``.``,
    high-bit as U+FFFD, cut at about 150 characters): after the echoed
    wildcard name and a 12-byte header come 18-byte entries of a space-padded
    15-character name, a suffix byte and two flag bytes. The group bit is the
    high bit of the first flag byte. A cut-off last entry is dropped.

    The name count is a non-printable byte, so it is not recoverable and the
    table end is not known: the 46-byte statistics block that follows starts
    with the adapter's MAC and would read as a name. A candidate therefore
    has to look like a NetBIOS name (letters, digits, ``-``, ``_``; no ``.``,
    no U+FFFD) or it is dropped. That is also what removes ``__MSBROWSE__``
    (printed ``..__MSBROWSE__.``, so it carries dots; as a group name it has
    the group bit too). Names with a space, ``.`` or ``$`` inside are lost
    on purpose. The suffix byte is not told apart, so a logged-in
    user name (suffix 0x03) is returned too.
    """
    anchor = _NBSTAT_ANCHOR.search(banner)
    if anchor is None:
        return []
    table = banner[anchor.end() + _NBSTAT_HEADER_LEN :]
    names: list[str] = []
    for start in range(0, len(table) - _NBSTAT_ENTRY_LEN + 1, _NBSTAT_ENTRY_LEN):
        entry = table[start : start + _NBSTAT_ENTRY_LEN]
        name = entry[:_NBSTAT_NAME_LEN].rstrip(" ")
        if entry[_NBSTAT_NAME_LEN + 1] == _GROUP_FLAG:
            continue
        if _NETBIOS_NAME_RE.fullmatch(name):
            names.append(name)
    return merge_name_lists(names)


def valid_hostname(name: str) -> bool:
    """Letters, digits, ``-`` and ``_``, dot-separated labels of 1-63, 253 in all."""
    if not name or len(name) > 253:
        return False
    return all(label and len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9_-]+", label) for label in name.split("."))


def mdns_names(banner: str) -> list[str]:
    """``*.local`` host names in a UDP/5353 banner; service types are not names.

    Pulse asks ``_services._dns-sd._udp.local`` and normally gets service types
    (``_ssh._tcp``) back. A label that starts with ``_`` is a service label, so
    ``_services._dns-sd._udp.local`` and ``_udp.local`` never qualify. Only the
    first ``MDNS_PARSE_LIMIT`` characters are read, in one pass over runs of
    host-name characters (length bytes show up as ``.``, so a run may hold
    several names and empty labels end one), so a hostile banner cannot cost more than linear time.
    """
    names: list[str] = []
    for run in _HOST_RUN_RE.findall(banner[:MDNS_PARSE_LIMIT]):
        labels = run.split(".")
        for index, label in enumerate(labels):
            if index == 0 or label.lower() != "local":
                continue
            host: list[str] = []
            for before in reversed(labels[:index]):
                # An earlier ``local`` ends the previous name; it is not a label of this one.
                if before.lower() == "local" or not _HOST_LABEL_RE.fullmatch(before):
                    break
                host.append(before)
            if host:
                name = ".".join([*reversed(host), label])
                if valid_hostname(name):
                    names.append(name)
    return merge_name_lists(names)


def parse_pulse_l2(
    payload: Any, scope: list[str], macs: dict[str, str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, list[str]], list[dict[str, Any]]]:
    """Alive hosts (with MAC), names by host and name evidence from Pulse JSON.

    Everything is constrained to ``scope``: a row for an address outside the
    selected networks is dropped before it can seed discovery.
    """
    rows = _pulse_rows(payload, scope)
    alive = sorted({str(row["ip"]) for row in rows}, key=ipaddress.IPv4Address)
    hosts = [{"host": ip, "mac": (macs or {}).get(ip), "vendor": None} for ip in alive]
    mapping: dict[str, list[str]] = {}
    evidence: list[dict[str, Any]] = []
    for row in rows:
        banner = row.get("banner")
        port = row.get("port")
        if not isinstance(banner, str) or not banner or row.get("protocol") != "udp":
            continue
        if port == NETBIOS_PORT:
            script_id, names = "pulse:netbios-ns", nbstat_names(banner)
        elif port == MDNS_PORT:
            script_id, names = "pulse:mdns", mdns_names(banner)
        else:
            continue
        ip = str(row["ip"])
        if names:
            mapping[ip] = merge_name_lists(mapping.get(ip, []), names)
        evidence.append({"host": ip, "script_id": script_id, "names": names, "output": banner[:4096]})
    return hosts, mapping, evidence


def merge_l2_names(hostnames: dict[str, dict[str, Any]], l2_names: dict[str, list[str]]) -> dict:
    """Merge link-local names into hostnames.json without calling them DNS facts."""
    result = {host: dict(entry) for host, entry in hostnames.items()}
    for host, names in l2_names.items():
        entry = result.setdefault(host, {"forward": [], "reverse": [], "names": []})
        entry["l2"] = merge_name_lists(list(entry.get("l2") or []), names)
        entry["names"] = merge_name_lists(
            list(entry.get("forward") or []),
            list(entry.get("reverse") or []),
            list(entry.get("l2") or []),
        )
        if entry["names"]:
            entry["primary"] = entry["names"][0]
    return result


def _stop(artifact: Path, result: dict[str, Any], reason: str) -> dict[str, Any]:
    result["skipped_reason"] = reason
    save_json(artifact, result)
    return result


def run_l2_discovery(
    targets: list[str],
    config: L2DiscoveryConfig,
    output_dir: Path,
    *,
    retries: int = 0,
    exclude_ports: list[int] | None = None,
    pulse_bin: str = "",
) -> dict[str, Any]:
    """Run one bounded Pulse pass: ARP-triggered liveness plus NetBIOS/mDNS names.

    The stage is opt-in enrichment, so a command that times out or cannot
    start is recorded as a skipped reason instead of failing the whole run.
    ``exclude_ports`` is ``ports.exclude_ports``: a name probe on a port the
    policy forbids is dropped, and port 9, which Pulse's ARP trigger always
    hits, switches the stage off. ``pulse_bin`` is ``service_probe.pulse.bin``.
    """
    excluded = {int(port) for port in (exclude_ports or [])}
    artifact = output_dir / "l2_discovery.json"
    result: dict[str, Any] = {
        "enabled": config.enabled,
        "engine": "pulse",
        "networks": [],
        "alive_hosts": [],
        "hosts": [],
        "names_by_host": {},
        "name_evidence": [],
        "skipped_networks": [],
        "skipped_reason": None,
        "pulse_rate": None,
        "rate_divisor": None,
    }
    if not config.enabled:
        return _stop(artifact, result, "l2.disabled")
    binary = resolve_pulse_bin(pulse_bin)
    if not _pulse_available(binary):
        LOG.warning(
            "pulse binary not found (%s); skipping L2 discovery. Install Pulse "
            "or set service_probe.pulse.bin (docs/pulse-backend.md#l2-discovery).",
            binary,
        )
        return _stop(artifact, result, "pulse.unavailable")

    # Pulse's ARP method reads the neighbour table through `ip -4 neigh`. With
    # no `ip` on its PATH it finds nothing, prints nothing and exits 0, which
    # would pass for "no live hosts" - so refuse to run instead.
    if shutil.which("ip", path=pulse_env(Path("/")).get("PATH") or os.defpath) is None:
        LOG.warning(
            "`ip` (iproute2) not found on PATH; Pulse ARP discovery would report no hosts, "
            "skipping L2 discovery (docs/pulse-backend.md#l2-discovery)."
        )
        return _stop(artifact, result, "pulse.arp_needs_iproute2")

    networks, skipped = select_l2_networks(targets, config)
    result["skipped_networks"] = skipped
    if not networks:
        return _stop(artifact, result, "no_in_scope_local_networks")
    if ARP_TRIGGER_PORT in excluded:
        # Pulse's ARP trigger is a UDP datagram to port 9 of every candidate.
        return _stop(artifact, result, f"arp.trigger_port_excluded:{ARP_TRIGGER_PORT}")

    if config.interface:
        # Pulse cannot be pinned to an interface; the routing table picks it.
        # Only networks the routing table sends out of the configured one are safe.
        on_link = interface_networks(config.interface)
        if on_link is None:
            return _stop(artifact, result, "interface.unverifiable")
        usable, off_link = split_by_routes(networks, on_link)
        skipped.extend(
            {"network": str(network), "reason": f"not_on_interface:{config.interface}"}
            for network in off_link
        )
        networks = usable
        if not networks:
            return _stop(artifact, result, "no_in_scope_local_networks")
    result["networks"] = [str(network) for network in networks]

    name_ports = [
        port
        for port, wanted in ((NETBIOS_PORT, config.netbios), (MDNS_PORT, config.mdns))
        if wanted and port not in excluded
    ]
    solicit = mcast_solicit(config.interface)
    # A candidate costs its datagram plus ``solicit`` ARP requests, and the
    # measured peaks run over that: divisor 4 gave 103 pps at ``--rate 25``
    # even without name probes, divisor 5 stayed under 100 with and without
    # them. So one more, whether or not names are probed.
    divisor = solicit + 2
    rate = config.max_rate // divisor
    result["rate_divisor"] = divisor
    if rate < 1:
        # --rate counts candidates; below one candidate per second the packet
        # ceiling cannot be held, and --rate 0 would mean unlimited.
        return _stop(artifact, result, f"rate_cap_unenforceable:{config.max_rate}")
    result["pulse_rate"] = rate
    # Candidates are paced at ``rate`` per second and the last dead one still
    # waits out its ARP retries (about a second each). A sweep that cannot
    # finish inside the timeout would be killed with no result at all.
    candidates = sum(_host_count(network) for network in networks)
    estimate = math.ceil(candidates / rate + solicit)
    if estimate > config.timeout_seconds:
        return _stop(artifact, result, f"timeout_unreachable:{estimate}s")

    discover_dir = output_dir / "discover"
    discover_dir.mkdir(parents=True, exist_ok=True)
    scope = [str(network) for network in networks]
    targets_file = discover_dir / "l2-targets.txt"
    write_lines(targets_file, scope)
    command = [
        binary,
        "--targets-file", str(targets_file),
        "-D", "--discover-method", "arp",
        "--rate", str(rate),
        "--max-hosts", str(config.max_hosts),
        "-f", "json", "-q", "--all",
        "--protocol", "udp",
        "-p", ",".join(str(port) for port in (name_ports or [ARP_TRIGGER_PORT])),
        "--services-db", resolve_services_db(),
    ]  # fmt: skip
    if name_ports:
        command.append("-b")
    try:
        with tempfile.TemporaryDirectory(prefix="pulse-home-") as home:
            completed = run_command(
                command,
                timeout=config.timeout_seconds,
                retries=retries,
                check=False,
                env=pulse_env(Path(home)),
            )
    except Exception as exc:  # noqa: BLE001 - TimeoutExpired, OSError
        LOG.warning("L2 Pulse sweep did not complete: %s", exc)
        return _stop(artifact, result, f"arp.failed:{type(exc).__name__}")
    stdout = (completed.stdout or "").strip()
    if stdout:
        (discover_dir / "l2-pulse.json").write_text(stdout + "\n", encoding="utf-8")
    if completed.returncode != 0:
        return _stop(artifact, result, f"arp.failed:{completed.returncode}")

    payload: Any = {}
    if stdout:  # no live host: Pulse prints nothing and exits 0
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return _stop(artifact, result, "arp.failed:invalid_json")
        if not isinstance(payload, dict):
            return _stop(artifact, result, "arp.failed:invalid_json")

    hosts, names, evidence = parse_pulse_l2(payload, scope, neighbour_macs(config.interface))
    alive = [row["host"] for row in hosts]
    result["hosts"] = hosts
    result["alive_hosts"] = alive
    result["names_by_host"] = names
    result["name_evidence"] = evidence
    write_lines(discover_dir / "l2-alive.txt", alive)

    save_json(artifact, result)
    LOG.info(
        "L2 discovery: %d network(s), %d ARP-alive host(s), %d named host(s), %d skipped network(s)",
        len(networks),
        len(alive),
        len(names),
        len(skipped),
    )
    return result
