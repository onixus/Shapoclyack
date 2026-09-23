"""Directly attached IPv4 discovery for internal sensor deployments (#364).

The ordinary discovery ladder is routed IP discovery. This stage is deliberately
separate: ARP, mDNS and NetBIOS are link-local protocols, so pretending that an
RFC1918 target is automatically on the sensor's Ethernet would be a scope and
operational lie. The stage is opt-in, never widens the run's target set, and
caps the number of addresses before invoking nmap.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import fromstring as safe_fromstring

from .config_schema import L2DiscoveryConfig
from .discovery_targets import host_in_batch_scope
from .hostnames import merge_name_lists
from .utils import run_command, save_json, write_lines

LOG = logging.getLogger("shapoclyack.l2-discovery")
_NETBIOS_NAME_RE = re.compile(r"(?im)^\s*(?:NetBIOS name|name)\s*:\s*([^\s,;]+)")
_LOCAL_NAME_RE = re.compile(r"(?i)\b(?:[a-z0-9_-]+\.)+[a-z0-9_-]*local\.?\b")
_NAME_KEYS = {"hostname", "name", "target", "targetname", "service"}


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


def _address(host: ET.Element) -> tuple[str, str | None, str | None]:
    ip = ""
    mac = None
    vendor = None
    for node in host.findall("address"):
        kind = node.attrib.get("addrtype")
        if kind == "ipv4":
            ip = node.attrib.get("addr", "")
        elif kind == "mac":
            mac = node.attrib.get("addr") or None
            vendor = node.attrib.get("vendor") or None
    return ip, mac, vendor


def parse_arp_xml(text: str, scope: list[str]) -> list[dict[str, Any]]:
    """Parse alive IPv4/MAC rows from nmap XML, constrained to requested scope."""
    try:
        root = safe_fromstring(text)
    except ET.ParseError:
        return []
    rows: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue
        ip, mac, vendor = _address(host)
        if not ip or not host_in_batch_scope(ip, scope):
            continue
        rows.append({"host": ip, "mac": mac, "vendor": vendor})
    return sorted(rows, key=lambda row: row["host"])


def _structured_names(script: ET.Element) -> list[str]:
    names: list[str] = []
    for elem in script.findall(".//elem"):
        key = str(elem.attrib.get("key") or "").lower()
        value = (elem.text or "").strip()
        if value and key in _NAME_KEYS:
            names.append(value)
    return names


def parse_name_xml(text: str, scope: list[str]) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Extract mDNS/NetBIOS names while retaining script evidence for operators."""
    try:
        root = safe_fromstring(text)
    except ET.ParseError:
        return {}, []
    mapping: dict[str, list[str]] = {}
    evidence: list[dict[str, Any]] = []
    for host in root.findall("host"):
        ip, _mac, _vendor = _address(host)
        if not ip or not host_in_batch_scope(ip, scope):
            continue
        for script in host.findall("./ports/port/script") + host.findall("./hostscript/script"):
            script_id = str(script.attrib.get("id") or "")
            output = str(script.attrib.get("output") or "")
            names = _structured_names(script)
            if script_id == "nbstat":
                names.extend(match.group(1) for match in _NETBIOS_NAME_RE.finditer(output))
            if script_id in {"dns-service-discovery", "broadcast-dns-service-discovery"}:
                names.extend(match.group(0) for match in _LOCAL_NAME_RE.finditer(output))
            normalized = merge_name_lists(names)
            if normalized:
                mapping[ip] = merge_name_lists(mapping.get(ip, []), normalized)
            evidence.append(
                {
                    "host": ip,
                    "script_id": script_id,
                    "names": normalized,
                    "output": output[:4096],
                }
            )
    return mapping, evidence


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


def run_l2_discovery(
    targets: list[str],
    config: L2DiscoveryConfig,
    output_dir: Path,
    *,
    retries: int = 0,
) -> dict[str, Any]:
    """Run bounded ARP discovery, then optional mDNS/NetBIOS probes."""
    artifact = output_dir / "l2_discovery.json"
    result: dict[str, Any] = {
        "enabled": config.enabled,
        "networks": [],
        "alive_hosts": [],
        "hosts": [],
        "names_by_host": {},
        "name_evidence": [],
        "skipped_networks": [],
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "l2.disabled"
        save_json(artifact, result)
        return result
    if shutil.which("nmap") is None:
        result["skipped_reason"] = "nmap.unavailable"
        save_json(artifact, result)
        return result

    networks, skipped = select_l2_networks(targets, config)
    result["networks"] = [str(network) for network in networks]
    result["skipped_networks"] = skipped
    if not networks:
        result["skipped_reason"] = "no_in_scope_local_networks"
        save_json(artifact, result)
        return result

    discover_dir = output_dir / "discover"
    discover_dir.mkdir(parents=True, exist_ok=True)
    arp_xml = discover_dir / "l2-arp.xml"
    command = [
        "nmap",
        "-sn",
        "-PR",
        "-n",
        "--max-rate",
        str(config.max_rate),
        "-oX",
        str(arp_xml),
    ]
    if config.interface:
        command.extend(["-e", config.interface])
    command.extend(str(network) for network in networks)
    completed = run_command(
        command,
        timeout=config.timeout_seconds,
        retries=retries,
        check=False,
    )
    if not arp_xml.exists():
        result["skipped_reason"] = f"arp.failed:{completed.returncode}"
        save_json(artifact, result)
        return result

    scope = [str(network) for network in networks]
    rows = parse_arp_xml(arp_xml.read_text(encoding="utf-8", errors="replace"), scope)
    alive = [str(row["host"]) for row in rows]
    result["hosts"] = rows
    result["alive_hosts"] = alive
    write_lines(discover_dir / "l2-alive.txt", alive)

    if alive and (config.mdns or config.netbios):
        name_targets = discover_dir / "l2-name.targets.txt"
        name_xml = discover_dir / "l2-names.xml"
        write_lines(name_targets, alive)
        scripts: list[str] = []
        ports: list[str] = []
        if config.netbios:
            scripts.append("nbstat")
            ports.append("137")
        if config.mdns:
            scripts.append("dns-service-discovery")
            ports.append("5353")
        name_command = [
            "nmap",
            "-sU",
            "-Pn",
            "-n",
            "--max-rate",
            str(config.max_rate),
            "-p",
            ",".join(ports),
            "--script",
            ",".join(scripts),
            "-iL",
            str(name_targets),
            "-oX",
            str(name_xml),
        ]
        if config.interface:
            name_command.extend(["-e", config.interface])
        run_command(
            name_command,
            timeout=config.timeout_seconds,
            retries=retries,
            check=False,
        )
        if name_xml.exists():
            names, evidence = parse_name_xml(
                name_xml.read_text(encoding="utf-8", errors="replace"), scope
            )
            result["names_by_host"] = names
            result["name_evidence"] = evidence

    save_json(artifact, result)
    LOG.info(
        "L2 discovery: %d network(s), %d ARP-alive host(s), %d named host(s), %d skipped network(s)",
        len(networks),
        len(alive),
        len(result["names_by_host"]),
        len(skipped),
    )
    return result
