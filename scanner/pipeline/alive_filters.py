from __future__ import annotations

import ipaddress

from .batching import _parse_network
from .coverage_tracker import is_ipv4_last_octet


def filter_alive_hosts(
    hosts: list[str],
    *,
    exclude_hosts: list[str] | None = None,
    exclude_last_octets: list[int] | None = None,
) -> list[str]:
    """Drop configured false-positive alive hosts after discovery."""
    literal_excludes: set[str] = set()
    excluded_networks: list[ipaddress._BaseNetwork] = []
    for value in exclude_hosts or []:
        net = _parse_network(value)
        if net is not None:
            excluded_networks.append(net)
        else:
            literal_excludes.add(value)

    last_octets = set(exclude_last_octets or [])
    kept: list[str] = []
    for host in hosts:
        if host in literal_excludes:
            continue
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and any(ip in net for net in excluded_networks):
            continue
        if last_octets and is_ipv4_last_octet(host, last_octets):
            continue
        kept.append(host)
    return sorted(set(kept))
