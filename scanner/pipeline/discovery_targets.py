from __future__ import annotations

import ipaddress

from .batching import _parse_network


def host_in_batch_scope(host: str, members: list[str]) -> bool:
    """Return True if ``host`` belongs to any batch member (IP or CIDR)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in members

    for member in members:
        net = _parse_network(member)
        if net is not None and ip in net:
            return True
        if member == host:
            return True
    return False


def filter_hosts_in_scope(hosts: list[str], members: list[str]) -> list[str]:
    return sorted({host for host in hosts if host_in_batch_scope(host, members)})


def pending_discovery_targets(
    members: list[str],
    known_alive: set[str],
    *,
    max_hosts: int | None = 65536,
) -> list[str]:
    """Hosts/CIDR members not yet marked alive — inputs for the next naabu batch.

    CIDR members expand to individual IPs excluding ``known_alive``. When the
    expanded list is empty the batch can be skipped entirely.
    """
    pending: list[str] = []
    for member in members:
        net = _parse_network(member)
        if net is not None:
            for host in net.hosts():
                ip = str(host)
                if ip in known_alive:
                    continue
                pending.append(ip)
                if max_hosts is not None and len(pending) >= max_hosts:
                    return sorted(set(pending))
        elif member not in known_alive:
            pending.append(member)
    return sorted(set(pending))
