from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .batching import _parse_network


def expand_target_ips(
    targets: list[str],
    *,
    max_hosts: int | None = None,
) -> set[str]:
    """Expand CIDR targets to individual host IPs; pass through single IPs."""
    ips: set[str] = set()
    for raw in targets:
        value = raw.strip()
        if not value:
            continue
        net = _parse_network(value)
        if net is not None:
            for host in net.hosts():
                ips.add(str(host))
                if max_hosts is not None and len(ips) >= max_hosts:
                    return ips
        else:
            ips.add(value)
    return ips


@dataclass
class CoverageTracker:
    """Track expected scan scope vs confirmed alive hosts for gap detection."""

    scope: set[str] = field(default_factory=set)
    found: set[str] = field(default_factory=set)

    @classmethod
    def from_targets(
        cls,
        targets: list[str],
        *,
        max_scope_hosts: int | None = None,
    ) -> CoverageTracker:
        return cls(scope=expand_target_ips(targets, max_hosts=max_scope_hosts))

    def mark_found(self, hosts: list[str] | set[str]) -> None:
        for host in hosts:
            if host in self.scope:
                self.found.add(host)

    def gap(self) -> list[str]:
        return sorted(self.scope - self.found)

    def coverage_ratio(self) -> float:
        if not self.scope:
            return 1.0
        return len(self.found & self.scope) / len(self.scope)

    def stats(self) -> dict[str, int | float]:
        gap_count = len(self.scope - self.found)
        return {
            "scope_hosts": len(self.scope),
            "found_hosts": len(self.found & self.scope),
            "gap_hosts": gap_count,
            "coverage_pct": round(self.coverage_ratio() * 100.0, 2),
        }


def batches_are_disjoint(batches: list[tuple[str, list[str]]]) -> bool:
    """Return True when expanded batch members do not overlap."""
    seen: set[str] = set()
    for _, members in batches:
        batch_ips = expand_target_ips(members)
        if seen.intersection(batch_ips):
            return False
        seen.update(batch_ips)
    return True


def is_ipv4_last_octet(host: str, octets: set[int]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return ip.packed[-1] in octets
