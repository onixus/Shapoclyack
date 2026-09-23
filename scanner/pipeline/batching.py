from __future__ import annotations

import hashlib
import ipaddress


def _parse_network(value: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def batch_id(members: list[str]) -> str:
    """Stable id for a batch derived from its sorted members.

    If members change between runs the id changes, so resume reprocesses only
    what actually differs.
    """
    joined = ",".join(sorted(members))
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]


def _chunk(items: list[str], size: int) -> list[list[str]]:
    size = max(1, size)
    return [items[i : i + size] for i in range(0, len(items), size)]


def expand_batches(
    targets: list[str],
    ipv4_prefix: int = 20,
    ipv6_prefix: int = 120,
    max_ipv6_batches: int = 4096,
    max_targets_per_batch: int = 4096,
) -> list[tuple[str, list[str]]]:
    """Split work into resumable batches.

    - Large IPv4 networks (prefixlen < ``ipv4_prefix``) are split into
      ``/ipv4_prefix`` subnets, one batch each.
    - IPv6 networks broader than ``ipv6_prefix`` are split the same way, but
      only when the number of generated subnets is bounded by
      ``max_ipv6_batches``. A ``/64`` is not a list anyone gets to materialise
      by accident.
    - Single IPs and networks already at or beyond their family threshold are
      grouped into chunks of up to ``max_targets_per_batch`` entries.

    Returns a deterministic list of ``(batch_id, members)`` tuples.
    """
    subnet_batches: list[str] = []
    singles: list[str] = []
    generated_ipv6 = 0

    for raw in targets:
        value = raw.strip()
        if not value:
            continue
        net = _parse_network(value)
        if net is not None and net.version == 4 and net.prefixlen < ipv4_prefix:
            for sub in net.subnets(new_prefix=ipv4_prefix):
                subnet_batches.append(str(sub))
        elif net is not None and net.version == 6 and net.prefixlen < ipv6_prefix:
            requested = 1 << (ipv6_prefix - net.prefixlen)
            if generated_ipv6 + requested > max_ipv6_batches:
                raise ValueError(
                    f"IPv6 target {net} would create {requested} /{ipv6_prefix} batches "
                    f"(limit {max_ipv6_batches}); narrow the target or raise "
                    "batching.max_ipv6_batches deliberately"
                )
            generated_ipv6 += requested
            for sub in net.subnets(new_prefix=ipv6_prefix):
                subnet_batches.append(str(sub))
        else:
            singles.append(value)

    batches: list[tuple[str, list[str]]] = []
    for cidr in sorted(set(subnet_batches), key=lambda c: ipaddress.ip_network(c)):
        batches.append((batch_id([cidr]), [cidr]))

    for chunk in _chunk(sorted(set(singles)), max_targets_per_batch):
        batches.append((batch_id(chunk), chunk))

    return batches


def single_batch(targets: list[str]) -> list[tuple[str, list[str]]]:
    """Fallback when batching is disabled: one batch with all targets."""
    members = sorted({t.strip() for t in targets if t.strip()})
    if not members:
        return []
    return [(batch_id(members), members)]
