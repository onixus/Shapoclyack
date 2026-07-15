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
    max_targets_per_batch: int = 4096,
) -> list[tuple[str, list[str]]]:
    """Split work into resumable batches.

    - Large IPv4 networks (prefixlen < ``ipv4_prefix``) are split into
      ``/ipv4_prefix`` subnets, one batch each.
    - Everything else (single IPs, IPv6, networks already >= ipv4_prefix) is
      grouped into chunks of up to ``max_targets_per_batch`` entries.

    Returns a deterministic list of ``(batch_id, members)`` tuples.
    """
    subnet_batches: list[str] = []
    singles: list[str] = []

    for raw in targets:
        value = raw.strip()
        if not value:
            continue
        net = _parse_network(value)
        if net is not None and net.version == 4 and net.prefixlen < ipv4_prefix:
            for sub in net.subnets(new_prefix=ipv4_prefix):
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
