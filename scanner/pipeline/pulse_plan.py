"""Pure TCP service-probe planning; no processes, files or scope expansion."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TcpProbeChunk:
    """Every host has exactly this port set; their product is safe to probe."""

    hosts: tuple[str, ...]
    ports: tuple[int, ...]

    @property
    def endpoint_count(self) -> int:
        return len(self.hosts) * len(self.ports)


def plan_tcp_probe(
    grouped: Mapping[str, Sequence[int]],
    *,
    chunk_hosts: int = 64,
    done_hosts: Iterable[str] = (),
) -> tuple[TcpProbeChunk, ...]:
    """Plan normalized, already-approved TCP endpoints without an overscan.

    Group by the entire sorted port signature BEFORE applying the host limit.
    A host occurs once, never once per endpoint. Sorting hosts before bucketing
    makes order deterministic without depending on discovery or dict order.
    Completed hosts are removed before re-cutting chunks on resume. The caller
    owns endpoint validation, UDP routing, policy and checkpoint persistence.
    """
    size = max(1, chunk_hosts)
    done = set(done_hosts)
    signatures: dict[tuple[int, ...], list[str]] = defaultdict(list)
    for host in sorted(grouped):
        if host in done:
            continue
        ports = tuple(sorted(set(grouped[host])))
        if ports:
            signatures[ports].append(host)
    return tuple(
        TcpProbeChunk(tuple(hosts[offset : offset + size]), ports)
        for ports, hosts in signatures.items()
        for offset in range(0, len(hosts), size)
    )
