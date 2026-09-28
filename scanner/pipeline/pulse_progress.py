"""Pulse per-host completion and scope-preserving reuse within one resumed run."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


def _identity(value: str) -> str:
    # No DNS lookup or hostname/IP equivalence inferred by this adapter.
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _identities(row: dict[str, Any]) -> set[str]:
    return {_identity(str(row[key]).strip()) for key in ("ip", "host") if row.get(key)}


def _port(row: dict[str, Any]) -> int:
    try:
        return int(row.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def completed_hosts(
    grouped: Mapping[str, Sequence[int]], payload: dict[str, Any], returncode: int
) -> set[str]:
    """Checkpoint only successful hosts with every expected TCP endpoint present.

    Partial JSON remains evidence, not proof that all hosts/ports were probed.
    An unknown service on an open endpoint still counts as an observed endpoint.
    """
    if returncode != 0:
        return set()
    observed: dict[str, set[int]] = defaultdict(set)
    for row in payload.get("open") or []:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "tcp").lower()
        state = str(row.get("state") or "open").lower()
        if proto not in {"tcp", "tcpsyn", "syn"} or state != "open" or row.get("open") is False:
            continue
        port = _port(row)
        if not 1 <= port <= 65535:
            continue
        for identity in _identities(row):
            observed[identity].add(port)
    return {
        host for host, ports in grouped.items()
        if ports and set(ports) <= observed.get(_identity(host), set())
    }


def retain_completed_payload(
    grouped: Mapping[str, Sequence[int]], done_hosts: set[str], payload: dict[str, Any]
) -> tuple[set[str], dict[str, Any]]:
    """Reuse only checkpointed, still-approved hosts with persisted evidence.

    Legacy checkpoints may have marked an entire partially answered group done.
    Missing evidence causes a safe re-probe, never a skipped host. Old overscan
    endpoints are not imported into the resumed canonical result. Stats/chunks
    remain diagnostics of the current pass, not counters inflated by cache reuse.
    """
    done = completed_hosts({h: grouped[h] for h in done_hosts if h in grouped}, payload, 0)
    allowed = {_identity(h): set(grouped[h]) for h in done}
    kept: dict[str, Any] = {}
    for field in ("open", "os", "cves", "findings", "tls"):
        rows = []
        for row in payload.get(field) or []:
            if not isinstance(row, dict):
                continue
            identities = _identities(row) & allowed.keys()
            if not identities:
                continue
            if field != "os":
                port = _port(row)
                if not any(port in allowed[host] for host in identities):
                    continue
                if field == "open" and str(row.get("protocol") or "tcp").lower() not in {"tcp", "tcpsyn", "syn"}:
                    continue
            rows.append(row)
        kept[field] = rows
    return done, kept
