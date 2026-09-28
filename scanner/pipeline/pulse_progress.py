"""Pulse per-host completion and scope-preserving reuse within one resumed run."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


COMPLETION_SCHEMA = "octo.pulse_completion.v1"


def normalize_host(value: str) -> str:
    """Canonicalize literal addresses without inferring DNS equivalence."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _identities(row: dict[str, Any]) -> set[str]:
    return {normalize_host(str(row[key]).strip()) for key in ("ip", "host") if row.get(key)}


def _port(row: dict[str, Any]) -> int:
    try:
        return int(row.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def _observed_tcp_ports(payload: dict[str, Any]) -> dict[str, set[int]]:
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
    return observed


def completed_hosts(
    grouped: Mapping[str, Sequence[int]], payload: dict[str, Any], returncode: int
) -> set[str]:
    """Checkpoint only successful hosts with every expected TCP endpoint present.

    Partial JSON remains evidence, not proof that all hosts/ports were probed.
    An unknown service on an open endpoint still counts as an observed endpoint.
    """
    if returncode != 0:
        return set()
    observed = _observed_tcp_ports(payload)
    return {
        host for host, ports in grouped.items()
        if ports and set(ports) <= observed.get(normalize_host(host), set())
    }


def completion_manifest(completed: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    """Persist receipts for already-validated successful per-host results.

    Call only for hosts accepted by completed_hosts or retain_completed_payload.
    Unlike current-pass chunks, these receipts survive repeated/all-done resume.
    They describe processing outcome, not vulnerability verification or a signature.
    """
    return {
        "schema": COMPLETION_SCHEMA,
        "hosts": {
            host: {"ports": sorted(set(ports)), "returncode": 0}
            for host, ports in sorted(completed.items())
        },
    }


def _successful_tcp_ports(payload: dict[str, Any]) -> dict[str, set[int]]:
    manifest = payload.get("completion")
    if not isinstance(manifest, dict) or manifest.get("schema") != COMPLETION_SCHEMA:
        return {}
    records = manifest.get("hosts")
    if not isinstance(records, dict):
        return {}
    successful: dict[str, set[int]] = defaultdict(set)
    for host, record in records.items():
        if not isinstance(host, str) or not isinstance(record, dict):
            continue
        # False and "0" must not be accepted as an exit status in a receipt.
        code = record.get("returncode")
        ports = record.get("ports")
        if type(code) is not int or code != 0 or not isinstance(ports, list):
            continue
        if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            continue
        successful[normalize_host(host)].update(ports)
    return successful


def retain_completed_payload(
    grouped: Mapping[str, Sequence[int]], done_hosts: set[str], payload: dict[str, Any]
) -> tuple[set[str], dict[str, Any]]:
    """Reuse checkpointed hosts only with success receipts AND endpoint evidence.

    Legacy artifacts without receipts are safely replayed once: endpoint data
    alone cannot establish whether the process finished its enrichment. Missing
    or invalid receipts never default to success. Retained receipts survive the
    current-pass stats/chunks reset, while scope exclusions still apply.
    """
    successful = _successful_tcp_ports(payload)
    observed = _observed_tcp_ports(payload)
    requested = {normalize_host(host) for host in done_hosts}
    done = {
        host for host, ports in grouped.items()
        if normalize_host(host) in requested and ports
        and set(ports) <= successful.get(normalize_host(host), set())
        and set(ports) <= observed.get(normalize_host(host), set())
    }
    # Several spellings of one IPv6 address may have different port sets.
    # Union them rather than letting arbitrary set iteration erase an endpoint.
    allowed: dict[str, set[int]] = defaultdict(set)
    for host in done:
        allowed[normalize_host(host)].update(grouped[host])
    kept: dict[str, Any] = {
        "completion": completion_manifest({host: grouped[host] for host in done}),
    }
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
