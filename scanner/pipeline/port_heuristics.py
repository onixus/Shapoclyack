"""S5 throughput heuristics: historical open ports ∪ top-N (not 1–1024).

Inventory-style jobs must not silently expand to a wide well-known range.
When a previous run's ``open_ports.txt`` is available, the ports stage scans
the union of those TCP opens and the curated top-N set. With no history,
naabu's ``-top-ports`` path remains (intent already forces top 100).

See FTT-PULSE-2026-057 / ADR 0014.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .protocol import parse_endpoint
from .top_tcp_ports import top_tcp_ports
from .utils import read_lines, write_lines

#: Cap on the union size so a pathological previous run cannot force a
#: near-full port sweep through the heuristic path.
MAX_HEURISTIC_PORTS = 4096

#: Marker written beside the generated ports file for audit / resume.
HEURISTIC_META_NAME = "port_heuristic_union.json"


def tcp_ports_from_open_ports_lines(lines: list[str]) -> set[int]:
    """Extract distinct TCP port numbers from ``host:port[/proto]`` lines."""
    ports: set[int] = set()
    for raw in lines:
        endpoint = parse_endpoint(raw)
        if endpoint is None:
            continue
        if endpoint.protocol != "tcp":
            continue
        try:
            port = int(endpoint.port)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ports


def historical_tcp_ports(previous_run_dir: Path | None) -> set[int]:
    """Read TCP opens from a prior run directory, or empty when absent."""
    if previous_run_dir is None:
        return set()
    path = previous_run_dir / "open_ports.txt"
    if not path.is_file():
        return set()
    return tcp_ports_from_open_ports_lines(read_lines(path))


def union_historical_and_top_n(
    *,
    historical: set[int],
    top_n: int,
    exclude: set[int] | None = None,
) -> list[int]:
    """Sorted unique TCP ports: historical ∪ curated top-N, minus excludes."""
    n = 100 if top_n <= 100 else 1000
    combined = set(historical) | set(top_tcp_ports(n))
    if exclude:
        combined -= set(exclude)
    ordered = sorted(p for p in combined if 1 <= p <= 65535)
    if len(ordered) > MAX_HEURISTIC_PORTS:
        logging.warning(
            "port heuristic union truncated from %s to %s ports",
            len(ordered),
            MAX_HEURISTIC_PORTS,
        )
        return ordered[:MAX_HEURISTIC_PORTS]
    return ordered


def custom_ports_file_is_operator_set(path: Path, *, default_marker: str = "# use profile top-ports") -> bool:
    """True when the custom ports file names real ports (not the shipped stub).

    The shipped ``scanner/inputs/ports.txt`` is a comment-only stub so naabu
    falls through to ``-top-ports``. Operator / CLI lists have real tokens.
    """
    if not path.is_file():
        return False
    lines = read_lines(path)
    if not lines:
        return False
    # Single-line shipped stub (or equivalent comment-only content).
    meaningful = [line for line in lines if line.strip() and not line.strip().startswith("#")]
    if not meaningful:
        # Preserve the historical default marker check for clarity in audits.
        joined = "\n".join(lines).strip()
        if default_marker in joined or joined.startswith("#"):
            return False
        return False
    return True


def write_heuristic_ports_file(
    ports: list[int],
    dest: Path,
) -> Path:
    """Write a naabu ``-p`` list file; returns ``dest``."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_lines(dest, [",".join(str(p) for p in ports)] if ports else [])
    return dest


def apply_historical_top_n_union(
    *,
    output_dir: Path,
    previous_run_dir: Path | None,
    top_n: int,
    exclude_ports: list[int] | None,
    existing_custom_ports_file: Path,
) -> Path | None:
    """Build historical∪top-N custom ports file when history exists.

    Returns the path to use as ``ports.custom_ports_file``, or ``None`` when
    the caller should keep naabu ``-top-ports`` (no history, or operator
    already supplied a real custom list).
    """
    if custom_ports_file_is_operator_set(existing_custom_ports_file):
        logging.info(
            "port heuristic union skipped: operator custom ports file %s",
            existing_custom_ports_file,
        )
        return None

    historical = historical_tcp_ports(previous_run_dir)
    if not historical:
        logging.info("port heuristic union: no historical opens; using top_ports=%s", top_n)
        return None

    ports = union_historical_and_top_n(
        historical=historical,
        top_n=top_n,
        exclude=set(exclude_ports or ()),
    )
    dest = output_dir / "ports" / "heuristic_union_ports.txt"
    write_heuristic_ports_file(ports, dest)
    meta = {
        "schema": "octo.port_heuristic_union.v1",
        "historical_count": len(historical),
        "top_n": 100 if top_n <= 100 else 1000,
        "union_count": len(ports),
        "previous_run_dir": str(previous_run_dir) if previous_run_dir else "",
        "ports_file": str(dest),
    }
    try:
        from .utils import save_json

        save_json(output_dir / "ports" / HEURISTIC_META_NAME, meta)
    except OSError as exc:
        logging.warning("port heuristic meta not written: %s", exc)
    logging.info(
        "port heuristic union: %s historical + top-%s → %s ports (%s)",
        len(historical),
        meta["top_n"],
        len(ports),
        dest,
    )
    return dest
