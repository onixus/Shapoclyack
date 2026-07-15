from __future__ import annotations

import logging
from pathlib import Path

from .config_schema import DiscoveryConfig
from .coverage_tracker import expand_target_ips
from .discovery_targets import pending_discovery_targets
from .probe_ladder import run_probe_ladder
from .utils import write_lines


def host_discovery(
    targets: list[str],
    output_dir: Path,
    rate: int,
    timeout: int,
    retries: int,
    skip_discovery: bool,
    discovery: DiscoveryConfig,
    known_alive: set[str] | None = None,
    skip_known_alive: bool = False,
    max_pending_hosts: int | None = 65536,
    tag: str = "all",
) -> list[str]:
    """Run host discovery for a single batch via the configured probe ladder.

    Per-batch inputs/outputs live under ``output_dir/discover/<tag>.*`` so each
    batch is independent and resumable. Returns the alive hosts for this batch.
    """
    batch_dir = output_dir / "discover"
    input_file = batch_dir / f"{tag}.targets.txt"
    alive_file = batch_dir / f"{tag}.alive.txt"
    scan_targets = list(targets)
    if skip_known_alive and known_alive is not None:
        scan_targets = pending_discovery_targets(
            targets,
            known_alive,
            max_hosts=max_pending_hosts,
        )
        if not scan_targets:
            logging.info(
                "Discovery batch %s: skipping — all targets already alive (%s known)",
                tag,
                len(known_alive),
            )
            write_lines(input_file, [])
            write_lines(alive_file, [])
            return []

    write_lines(input_file, scan_targets)
    if not scan_targets:
        write_lines(alive_file, [])
        return []

    if skip_discovery:
        alive = sorted(set(scan_targets))
        write_lines(alive_file, alive)
        return alive

    probe_hosts = sorted(expand_target_ips(scan_targets, max_hosts=max_pending_hosts))
    if not probe_hosts:
        write_lines(alive_file, [])
        return []

    alive, _stats = run_probe_ladder(
        probe_hosts,
        output_dir,
        discovery,
        rate=rate,
        timeout=timeout,
        retries=retries,
        tag=tag,
        scope_members=targets,
    )
    write_lines(alive_file, alive)
    return alive
