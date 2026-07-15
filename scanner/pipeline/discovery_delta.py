from __future__ import annotations

import json
import logging
import random
from pathlib import Path

from .coverage_tracker import expand_target_ips
from .utils import read_lines, save_json, write_lines


def load_seed_alive(seed_alive_file: str) -> set[str]:
    if not seed_alive_file:
        return set()
    path = Path(seed_alive_file)
    if not path.exists():
        logging.warning("seed_alive_file not found: %s", path)
        return set()
    hosts = {line.strip() for line in read_lines(path) if line.strip()}
    logging.info("discovery seed_alive: loaded %s host(s) from %s", len(hosts), path)
    return hosts


def resolve_previous_alive_file(
    *,
    output_base: Path,
    state_base: Path,
    previous_run_dir: str,
    per_run_output: bool,
) -> Path | None:
    if previous_run_dir:
        candidate = Path(previous_run_dir) / "alive_ips.txt"
        return candidate if candidate.exists() else None

    if per_run_output:
        pointer = state_base / "latest_run.json"
        if not pointer.exists():
            return None
        run_id = json.loads(pointer.read_text(encoding="utf-8")).get("run_id")
        if not run_id:
            return None
        candidate = output_base / "runs" / str(run_id) / "alive_ips.txt"
        return candidate if candidate.exists() else None

    candidate = output_base / "alive_ips.txt"
    return candidate if candidate.exists() else None


def load_previous_alive(path: Path | None) -> set[str]:
    if path is None:
        return set()
    hosts = set(read_lines(path))
    logging.info("discovery delta: loaded %s previous alive host(s) from %s", len(hosts), path)
    return hosts


def compute_delta_plan(
    all_targets: list[str],
    *,
    seed_alive: set[str],
    previous_alive: set[str],
    refresh_rate: float,
    refresh_seed: int = 0,
    max_scope_hosts: int | None = 65536,
) -> tuple[set[str], list[str], list[str]]:
    """Return (initial_alive, wave1_ips, refresh_ips) for delta discovery."""
    scope_ips = expand_target_ips(all_targets, max_hosts=max_scope_hosts)
    in_scope_previous = {host for host in previous_alive if host in scope_ips}
    initial_alive = set(seed_alive) | in_scope_previous
    wave1_ips = sorted(scope_ips - initial_alive)
    refresh_candidates = sorted(in_scope_previous - seed_alive)
    refresh_ips = select_refresh_hosts(refresh_candidates, refresh_rate, seed=refresh_seed)
    return initial_alive, wave1_ips, refresh_ips


def select_refresh_hosts(hosts: list[str], refresh_rate: float, *, seed: int = 0) -> list[str]:
    unique = sorted(set(hosts))
    if not unique:
        return []
    if refresh_rate >= 1.0:
        return unique
    if refresh_rate <= 0:
        return []
    count = max(1, int(len(unique) * refresh_rate))
    if count >= len(unique):
        return unique
    rng = random.Random(seed)
    return sorted(rng.sample(unique, count))


def write_delta_plan(
    output_dir: Path,
    *,
    scope_hosts: int,
    initial_alive: set[str],
    wave1_ips: list[str],
    refresh_ips: list[str],
    previous_source: str,
) -> None:
    save_json(
        output_dir / "discovery_delta.json",
        {
            "scope_hosts": scope_hosts,
            "initial_alive": len(initial_alive),
            "wave1_hosts": len(wave1_ips),
            "refresh_hosts": len(refresh_ips),
            "previous_source": previous_source,
        },
    )
    batch_dir = output_dir / "discover"
    batch_dir.mkdir(parents=True, exist_ok=True)
    write_lines(batch_dir / "delta.wave1.targets.txt", wave1_ips)
    write_lines(batch_dir / "delta.refresh.targets.txt", refresh_ips)
