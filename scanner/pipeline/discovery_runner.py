from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from .alive_filters import filter_alive_hosts
from .batch_runner import run_batches_parallel
from .batching import expand_batches, single_batch
from .checkpoint import CheckpointStore
from .config_schema import AppConfig, ProfileConfig
from .coverage_tracker import CoverageTracker, batches_are_disjoint, expand_target_ips
from .discovery_delta import compute_delta_plan, write_delta_plan
from .discover import host_discovery
from .probe_ladder import merge_discovery_stats
from .protocol import parse_endpoint
from .utils import read_lines, write_lines


def _wave2_rate(profile: ProfileConfig, configured: int | None) -> int:
    if configured is not None:
        return configured
    return max(500, profile.discover_rate // 4)


def _discover_concurrency(
    config: AppConfig,
    batches: list[tuple[str, list[str]]],
    *,
    skip_known_alive: bool,
) -> int:
    """Return discover worker count: parallel when batches are disjoint, else serial if skipping known alive."""
    disjoint = config.discovery.disjoint_batches and batches_are_disjoint(batches)
    if disjoint:
        return config.runtime.discover_concurrency
    if skip_known_alive:
        return 1
    return config.runtime.discover_concurrency


def _make_batches(config: AppConfig, items: list[str]) -> list[tuple[str, list[str]]]:
    batching = config.batching
    if batching.enabled:
        return expand_batches(
            items,
            ipv4_prefix=batching.ipv4_prefix,
            max_targets_per_batch=batching.max_targets_per_batch,
        )
    return single_batch(items)


def _run_discover_batches(
    *,
    stage: str,
    checkpoint_key: str,
    batches: list[tuple[str, list[str]]],
    alive_set: set[str],
    alive_file: Path,
    output_dir: Path,
    rate: int,
    timeout: int,
    retries: int,
    skip_discovery: bool,
    skip_known_alive: bool,
    concurrency: int,
    checkpoint: CheckpointStore,
    done_ids: set[str],
    config: AppConfig,
) -> None:
    def _discover_batch(bid: str, members: list[str]) -> list[str]:
        known = set(alive_set) if skip_known_alive else None
        return host_discovery(
            members,
            output_dir=output_dir,
            rate=rate,
            timeout=timeout,
            retries=retries,
            skip_discovery=skip_discovery,
            known_alive=known,
            skip_known_alive=skip_known_alive,
            max_pending_hosts=65536,
            tag=bid,
            discovery=config.discovery,
        )

    run_batches_parallel(
        stage=stage,
        batches=batches,
        done_ids=done_ids,
        concurrency=concurrency,
        process_batch=_discover_batch,
        aggregate=alive_set,
        aggregate_file=alive_file,
        checkpoint=checkpoint,
        checkpoint_key=checkpoint_key,
    )


def _apply_alive_filters(hosts: set[str], config: AppConfig, alive_file: Path) -> set[str]:
    filtered = set(
        filter_alive_hosts(
            sorted(hosts),
            exclude_hosts=config.discovery.exclude_alive,
            exclude_last_octets=config.discovery.exclude_last_octets,
        )
    )
    write_lines(alive_file, sorted(filtered))
    return filtered


def run_discovery_stage(
    *,
    all_targets: list[str],
    config: AppConfig,
    profile: ProfileConfig,
    output_dir: Path,
    alive_file: Path,
    timeout: int,
    retries: int,
    checkpoint: CheckpointStore,
    resume: bool,
    make_batches: Callable[[list[str]], list[tuple[str, list[str]]]] | None = None,
    seed_alive: set[str] | None = None,
    previous_alive: set[str] | None = None,
    previous_alive_source: str = "",
) -> list[str]:
    """Run wave-1 (batched) and optional adaptive wave-2 host discovery."""
    if resume and checkpoint.is_done("discover"):
        return sorted(set(read_lines(alive_file)))

    batch_fn = make_batches or (lambda items: _make_batches(config, items))
    alive_set: set[str] = set(read_lines(alive_file)) if resume and alive_file.exists() else set()
    discovery = config.discovery
    runtime = config.runtime
    delta = discovery.delta

    wave1_members = all_targets
    refresh_hosts: list[str] = []
    if delta.enabled and not discovery.skip_discovery and not resume:
        initial_alive, wave1_ips, refresh_hosts = compute_delta_plan(
            all_targets,
            seed_alive=seed_alive or set(),
            previous_alive=previous_alive or set(),
            refresh_rate=delta.refresh_rate,
            refresh_seed=delta.refresh_seed,
            max_scope_hosts=discovery.adaptive.max_gap_hosts,
        )
        alive_set.update(initial_alive)
        wave1_members = wave1_ips
        scope_count = len(
            expand_target_ips(all_targets, max_hosts=discovery.adaptive.max_gap_hosts)
        )
        write_delta_plan(
            output_dir,
            scope_hosts=scope_count,
            initial_alive=alive_set,
            wave1_ips=wave1_ips,
            refresh_ips=refresh_hosts,
            previous_source=previous_alive_source,
        )
        logging.info(
            "discovery delta: scope=%s initial_alive=%s wave1=%s refresh=%s",
            scope_count,
            len(initial_alive),
            len(wave1_ips),
            len(refresh_hosts),
        )
    elif seed_alive and not resume:
        alive_set.update(seed_alive)
        logging.info("discovery seed_alive: pre-seeded %s host(s)", len(seed_alive))

    wave1_done = checkpoint.done_items("discover") if resume else set()
    wave1_batches = batch_fn(wave1_members) if wave1_members else []
    disjoint = discovery.disjoint_batches and batches_are_disjoint(wave1_batches)
    skip_known = discovery.skip_known_alive and not disjoint
    wave1_workers = _discover_concurrency(config, wave1_batches, skip_known_alive=skip_known)
    if skip_known and runtime.discover_concurrency > 1:
        logging.info(
            "discovery: overlapping batches — sequential discover with skip_known_alive",
        )
    elif disjoint:
        logging.info(
            "discovery: disjoint batches — parallel discover (concurrency=%s)",
            wave1_workers,
        )
    if discovery.icmp.enabled and not discovery.skip_discovery:
        logging.info(
            "discovery: ICMP pre-filter enabled (tool=%s, timeout_ms=%s)",
            discovery.icmp.tool,
            discovery.icmp.timeout_ms,
        )
    if discovery.tcp_probe.enabled and not discovery.skip_discovery:
        logging.info(
            "discovery: TCP probe enabled (ports=%s)",
            discovery.tcp_probe.ports,
        )
    if not discovery.skip_discovery:
        logging.info("discovery: probe ladder order=%s", discovery.probe_order)

    if wave1_batches:
        _run_discover_batches(
            stage="discover",
            checkpoint_key="discover",
            batches=wave1_batches,
            alive_set=alive_set,
            alive_file=alive_file,
            output_dir=output_dir,
            rate=profile.discover_rate,
            timeout=timeout,
            retries=retries,
            skip_discovery=discovery.skip_discovery,
            skip_known_alive=skip_known,
            concurrency=wave1_workers,
            checkpoint=checkpoint,
            done_ids=wave1_done,
            config=config,
        )
        alive_set = _apply_alive_filters(alive_set, config, alive_file)
    elif not resume:
        alive_set = _apply_alive_filters(alive_set, config, alive_file)

    if (
        delta.enabled
        and not discovery.skip_discovery
        and not (resume and checkpoint.is_done("discover-refresh"))
    ):
        if not refresh_hosts and resume:
            refresh_hosts = read_lines(output_dir / "discover" / "delta.refresh.targets.txt")
        if refresh_hosts:
            probe_rate = max(500, profile.discover_rate // 4)
            logging.info(
                "discovery delta refresh: re-probing %s known host(s) at rate %s",
                len(refresh_hosts),
                probe_rate,
            )
            confirmed = host_discovery(
                refresh_hosts,
                output_dir=output_dir,
                rate=probe_rate,
                timeout=timeout,
                retries=retries,
                skip_discovery=False,
                discovery=discovery,
                tag="delta-refresh",
            )
            confirmed_set = set(confirmed)
            for host in refresh_hosts:
                if host not in confirmed_set:
                    alive_set.discard(host)
            alive_set.update(confirmed_set)
            alive_set = _apply_alive_filters(alive_set, config, alive_file)
        checkpoint.mark_done("discover-refresh")

    adaptive = discovery.adaptive
    if adaptive.enabled and not discovery.skip_discovery:
        tracker = CoverageTracker.from_targets(
            all_targets,
            max_scope_hosts=adaptive.max_gap_hosts,
        )
        tracker.mark_found(alive_set)
        gap = tracker.gap()
        stats = tracker.stats()
        logging.info(
            "discovery adaptive: scope=%s found=%s gap=%s (%.1f%%)",
            stats["scope_hosts"],
            stats["found_hosts"],
            stats["gap_hosts"],
            stats["coverage_pct"],
        )
        if len(gap) >= adaptive.min_gap:
            skip_wave2 = (
                adaptive.min_coverage_pct is not None
                and stats["coverage_pct"] >= adaptive.min_coverage_pct
            )
            if skip_wave2:
                logging.info(
                    "discovery wave2: skipped (coverage %.1f%% >= %.1f%%)",
                    stats["coverage_pct"],
                    adaptive.min_coverage_pct,
                )
            else:
                wave2_rate = _wave2_rate(profile, adaptive.wave2_rate)
                logging.info(
                    "discovery wave2: %s gap host(s) at rate %s",
                    len(gap),
                    wave2_rate,
                )
                wave2_batches = batch_fn(gap)
                wave2_disjoint = discovery.disjoint_batches and batches_are_disjoint(wave2_batches)
                wave2_workers = _discover_concurrency(
                    config,
                    wave2_batches,
                    skip_known_alive=True,
                )
                if wave2_disjoint and wave2_workers > 1:
                    logging.info(
                        "discovery wave2: disjoint batches — parallel discover (concurrency=%s)",
                        wave2_workers,
                    )
                wave2_done = checkpoint.done_items("discover-wave2") if resume else set()
                _run_discover_batches(
                    stage="discover-wave2",
                    checkpoint_key="discover-wave2",
                    batches=wave2_batches,
                    alive_set=alive_set,
                    alive_file=alive_file,
                    output_dir=output_dir,
                    rate=wave2_rate,
                    timeout=timeout,
                    retries=retries,
                    skip_discovery=False,
                    skip_known_alive=True,
                    concurrency=wave2_workers,
                    checkpoint=checkpoint,
                    done_ids=wave2_done,
                    config=config,
                )
                alive_set = _apply_alive_filters(alive_set, config, alive_file)
        checkpoint.mark_done("discover-wave2")

    if not discovery.skip_discovery:
        merge_discovery_stats(output_dir)

    checkpoint.mark_done("discover")
    return sorted(alive_set)


def verify_alive_without_ports(
    *,
    alive_hosts: list[str],
    open_ports: list[str],
    config: AppConfig,
    profile: ProfileConfig,
    output_dir: Path,
    timeout: int,
    retries: int,
) -> list[str]:
    """Re-probe alive hosts with no open ports at a lower rate; drop unconfirmed."""
    verify = config.discovery.verify
    if not verify.enabled or config.discovery.skip_discovery:
        return alive_hosts

    hosts_with_ports: set[str] = set()
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is not None:
            hosts_with_ports.add(parsed.host)

    suspects = sorted({host for host in alive_hosts if host not in hosts_with_ports})
    if not suspects:
        return alive_hosts

    rate = verify.rate if verify.rate is not None else max(500, profile.discover_rate // 4)
    logging.info(
        "discovery verify: re-probing %s alive host(s) without open ports at rate %s",
        len(suspects),
        rate,
    )
    confirmed = host_discovery(
        suspects,
        output_dir=output_dir,
        rate=rate,
        timeout=timeout,
        retries=retries,
        skip_discovery=False,
        discovery=config.discovery,
        tag="verify",
    )
    confirmed_set = set(confirmed)
    kept = sorted({host for host in alive_hosts if host in hosts_with_ports or host in confirmed_set})
    dropped = len(alive_hosts) - len(kept)
    if dropped:
        logging.info("discovery verify: dropped %s unconfirmed alive host(s)", dropped)
    return kept
