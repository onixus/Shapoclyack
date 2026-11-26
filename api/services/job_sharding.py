"""Stable target partitioning for claimable scan job shards (FTT-PULSE-2026-052).

One estate scan can be split into N independent queued jobs so distinct
sensors claim disjoint target sets. Partitioning is pure and deterministic:
the same non-empty target lines and ``shard_count`` always yield the same
shards. Empty / comment lines are dropped before cutting; empty shards are
omitted from the result (fewer than N jobs) rather than creating no-op work.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_SHARD_COUNT = 64
MIN_SHARD_COUNT = 2


@dataclass(frozen=True, slots=True)
class TargetPartition:
    """One shard's newline-joined ranges and domains (may be empty strings)."""

    shard_index: int
    shard_count: int
    ranges: str
    domains: str

    @property
    def is_empty(self) -> bool:
        return not self.ranges.strip() and not self.domains.strip()


def _normalize_lines(text: str | None) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def _round_robin(lines: list[str], shard_count: int) -> list[list[str]]:
    buckets: list[list[str]] = [[] for _ in range(shard_count)]
    for index, line in enumerate(lines):
        buckets[index % shard_count].append(line)
    return buckets


def partition_targets(
    *,
    ranges: str | None,
    domains: str | None,
    shard_count: int,
) -> tuple[TargetPartition, ...]:
    """Split admitted-style target text into stable, disjoint shards.

    Raises ``ValueError`` when ``shard_count`` is out of bounds or when every
    shard would be empty (no usable target lines).
    """
    if shard_count < MIN_SHARD_COUNT or shard_count > MAX_SHARD_COUNT:
        raise ValueError(
            f"shard_count must be between {MIN_SHARD_COUNT} and {MAX_SHARD_COUNT}"
        )
    range_lines = _normalize_lines(ranges)
    domain_lines = _normalize_lines(domains)
    if not range_lines and not domain_lines:
        raise ValueError(
            "sharding requires at least one non-empty ranges or domains line"
        )

    range_buckets = _round_robin(range_lines, shard_count)
    domain_buckets = _round_robin(domain_lines, shard_count)
    partitions = tuple(
        TargetPartition(
            shard_index=index,
            shard_count=shard_count,
            ranges="\n".join(range_buckets[index]),
            domains="\n".join(domain_buckets[index]),
        )
        for index in range(shard_count)
    )
    kept = tuple(part for part in partitions if not part.is_empty)
    if not kept:
        raise ValueError("sharding produced no non-empty partitions")
    # Re-index kept shards so operators see contiguous 0..len-1 while
    # ``shard_count`` remains the requested N (horizontal scale intent).
    return tuple(
        TargetPartition(
            shard_index=index,
            shard_count=shard_count,
            ranges=part.ranges,
            domains=part.domains,
        )
        for index, part in enumerate(kept)
    )
