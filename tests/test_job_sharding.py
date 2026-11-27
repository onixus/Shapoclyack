"""Unit tests for claimable job target sharding (FTT-PULSE-2026-052)."""

from __future__ import annotations

import pytest

from api.services.job_sharding import partition_targets


def test_partition_is_stable_disjoint_and_complete():
    ranges = "10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/24\n10.0.3.0/24\n"
    domains = "a.example\nb.example\n"
    first = partition_targets(ranges=ranges, domains=domains, shard_count=3)
    second = partition_targets(ranges=ranges, domains=domains, shard_count=3)
    assert first == second
    assert len(first) == 3

    range_lines: list[str] = []
    domain_lines: list[str] = []
    for part in first:
        assert part.shard_count == 3
        range_lines.extend(part.ranges.splitlines() if part.ranges else [])
        domain_lines.extend(part.domains.splitlines() if part.domains else [])
    assert sorted(range_lines) == sorted(
        ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    )
    assert sorted(domain_lines) == ["a.example", "b.example"]
    # Disjoint
    assert len(range_lines) == len(set(range_lines))
    assert len(domain_lines) == len(set(domain_lines))


def test_partition_skips_empty_and_comments():
    parts = partition_targets(
        ranges="# comment\n\n10.0.0.0/8\n10.0.0.0/8\n",
        domains=None,
        shard_count=2,
    )
    assert len(parts) == 1
    assert parts[0].ranges == "10.0.0.0/8"
    # The empty bucket is a gap, not a renumbered shard 0 of a 2-wide group.
    assert parts[0].shard_index == 0
    assert parts[0].shard_count == 2


def test_a_gap_keeps_its_bucket_index():
    """One line that lands past bucket 0 must not be renumbered to shard 0.

    Operators read ``shard_index`` against the requested ``shard_count``. A
    renumbered 0 of a 2-wide group looks like a lost sibling.
    """
    parts = partition_targets(ranges=None, domains="only.example", shard_count=2)
    assert len(parts) == 1
    assert parts[0].shard_index == 0
    assert parts[0].domains == "only.example"

    # Two lines into three buckets: index 2 stays empty and is dropped, and
    # the kept shards keep the buckets they were cut into.
    parts = partition_targets(
        ranges="10.0.0.0/24\n10.0.1.0/24", domains=None, shard_count=3
    )
    assert [part.shard_index for part in parts] == [0, 1]
    assert all(part.shard_count == 3 for part in parts)


def test_partition_rejects_bad_count_and_empty_input():
    with pytest.raises(ValueError):
        partition_targets(ranges="10.0.0.0/8", domains=None, shard_count=1)
    with pytest.raises(ValueError):
        partition_targets(ranges="10.0.0.0/8", domains=None, shard_count=100)
    with pytest.raises(ValueError):
        partition_targets(ranges="# only\n", domains=None, shard_count=2)


def test_shard_count_requires_agent_execution_mode():
    """Local mode must refuse fan-out: uncancellable threads + API-pod load."""
    from api.services.job_sharding import require_agent_execution_for_shards

    require_agent_execution_for_shards("agent")
    with pytest.raises(ValueError, match="job_execution_mode=agent"):
        require_agent_execution_for_shards("local")
