from __future__ import annotations

from scanner.pipeline.alive_filters import filter_alive_hosts
from scanner.pipeline.coverage_tracker import CoverageTracker, batches_are_disjoint, expand_target_ips


def test_expand_target_ips_cidr():
    ips = expand_target_ips(["10.99.0.0/29"])
    assert ips == {"10.99.0.1", "10.99.0.2", "10.99.0.3", "10.99.0.4", "10.99.0.5", "10.99.0.6"}


def test_coverage_tracker_gap():
    tracker = CoverageTracker.from_targets(["10.99.0.0/29"])
    tracker.mark_found(["10.99.0.1", "10.99.0.2"])
    assert tracker.gap() == ["10.99.0.3", "10.99.0.4", "10.99.0.5", "10.99.0.6"]
    assert tracker.stats()["gap_hosts"] == 4


def test_batches_are_disjoint_for_subnets():
    batches = [
        ("a", ["10.99.0.0/24"]),
        ("b", ["10.99.1.0/24"]),
    ]
    assert batches_are_disjoint(batches)


def test_batches_are_disjoint_false_when_overlap():
    batches = [
        ("a", ["10.99.0.0/24"]),
        ("b", ["10.99.0.0/30"]),
    ]
    assert not batches_are_disjoint(batches)


def test_filter_alive_hosts_last_octet():
    alive = ["10.99.0.1", "10.99.0.10", "10.99.1.1"]
    assert filter_alive_hosts(alive, exclude_last_octets=[1]) == ["10.99.0.10"]


def test_filter_alive_hosts_explicit():
    alive = ["10.99.0.1", "10.99.0.10"]
    assert filter_alive_hosts(alive, exclude_hosts=["10.99.0.10"]) == ["10.99.0.1"]
