from __future__ import annotations

from scanner.pipeline.discovery_targets import (
    filter_hosts_in_scope,
    host_in_batch_scope,
    pending_discovery_targets,
)


def test_host_in_batch_scope_cidr():
    assert host_in_batch_scope("10.99.0.10", ["10.99.0.0/24"])
    assert not host_in_batch_scope("10.99.1.10", ["10.99.0.0/24"])


def test_filter_hosts_in_scope_drops_out_of_range():
    alive = ["10.99.0.10", "10.99.1.5", "10.99.0.1"]
    assert filter_hosts_in_scope(alive, ["10.99.0.0/24"]) == ["10.99.0.1", "10.99.0.10"]


def test_pending_discovery_targets_excludes_known_alive():
    pending = pending_discovery_targets(
        ["10.99.0.0/29"],
        {"10.99.0.1", "10.99.0.2"},
    )
    assert pending == ["10.99.0.3", "10.99.0.4", "10.99.0.5", "10.99.0.6"]


def test_pending_discovery_targets_empty_when_all_known():
    pending = pending_discovery_targets(
        ["10.0.0.1", "10.0.0.2"],
        {"10.0.0.1", "10.0.0.2"},
    )
    assert pending == []
