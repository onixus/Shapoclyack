from __future__ import annotations

from scanner.pipeline.batching import batch_id, expand_batches, single_batch


def test_expand_splits_ipv4_cidr_into_prefix_batches():
    batches = expand_batches(["10.0.0.0/16"], ipv4_prefix=20, max_targets_per_batch=4096)
    # /16 -> 16 x /20
    assert len(batches) == 16
    members = [m for _, ms in batches for m in ms]
    assert "10.0.0.0/20" in members
    assert "10.0.240.0/20" in members
    # each batch holds exactly one /20 CIDR
    assert all(len(ms) == 1 for _, ms in batches)


def test_expand_groups_singletons_into_chunks():
    ips = [f"10.0.0.{i}" for i in range(1, 11)]
    batches = expand_batches(ips, ipv4_prefix=20, max_targets_per_batch=4)
    assert [len(ms) for _, ms in batches] == [4, 4, 2]


def test_expand_does_not_split_ipv6():
    batches = expand_batches(["2001:db8::/32"], ipv4_prefix=20)
    assert len(batches) == 1
    assert batches[0][1] == ["2001:db8::/32"]


def test_expand_keeps_small_ipv4_net_as_single_member():
    # /25 is smaller than /20 threshold -> not split, grouped as a singleton
    batches = expand_batches(["10.0.0.0/25"], ipv4_prefix=20)
    assert len(batches) == 1
    assert batches[0][1] == ["10.0.0.0/25"]


def test_batch_id_is_stable_and_order_independent():
    assert batch_id(["a", "b"]) == batch_id(["b", "a"])
    assert batch_id(["a"]) != batch_id(["b"])


def test_single_batch_groups_everything():
    batches = single_batch(["10.0.0.1", "10.0.0.2"])
    assert len(batches) == 1
    assert batches[0][1] == ["10.0.0.1", "10.0.0.2"]


def test_single_batch_empty():
    assert single_batch([]) == []
