"""Unit tests for Stage2 enrichment queue (FTT-PULSE-2026-054)."""

from __future__ import annotations

import pytest

from api.services import scan_intents
from api.services import stage2_enrichment as s2
from scanner.pipeline import config_overlay


def test_hosts_from_open_ports_are_unique_stable_and_skip_junk():
    text = """
# comment
10.0.0.1:443
10.0.0.1:80/tcp
10.0.0.2:22
not-an-endpoint
10.0.0.2:443

[2001:db8::1]:443
"""
    hosts = s2.hosts_from_open_ports_text(text)
    assert hosts == ("10.0.0.1", "10.0.0.2", "2001:db8::1")


def test_partition_hosts_round_robin_omits_empty_and_caps():
    hosts = tuple(f"10.0.0.{i}" for i in range(1, 6))
    parts = s2.partition_hosts(hosts, shard_count=3)
    assert len(parts) == 3
    assert sorted(h for part in parts for h in part) == sorted(hosts)
    # Disjoint
    flat = [h for part in parts for h in part]
    assert len(flat) == len(set(flat))

    with pytest.raises(ValueError):
        s2.partition_hosts(hosts, shard_count=0)
    with pytest.raises(ValueError):
        s2.partition_hosts(hosts, shard_count=s2.MAX_STAGE2_SHARDS + 1)
    assert s2.partition_hosts((), shard_count=2) == ()


def test_stage2_width_uses_requested_shard_count_not_realized_partitions():
    """``shard_of`` is how many buckets were non-empty, not the operator N."""
    options = {"shard_count": 8, "shard_of": 3, "shard_group_id": "abc"}
    requested = options.get("shard_count")
    assert requested == 8
    assert s2.stage2_shard_count(20, requested=int(requested)) == 8
    # The old lookup (shard_of first) would have opened only 3 Stage2 jobs.
    assert s2.stage2_shard_count(20, requested=int(options["shard_of"])) == 3


def test_stage2_shard_count_respects_caps_and_host_count():
    assert s2.stage2_shard_count(0) == 0
    assert s2.stage2_shard_count(5) == 1
    assert s2.stage2_shard_count(5, requested=3) == 3
    assert s2.stage2_shard_count(2, requested=8) == 2
    assert s2.stage2_shard_count(100, requested=s2.MAX_STAGE2_SHARDS + 10) == (
        s2.MAX_STAGE2_SHARDS
    )


def test_should_enqueue_guards():
    assert s2.should_enqueue_stage2({"stage2_enrichment": True, "intent": "inventory"})
    assert s2.should_enqueue_stage2(
        {"stage2_enrichment": True, "intent": "inventory_services"}
    )
    # Flag off
    assert not s2.should_enqueue_stage2({"intent": "inventory"})
    # Recursion
    assert not s2.should_enqueue_stage2(
        {"stage2_enrichment": True, "intent": "inventory", "stage2_of": "parent"}
    )
    # Already-assessment intent must not spawn Stage2
    assert not s2.should_enqueue_stage2(
        {"stage2_enrichment": True, "intent": "full"}
    )
    # Legacy (no intent) with flag — allow (Stage1-shaped by operator)
    assert s2.should_enqueue_stage2({"stage2_enrichment": True})


def test_require_agent_execution_for_stage2():
    s2.require_agent_execution_for_stage2("agent")
    with pytest.raises(ValueError, match="job_execution_mode=agent"):
        s2.require_agent_execution_for_stage2("local")


def test_build_stage2_request_is_enrichment_without_recursion():
    req = s2.build_stage2_request(
        {
            "requested_mode": "fast",
            "surface": "internal",
            "agent_group": "edge",
            "notify": True,
        },
        hosts=("10.0.0.1", "10.0.0.2"),
        tenant_id="acme",
    )
    assert req.intent == "enrichment"
    assert req.stage2_enrichment is False
    assert req.ranges == "10.0.0.1\n10.0.0.2"
    assert req.tenant_id == "acme"
    assert req.surface == "internal"
    assert req.agent_group == "edge"
    assert req.mode == "fast"
    assert req.notify is True


def test_build_stage2_meta_links_parent():
    meta = s2.build_stage2_meta(
        group_id="abc",
        index=1,
        count=3,
        parent_job_id="parent1",
        parent_run_id="run1",
    )
    assert meta == {
        "stage2_group_id": "abc",
        "stage2_index": 1,
        "stage2_count": 3,
        "stage2_of": "parent1",
        "stage2_of_run_id": "run1",
    }


def test_enrichment_intent_overlay_paths_are_v4_allowed():
    resolved = scan_intents.resolve_scan_options(
        intent="enrichment", mode="balanced", delta=False, skip_nse=False
    )
    assert resolved.intent == "enrichment"
    assert resolved.config_extra["tls_posture"]["enumerate_ciphers"] is True
    assert resolved.config_extra["service_probe"]["pulse"]["plugins"] is True
    assert resolved.config_extra["nuclei"]["enabled"] is True
    # Must not ask for paths a v4 sensor would refuse.
    flat = config_overlay._flatten(resolved.config_extra)  # noqa: SLF001
    unknown = set(flat) - config_overlay.OVERLAY_PATHS
    assert unknown == set(), f"enrichment intent uses non-overlay paths: {unknown}"


def test_post_publication_includes_stage2_on_success():
    from api.services import job_states
    from api.services import run_completion

    assert run_completion.STAGE2 in run_completion.actions_for(job_states.SUCCEEDED)
    assert run_completion.STAGE2 not in run_completion.actions_for(job_states.FAILED)
    assert run_completion.STAGE2 not in run_completion.actions_for(
        job_states.CANCELLED
    )
