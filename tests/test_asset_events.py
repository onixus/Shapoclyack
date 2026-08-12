"""Phase 10.2 — asset-level event bus (subjects, envelopes, publish plumbing)."""

from __future__ import annotations

import json
from pathlib import Path

from api.services import asset_events, nats_bus


def _diff(events: list[dict]) -> dict:
    return {"has_changes": bool(events), "events": events}


def test_subject_puts_tenant_before_kind_and_sanitizes_tokens():
    assert (
        nats_bus.asset_event_subject("ten_acme", "new_cve") == "events.asset.ten_acme.new_cve"
    )
    # A tenant id carrying NATS separators/wildcards must not reshape the tree.
    assert nats_bus.asset_event_subject("a.b*c>d", "new_cve") == "events.asset.a_b_c_d.new_cve"
    assert nats_bus.asset_event_subject("", "") == "events.asset.default.unknown"


def test_build_events_wraps_each_kind_and_keeps_payload_under_data():
    diff = _diff(
        [
            {"kind": "new_asset", "host": "10.0.0.1"},
            {"kind": "new_open_port", "host": "10.0.0.1", "port": 443, "protocol": "tcp"},
            {"kind": "new_cve", "host": "10.0.0.1", "port": 443, "cve": "CVE-2024-1", "severity": "high"},
            {
                "kind": "cert_expiring",
                "issue_kind": "cert_expiring_soon",
                "host": "10.0.0.1",
                "port": "443",
                "days": 9,
            },
        ]
    )
    envelopes, dropped = asset_events.build_events(diff, tenant_id="ten_acme", run_id="r1", job_id="j1")

    assert dropped == 0
    assert [e["kind"] for e in envelopes] == [
        "new_asset",
        "new_open_port",
        "new_cve",
        "cert_expiring",
    ]
    for envelope in envelopes:
        assert envelope["tenant_id"] == "ten_acme"
        assert envelope["run_id"] == "r1"
        assert envelope["job_id"] == "j1"
        assert envelope["source"] == "run_diff"
        assert envelope["event_id"]
        assert "kind" not in envelope["data"]
    # Kind-specific fields survive verbatim rather than being flattened away.
    assert envelopes[2]["data"]["severity"] == "high"
    assert envelopes[3]["data"]["issue_kind"] == "cert_expiring_soon"


def test_unknown_kind_is_dropped_so_it_cannot_name_a_subject():
    envelopes, dropped = asset_events.build_events(
        _diff([{"kind": "totally_new", "host": "h"}, {"kind": "new_asset", "host": "h"}]),
        tenant_id="t",
        run_id="r",
    )
    assert dropped == 0
    assert [e["kind"] for e in envelopes] == ["new_asset"]


def test_event_id_is_stable_per_occurrence_and_run_scoped():
    event = {"kind": "new_cve", "host": "h", "port": 443, "cve": "CVE-2024-1"}
    first, _ = asset_events.build_events(_diff([event]), tenant_id="t", run_id="r1")
    replay, _ = asset_events.build_events(_diff([event]), tenant_id="t", run_id="r1")
    later_run, _ = asset_events.build_events(_diff([event]), tenant_id="t", run_id="r2")
    other_tenant, _ = asset_events.build_events(_diff([event]), tenant_id="t2", run_id="r1")

    # A replayed upload dedupes; a re-appearance in a later run does not.
    assert first[0]["event_id"] == replay[0]["event_id"]
    assert first[0]["event_id"] != later_run[0]["event_id"]
    assert first[0]["event_id"] != other_tenant[0]["event_id"]


def test_per_run_cap_reports_the_overflow_instead_of_hiding_it():
    events = [{"kind": "new_asset", "host": f"10.0.0.{i}"} for i in range(10)]
    envelopes, dropped = asset_events.build_events(
        _diff(events), tenant_id="t", run_id="r", max_events=4
    )
    assert len(envelopes) == 4
    assert dropped == 6


def test_missing_or_broken_diff_yields_no_events(tmp_path: Path):
    # A first-ever run writes no diff.json at all.
    assert asset_events.load_run_diff(tmp_path) == {}
    (tmp_path / "diff.json").write_text("{not json", encoding="utf-8")
    assert asset_events.load_run_diff(tmp_path) == {}
    (tmp_path / "diff.json").write_text(json.dumps({"events": "nope"}), encoding="utf-8")
    assert asset_events.build_events(asset_events.load_run_diff(tmp_path), tenant_id="t", run_id="r") == ([], 0)


def test_publish_run_events_is_a_noop_without_a_broker(tmp_path: Path):
    (tmp_path / "diff.json").write_text(
        json.dumps(_diff([{"kind": "new_asset", "host": "10.0.0.1"}])), encoding="utf-8"
    )
    nats_bus.reset_bus_for_tests()
    published = asset_events.publish_run_events(
        nats_url="", run_dir=tmp_path, tenant_id="t", run_id="r"
    )
    assert published == 0


def test_publish_events_uses_the_event_id_as_the_dedupe_msg_id(monkeypatch):
    sent: list[tuple[str, dict, str | None, dict | None]] = []

    class _FakeBus:
        def publish_json(self, subject, payload, *, msg_id=None, headers=None, retries=3):
            sent.append((subject, payload, msg_id, headers))
            return True

        publish_asset_event = nats_bus.NatsBus.publish_asset_event

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: _FakeBus())
    envelopes, _ = asset_events.build_events(
        _diff([{"kind": "new_cve", "host": "h", "port": 443, "cve": "CVE-2024-1"}]),
        tenant_id="ten_acme",
        run_id="r1",
    )
    assert asset_events.publish_events("nats://x:4222", envelopes) == 1

    subject, payload, msg_id, headers = sent[0]
    assert subject == "events.asset.ten_acme.new_cve"
    assert msg_id == envelopes[0]["event_id"]
    assert headers == {"tenant_id": "ten_acme", "event_kind": "new_cve"}
    assert payload["data"]["cve"] == "CVE-2024-1"


def test_a_failed_publish_is_counted_not_raised(monkeypatch):
    class _BrokenBus:
        def publish_asset_event(self, envelope):
            raise RuntimeError("broker gone")

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: _BrokenBus())
    envelopes, _ = asset_events.build_events(
        _diff([{"kind": "new_asset", "host": "h"}]), tenant_id="t", run_id="r"
    )
    assert asset_events.publish_events("nats://x:4222", envelopes) == 0


def test_operator_status_event_carries_the_asset_not_a_run(monkeypatch):
    sent: list[dict] = []

    class _FakeBus:
        def publish_asset_event(self, envelope):
            sent.append(envelope)
            return True

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: _FakeBus())
    assert asset_events.publish_asset_status_event(
        nats_url="nats://x:4222",
        tenant_id="ten_acme",
        kind="decommissioned_host",
        asset_id="asset-1",
        host="10.0.0.1",
        data={"previous_status": "active"},
    )
    assert sent[0]["run_id"] is None
    assert sent[0]["asset_id"] == "asset-1"
    assert sent[0]["source"] == "operator"
    assert sent[0]["data"]["previous_status"] == "active"

    # An unknown kind never reaches the bus.
    assert not asset_events.publish_asset_status_event(
        nats_url="nats://x:4222", tenant_id="t", kind="made_up", asset_id="a"
    )
