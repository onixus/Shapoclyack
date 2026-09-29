"""PR #491 review regressions: outcome-aware cache, invalidation and IPv6."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.pipeline import pulse_probe as pp
from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.pulse_plan import plan_tcp_probe
from scanner.pipeline.pulse_progress import (
    COMPLETION_SCHEMA,
    completed_hosts,
    completion_manifest,
    retain_completed_payload,
)


def payload(*pairs):
    return {"open": [{"ip": host, "port": port, "protocol": "tcp"} for host, port in pairs]}


def cached(grouped):
    result = payload(*((h, p) for h, ports in grouped.items() for p in ports))
    result["completion"] = completion_manifest(grouped)
    return result


def test_failed_replay_must_not_revalidate_a_stale_checkpoint():
    grouped, stale = {"192.0.2.1": [443]}, {"192.0.2.1"}
    assert retain_completed_payload(grouped, stale, {})[0] == set()
    failed = payload(("192.0.2.1", 443))
    failed["chunks"] = [{"hosts": list(stale), "ports": [443], "returncode": 2,
                         "resolved": False, "unresolved_hosts": list(stale)}]
    assert completed_hosts(grouped, failed, 2) == set()
    assert retain_completed_payload(grouped, stale, failed)[0] == set()


def test_ipv6_aliases_must_not_drop_a_retained_endpoint():
    short, expanded = "2001:db8::1", "2001:0db8:0:0:0:0:0:1"
    grouped = {short: [22], expanded: [443]}
    previous = cached(grouped)
    previous["findings"] = [{"ip": short, "port": p, "cve_id": f"CVE-2023-{p:04d}"} for p in (22, 443)]
    previous["tls"] = [{"ip": short, "port": p} for p in (22, 443)]
    done, kept = retain_completed_payload(grouped, set(grouped), previous)
    assert done == set(grouped)
    assert plan_tcp_probe(grouped, done_hosts=done) == ()
    for field in ("open", "findings", "tls"):
        assert {row["port"] for row in kept[field]} == {22, 443}
    # Receipts and all evidence must also survive a second zero-work pass.
    assert retain_completed_payload(grouped, done, kept) == (done, kept)


@pytest.mark.parametrize("receipt", [None, {}, {"schema": "unknown", "hosts": {}},
    {"schema": COMPLETION_SCHEMA, "hosts": []},
    *({"schema": COMPLETION_SCHEMA, "hosts": {"192.0.2.1": record}} for record in [
        None, {}, {"ports": [443]}, {"ports": [443], "returncode": 2},
        {"ports": [443], "returncode": False}, {"ports": [443], "returncode": "0"},
        {"ports": ["443"], "returncode": 0}, {"ports": [0], "returncode": 0},
        {"ports": [65536], "returncode": 0}, {"ports": [True], "returncode": 0},
        {"ports": [], "returncode": 0}, {"ports": None, "returncode": 0},
    ]),
])
def test_missing_invalid_or_unsuccessful_receipt_never_implies_success(receipt):
    previous = payload(("192.0.2.1", 443))
    previous["completion"] = receipt
    done, kept = retain_completed_payload({"192.0.2.1": [443]}, {"192.0.2.1"}, previous)
    assert done == set()
    assert kept["open"] == []


def test_receipt_does_not_replace_missing_or_partial_endpoint_evidence():
    previous = cached({"192.0.2.1": [22, 443]})
    previous["open"].pop()
    assert retain_completed_payload({"192.0.2.1": [22, 443]}, {"192.0.2.1"}, previous)[0] == set()


def test_receipt_cannot_complete_an_unobserved_new_port_or_dns_alias():
    previous = cached({"192.0.2.1": [443]})
    previous["open"].append({"ip": "192.0.2.1", "port": 22})
    assert retain_completed_payload({"192.0.2.1": [22, 443]}, {"192.0.2.1"}, previous)[0] == set()
    assert retain_completed_payload({"site.example": [443]}, {"site.example"}, previous)[0] == set()


def test_checkpoint_restart_replaces_stale_marks_and_preserves_other_stages(tmp_path):
    store = CheckpointStore(tmp_path / "checkpoint.json")
    for stage in ("pulse", "nse"):
        store.mark_done(stage)
        store.mark_item_done(stage, "stale")
    store.restart_stage("pulse", iter(["verified"]))
    restored = CheckpointStore(store.state_file)
    assert not restored.is_done("pulse")
    assert restored.done_items("pulse") == {"verified"}
    assert restored.is_done("nse")
    assert restored.done_items("nse") == {"stale"}
    restored.restart_stage("pulse")
    assert CheckpointStore(store.state_file).done_items("pulse") == set()


@pytest.fixture
def driver(monkeypatch):
    calls = []
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "fixture")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    monkeypatch.setattr(pp.time, "sleep", lambda _: None)

    def install(code=0, before_spawn=None):
        def run(command, **kwargs):
            if before_spawn:
                before_spawn()
            hosts = Path(command[command.index("--targets-file") + 1]).read_text().splitlines()
            ports = [int(p) for p in command[command.index("-p") + 1].split(",")]
            pairs = [(h, p) for h in hosts for p in ports]
            calls.append(pairs)
            result = payload(*pairs)
            result["os"] = [{"ip": h, "family": "Linux"} for h in hosts]
            result["findings"] = [{"ip": h, "port": p, "cve_id": "CVE-2023-0001"} for h, p in pairs]
            result["tls"] = [{"ip": h, "port": p, "subject_cn": "fixture"} for h, p in pairs]
            return subprocess.CompletedProcess(command, code, json.dumps(result), "")
        monkeypatch.setattr(pp, "run_command", run)
        return calls
    return install


def test_failed_replay_invalidates_checkpoint_before_spawn_and_is_retried(tmp_path, driver):
    path = tmp_path / "checkpoint.json"
    store = CheckpointStore(path)
    store.mark_item_done("pulse", "192.0.2.1")
    store.mark_done("pulse")

    def check_invalidated():
        disk = CheckpointStore(path)
        assert not disk.is_done("pulse")
        assert disk.done_items("pulse") == set()

    def run():
        disk = CheckpointStore(path)
        pp.run_pulse_probe(["192.0.2.1:443"], output_dir=tmp_path,
            done_hosts=disk.done_items("pulse"),
            on_resume_validated=lambda valid: disk.restart_stage("pulse", valid),
            on_host_done=lambda host: disk.mark_item_done("pulse", host))

    calls = driver(2, check_invalidated)
    run()
    assert CheckpointStore(path).done_items("pulse") == set()
    previous = json.loads((tmp_path / "pulse/raw.json").read_text())
    assert previous["completion"]["hosts"] == {}
    assert previous["open"]  # Partial evidence was not discarded.
    assert retain_completed_payload({"192.0.2.1": [443]}, {"192.0.2.1"}, previous)[0] == set()
    driver(0, check_invalidated)
    run()
    assert len(calls) == 2
    assert CheckpointStore(path).done_items("pulse") == {"192.0.2.1"}
    run()
    assert len(calls) == 2  # Verified success is reusable, including after chunks reset.
    run()
    assert len(calls) == 2


def test_receipts_and_canonical_evidence_survive_multiple_partial_and_zero_work_passes(tmp_path, driver):
    calls = driver()
    pp.run_pulse_probe(["192.0.2.1:443"], output_dir=tmp_path)
    driver(2)
    pp.run_pulse_probe(["192.0.2.1:443", "192.0.2.2:22"], output_dir=tmp_path,
                       done_hosts={"192.0.2.1"})
    assert calls[-1] == [("192.0.2.2", 22)]
    driver(0)
    pp.run_pulse_probe(["192.0.2.1:443", "192.0.2.2:22"], output_dir=tmp_path,
                       done_hosts={"192.0.2.1", "192.0.2.2"})
    assert calls[-1] == [("192.0.2.2", 22)]
    for _ in range(2):
        pp.run_pulse_probe(["192.0.2.1:443", "192.0.2.2:22"], output_dir=tmp_path,
                           done_hosts={"192.0.2.1", "192.0.2.2"})
    assert len(calls) == 3
    raw = json.loads((tmp_path / "pulse/raw.json").read_text())
    assert raw["chunks"] == []
    assert set(raw["completion"]["hosts"]) == {"192.0.2.1", "192.0.2.2"}
    for field in ("open", "os", "findings", "tls"):
        assert {row["ip"] for row in raw[field]} == {"192.0.2.1", "192.0.2.2"}


def test_ipv6_is_normalized_consistently_in_input_receipts_and_checkpoint(tmp_path, driver):
    short, expanded = "2001:db8::1", "2001:0db8:0:0:0:0:0:1"
    calls = driver()
    endpoints = [f"[{short}]:22", f"[{expanded}]:443", f"[{expanded}]:22"]
    pp.run_pulse_probe(endpoints, output_dir=tmp_path)
    assert calls == [[(short, 22), (short, 443)]]
    validated = []
    pp.run_pulse_probe(endpoints, output_dir=tmp_path, done_hosts={expanded},
                       on_resume_validated=validated.append)
    assert validated == [{short}]
    assert len(calls) == 1
    raw = json.loads((tmp_path / "pulse/raw.json").read_text())
    assert {row["port"] for row in raw["open"]} == {22, 443}
    assert raw["adapter"]["input_unique_tcp_endpoints"] == 2


def test_failed_checkpoint_reconciliation_prevents_spawn(tmp_path, driver):
    calls = driver()
    def reject(_):
        raise OSError("checkpoint storage unavailable")
    with pytest.raises(OSError, match="checkpoint storage"):
        pp.run_pulse_probe(["192.0.2.1:443"], output_dir=tmp_path, on_resume_validated=reject)
    assert calls == []
