"""Exact endpoint planning and resume regressions; never invoke an external scan."""

from __future__ import annotations

import json
import random
import subprocess
from pathlib import Path

import pytest

from scanner.pipeline import pulse_probe as pp
from scanner.pipeline.pulse_plan import plan_tcp_probe
from scanner.pipeline.pulse_progress import completed_hosts


def _pairs(chunks):
    return [(host, port) for chunk in chunks for host in chunk.hosts for port in chunk.ports]


@pytest.mark.parametrize("size", [-1, 0, 1, 2, 3, 64, 65])
@pytest.mark.parametrize("seed", range(20))
def test_plan_is_an_exact_deterministic_partition(size, seed):
    rng = random.Random(seed)
    grouped = {
        host: [rng.choice([22, 80, 443, 5432]) for _ in range(rng.randrange(6))]
        for host in ["10.0.0.1", "10.0.0.2", "2001:db8::1", "app.example", "10.0.0.3"]
    }
    done = {host for host in grouped if rng.randrange(4) == 0}
    plan = plan_tcp_probe(grouped, chunk_hosts=size, done_hosts=iter(done))
    expected = {(h, p) for h, ports in grouped.items() if h not in done for p in ports}
    pairs = _pairs(plan)
    assert set(pairs) == expected
    assert len(pairs) == len(expected)  # No duplicate scheduled work either.
    assert all(0 < len(chunk.hosts) <= max(1, size) for chunk in plan)
    assert sum(chunk.endpoint_count for chunk in plan) == len(expected)
    reordered = {h: list(reversed(ports)) for h, ports in reversed(list(grouped.items()))}
    assert plan == plan_tcp_probe(reordered, chunk_hosts=size, done_hosts=done)


def test_heterogeneous_example_is_three_pairs_not_nine():
    plan = plan_tcp_probe({"A": [22], "B": [443], "C": [5432]})
    assert _pairs(plan) == [("A", 22), ("B", 443), ("C", 5432)]


def test_identical_signatures_batch_hosts_not_individual_endpoints():
    plan = plan_tcp_probe({f"10.0.0.{i}": [443, 22, 443] for i in range(1, 66)}, chunk_hosts=64)
    assert [len(chunk.hosts) for chunk in plan] == [64, 1]
    assert all(chunk.ports == (22, 443) for chunk in plan)


def test_normalized_input_skips_udp_invalid_duplicates_and_excluded_ports():
    # Policy/discovery already excluded port 8080; planning must not reintroduce it.
    grouped = pp._group_tcp_ports([
        "10.0.0.1:22", "10.0.0.1:22/tcp", "10.0.0.1:53/udp",
        "[2001:db8::1]:443/tcp", "invalid", "10.0.0.1:0", "10.0.0.1:65536",
    ])
    assert set(_pairs(plan_tcp_probe(grouped))) == {("10.0.0.1", 22), ("2001:db8::1", 443)}
    assert plan_tcp_probe({}) == ()


def _command_pairs(command):
    hosts = Path(command[command.index("--targets-file") + 1]).read_text().splitlines()
    ports = [int(p) for p in command[command.index("-p") + 1].split(",")]
    return [(host, port) for host in hosts for port in ports]


def _payload(pairs):
    return {"open": [{"ip": host, "port": port, "service": "fixture", "protocol": "tcp"} for host, port in pairs]}


@pytest.fixture
def driver(monkeypatch):
    calls = []
    sleeps = []
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "fixture-pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    monkeypatch.setattr(pp.time, "sleep", sleeps.append)

    def install(responder=None):
        def run(command, **kwargs):
            pairs = _command_pairs(command)
            calls.append((command, pairs, kwargs))
            if responder is not None:
                body, code, stderr = responder(len(calls), pairs)
            else:
                body, code, stderr = _payload(pairs), 0, ""
            return subprocess.CompletedProcess(command, code, json.dumps(body) if body is not None else "", stderr)
        monkeypatch.setattr(pp, "run_command", run)
        return calls, sleeps

    return install


def _raw(path):
    return json.loads((path / "pulse" / "raw.json").read_text())


def test_adapter_argv_preserves_scope_and_load_controls(tmp_path, driver):
    calls, _ = driver()
    endpoints = ["10.0.0.1:22/tcp", "10.0.0.2:443/tcp", "[2001:db8::1]:5432/tcp", "10.0.0.1:53/udp"]
    done = []
    pp.run_pulse_probe(endpoints, output_dir=tmp_path, concurrency=7, rate=11, host_parallel=2,
                       adaptive=False, timeout_ms=123, retries=2, syn=True, on_host_done=done.append)
    assert {pair for _, pairs, _ in calls for pair in pairs} == {
        ("10.0.0.1", 22), ("10.0.0.2", 443), ("2001:db8::1", 5432),
    }
    for command, _, kwargs in calls:
        assert command[command.index("-c") + 1] == "7"
        assert command[command.index("--rate") + 1] == "11"
        assert command[command.index("--host-parallel") + 1] == "2"
        assert command[command.index("-t") + 1] == "123"
        assert "--syn" in command and "--adaptive" not in command
        assert "--checkpoint" not in command and "--resume" not in command
        assert kwargs["retries"] == 2
    assert set(done) == {"10.0.0.1", "10.0.0.2", "2001:db8::1"}
    stats = _raw(tmp_path)["adapter"]
    assert stats["input_unique_tcp_endpoints"] == stats["pending_unique_tcp_endpoints"] == 3
    assert stats["planned_tcp_combinations"] == stats["planned_chunks"] == stats["chunk_probe_calls"] == 3
    assert stats["adapter_retry_calls"] == 0


def test_empty_udp_input_records_zero_work_without_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(pp, "_pulse_available", lambda _: pytest.fail("must not need a binary"))
    pp.run_pulse_probe(["10.0.0.1:53/udp"], output_dir=tmp_path)
    assert _raw(tmp_path)["adapter"]["planned_tcp_combinations"] == 0
    assert _raw(tmp_path)["adapter"]["chunk_probe_calls"] == 0


@pytest.mark.parametrize("kind", ["settle", "crash", "raw-sockets"])
def test_retry_is_same_endpoint_set_and_counted_separately(tmp_path, driver, kind):
    def respond(index, pairs):
        if index == 1:
            if kind == "settle":
                return {"open": []}, 0, ""
            return None, 1, "OS detection needs raw sockets" if kind == "raw-sockets" else "panic"
        return _payload(pairs), 0, ""
    calls, sleeps = driver(respond)
    pp.run_pulse_probe(["10.0.0.1:22", "10.0.0.2:443"], output_dir=tmp_path)
    assert len(calls) == 3
    assert calls[0][1] == calls[1][1] == [("10.0.0.1", 22)]
    assert calls[2][1] == [("10.0.0.2", 443)]
    assert sleeps == ([15] if kind == "settle" else [])
    stats = _raw(tmp_path)["adapter"]
    assert stats["planned_tcp_combinations"] == stats["planned_chunks"] == 2
    assert stats["chunk_probe_calls"] == 3
    assert stats["adapter_retry_calls"] == stats["adapter_retry_tcp_combinations"] == 1
    if kind == "raw-sockets":
        assert "--os" in calls[0][0]
        assert all("--os" not in call[0] for call in calls[1:])


@pytest.mark.parametrize("kind", ["partial-host", "partial-port", "failed-json"])
def test_partial_results_are_not_false_completion(tmp_path, driver, kind):
    endpoints = ["10.0.0.1:22", "10.0.0.2:22"] if kind == "partial-host" else ["10.0.0.1:22", "10.0.0.1:443"]
    driver(lambda _, pairs: (_payload(pairs[:1]), 2 if kind == "failed-json" else 0, ""))
    done, unresolved = [], []
    pp.run_pulse_probe(endpoints, output_dir=tmp_path, on_host_done=done.append, on_unresolved=unresolved.extend)
    assert done == (["10.0.0.1"] if kind == "partial-host" else [])
    assert unresolved == (["10.0.0.2"] if kind == "partial-host" else ["10.0.0.1"])
    assert len(_raw(tmp_path)["open"]) == 1  # Do not discard partial evidence.
    assert _raw(tmp_path)["chunks"][0]["resolved"] is False


def test_resume_replans_pending_and_keeps_completed_services(tmp_path, driver):
    driver(lambda _, pairs: (_payload(pairs[:1]), 0, ""))
    endpoints = ["10.0.0.1:22", "10.0.0.2:22"]
    done = []
    pp.run_pulse_probe(endpoints, output_dir=tmp_path, on_host_done=done.append)
    assert done == ["10.0.0.1"]
    calls, _ = driver()
    offset = len(calls)
    pp.run_pulse_probe(endpoints, output_dir=tmp_path, done_hosts=done, chunk_hosts=1)
    assert [pairs for _, pairs, _ in calls[offset:]] == [[("10.0.0.2", 22)]]
    services = json.loads((tmp_path / "services.json").read_text())
    assert {(s["ip"], s["port"]) for s in services} == {("10.0.0.1", 22), ("10.0.0.2", 22)}
    assert _raw(tmp_path)["adapter"]["resumed_hosts"] == 1
    assert _raw(tmp_path)["adapter"]["planned_tcp_combinations"] == 1
    offset = len(calls)
    pp.run_pulse_probe(endpoints, output_dir=tmp_path, done_hosts=["10.0.0.1", "10.0.0.2"])
    assert len(calls) == offset  # All done must NOT erase artifacts.
    assert len(json.loads((tmp_path / "services.json").read_text())) == 2


@pytest.mark.parametrize("cached", [None, "broken json", "[]", '{"open": 12}'])
def test_missing_checkpoint_evidence_replays_instead_of_skipping(tmp_path, driver, cached):
    calls, _ = driver()
    if cached is not None:
        (tmp_path / "pulse").mkdir()
        (tmp_path / "pulse" / "raw.json").write_text(cached)
    pp.run_pulse_probe(["10.0.0.1:22"], output_dir=tmp_path, done_hosts=["10.0.0.1"])
    assert len(calls) == 1
    assert _raw(tmp_path)["adapter"]["replayed_checkpoint_hosts"] == 1


def test_legacy_partial_checkpoint_and_overscan_are_not_trusted(tmp_path, driver):
    calls, _ = driver()
    (tmp_path / "pulse").mkdir()
    (tmp_path / "pulse" / "raw.json").write_text(json.dumps(_payload([
        ("10.0.0.1", 22), ("10.0.0.1", 8080), ("10.0.0.99", 22),
    ])))
    pp.run_pulse_probe(["10.0.0.1:22", "10.0.0.2:443"], output_dir=tmp_path,
                       done_hosts=["10.0.0.1", "10.0.0.2"])
    assert [pairs for _, pairs, _ in calls] == [[("10.0.0.2", 443)]]
    assert {(r["ip"], r["port"]) for r in _raw(tmp_path)["open"]} == {("10.0.0.1", 22), ("10.0.0.2", 443)}
    assert _raw(tmp_path)["adapter"]["replayed_checkpoint_hosts"] == 1


def test_completion_normalizes_literal_ipv6_but_never_infers_dns():
    grouped = {"2001:db8::1": [443], "site.example": [443]}
    assert completed_hosts(grouped, _payload([("2001:0db8:0:0:0:0:0:1", 443)]), 0) == {"2001:db8::1"}
    assert completed_hosts({"site.example": [443]}, _payload([("10.0.0.1", 443)]), 0) == set()


@pytest.mark.parametrize("row", [
    {"ip": "10.0.0.1", "port": 22, "protocol": "udp"},
    {"ip": "10.0.0.1", "port": 22, "protocol": "other"},
    {"ip": "10.0.0.1", "port": 22, "state": "closed"},
    {"ip": "10.0.0.1", "port": 22, "open": False},
    {"ip": "10.0.0.1", "port": "invalid"}, None,
])
def test_unusable_observation_cannot_complete_host(row):
    assert completed_hosts({"10.0.0.1": [22]}, {"open": [row]}, 0) == set()


def test_crash_loop_is_bounded_and_uses_exact_chunks(tmp_path, driver):
    calls, sleeps = driver(lambda _, pairs: (None, 2, "panic"))
    with pytest.raises(pp.PulseCrashLoopError):
        pp.run_pulse_probe([f"10.0.0.{i}:{20+i}" for i in range(1, 10)], output_dir=tmp_path)
    assert len(calls) == 2 * pp.MAX_CONSECUTIVE_CRASHED_CHUNKS
    assert sleeps == []
    assert all(len(pairs) == 1 for _, pairs, _ in calls)


def test_missing_binary_still_fails_loud(tmp_path, monkeypatch):
    monkeypatch.setattr(pp, "_pulse_available", lambda _: False)
    with pytest.raises(FileNotFoundError, match="install-pulse.sh"):
        pp.run_pulse_probe(["10.0.0.1:22"], output_dir=tmp_path)


def test_resume_keeps_completed_os_cve_and_tls_evidence(tmp_path, driver):
    def respond(_, pairs):
        payload = _payload(pairs)
        host, port = pairs[0]
        payload.update({
            "os": [{"ip": host, "family": "Linux", "confidence": 72}],
            "findings": [{"ip": host, "port": port, "cve_id": "CVE-2023-0001"}],
            "tls": [{"ip": host, "port": port, "subject_cn": "fixture.example"}],
        })
        return payload, 0, ""
    driver(respond)
    pp.run_pulse_probe(["10.0.0.1:443"], output_dir=tmp_path)
    calls, _ = driver()
    offset = len(calls)
    pp.run_pulse_probe(["10.0.0.1:443", "10.0.0.2:22"], output_dir=tmp_path, done_hosts=["10.0.0.1"])
    assert [pairs for _, pairs, _ in calls[offset:]] == [[("10.0.0.2", 22)]]
    raw = _raw(tmp_path)
    assert raw["os"][0]["family"] == "Linux"
    assert raw["findings"][0]["cve_id"] == "CVE-2023-0001"
    assert raw["tls"][0]["subject_cn"] == "fixture.example"
    assert json.loads((tmp_path / "pulse_cves.json").read_text())[0]["cve_id"] == "CVE-2023-0001"


def test_interruption_after_checkpoint_before_artifact_replays_safely(tmp_path, driver):
    calls, _ = driver()
    done = []
    def interrupted(host):
        done.append(host)
        raise RuntimeError("simulated interruption before artifact write")
    with pytest.raises(RuntimeError, match="simulated interruption"):
        pp.run_pulse_probe(["10.0.0.1:22"], output_dir=tmp_path, on_host_done=interrupted)
    assert done == ["10.0.0.1"]
    offset = len(calls)
    pp.run_pulse_probe(["10.0.0.1:22"], output_dir=tmp_path, done_hosts=done)
    assert [pairs for _, pairs, _ in calls[offset:]] == [[("10.0.0.1", 22)]]
    assert len(_raw(tmp_path)["open"]) == 1


def test_inner_command_timeout_retry_does_not_expand_targets(tmp_path, monkeypatch):
    from scanner.pipeline import utils
    calls = []
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "fixture-pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    monkeypatch.setattr(utils.time, "sleep", lambda _: None)
    def run(command, **kwargs):
        pairs = _command_pairs(command)
        calls.append(pairs)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, json.dumps(_payload(pairs)), "")
    monkeypatch.setattr(utils.subprocess, "run", run)
    pp.run_pulse_probe(["10.0.0.1:22"], output_dir=tmp_path, retries=1)
    assert calls == [[("10.0.0.1", 22)], [("10.0.0.1", 22)]]
    # Logical adapter calls deliberately do not claim to count subprocess retries.
    assert _raw(tmp_path)["adapter"]["chunk_probe_calls"] == 1
    assert _raw(tmp_path)["adapter"]["command_retries"] == 1
