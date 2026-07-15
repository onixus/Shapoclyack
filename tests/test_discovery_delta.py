from __future__ import annotations

from pathlib import Path

from scanner.pipeline.discovery_delta import (
    compute_delta_plan,
    load_previous_alive,
    load_seed_alive,
    resolve_previous_alive_file,
    select_refresh_hosts,
)


def test_compute_delta_plan_new_scope_only():
    initial, wave1, refresh = compute_delta_plan(
        ["10.0.0.0/29"],
        seed_alive={"10.0.0.1"},
        previous_alive={"10.0.0.2", "10.0.0.9"},
        refresh_rate=0.5,
        refresh_seed=1,
    )
    assert "10.0.0.1" in initial
    assert "10.0.0.2" in initial
    assert "10.0.0.9" not in initial  # outside /29
    assert "10.0.0.1" not in wave1
    assert "10.0.0.2" not in wave1
    assert set(wave1) == {"10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
    assert "10.0.0.1" not in refresh
    assert "10.0.0.2" in refresh


def test_select_refresh_hosts_rate_one():
    hosts = [f"10.0.0.{index}" for index in range(1, 6)]
    assert select_refresh_hosts(hosts, 1.0) == hosts


def test_select_refresh_hosts_rate_zero():
    assert select_refresh_hosts(["10.0.0.1"], 0.0) == []


def test_load_seed_alive_missing_file(tmp_path: Path):
    assert load_seed_alive(str(tmp_path / "missing.txt")) == set()


def test_load_seed_alive_reads_hosts(tmp_path: Path):
    path = tmp_path / "seed.txt"
    path.write_text("10.0.0.5\n10.0.0.6\n", encoding="utf-8")
    assert load_seed_alive(str(path)) == {"10.0.0.5", "10.0.0.6"}


def test_resolve_previous_alive_file_explicit_dir(tmp_path: Path):
    run_dir = tmp_path / "prev-run"
    run_dir.mkdir()
    (run_dir / "alive_ips.txt").write_text("10.0.0.1\n", encoding="utf-8")
    found = resolve_previous_alive_file(
        output_base=tmp_path / "output",
        state_base=tmp_path / "state",
        previous_run_dir=str(run_dir),
        per_run_output=True,
    )
    assert found == run_dir / "alive_ips.txt"
    assert load_previous_alive(found) == {"10.0.0.1"}


def test_resolve_previous_alive_file_from_latest_pointer(tmp_path: Path):
    output_base = tmp_path / "output"
    state_base = tmp_path / "state"
    run_dir = output_base / "runs" / "20260101T000000Z"
    run_dir.mkdir(parents=True)
    (run_dir / "alive_ips.txt").write_text("10.0.0.8\n", encoding="utf-8")
    state_base.mkdir()
    (state_base / "latest_run.json").write_text('{"run_id": "20260101T000000Z"}\n', encoding="utf-8")
    found = resolve_previous_alive_file(
        output_base=output_base,
        state_base=state_base,
        previous_run_dir="",
        per_run_output=True,
    )
    assert found is not None
    assert load_previous_alive(found) == {"10.0.0.8"}
