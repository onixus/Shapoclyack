"""Unit tests for FTT-PULSE-2026-055 estate throughput Measure harness."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.fixtures import throughput_measure as tm

FIXTURE_PACK = Path("docs/benchmarks/throughput-okr-estate-baseline")
CALIBRATION = FIXTURE_PACK / "calibration.json"


def test_hosts_per_hour_basic() -> None:
    assert tm.hosts_per_hour(1000, 3600) == 1000.0
    assert tm.hosts_per_hour(1000, 720) == 5000.0
    assert tm.hosts_per_hour(0, 10) == 0.0
    assert tm.hosts_per_hour(10, 0) is None
    assert tm.hosts_per_hour(10, -1) is None


def test_l4_enrichment_split() -> None:
    split = tm.l4_enrichment_split(
        pulse_stage_sec=720.0,
        stats={
            "elapsed_ms": 180_000,
            "l4_complete": True,
            "complete": True,
            "open": 12,
            "total": 100,
            "rate_pps": 55.6,
        },
    )
    assert split["l4_wall_sec"] == 180.0
    assert split["enrichment_wall_sec"] == 540.0
    assert split["l4_share"] == 0.25
    assert split["enrichment_share"] == 0.75
    assert split["l4_complete"] is True
    assert split["complete"] is True


def test_l4_enrichment_split_missing_stats() -> None:
    split = tm.l4_enrichment_split(pulse_stage_sec=10.0, stats=None)
    assert split["l4_wall_sec"] is None
    assert split["enrichment_wall_sec"] is None


def test_l4_complete_true_when_full_complete_false(tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "pulse").mkdir(parents=True)
    hosts = ["doc-host-0000.invalid", "doc-host-0001.invalid"]
    (run / "alive_hosts.json").write_text(json.dumps(hosts), encoding="utf-8")
    (run / "stage_timings.json").write_text(
        json.dumps(
            {
                "synthetic": tm.SYNTHETIC_MARKER,
                "pipeline_wall_sec": 100.0,
                "stages_sum_sec": 90.0,
                "stages": [{"name": "pulse", "duration_sec": 90.0, "status": "incomplete"}],
                "top_stages": [{"name": "pulse", "duration_sec": 90.0}],
            }
        ),
        encoding="utf-8",
    )
    (run / "pulse" / "raw.json").write_text(
        json.dumps(
            {
                "stats": {
                    "elapsed_ms": 20_000,
                    "l4_complete": True,
                    "complete": False,
                    "open": 1,
                    "total": 2,
                }
            }
        ),
        encoding="utf-8",
    )
    row = tm.analyze_run(run, cohort="enrichment")
    assert row is not None
    assert row["hosts"] == 2
    assert row["hosts_per_hour"] == 72.0
    assert row["pulse"]["l4_complete"] is True
    assert row["pulse"]["complete"] is False
    assert row["pulse"]["enrichment_wall_sec"] == 70.0


def test_skips_foreign_synthetic_without_cohort(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "alive_hosts.json").write_text("[]", encoding="utf-8")
    (run / "stage_timings.json").write_text(
        json.dumps({"synthetic": "tests.fixtures.scale_measure", "pipeline_wall_sec": 1}),
        encoding="utf-8",
    )
    assert tm.analyze_run(run) is None


def test_fixture_pack_cohorts() -> None:
    assert FIXTURE_PACK.is_dir()
    summary = tm.analyze_tree(FIXTURE_PACK / "fixtures")
    assert set(summary["cohorts"]) == set(tm.COHORTS)
    assert summary["cohorts"]["inventory"]["hosts_per_hour_median"] == 5000.0
    assert summary["cohorts"]["inventory_services"]["hosts_per_hour_median"] == 4000.0
    assert summary["cohorts"]["enrichment"]["hosts_per_hour_median"] == 200.0
    assert summary["cohorts"]["full"]["hosts_per_hour_median"] == 125.0
    assert summary["cohorts"]["inventory_services"]["enrichment_share_median"] == 0.75
    assert summary["cohorts"]["enrichment"]["l4_complete_true"] == 2
    assert summary["cohorts"]["enrichment"]["complete_false"] == 1
    assert summary["cohorts"]["full"]["top_stages_sample"][0]["name"] == "pulse"


def test_calibration_matches_committed() -> None:
    summary = tm.analyze_tree(FIXTURE_PACK / "fixtures")
    got = tm.calibration_coefficients(summary)
    committed = json.loads(CALIBRATION.read_text(encoding="utf-8"))
    assert got["cohorts"] == committed["cohorts"]


def test_cli_fixtures(tmp_path: Path) -> None:
    out = tmp_path / "summary.json"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.fixtures.throughput_measure",
            "fixtures",
            str(FIXTURE_PACK),
            "--out",
            str(out),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "shapoclyack.throughput_okr_baseline.v1"
    assert "inventory" in data["cohorts"]


def test_scale_measure_okr_baseline() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.fixtures.scale_measure",
            "okr-baseline",
            str(FIXTURE_PACK / "fixtures"),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["cohorts"]["inventory"]["hosts_per_hour_median"] == 5000.0


def test_model_calibration_flag() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/throughput_okr_model.py",
            "--calibration",
            str(CALIBRATION),
            "--calibration-only",
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "measured inventory" in proc.stdout
    assert "measured full" in proc.stdout
    assert "MISS" in proc.stdout


def test_malformed_timings_still_counts_hosts(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "alive_hosts.json").write_text(json.dumps(["a", "b", "c"]), encoding="utf-8")
    (run / "stage_timings.json").write_text("{not-json", encoding="utf-8")
    row = tm.analyze_run(run, cohort="inventory")
    assert row is not None
    assert row["hosts"] == 3
    assert row["pipeline_wall_sec"] is None
    assert row["hosts_per_hour"] is None
