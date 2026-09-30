"""No stand is needed to test that incomplete stand evidence is not accepted."""
import json
from pathlib import Path

import pytest

from tests.fixtures.scale_calibration import CampaignError, audit_campaign

FIELDS = {"source", "run_dir_bytes_is_floor", "sensor_cpu_seconds_per_host", "ch_idle_rss_bytes"}


def campaign(tmp_path, repeats=3):
    samples = []
    for index in range(repeats):
        env = {"measured_at": f"2026-09-30T12:0{index}:00Z", "git_commit": "abc123",
               "platform": "test-only", "cpu_count": 2, "mem_total_bytes": 1024,
               "postgres": dict.fromkeys(("fsync", "full_page_writes", "synchronous_commit", "autovacuum"), "on")}
        raw = {"environment": env, "runs_dir": {"runs": [
            {"hosts": n, "archive_bytes": n * 100, "resources": dict.fromkeys(("cpu_sec", "children_cpu_sec", "max_rss_mb", "children_max_rss_mb"), 1)}
            for n in (10, 20)], "skipped": {"synthetic": 1}}}
        result = {"coefficients": {"source": f"test-only-{index}", "run_dir_bytes_is_floor": False,
                                   "sensor_cpu_seconds_per_host": index + 1}}
        (tmp_path / f"raw{index}.json").write_text(json.dumps(raw))
        (tmp_path / f"result{index}.json").write_text(json.dumps(result))
        samples.append({"id": str(index), "result": f"result{index}.json", "raw_results": [f"raw{index}.json"]})
    manifest = tmp_path / "campaign.json"
    manifest.write_text(json.dumps({"schema_version": 1, "deployment": "kind", "scanner_mode": "scanner-executor", "samples": samples}))
    return manifest


def modify(path, fn):
    data = json.loads(path.read_text())
    fn(data)
    path.write_text(json.dumps(data))


def test_provenance_and_missing_coefficients_are_not_invented(tmp_path):
    report = audit_campaign(campaign(tmp_path), known_coefficients=FIELDS)
    assert report["checks_passed"]
    assert report["capacity_validated"] is False
    assert len(report["sources"]) == 3
    assert len(report["sources"][0]["raw"][0]["sha256"]) == 64
    assert report["comparison"]["sensor_cpu_seconds_per_host"]["median"] == 2
    assert report["comparison"]["sensor_cpu_seconds_per_host"]["relative_span"] == 1
    assert report["comparison"]["ch_idle_rss_bytes"]["median"] is None
    assert report["missing_coefficients"] == ["ch_idle_rss_bytes"]


@pytest.mark.parametrize("setting", ["fsync", "full_page_writes", "synchronous_commit", "autovacuum"])
def test_non_production_postgres_is_reported(tmp_path, setting):
    path = campaign(tmp_path)
    modify(tmp_path / "raw0.json", lambda d: d["environment"]["postgres"].update({setting: "off"}))
    report = audit_campaign(path, known_coefficients=FIELDS)
    assert not report["checks_passed"]
    assert any(setting in problem for problem in report["problems"])


@pytest.mark.parametrize("bad", [-1, float("nan"), float("inf"), True, "12"])
def test_invalid_coefficients_cannot_reach_comparison(tmp_path, bad):
    path = campaign(tmp_path)
    modify(tmp_path / "result0.json", lambda d: d["coefficients"].update(sensor_cpu_seconds_per_host=bad))
    with pytest.raises(CampaignError, match="finite non-negative"):
        audit_campaign(path, known_coefficients=FIELDS)


def test_duplicate_raws_and_derived_results_are_not_repetitions(tmp_path):
    path = campaign(tmp_path)
    modify(path, lambda d: d["samples"][1].update(result="result0.json", raw_results=["raw0.json"]))
    report = audit_campaign(path, known_coefficients=FIELDS)
    assert not report["checks_passed"]
    assert any("duplicate derived" in problem for problem in report["problems"])
    assert any("repeated raw" in problem for problem in report["problems"])


def test_requires_repetitions_real_runs_and_environment(tmp_path):
    path = campaign(tmp_path, repeats=1)
    modify(tmp_path / "raw0.json", lambda d: (d.pop("environment"), d.pop("runs_dir")))
    report = audit_campaign(path, known_coefficients=FIELDS)
    assert not report["checks_passed"]
    assert any("3 independent" in p for p in report["problems"])
    assert any("durability" in p for p in report["problems"])
    assert any("two distinct" in p for p in report["problems"])


@pytest.mark.parametrize("bad", ["../elsewhere.json", "/etc/passwd", None])
def test_path_escape_is_rejected(tmp_path, bad):
    path = campaign(tmp_path)
    modify(path, lambda d: d["samples"][0].update(result=bad))
    with pytest.raises(CampaignError):
        audit_campaign(path, known_coefficients=FIELDS)


def test_symlink_escape_is_rejected(tmp_path):
    path = campaign(tmp_path)
    (tmp_path / "link.json").symlink_to(Path("/etc/passwd"))
    modify(path, lambda d: d["samples"][0].update(result="link.json"))
    with pytest.raises(CampaignError, match="escapes"):
        audit_campaign(path, known_coefficients=FIELDS)


@pytest.mark.parametrize("field,value", [("schema_version", True), ("deployment", "sandbox"), ("scanner_mode", "mixed")])
def test_campaigns_must_be_explicit_and_separate(tmp_path, field, value):
    path = campaign(tmp_path)
    modify(path, lambda d: d.update({field: value}))
    with pytest.raises(CampaignError):
        audit_campaign(path, known_coefficients=FIELDS)


def test_unknown_coefficient_rejected(tmp_path):
    path = campaign(tmp_path)
    modify(tmp_path / "result0.json", lambda d: d["coefficients"].update(guessed_capacity=10000))
    with pytest.raises(CampaignError, match="unknown fields"):
        audit_campaign(path, known_coefficients=FIELDS)
