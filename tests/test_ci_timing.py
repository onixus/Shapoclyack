"""Prove timing evidence survives abrupt termination without changing outcomes."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("abrupt", [False, True])
def test_timing_is_incremental_and_preserves_outcomes(tmp_path, abrupt):
    source = "import os, pytest\ndef test_ok(): pass\n"
    if abrupt:
        source += "def test_exit(): os._exit(7)\n"
    else:
        source += "def test_skip(): pytest.skip('fixture')\ndef test_fail(): assert False\n"
    (tmp_path / "test_sample.py").write_text(source)
    output = tmp_path / "timing.jsonl"
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
               PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "tests.ci_timing",
                             "--ci-timing-jsonl", str(output), str(tmp_path / "test_sample.py")],
                            cwd=tmp_path, env=env, capture_output=True, timeout=30)
    assert result.returncode == (7 if abrupt else 1), result.stderr
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    phases = [r for r in rows if r["event"] == "phase" and r["nodeid"].endswith("test_ok")]
    assert [r["phase"] for r in phases] == ["setup", "call", "teardown"]
    assert all(r["duration"] >= 0 and r["outcome"] == "passed" for r in phases)
    if abrupt:
        assert not any(r["event"] == "session_finish" for r in rows)
        assert any(r["event"] == "test_start" and r["nodeid"].endswith("test_exit") for r in rows)
    else:
        assert rows[-1]["exitstatus"] == 1
        assert {r["outcome"] for r in rows if r["event"] == "phase"} == {"passed", "failed", "skipped"}
    original = output.read_bytes()
    again = subprocess.run([sys.executable, "-m", "pytest", "-p", "tests.ci_timing",
                            "--ci-timing-jsonl", str(output)], cwd=tmp_path, env=env,
                           capture_output=True, timeout=30)
    assert again.returncode == 4
    assert output.read_bytes() == original
