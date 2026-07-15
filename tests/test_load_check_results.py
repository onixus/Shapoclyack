"""Unit tests for load-test result validation."""

from __future__ import annotations

import json
from pathlib import Path

from tests.load.check_results import _read_targets


def test_read_targets_skips_blanks(tmp_path: Path) -> None:
    path = tmp_path / "targets.txt"
    path.write_text("10.0.0.1\n\n10.0.0.2\n", encoding="utf-8")
    assert _read_targets(path) == ["10.0.0.1", "10.0.0.2"]


def test_check_results_passes_with_all_hosts(tmp_path: Path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n10.0.0.2\n", encoding="utf-8")
    out = tmp_path / "output"
    out.mkdir()
    (out / "summary.json").write_text(
        json.dumps({"alive_hosts": 2, "nmap_open_services": 2}),
        encoding="utf-8",
    )
    (out / "open_ports.txt").write_text("10.0.0.1:80\n10.0.0.2:80\n", encoding="utf-8")
    for name in ("findings.json", "vulnerabilities.json", "summary.md"):
        (out / name).write_text("{}", encoding="utf-8")

    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "tests/load/check_results.py", str(out), str(targets)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert proc.returncode == 0, proc.stderr
