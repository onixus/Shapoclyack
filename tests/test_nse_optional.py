"""Phase 5: nmap NSE path is optional when binary is missing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from scanner.pipeline.nse import run_nse


def test_run_nse_skips_when_nmap_missing(tmp_path: Path):
    with patch("scanner.pipeline.nse.shutil.which", return_value=None):
        out = run_nse(
            ["10.0.0.1:443/tcp"],
            output_dir=tmp_path,
            scripts="default,safe",
            version_detection=True,
            os_detection=False,
            nmap_timing="T4",
            timeout=30,
            retries=0,
            concurrency=1,
        )
    assert out == tmp_path / "nmap"
    assert (out / "SKIPPED_NMAP_MISSING").exists()
    assert not list(out.glob("*.xml"))


def test_run_nse_empty_targets_no_skip_marker_when_nmap_present(tmp_path: Path):
    with patch("scanner.pipeline.nse.shutil.which", return_value="/usr/bin/nmap"):
        out = run_nse(
            [],
            output_dir=tmp_path,
            scripts="default",
            version_detection=False,
            os_detection=False,
            nmap_timing="T3",
            timeout=30,
            retries=0,
            concurrency=1,
        )
    assert out == tmp_path / "nmap"
    assert not (out / "SKIPPED_NMAP_MISSING").exists()
