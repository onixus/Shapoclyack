"""Screenshot PNG reaper (P4.4). File-only — no Postgres."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

from api.services.screenshot_retention import sweep
from tests.conftest import make_settings

PNG = b"\x89PNG\r\n\x1a\nfake"


def _age(path: Path, *, days: float) -> None:
    when = time.time() - days * 86400.0
    os.utime(path, (when, when))


def _write_run(root: Path, run_id: str, *, png_name: str = "aabbccddeeff0011.png") -> Path:
    run_dir = root / "runs" / run_id
    shots = run_dir / "screenshots"
    shots.mkdir(parents=True)
    (run_dir / "run_meta.json").write_text("{}", encoding="utf-8")
    (run_dir / "screenshots.json").write_text('{"captured_count": 1}', encoding="utf-8")
    png = shots / png_name
    png.write_bytes(PNG)
    return png


def test_sweep_deletes_aged_png_keeps_json(tmp_path: Path):
    settings = make_settings(tmp_path, screenshot_retention_days=14)
    png = _write_run(settings.output_dir, "run-old")
    _age(png, days=20)
    _age(png.parent.parent / "run_meta.json", days=20)

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 1
    assert stats["kept"] == 0
    assert not png.exists()
    assert (settings.output_dir / "runs" / "run-old" / "screenshots.json").exists()


def test_sweep_keeps_fresh_png(tmp_path: Path):
    settings = make_settings(tmp_path, screenshot_retention_days=14)
    png = _write_run(settings.output_dir, "run-new")

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 0
    assert stats["kept"] == 1
    assert png.exists()


def test_zero_days_disables_reaper(tmp_path: Path):
    settings = make_settings(tmp_path, screenshot_retention_days=0)
    png = _write_run(settings.output_dir, "run-old")
    _age(png, days=90)

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats == {"deleted": 0, "errors": 0, "kept": 0}
    assert png.exists()


def test_uses_older_of_png_and_run_meta(tmp_path: Path):
    """A freshly-touched PNG on an old run still expires — PII must not linger
    because someone opened the file."""
    settings = make_settings(tmp_path, screenshot_retention_days=14)
    png = _write_run(settings.output_dir, "run-touched")
    _age(png.parent.parent / "run_meta.json", days=30)
    # PNG mtime is "now"; min(png, meta) is the old meta → delete.

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 1
    assert not png.exists()


def test_legacy_output_dir_screenshots(tmp_path: Path):
    settings = make_settings(tmp_path, screenshot_retention_days=7)
    shots = settings.output_dir / "screenshots"
    shots.mkdir(parents=True)
    png = shots / "legacy.png"
    png.write_bytes(PNG)
    _age(png, days=10)

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 1
    assert not png.exists()
