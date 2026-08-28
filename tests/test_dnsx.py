"""The dnsx JSONL wrapper shared by the org_profile DNS stages (M2, #182).

The stages mock this module out, so it is the one layer of M2 that no other
test exercises -- and it is the layer every real run depends on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.pipeline import dnsx
from scanner.pipeline.dnsx import DnsxError, query


def _fake_run(output: str, *, calls: list[list[str]] | None = None):
    def run_command(command, timeout, retries):
        if calls is not None:
            calls.append(command)
        Path(command[command.index("-o") + 1]).write_text(output, encoding="utf-8")
        return None

    return run_command


def test_empty_name_list_runs_nothing(tmp_path: Path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("dnsx must not run for an empty target list")

    monkeypatch.setattr(dnsx, "run_command", explode)
    assert query([], tmp_path, stage="s", kind="ns", flags=["-ns"], timeout=5, retries=0) == {}


def test_records_are_keyed_by_normalised_host(tmp_path: Path, monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(
        dnsx,
        "run_command",
        _fake_run('{"host": "Example.COM.", "ns": ["ns1.example.com"]}\n\n', calls=calls),
    )

    records = query(
        ["example.com"], tmp_path, stage="dns_hygiene", kind="ns", flags=["-ns"], timeout=7, retries=1
    )

    assert records == {"example.com": {"host": "Example.COM.", "ns": ["ns1.example.com"]}}
    assert calls[0][:2] == ["dnsx", "-l"]
    assert "-ns" in calls[0] and "-json" in calls[0] and "-silent" in calls[0]
    # Each record type gets its own target/output pair under the stage directory.
    assert (tmp_path / "dns_hygiene" / "ns_targets.txt").read_text(encoding="utf-8") == "example.com\n"


def test_unparseable_line_does_not_lose_the_batch(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.setattr(
        dnsx, "run_command", _fake_run('not json\n{"host": "a.example", "ns": []}\n["list"]\n')
    )
    records = query(
        ["a.example"], tmp_path, stage="s", kind="ns", flags=["-ns"], timeout=5, retries=0
    )
    assert set(records) == {"a.example"}
    assert "unparseable" in caplog.text


def test_missing_output_file_is_not_an_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(dnsx, "run_command", lambda command, timeout, retries: None)
    assert query(["a.example"], tmp_path, stage="s", kind="txt", flags=["-txt"], timeout=5, retries=0) == {}


def test_tool_failure_becomes_dnsx_error(tmp_path: Path, monkeypatch):
    def boom(command, timeout, retries):
        raise FileNotFoundError("dnsx")

    monkeypatch.setattr(dnsx, "run_command", boom)
    # Not a bare FileNotFoundError: _run_stage would turn that into
    # StageFailureError and end the run from inside a fail-soft control.
    with pytest.raises(DnsxError, match="txt lookup failed"):
        query(["a.example"], tmp_path, stage="s", kind="txt", flags=["-txt"], timeout=5, retries=0)
