from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.contract import validate_inputs


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_validate_inputs_classifies_and_rejects(tmp_path: Path):
    ranges = tmp_path / "ranges.txt"
    domains = tmp_path / "domains.txt"
    output = tmp_path / "output"
    _write(ranges, ["10.0.0.0/16", "10.0.1.10", "# comment", "not-an-ip"])
    _write(domains, ["api.example.com", "example.com.", "-bad.host"])

    result = validate_inputs(ranges, domains, output)

    assert result.valid_ips_or_cidr == ["10.0.0.0/16", "10.0.1.10"]
    assert result.valid_fqdns == ["api.example.com", "example.com"]
    assert "not-an-ip" in result.rejected
    assert "-bad.host" in result.rejected

    report = json.loads((output / "normalized" / "contract_validation.json").read_text(encoding="utf-8"))
    assert report["valid_ip_or_cidr_count"] == 2
    assert report["valid_fqdn_count"] == 2
    assert report["rejected_count"] == 2


def test_validate_inputs_handles_missing_files(tmp_path: Path):
    result = validate_inputs(tmp_path / "missing_ranges.txt", tmp_path / "missing_domains.txt", tmp_path / "out")
    assert result.valid_ips_or_cidr == []
    assert result.valid_fqdns == []
    assert result.rejected == []
