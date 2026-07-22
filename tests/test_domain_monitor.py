from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline import domain_monitor
from scanner.pipeline.config_schema import DomainMonitorConfig
from scanner.pipeline.domain_monitor import (
    _classify_dangling_cname,
    _classify_typosquat,
    _generate_typosquat_candidates,
    monitor_domains,
)


def test_domain_monitor_disabled(tmp_path: Path):
    result = monitor_domains(["example.com"], [], DomainMonitorConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "domain_monitor.disabled"
    assert (tmp_path / "domain_monitor.json").exists()


def test_domain_monitor_no_domains(tmp_path: Path):
    result = monitor_domains([], [], DomainMonitorConfig(enabled=True), tmp_path)
    assert result["skipped_reason"] == "no_domains"


def test_typosquat_finding_present(tmp_path: Path, monkeypatch):
    candidates = _generate_typosquat_candidates("example.com", max_candidates=50)
    assert candidates
    picked = candidates[0]

    def fake_a_aaaa(domains, output_dir, *, timeout, retries):
        return {picked.lower(): {"a": ["1.2.3.4"], "aaaa": []}}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", fake_a_aaaa)

    result = monitor_domains(
        ["example.com"],
        [],
        DomainMonitorConfig(enabled=True, dangling_cname_enabled=False, max_candidates=50),
        tmp_path,
    )
    findings = result["typosquat"]["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "typosquat_registered"
    assert finding["seed"] == "example.com"
    assert finding["candidate"] == picked
    assert finding["a"] == ["1.2.3.4"]


def test_typosquat_no_finding_when_not_resolved(tmp_path: Path, monkeypatch):
    def fake_a_aaaa(domains, output_dir, *, timeout, retries):
        return {}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", fake_a_aaaa)

    result = monitor_domains(
        ["example.com"],
        [],
        DomainMonitorConfig(enabled=True, dangling_cname_enabled=False, max_candidates=20),
        tmp_path,
    )
    assert result["typosquat"]["findings"] == []


def test_dangling_cname_finding_present(tmp_path: Path, monkeypatch):
    def fake_cname(fqdns, output_dir, *, timeout, retries):
        return {"staging.example.com": {"cname": ["abandoned.github.io"], "a": [], "aaaa": []}}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        [],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False),
        tmp_path,
    )
    findings = result["dangling_cname"]["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "dangling_cname"
    assert finding["fqdn"] == "staging.example.com"
    assert finding["cname_target"] == "abandoned.github.io"
    assert finding["matched_suffix"] == "github.io"


def test_dangling_cname_no_finding_when_a_present(tmp_path: Path, monkeypatch):
    def fake_cname(fqdns, output_dir, *, timeout, retries):
        return {
            "staging.example.com": {
                "cname": ["abandoned.github.io"],
                "a": ["1.2.3.4"],
                "aaaa": [],
            }
        }

    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        [],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False),
        tmp_path,
    )
    assert result["dangling_cname"]["findings"] == []


def test_dangling_cname_no_finding_when_no_suffix_match(tmp_path: Path, monkeypatch):
    def fake_cname(fqdns, output_dir, *, timeout, retries):
        return {
            "staging.example.com": {
                "cname": ["internal-lb.example-corp.net"],
                "a": [],
                "aaaa": [],
            }
        }

    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        [],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False),
        tmp_path,
    )
    assert result["dangling_cname"]["findings"] == []


def test_generate_typosquat_candidates_spans_classes_and_caps():
    candidates = _generate_typosquat_candidates("example.com", max_candidates=12)
    assert 0 < len(candidates) <= 12
    assert "example.com" not in candidates

    # Confirm round-robin fairness: candidates from at least 3 different
    # generator classes appear (omission drops a char; keyboard-adjacent
    # substitutes a char but keeps the same length; TLD swap keeps "example").
    has_shorter = any(len(c.split(".")[0]) < len("example") for c in candidates)
    has_tld_swap = any(c.startswith("example.") and c != "example.com" for c in candidates)
    has_same_length_diff_label = any(
        len(c.split(".")[0]) == len("example") and c.split(".")[0] != "example" for c in candidates
    )
    assert sum([has_shorter, has_tld_swap, has_same_length_diff_label]) >= 3


def test_generate_typosquat_candidates_truncates_with_small_cap():
    candidates = _generate_typosquat_candidates("example.com", max_candidates=6)
    assert len(candidates) <= 6
    assert len(candidates) > 0


def test_generate_typosquat_candidates_dedup_no_original():
    candidates = _generate_typosquat_candidates("example.com", max_candidates=500)
    lowered = [c.lower() for c in candidates]
    assert len(lowered) == len(set(lowered))
    assert "example.com" not in lowered


def test_persisted_files_reflect_both_findings(tmp_path: Path, monkeypatch):
    candidates = _generate_typosquat_candidates("example.com", max_candidates=50)
    picked = candidates[0]

    def fake_a_aaaa(domains, output_dir, *, timeout, retries):
        return {picked.lower(): {"a": ["1.2.3.4"], "aaaa": []}}

    def fake_cname(fqdns, output_dir, *, timeout, retries):
        return {"staging.example.com": {"cname": ["abandoned.github.io"], "a": [], "aaaa": []}}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", fake_a_aaaa)
    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        ["example.com"],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, max_candidates=50),
        tmp_path,
    )

    saved = json.loads((tmp_path / "domain_monitor.json").read_text(encoding="utf-8"))
    assert saved["typosquat"]["findings"] == result["typosquat"]["findings"]
    assert saved["dangling_cname"]["findings"] == result["dangling_cname"]["findings"]

    lines = (tmp_path / "domain_monitor_findings.txt").read_text(encoding="utf-8").splitlines()
    assert any(line.startswith(f"typosquat:example.com:{picked}:") for line in lines)
    assert any(line == "dangling_cname:staging.example.com:abandoned.github.io" for line in lines)


def test_classify_helpers_return_none_when_appropriate():
    assert _classify_typosquat("example.com", "examp1e.com", {"a": [], "aaaa": []}) is None
    assert _classify_dangling_cname("host.example.com", {"cname": [], "a": [], "aaaa": []}) is None
