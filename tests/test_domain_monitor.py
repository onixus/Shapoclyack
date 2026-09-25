from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.pipeline import domain_monitor
from scanner.pipeline.config_schema import DomainMonitorConfig
from scanner.pipeline.domain_monitor import (
    _classify_dangling_cname,
    _classify_typosquat,
    _generate_typosquat_candidates,
    _split_domain,
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


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("bbc.co.uk", ("bbc", "co.uk")),
        ("example.com.ru", ("example", "com.ru")),
        ("shop.example.com.ru", ("example", "com.ru")),
        ("x.github.io", ("x", "github.io")),
        ("example.com", ("example", "com")),
    ],
)
def test_split_domain_is_registrable_label_and_public_suffix(domain, expected):
    assert _split_domain(domain) == expected


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("co.uk", ("co", "uk")),
        ("github.io", ("github", "io")),
        ("localhost", ("localhost", "")),
        ("192.0.2.1", ("192.0.2", "1")),
    ],
)
def test_split_domain_without_registrable_domain_splits_at_last_dot(domain, expected):
    assert _split_domain(domain) == expected


def _suffix_after_first_label(candidate: str) -> tuple[str, str]:
    label, _, suffix = candidate.partition(".")
    return label, suffix


def test_typosquat_candidates_keep_a_multi_label_suffix_whole():
    candidates = _generate_typosquat_candidates("bbc.co.uk", max_candidates=500)

    assert "bbcc.co.uk" in candidates  # doubling
    assert "vbc.co.uk" in candidates  # keyboard-adjacent
    assert "bbc.com" in candidates  # co.uk swapped as a unit
    assert "bbc.uk" in candidates  # the suffix's own TLD
    assert "bbc.co" in candidates
    assert "bbc.co.com" not in candidates
    swaps = {"uk", "com", "net", "org", "co", "io", "info", "biz", "cc", "xyz"}
    for candidate in candidates:
        label, suffix = _suffix_after_first_label(candidate)
        # Only the label is ever mutated; the suffix is kept or swapped whole.
        assert suffix == "co.uk" or (label == "bbc" and suffix in swaps), candidate


def test_typosquat_candidates_for_a_subdomain_seed_mutate_the_registrable_label():
    candidates = _generate_typosquat_candidates("shop.example.com.ru", max_candidates=500)

    assert "exmaple.com.ru" in candidates
    assert "example.ru" in candidates
    assert "example.com" in candidates
    assert not [c for c in candidates if "shop" in c]


def test_typosquat_candidates_under_a_private_suffix():
    candidates = _generate_typosquat_candidates("x.github.io", max_candidates=500)

    assert "z.github.io" in candidates
    assert "x.io" in candidates
    assert "x.com" in candidates
    assert "xgithub.io" not in candidates
    assert "x.github.com" not in candidates


def test_typosquat_candidates_never_include_the_seeds_own_registrable_domain():
    # Transposing the two b's of "bbc" gives "bbc" back.
    candidates = _generate_typosquat_candidates("www.bbc.co.uk", max_candidates=500)

    assert "bbc.co.uk" not in candidates


def test_org_registrable_domain_is_not_reported_as_its_own_typosquat(tmp_path: Path, monkeypatch):
    def resolve_everything(domains, output_dir, *, timeout, retries):
        return {d.lower(): {"a": ["192.0.2.10"], "aaaa": []} for d in domains}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", resolve_everything)

    result = monitor_domains(
        ["www.bbc.co.uk"],
        [],
        DomainMonitorConfig(enabled=True, dangling_cname_enabled=False, max_candidates=500),
        tmp_path,
    )
    reported = {finding["candidate"] for finding in result["typosquat"]["findings"]}
    assert reported
    assert "bbc.co.uk" not in reported
    assert "bbc.com" in reported
