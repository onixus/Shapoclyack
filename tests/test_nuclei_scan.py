from __future__ import annotations

import ast
import json
from pathlib import Path
from unittest.mock import MagicMock

from scanner.pipeline import dns_resolvers
from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_scan import (
    _candidate_endpoints,
    _to_finding,
    _to_vulnerability_rows,
    run_nuclei_scan,
)


def _fake_which_present(name: str) -> str | None:
    return "/usr/local/bin/nuclei" if name == "nuclei" else None


def test_candidate_endpoints_dedupes_and_classifies_scheme():
    candidates = _candidate_endpoints(
        ["10.0.0.1:80/tcp", "10.0.0.1:443/tcp", "10.0.0.1:80/tcp", "10.0.0.2:22/tcp"],
        http_ports={80},
        https_ports={443},
    )
    assert candidates == [("10.0.0.1", 80, "http"), ("10.0.0.1", 443, "https")]


def test_candidate_endpoints_probes_both_schemes_for_ambiguous_custom_port():
    # A custom port whose scheme is unknown is classified as both http and
    # https (see extend_web_ports_with_custom) so nuclei must emit a candidate
    # for each scheme rather than silently dropping one.
    candidates = _candidate_endpoints(
        ["10.0.0.1:9000/tcp", "10.0.0.1:443/tcp"],
        http_ports={80, 9000},
        https_ports={443, 9000},
    )
    assert candidates == [
        ("10.0.0.1", 443, "https"),
        ("10.0.0.1", 9000, "http"),
        ("10.0.0.1", 9000, "https"),
    ]


def test_to_finding_extracts_cve_and_severity():
    raw = {
        "template-id": "cve-2021-44228",
        "host": "10.0.0.1",
        "port": "8080",
        "matched-at": "http://10.0.0.1:8080/",
        "info": {
            "name": "Log4Shell",
            "severity": "Critical",
            "tags": ["cve", "cve2021", "rce"],
            "classification": {
                "cve-id": ["CVE-2021-44228"],
                "cvss-score": 10.0,
                "cwe-id": ["CWE-20", "CWE-400"],
            },
        },
    }
    finding = _to_finding(raw)
    assert finding["severity"] == "critical"
    assert finding["cve"] == ["CVE-2021-44228"]
    assert finding["cvss_score"] == 10.0
    assert finding["cwe"] == ["CWE-20", "CWE-400"]


def test_to_vulnerability_rows_empty_without_cve():
    finding = _to_finding({"host": "10.0.0.1", "port": "80", "info": {"severity": "info"}})
    assert _to_vulnerability_rows(finding) == []


def test_to_vulnerability_rows_falls_back_to_severity_floor_without_cvss():
    finding = _to_finding(
        {
            "host": "10.0.0.1",
            "port": "80",
            "template-id": "some-cve-check",
            "info": {"severity": "high", "classification": {"cve-id": ["CVE-2020-1"]}},
        }
    )
    rows = _to_vulnerability_rows(finding)
    assert rows == [
        {
            "host": "10.0.0.1",
            "port": "80",
            "cve": "CVE-2020-1",
            "cvss": 7.5,
            "severity": "high",
            "script_id": "nuclei:some-cve-check",
            "source": "nuclei",
            "cwe": [],
        }
    ]


def test_to_vulnerability_rows_emits_one_row_per_cve():
    finding = _to_finding(
        {
            "host": "10.0.0.1",
            "port": "8080",
            "template-id": "cve-2021-44228",
            "info": {
                "severity": "critical",
                "classification": {
                    "cve-id": ["CVE-2021-44228", "CVE-2021-45046"],
                    "cvss-score": 10.0,
                },
            },
        }
    )
    rows = _to_vulnerability_rows(finding)
    assert [row["cve"] for row in rows] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert all(row["cvss"] == 10.0 and row["source"] == "nuclei" for row in rows)


def test_run_nuclei_scan_disabled(tmp_path: Path):
    config = NucleiConfig(enabled=False)
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "nuclei.disabled"
    assert json.loads((tmp_path / "nuclei.json").read_text(encoding="utf-8"))["skipped_reason"] == "nuclei.disabled"


def test_run_nuclei_scan_no_web_ports(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir))
    result = run_nuclei_scan(["10.0.0.1:22/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "no_web_ports"


def test_run_nuclei_scan_binary_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", lambda name: None)
    config = NucleiConfig(enabled=True)
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "nuclei_binary_missing"


def test_run_nuclei_scan_templates_dir_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    config = NucleiConfig(enabled=True, templates_dir=str(tmp_path / "does-not-exist"))
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "templates_dir_missing"


def test_run_nuclei_scan_run_failure_is_fail_soft(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    def fake_run_command(command, **kwargs):
        raise TimeoutError("nuclei took too long")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir))
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "nuclei_run_failed"


def test_run_nuclei_scan_parses_jsonl_and_splits_cve_findings(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    def fake_run_command(command, **kwargs):
        jsonl_path = Path(command[command.index("-jsonl-export") + 1])
        rows = [
            {
                "template-id": "cve-2021-44228",
                "host": "10.0.0.1",
                "port": "8080",
                "info": {
                    "name": "Log4Shell",
                    "severity": "critical",
                    "tags": ["cve"],
                    "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0},
                },
            },
            {
                "template-id": "exposed-panel-generic",
                "host": "10.0.0.1",
                "port": "8080",
                "info": {"name": "Exposed Admin Panel", "severity": "info", "tags": ["panel"]},
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return MagicMock()

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir))
    result = run_nuclei_scan(["10.0.0.1:8080/tcp"], config, tmp_path)

    assert result["skipped_reason"] is None
    assert len(result["findings"]) == 2
    assert len(result["cve_findings"]) == 1
    cve_row = result["cve_findings"][0]
    assert cve_row["cve"] == "CVE-2021-44228"
    assert cve_row["cvss"] == 10.0
    assert cve_row["severity"] == "critical"
    assert cve_row["source"] == "nuclei"
    assert (tmp_path / "nuclei.json").exists()
    assert (tmp_path / "nuclei_findings.txt").exists()


def test_run_nuclei_scan_truncates_over_max_targets(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    def fake_run_command(command, **kwargs):
        jsonl_path = Path(command[command.index("-jsonl-export") + 1])
        jsonl_path.write_text("", encoding="utf-8")
        return MagicMock()

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    open_ports = [f"10.0.0.{i}:80/tcp" for i in range(1, 6)]
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir), max_targets=2)
    result = run_nuclei_scan(open_ports, config, tmp_path)
    assert result["targets_considered"] == 5
    assert result["checked_count"] == 2
    assert result["truncated"] is True


def test_run_nuclei_scan_passes_tags_and_custom_templates(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    custom_dir = tmp_path / "custom-templates"
    custom_dir.mkdir()

    captured_command: list[str] = []

    def fake_run_command(command, **kwargs):
        nonlocal captured_command
        captured_command = list(command)
        jsonl_path = Path(command[command.index("-jsonl-export") + 1])
        jsonl_path.write_text("", encoding="utf-8")
        return MagicMock()

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    config = NucleiConfig(
        enabled=True,
        templates_dir=str(templates_dir),
        custom_templates_dir=str(custom_dir),
        tags=["cve", "panel"],
        exclude_tags=["dos"],
    )
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] is None
    assert "-tags" in captured_command
    assert captured_command[captured_command.index("-tags") + 1] == "cve,panel"
    assert captured_command.count("-templates") == 2
    assert str(custom_dir) in captured_command


def _capture_nuclei(monkeypatch) -> dict:
    """Stub nuclei; record its argv and the resolvers file as it was at launch."""
    seen: dict = {}

    def fake_run_command(command, **kwargs):
        seen["argv"] = list(command)
        resolvers_path = Path(command[command.index("-resolvers") + 1])
        seen["resolvers"] = resolvers_path.read_text(encoding="utf-8").splitlines()
        Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
        return MagicMock()

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    return seen


def test_run_nuclei_scan_argv_is_pinned_and_names_the_system_resolver(tmp_path: Path, monkeypatch):
    """The whole command, so a flag cannot drop out unnoticed.

    ``-resolvers`` is the one that matters here. Without it nuclei v3.11.1
    rotates 1.1.1.1/1.0.0.1/8.8.8.8/8.8.4.4 in with the system resolver.
    Measured on the kind stand: four lookups in five went to a public server,
    and an internal-only name never resolved.
    """
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text(
        "search default.svc.cluster.local svc.cluster.local cluster.local\n"
        "nameserver 10.96.0.10\n"
        "options ndots:5\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dns_resolvers, "RESOLV_CONF", resolv_conf)
    seen = _capture_nuclei(monkeypatch)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    result = run_nuclei_scan(
        ["10.0.0.1:80/tcp"], NucleiConfig(enabled=True, templates_dir=str(templates_dir)), out
    )

    assert result["skipped_reason"] is None
    assert seen["argv"] == [
        "nuclei",
        "-disable-update-check",
        "-list", str(out / "nuclei_targets.txt"),
        "-templates", str(templates_dir),
        "-resolvers", str(out / "nuclei_resolvers.txt"),
        "-severity", "critical,high,medium",
        "-exclude-tags", "intrusive,fuzz,dos",
        "-jsonl-export", str(out / "nuclei_raw.jsonl"),
        "-rate-limit", "150",
        "-concurrency", "10",
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        "-no-color",
        # No public interactsh servers (test_nuclei_oast.py).
        "-no-interactsh",
    ]  # fmt: skip
    assert seen["resolvers"] == ["10.96.0.10:53"]


def test_configured_resolvers_replace_the_system_ones_in_the_given_order(
    tmp_path: Path, monkeypatch
):
    resolv_conf = tmp_path / "resolv.conf"
    resolv_conf.write_text("nameserver 10.96.0.10\n", encoding="utf-8")
    monkeypatch.setattr(dns_resolvers, "RESOLV_CONF", resolv_conf)
    seen = _capture_nuclei(monkeypatch)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    run_nuclei_scan(
        ["10.0.0.1:80/tcp"],
        NucleiConfig(enabled=True, templates_dir=str(templates_dir)),
        tmp_path,
        resolvers=["10.20.0.53", "2001:db8::53", "[2001:db8::54]:5353", "10.20.0.54:5353"],
    )

    # Bracketed and with an explicit port: nuclei appends ":53" only to a line
    # with no colon, so a bare IPv6 address would be read as host:port.
    assert seen["resolvers"] == [
        "10.20.0.53:53",
        "[2001:db8::53]:53",
        "[2001:db8::54]:5353",
        "10.20.0.54:5353",
    ]


def test_the_pipeline_hands_nuclei_the_configured_resolvers():
    """``scanner/main.py`` must pass ``config.dns.resolvers`` through.

    Leaving it out would still use the system resolvers, not the public ones.
    But ``dns.resolvers`` would then do nothing at all, and no run would show
    that.
    """
    main_py = Path(__file__).resolve().parents[1] / "scanner" / "main.py"
    calls = [
        node
        for node in ast.walk(ast.parse(main_py.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_nuclei_scan"
    ]
    assert len(calls) == 1, "expected exactly one run_nuclei_scan call in scanner/main.py"
    passed = {kw.arg: ast.unparse(kw.value) for kw in calls[0].keywords}
    assert passed.get("resolvers") == "config.dns.resolvers"


# ---------------------------------------------------------------------------
# A verification run pins the templates that found the finding (#451)
# ---------------------------------------------------------------------------


def _template(directory: Path, template_id: str, *, severity: str = "medium", tags: str = "cve") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{template_id}.yaml").write_text(
        f"id: {template_id}\n\ninfo:\n  name: {template_id}\n  author: tests\n"
        f"  severity: {severity}\n  description: |\n    A template.\n  tags: {tags}\n\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/'\n",
        encoding="utf-8",
    )


def _clean_exit(seen: dict | None = None):
    import subprocess

    def fake_run_command(command, **kwargs):
        if seen is not None:
            seen["argv"] = list(command)
        Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    return fake_run_command


def test_pinned_templates_run_by_id_whatever_their_severity(tmp_path: Path, monkeypatch):
    """A medium template re-checked under a critical/high floor was never
    loaded, and its silence closed the finding as verified-fixed."""
    templates = tmp_path / "templates"
    _template(templates / "http" / "cves" / "2024", "CVE-2024-0001", severity="medium")
    _template(templates / "http" / "misc", "unrelated-detect", severity="info")
    seen: dict = {}
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", _clean_exit(seen))
    out = tmp_path / "out"
    out.mkdir()
    config = NucleiConfig(
        templates_dir=str(templates),
        template_ids=["CVE-2024-0001"],
        severities=["critical", "high"],
        tags=["panel"],
    )

    result = run_nuclei_scan(["10.0.0.5:443/tcp"], config, out)

    argv = seen["argv"]
    assert argv[argv.index("-id") + 1] == "CVE-2024-0001"
    assert "-severity" not in argv
    assert "-tags" not in argv
    # The host's own exclusions still apply to a platform-sent id.
    assert "-exclude-tags" in argv
    coverage = result["coverage"]
    assert coverage == {
        "ran": True,
        "returncode": 0,
        "targets": ["https://10.0.0.5:443/"],
        "template_ids_requested": ["CVE-2024-0001"],
        "template_ids_missing": [],
        "template_ids_excluded": [],
        "severities": None,
    }
    assert json.loads((out / "nuclei.json").read_text(encoding="utf-8"))["coverage"] == coverage


def test_a_pinned_id_the_host_does_not_have_is_recorded_missing(tmp_path: Path, monkeypatch):
    templates = tmp_path / "templates"
    _template(templates, "CVE-2024-0001")
    seen: dict = {}
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", _clean_exit(seen))
    config = NucleiConfig(templates_dir=str(templates), template_ids=["CVE-2024-0001", "CVE-2099-9999"])

    result = run_nuclei_scan(["10.0.0.5:443/tcp"], config, tmp_path)

    assert seen["argv"][seen["argv"].index("-id") + 1] == "CVE-2024-0001"
    assert result["coverage"]["template_ids_missing"] == ["CVE-2099-9999"]
    assert result["coverage"]["ran"] is True


def test_no_pinned_id_on_the_host_means_nuclei_does_not_run(tmp_path: Path, monkeypatch):
    """nuclei given ``-id`` that matches nothing either errors or, beside a
    match, says nothing; neither may read as "looked and found nothing"."""
    templates = tmp_path / "templates"
    _template(templates, "something-else")
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr(
        "scanner.pipeline.nuclei_scan.run_command",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("nuclei must not run")),
    )
    config = NucleiConfig(templates_dir=str(templates), template_ids=["CVE-2099-9999"])

    result = run_nuclei_scan(["10.0.0.5:443/tcp"], config, tmp_path)

    assert result["skipped_reason"] == "template_ids_missing"
    assert result["coverage"]["ran"] is False
    assert result["coverage"]["template_ids_missing"] == ["CVE-2099-9999"]


def test_a_pinned_template_the_host_excludes_is_not_run(tmp_path: Path, monkeypatch):
    templates = tmp_path / "templates"
    _template(templates, "CVE-2024-0001", tags="cve,intrusive")
    _template(templates, "CVE-2024-0002", tags="cve")
    seen: dict = {}
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", _clean_exit(seen))
    config = NucleiConfig(templates_dir=str(templates), template_ids=["CVE-2024-0001", "CVE-2024-0002"])

    result = run_nuclei_scan(["10.0.0.5:443/tcp"], config, tmp_path)

    assert seen["argv"][seen["argv"].index("-id") + 1] == "CVE-2024-0002"
    assert result["coverage"]["template_ids_excluded"] == ["CVE-2024-0001"]

    only_excluded = NucleiConfig(templates_dir=str(templates), template_ids=["CVE-2024-0001"])
    skipped = run_nuclei_scan(["10.0.0.5:443/tcp"], only_excluded, tmp_path)
    assert skipped["skipped_reason"] == "template_ids_excluded"
    assert skipped["coverage"]["ran"] is False


def test_an_unpinned_run_keeps_its_severity_floor(tmp_path: Path, monkeypatch):
    templates = tmp_path / "templates"
    templates.mkdir()
    seen: dict = {}
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", _clean_exit(seen))

    result = run_nuclei_scan(
        ["10.0.0.5:443/tcp"], NucleiConfig(templates_dir=str(templates), severities=["critical"]), tmp_path
    )

    assert "-id" not in seen["argv"]
    assert seen["argv"][seen["argv"].index("-severity") + 1] == "critical"
    assert result["coverage"]["severities"] == ["critical"]


def test_a_skipped_or_failed_nuclei_is_not_coverage(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", lambda name: None)
    skipped = run_nuclei_scan(["10.0.0.5:443/tcp"], NucleiConfig(templates_dir=str(tmp_path)), tmp_path)
    assert skipped["skipped_reason"] == "nuclei_binary_missing"
    assert skipped["coverage"]["ran"] is False

    import subprocess

    def exits_one(command, **kwargs):
        Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 1, "", "[FTL] Could not run nuclei")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", exits_one)
    failed = run_nuclei_scan(["10.0.0.5:443/tcp"], NucleiConfig(templates_dir=str(tmp_path)), tmp_path)
    # Its findings are kept as before; it is just not a run that looked.
    assert failed["skipped_reason"] is None
    assert failed["coverage"]["ran"] is False
    assert failed["coverage"]["returncode"] == 1


def test_a_template_id_outside_the_alphabet_is_refused():
    """The id crosses the platform-to-sensor boundary and lands in argv."""
    import pytest
    from pydantic import ValidationError

    for bad in ("a,b", "*", "../etc/passwd", "-tags", "", "id with space", "x" * 201):
        with pytest.raises(ValidationError):
            NucleiConfig(template_ids=[bad])
    assert NucleiConfig(template_ids=["CVE-2021-44228", "tech_detect.v2", "CVE-2021-44228"]).template_ids == [
        "CVE-2021-44228",
        "tech_detect.v2",
    ]


def test_the_template_index_reads_ids_not_file_names(tmp_path: Path):
    from scanner.pipeline.nuclei_scan import index_template_ids

    (tmp_path / "renamed.yaml").write_text("# header\nid: CVE-2024-0001\ninfo:\n  tags: cve, rce\n", encoding="utf-8")
    (tmp_path / "CVE-2024-0002.yaml").write_text("id: other-id\n", encoding="utf-8")
    found = index_template_ids(["CVE-2024-0001", "CVE-2024-0002"], [tmp_path])
    assert found == {"CVE-2024-0001": {"cve", "rce"}}
