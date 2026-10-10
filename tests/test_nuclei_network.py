"""The Nuclei network pass (#547): which endpoints get which template, and what is recorded.

The web sweep feeds nuclei ``http(s)://`` URLs only, so the SMB template that
answers Nmap's ``smb2-security-mode`` could never run. These tests pin the plan
(service name first, default port only for an unnamed service), the command of
the second pass (``-id`` pinned, the host's ``exclude_tags`` kept, no OAST), and
the evidence block that keeps "not observed" apart from "not looked for". The
live behaviour of nuclei v3.11.1 against a Samba stand is in
``docs/nse-vuln-coverage.md``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.pipeline.config_schema import NUCLEI_TEMPLATE_ID_RE, NucleiConfig
from scanner.pipeline.nuclei_network import (
    NETWORK_RULES,
    NetworkRule,
    load_service_names,
    plan_network_targets,
    rule_applies,
)
from scanner.pipeline.nuclei_scan import run_nuclei_scan

SMB_ID = "smb-signing-not-required"
SMB_RULE = NETWORK_RULES[0]


def _which(name: str) -> str | None:
    return f"/usr/bin/{name}"


def _js_template(root: Path, template_id: str, *, severity: str = "medium", tags: str = "js,network,smb,enum") -> None:
    directory = root / "javascript" / "misconfiguration" / "smb"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{template_id}.yaml").write_text(
        f"id: {template_id}\n\ninfo:\n  name: {template_id}\n  author: tests\n  severity: {severity}\n"
        f"  tags: {tags}\njavascript:\n  - code: |\n      Export(1)\n    args:\n      Port: \"445\"\n",
        encoding="utf-8",
    )


def _services(out: Path, rows: list[tuple[str, int, str]]) -> None:
    (out / "services.json").write_text(
        json.dumps([{"ip": ip, "port": port, "protocol": "tcp", "service": name} for ip, port, name in rows]),
        encoding="utf-8",
    )


class Nuclei:
    """Stubbed nuclei: records every argv, answers like v3.11.1 (loaded count on stderr)."""

    def __init__(self, monkeypatch, *, returncode: int = 0, stderr: str | None = None, jsonl: dict[str, str] | None = None):
        self.calls: list[list[str]] = []
        self.targets: list[list[str]] = []
        self._returncode, self._stderr, self._jsonl = returncode, stderr, jsonl or {}
        monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _which)
        monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", self)

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        self.targets.append(Path(command[command.index("-list") + 1]).read_text(encoding="utf-8").split())
        ids = command[command.index("-id") + 1].split(",") if "-id" in command else []
        key = "network" if "-id" in command else "web"
        Path(command[command.index("-jsonl-export") + 1]).write_text(self._jsonl.get(key, ""), encoding="utf-8")
        stderr = self._stderr if self._stderr is not None else f"[INF] Templates loaded for current scan: {len(ids)}\n"
        return subprocess.CompletedProcess(command, self._returncode, "", stderr)

    @property
    def network_calls(self) -> list[list[str]]:
        return [c for c in self.calls if "-id" in c]


@pytest.fixture
def stand(tmp_path: Path):
    templates = tmp_path / "templates"
    _js_template(templates, SMB_ID)
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("10.0.0.5", 445, "smb"), ("10.0.0.5", 80, "http"), ("10.0.0.5", 22, "ssh")])
    return templates, out


def _config(templates: Path, **kw) -> NucleiConfig:
    return NucleiConfig(templates_dir=str(templates), **kw)


# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------


def test_the_table_is_well_formed():
    names = [rule.name for rule in NETWORK_RULES]
    assert len(names) == len(set(names))
    for rule in NETWORK_RULES:
        assert rule.template_ids and rule.services and rule.nse
        assert all(NUCLEI_TEMPLATE_ID_RE.fullmatch(template_id) for template_id in rule.template_ids)


def test_service_name_decides_on_any_port():
    assert rule_applies(SMB_RULE, "smb", 14450)
    assert rule_applies(SMB_RULE, "microsoft-ds", 445)
    assert not rule_applies(SMB_RULE, "ssh", 445), "a named service is not SMB because of its port"
    assert not rule_applies(SMB_RULE, "http", 445)


def test_the_default_port_counts_only_for_an_unnamed_service():
    assert rule_applies(SMB_RULE, "", 445)
    assert rule_applies(SMB_RULE, "unknown", 445)
    assert not rule_applies(SMB_RULE, "", 4450)


def test_plan_covers_tcp_endpoints_only_once_and_in_order():
    services = {("10.0.0.9", 14450): "smb", ("10.0.0.2", 445): "microsoft-ds", ("fd00::5", 445): "smb"}
    plan = plan_network_targets(
        ["10.0.0.9:14450/tcp", "10.0.0.2:445/tcp", "10.0.0.2:445/tcp", "10.0.0.2:445/udp", "[fd00::5]:445/tcp", "10.0.0.3:22/tcp"],
        services,
    )
    assert plan == {"smb": [("10.0.0.2", 445), ("10.0.0.9", 14450), ("fd00::5", 445)]}


def test_plan_is_empty_without_a_matching_service():
    assert plan_network_targets(["10.0.0.3:22/tcp", "10.0.0.3:80/tcp"], {}) == {}


def test_services_json_that_is_missing_or_broken_degrades_to_default_ports(tmp_path: Path):
    assert load_service_names(tmp_path) == {}
    (tmp_path / "services.json").write_text("{not json", encoding="utf-8")
    assert load_service_names(tmp_path) == {}
    (tmp_path / "services.json").write_text(
        json.dumps([{"ip": "10.0.0.1", "port": "x", "service": "smb"}, "junk", {"ip": "10.0.0.1", "port": 445, "protocol": "udp", "service": "smb"}]),
        encoding="utf-8",
    )
    assert load_service_names(tmp_path) == {}


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------


def test_the_network_pass_runs_the_pinned_id_against_host_port_and_leaves_the_web_sweep_alone(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp", "10.0.0.5:22/tcp"], _config(templates), out)

    web = [c for c in nuclei.calls if "-id" not in c]
    assert len(web) == 1 and len(nuclei.network_calls) == 1
    assert nuclei.targets[nuclei.calls.index(web[0])] == ["http://10.0.0.5:80/"]
    argv = nuclei.network_calls[0]
    assert nuclei.targets[nuclei.calls.index(argv)] == ["10.0.0.5:445"]
    assert argv[argv.index("-id") + 1] == SMB_ID
    # The two dials are applied by us (below), not handed to nuclei where -id would swallow an id silently.
    assert "-severity" not in argv and "-tags" not in argv
    assert argv[argv.index("-exclude-tags") + 1] == "intrusive,fuzz,dos"
    assert "-no-interactsh" in argv and "-interactsh-server" not in argv
    assert "-silent" not in argv, "the loaded-templates line is INFO and -silent hides it"
    assert argv.count("-templates") == 1
    assert result["coverage"]["targets"] == ["http://10.0.0.5:80/"], "the web coverage is untouched"
    network = result["coverage"]["network"]
    assert network["ran"] is True and network["skipped_reason"] is None
    (entry,) = network["passes"]
    assert entry["rule"] == "smb" and entry["nse"] == ["smb2-security-mode"]
    assert entry["targets"] == ["10.0.0.5:445"]
    assert entry["template_ids_requested"] == [SMB_ID]
    assert entry["template_ids_missing"] == entry["template_ids_excluded"] == entry["template_ids_below_floor"] == []
    assert (entry["templates_loaded"], entry["templates_expected"], entry["returncode"]) == (1, 1, 0)
    assert json.loads((out / "nuclei.json").read_text(encoding="utf-8"))["coverage"]["network"] == network


def test_a_match_is_a_finding_marked_as_the_network_pass(stand, monkeypatch):
    templates, out = stand
    line = json.dumps({
        "template-id": SMB_ID, "host": "10.0.0.5", "port": "445", "matched-at": "10.0.0.5:445",
        "info": {"name": "SMB Signing Not Required", "severity": "medium", "tags": ["js", "smb"]},
    })
    Nuclei(monkeypatch, jsonl={"network": line + "\n"})

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    (finding,) = result["findings"]
    assert (finding["template_id"], finding["port"], finding["severity"]) == (SMB_ID, "445", "medium")
    assert finding["pass"] == "network" and finding["rule"] == "smb"
    assert result["cve_findings"] == []
    assert "10.0.0.5:445:smb-signing-not-required:medium" in (out / "nuclei_findings.txt").read_text(encoding="utf-8")


def test_smb_without_a_web_port_still_gets_the_network_pass(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    assert result["skipped_reason"] == "no_web_ports"
    assert result["coverage"]["ran"] is False, "no web look happened and the block says so"
    assert len(nuclei.calls) == 1 and result["coverage"]["network"]["ran"] is True


def test_a_service_on_a_non_standard_port_is_found_by_its_name(tmp_path: Path, monkeypatch):
    templates = tmp_path / "t"
    _js_template(templates, SMB_ID)
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("10.0.0.5", 14450, "smb")])
    nuclei = Nuclei(monkeypatch)

    run_nuclei_scan(["10.0.0.5:14450/tcp"], _config(templates), out)

    assert nuclei.targets == [["10.0.0.5:14450"]]


def test_port_445_with_another_named_service_is_not_scanned_as_smb(tmp_path: Path, monkeypatch):
    templates = tmp_path / "t"
    _js_template(templates, SMB_ID)
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("10.0.0.5", 445, "http")])
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    assert nuclei.network_calls == []
    assert result["coverage"]["network"]["skipped_reason"] == "no_network_targets"


def test_exclude_tags_keep_their_hold_over_a_network_template(stand, monkeypatch):
    templates, out = stand
    _js_template(templates, SMB_ID, tags="js,network,smb,intrusive")
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    assert nuclei.network_calls == []
    (entry,) = result["coverage"]["network"]["passes"]
    assert entry["template_ids_excluded"] == [SMB_ID]
    assert entry["ran"] is False and entry["skipped_reason"] == "no_template_available"
    assert result["coverage"]["network"]["ran"] is False
    assert result["coverage"]["network"]["skipped_reason"] == "not_all_passes_ran"


def test_an_operator_who_widens_exclude_tags_also_drops_the_template(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, exclude_tags=["intrusive", "smb"]), out)

    assert nuclei.network_calls == []
    assert result["coverage"]["network"]["passes"][0]["template_ids_excluded"] == [SMB_ID]


def test_the_severity_floor_applies_and_names_what_it_left_out(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, severities=["critical", "high"]), out)

    assert nuclei.network_calls == []
    (entry,) = result["coverage"]["network"]["passes"]
    assert entry["template_ids_below_floor"] == [SMB_ID]
    assert entry["skipped_reason"] == "no_template_available"


def test_no_floor_when_severities_is_empty(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, severities=[]), out)

    assert len(nuclei.network_calls) == 1


def test_a_template_the_host_does_not_have_is_recorded_missing_not_assumed(tmp_path: Path, monkeypatch):
    templates = tmp_path / "t"
    templates.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("10.0.0.5", 445, "smb")])
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    assert nuclei.network_calls == []
    (entry,) = result["coverage"]["network"]["passes"]
    assert entry["template_ids_missing"] == [SMB_ID] and entry["ran"] is False


def test_a_pinned_verification_run_makes_no_network_pass_and_keeps_its_coverage_unchanged(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates, template_ids=[SMB_ID]), out)

    assert len(nuclei.calls) == 1
    assert "network" not in result["coverage"]
    assert "network" not in json.loads((out / "nuclei.json").read_text(encoding="utf-8"))["coverage"]


def test_the_switch_turns_the_pass_off_and_says_so(stand, monkeypatch):
    templates, out = stand
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, network_templates=False), out)

    assert nuclei.network_calls == []
    network = result["coverage"]["network"]
    assert network == {
        "enabled": False, "ran": False, "skipped_reason": "network_templates_disabled",
        "targets_considered": 0, "truncated": False, "severities": ["critical", "high", "medium"],
        "duplicates_of_sweep": 0, "passes": [],
    }


@pytest.mark.parametrize(
    ("which", "enabled", "reason"),
    [(lambda name: None, True, "nuclei_binary_missing"), (_which, False, "nuclei.disabled")],
)
def test_a_nuclei_that_cannot_run_gives_the_pass_the_same_reason(stand, monkeypatch, which, enabled, reason):
    templates, out = stand
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", which)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, enabled=enabled), out)

    assert result["skipped_reason"] == reason
    assert result["coverage"]["network"]["skipped_reason"] == reason
    assert result["coverage"]["network"]["ran"] is False


def test_a_non_zero_exit_is_not_a_look(stand, monkeypatch):
    templates, out = stand
    Nuclei(monkeypatch, returncode=1, stderr="[FTL] boom")

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    network = result["coverage"]["network"]
    assert network["ran"] is False and network["passes"][0]["returncode"] == 1
    assert network["skipped_reason"] == "not_all_passes_ran"


def test_a_target_nuclei_gave_up_on_is_recorded(stand, monkeypatch):
    templates, out = stand
    Nuclei(
        monkeypatch,
        stderr="[INF] Templates loaded for current scan: 1\n[INF] Skipped 10.0.0.5:445 from target list as found unresponsive permanently: x\n",
    )

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    assert result["coverage"]["network"]["passes"][0]["skipped_targets"] == ["10.0.0.5:445"]


def test_past_max_targets_the_pass_is_flagged_truncated(tmp_path: Path, monkeypatch):
    templates = tmp_path / "t"
    _js_template(templates, SMB_ID)
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("10.0.0.1", 445, "smb"), ("10.0.0.2", 445, "smb"), ("10.0.0.3", 445, "smb")])
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan([f"10.0.0.{n}:445/tcp" for n in (3, 1, 2)], _config(templates, max_targets=2), out)

    assert nuclei.targets == [["10.0.0.1:445", "10.0.0.2:445"]]
    network = result["coverage"]["network"]
    assert network["truncated"] is True and network["targets_considered"] == 3


def test_a_planner_bug_does_not_fail_the_scan(stand, monkeypatch):
    templates, out = stand
    Nuclei(monkeypatch)

    def boom(*args, **kwargs):
        raise RuntimeError("planner")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.plan_network_targets", boom)

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)

    assert result["coverage"]["ran"] is True, "the web sweep is unaffected"
    assert result["coverage"]["network"]["skipped_reason"] == "network_pass_error"


def test_ipv6_endpoints_are_bracketed_for_nuclei(tmp_path: Path, monkeypatch):
    templates = tmp_path / "t"
    _js_template(templates, SMB_ID)
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("fd00::5", 445, "smb")])
    nuclei = Nuclei(monkeypatch)

    run_nuclei_scan(["[fd00::5]:445/tcp"], _config(templates), out)

    assert nuclei.targets == [["[fd00::5]:445"]]


def test_each_rule_runs_its_own_ids_against_its_own_endpoints_only(tmp_path: Path, monkeypatch):
    """One process per rule: an SMB template must never meet an FTP endpoint."""
    templates = tmp_path / "t"
    _js_template(templates, SMB_ID)
    _js_template(templates, "ftp-check", tags="js,network,ftp")
    out = tmp_path / "out"
    out.mkdir()
    _services(out, [("10.0.0.5", 445, "smb"), ("10.0.0.6", 21, "ftp")])
    ftp = NetworkRule("ftp", frozenset({"ftp"}), frozenset({21}), ("ftp-check",), ("ftp-anon",))
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.NETWORK_RULES", (SMB_RULE, ftp))
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.6:21/tcp"], _config(templates), out)

    ran = {c[c.index("-id") + 1]: nuclei.targets[nuclei.calls.index(c)] for c in nuclei.network_calls}
    assert ran == {SMB_ID: ["10.0.0.5:445"], "ftp-check": ["10.0.0.6:21"]}
    assert [p["rule"] for p in result["coverage"]["network"]["passes"]] == ["ftp", "smb"]
    assert result["coverage"]["network"]["ran"] is True


def test_a_finding_the_sweep_already_made_on_the_same_host_and_port_is_not_doubled(stand, monkeypatch):
    """nuclei gives a javascript template its own port for a URL input, so the sweep reaches 445 of any host with a web port."""
    templates, out = stand
    line = json.dumps({
        "template-id": SMB_ID, "host": "10.0.0.5", "port": "445", "matched-at": "10.0.0.5:445",
        "info": {"name": "SMB Signing Not Required", "severity": "medium", "tags": ["js"]},
    }) + "\n"
    Nuclei(monkeypatch, jsonl={"web": line, "network": line})

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)

    assert [f.get("pass") for f in result["findings"]] == [None], "the sweep's finding stays, the network pass adds none"
    assert result["coverage"]["network"]["duplicates_of_sweep"] == 1


# --------------------------------------------------------------------------
# From the nuclei result to the report, the tracker's detector and the evidence (review of #547)
# --------------------------------------------------------------------------

#: The record nuclei v3.11.1 wrote for the real run on the corpus stand (trimmed of the request text).
REAL_SMB_RECORD = {
    "template-id": SMB_ID, "type": "javascript", "host": "10.0.0.5", "port": "445",
    "url": "10.0.0.5:445", "matched-at": "10.0.0.5:445", "ip": "10.0.0.5",
    "timestamp": "2026-10-10T18:14:02.298129346Z", "matcher-status": True,
    "info": {"name": "SMB Signing Not Required", "author": ["pussycat0x"], "tags": ["js", "network", "smb", "enum"],
             "severity": "medium"},
}


def _line(record: dict) -> str:
    return json.dumps(record) + "\n"


def test_a_cve_less_network_finding_reaches_vulnerabilities_json_and_the_trackers_detector(stand, monkeypatch):
    from api.services import vulnerabilities as tracker
    from scanner.pipeline.report import build_reports
    from tests.test_report import _setup

    templates, out = stand
    Nuclei(monkeypatch, jsonl={"network": _line(REAL_SMB_RECORD)})
    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    assert result["cve_findings"] == []
    (row,) = result["network_vulnerabilities"]
    assert (row["host"], row["port"], row["cve"], row["script_id"], row["source"]) == (
        "10.0.0.5", "445", "", "nuclei:smb-signing-not-required", "nuclei",
    )

    report_dir = out.parent / "report"
    report_dir.mkdir()
    build_reports(
        output_dir=report_dir, total_targets=1, alive_hosts=["10.0.0.5"], open_ports=["10.0.0.5:445"],
        nmap_dir=_setup(out.parent), markdown_summary=False, html_summary=False, csv_export=False,
        json_export=True, extra_vulnerabilities=result["cve_findings"] + result["network_vulnerabilities"],
    )
    rows = json.loads((report_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    mine = [r for r in rows if r.get("script_id") == "nuclei:smb-signing-not-required"]
    assert len(mine) == 1 and mine[0]["severity"] == "medium" and mine[0]["port"] == "445" and mine[0]["cve"] == ""
    # The tracker names the detector and the template id from the same row.
    assert tracker._detector_of(mine[0]["source"], mine[0]["script_id"]) == ("nuclei", SMB_ID)
    key = tracker.finding_key(asset_id="a1", cve=None, script_id=mine[0]["script_id"], port=mine[0]["port"])
    assert key == tracker.finding_key(asset_id="a1", cve="", script_id="nuclei:smb-signing-not-required", port="445")


def test_the_network_raw_jsonl_is_in_the_evidence_projection(stand, monkeypatch):
    from scanner.pipeline import evidence_artifacts

    templates, out = stand
    Nuclei(monkeypatch, jsonl={"network": _line(REAL_SMB_RECORD)})
    run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    result = evidence_artifacts.write_evidence_artifact(out, tenant_id="t", run_id="r")
    text = json.dumps(result)
    assert "nuclei_network_smb_raw.jsonl" in text and SMB_ID in text and "template_match" in text


def test_a_cve_bearing_network_finding_becomes_a_cve_row_with_host_port_and_script_id(stand, monkeypatch):
    record = {**REAL_SMB_RECORD, "info": {**REAL_SMB_RECORD["info"], "classification": {"cve-id": ["CVE-2099-0001"], "cvss-score": 6.5}}}
    Nuclei(monkeypatch, jsonl={"network": _line(record)})
    templates, out = stand

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    (row,) = result["cve_findings"]
    assert (row["host"], row["port"], row["cve"], row["script_id"], row["source"], row["cvss"]) == (
        "10.0.0.5", "445", "CVE-2099-0001", "nuclei:smb-signing-not-required", "nuclei", 6.5,
    )
    assert result["network_vulnerabilities"] == [], "a CVE row is not also a CVE-less one"


def test_the_report_merge_is_one_function_and_main_uses_it_for_extra_vulnerabilities():
    import ast

    from scanner.pipeline.nuclei_scan import nuclei_vulnerability_rows

    cve_row, plain_row = {"cve": "CVE-1"}, {"cve": "", "script_id": "nuclei:x"}
    assert nuclei_vulnerability_rows({"cve_findings": [cve_row], "network_vulnerabilities": [plain_row]}) == [cve_row, plain_row]
    # A --resume that reloads a nuclei.json from before the pass, or the stage's fallback.
    assert nuclei_vulnerability_rows({"cve_findings": [cve_row]}) == [cve_row]
    assert nuclei_vulnerability_rows({"cve_findings": []}) == []

    tree = ast.parse((Path(__file__).resolve().parents[1] / "scanner" / "main.py").read_text(encoding="utf-8"))
    assigned = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "nuclei_cve_findings" for t in n.targets)
    ]
    assert len(assigned) == 1
    call = assigned[0].value
    assert isinstance(call, ast.Call) and getattr(call.func, "id", "") == "nuclei_vulnerability_rows"
    kwargs = [
        k for n in ast.walk(tree) if isinstance(n, ast.Call)
        for k in n.keywords if k.arg == "extra_vulnerabilities"
    ]
    assert [getattr(k.value, "id", "") for k in kwargs] == ["nuclei_cve_findings"]


def test_a_host_with_a_web_port_and_smb_still_gets_its_row_when_the_sweep_made_the_match(stand, monkeypatch):
    """The sweep reaches 445 of a host with a web port; the pass then deduplicates, and the row must survive."""
    templates, out = stand
    web_shape = {**REAL_SMB_RECORD, "url": "http://10.0.0.5:80/"}
    Nuclei(monkeypatch, jsonl={"web": _line(web_shape), "network": _line(REAL_SMB_RECORD)})

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)

    assert len(result["findings"]) == 1
    assert [r["script_id"] for r in result["network_vulnerabilities"]] == ["nuclei:smb-signing-not-required"]
    assert result["network_vulnerabilities"][0]["port"] == "445"


def test_a_sweep_match_of_a_template_outside_the_table_gets_no_row(stand, monkeypatch):
    templates, out = stand
    other = {**REAL_SMB_RECORD, "template-id": "exposed-panel"}
    Nuclei(monkeypatch, jsonl={"web": _line(other)})

    result = run_nuclei_scan(["10.0.0.5:80/tcp"], _config(templates), out)

    assert len(result["findings"]) == 1 and result["network_vulnerabilities"] == []


def test_a_cve_less_nuclei_match_is_not_exploit_evidence_and_a_cve_one_still_is():
    from api.services.exploit_evidence import PROOF_OF_CONCEPT, ExploitEvidence

    evidence = ExploitEvidence(overlay={"CVE-OTHER-1": ("weaponized", ("metasploit",))})
    plain = evidence.assess({"source": "nuclei", "script_id": "nuclei:smb-signing-not-required"}, cve="", epss=0.0, kev_active=False)
    assert plain.maturity != PROOF_OF_CONCEPT and "nuclei-match" not in plain.sources
    assert plain.verified_on_host is True, "a template did fire on this host; that stays an observation"
    cve = evidence.assess({"source": "nuclei", "script_id": "nuclei:CVE-1"}, cve="CVE-1", epss=0.0, kev_active=False)
    assert cve.maturity == PROOF_OF_CONCEPT and cve.sources == ("nuclei-match",) and cve.verified_on_host is True
    plugin = evidence.assess({"source": "pulse-plugin", "script_id": "pulse-plugin:x"}, cve="", epss=0.0, kev_active=False)
    assert plugin.maturity == plain.maturity and plugin.verified_on_host is False
    # The verified flag survives every no-candidate branch, not only the sourced one.
    bare = ExploitEvidence()
    nuclei_item = {"source": "nuclei", "script_id": "nuclei:smb-signing-not-required"}
    assert bare.assess(nuclei_item, cve="", epss=0.0, kev_active=False).verified_on_host is True  # no source configured
    assert bare.assess(nuclei_item, cve="", epss=0.9, kev_active=False).verified_on_host is True  # epss floor
    assert evidence.assess({"source": "pulse-plugin"}, cve="", epss=0.9, kev_active=False).verified_on_host is False


def test_stale_network_files_of_an_earlier_attempt_are_removed_on_every_path(stand, monkeypatch):
    from scanner.pipeline import evidence_artifacts

    templates, out = stand
    Nuclei(monkeypatch)
    for name in ("nuclei_network_smb_raw.jsonl", "nuclei_network_smb_targets.txt", "nuclei_network_ftp_raw.jsonl"):
        (out / name).write_text(_line(REAL_SMB_RECORD), encoding="utf-8")

    run_nuclei_scan(["10.0.0.5:22/tcp"], _config(templates), out)  # nothing for the pass to do

    assert not list(out.glob("nuclei_network_*"))
    assert SMB_ID not in json.dumps(evidence_artifacts.write_evidence_artifact(out, tenant_id="t", run_id="r"))

    (out / "nuclei_network_smb_raw.jsonl").write_text(_line(REAL_SMB_RECORD), encoding="utf-8")
    run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, network_templates=False), out)
    assert not list(out.glob("nuclei_network_*"))

    (out / "nuclei_network_smb_raw.jsonl").write_text(_line(REAL_SMB_RECORD), encoding="utf-8")
    run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, template_ids=[SMB_ID]), out)  # a pinned run
    assert not list(out.glob("nuclei_network_*"))


def test_a_process_is_started_with_exactly_the_minimum_left_but_not_with_less(stand, monkeypatch):
    from scanner.pipeline import nuclei_scan

    templates, out = stand
    for left, started in ((nuclei_scan._MIN_PROCESS_SECONDS, True), (nuclei_scan._MIN_PROCESS_SECONDS - 1, False), (0, False)):
        clock = {"now": 0.0}
        monkeypatch.setattr(nuclei_scan.time, "monotonic", lambda clock=clock: clock["now"])
        calls: list[int] = []

        def run(command, clock=clock, calls=calls, **kwargs):
            calls.append(kwargs["timeout"])
            if "-id" not in command:
                clock["now"] = 1800 + nuclei_scan.NETWORK_GRACE_SECONDS - left
            Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "[INF] Templates loaded for current scan: 1\n")

        monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _which)
        monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", run)
        run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)
        assert (len(calls) == 2) is started, (left, calls)


def test_a_run_that_times_out_is_not_a_look_but_keeps_what_nuclei_had_written(stand, monkeypatch):
    templates, out = stand
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _which)

    def times_out(command, **kwargs):
        Path(command[command.index("-jsonl-export") + 1]).write_text(_line(REAL_SMB_RECORD), encoding="utf-8")
        raise TimeoutError("nuclei took too long")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", times_out)
    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    network = result["coverage"]["network"]
    (entry,) = network["passes"]
    assert entry["skipped_reason"] == "nuclei_run_failed" and entry["ran"] is False and entry["returncode"] is None
    assert network["ran"] is False and network["skipped_reason"] == "not_all_passes_ran"
    assert [f["template_id"] for f in result["findings"]] == [SMB_ID], "the partial observation is kept"


def test_the_stage_is_bounded_the_pass_gets_what_is_left_and_not_more(stand, monkeypatch):
    from scanner.pipeline import nuclei_scan

    templates, out = stand
    clock = {"now": 1000.0}
    monkeypatch.setattr(nuclei_scan.time, "monotonic", lambda: clock["now"])
    timeouts: list[tuple[bool, int]] = []

    def run(command, **kwargs):
        timeouts.append(("-id" in command, kwargs["timeout"]))
        if "-id" not in command:
            clock["now"] += 1790  # the sweep takes almost all of overall_timeout_seconds
        Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "[INF] Templates loaded for current scan: 1\n")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _which)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", run)

    run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)

    # overall 1800 + grace 120 = 1920 for the whole stage; 1790 spent, so 130 s are left.
    assert timeouts == [(False, 1800), (True, 130)]


def test_a_pass_reached_after_the_stage_deadline_is_recorded_not_run(stand, monkeypatch):
    from scanner.pipeline import nuclei_scan

    templates, out = stand
    clock = {"now": 0.0}
    monkeypatch.setattr(nuclei_scan.time, "monotonic", lambda: clock["now"])
    seen: list[list[str]] = []

    def run(command, **kwargs):
        seen.append(list(command))
        clock["now"] += 5000
        Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _which)
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", run)

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)

    assert len(seen) == 1
    (entry,) = result["coverage"]["network"]["passes"]
    assert entry["skipped_reason"] == "stage_deadline_exhausted" and entry["ran"] is False


def test_a_second_file_under_the_same_id_is_never_run(stand, tmp_path: Path, monkeypatch):
    """The table vouches for one reviewed file; a copy in custom_templates_dir would run on every SMB host."""
    templates, out = stand
    custom = tmp_path / "custom"
    _js_template(custom, SMB_ID)
    nuclei = Nuclei(monkeypatch)

    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates, custom_templates_dir=str(custom)), out)

    assert nuclei.network_calls == []
    assert result["coverage"]["network"]["passes"][0]["template_ids_ambiguous"] == [SMB_ID]


def test_the_sha256_of_the_template_that_ran_is_recorded(stand, monkeypatch):
    import hashlib

    templates, out = stand
    Nuclei(monkeypatch)
    result = run_nuclei_scan(["10.0.0.5:445/tcp"], _config(templates), out)

    path = templates / "javascript" / "misconfiguration" / "smb" / f"{SMB_ID}.yaml"
    assert result["coverage"]["network"]["passes"][0]["template_sha256"] == {
        SMB_ID: hashlib.sha256(path.read_bytes()).hexdigest()
    }


@pytest.mark.parametrize(
    "variant",
    [
        {"host": "10.0.0.5", "port": "445"},  # the real shape, both inputs
        {"host": "[fd00::5]", "port": "445"},
        {"host": "10.0.0.5:445", "port": ""},
        {"host": "10.0.0.5", "port": 445},
    ],
)
def test_the_dedup_key_reads_every_spelling_of_the_same_endpoint(variant):
    from scanner.pipeline.nuclei_scan import _finding_key

    other = {"template_id": SMB_ID, "host": "10.0.0.5", "port": "445"}
    probe = {"template_id": SMB_ID, **variant}
    if variant["host"].startswith("[fd00"):
        other = {**other, "host": "fd00::5"}
    assert _finding_key(probe) == _finding_key(other)


def test_the_sweep_s_real_shape_and_the_pass_s_dedupe_on_a_bracketless_host(stand, monkeypatch):
    templates, out = stand
    web_shape = {**REAL_SMB_RECORD, "url": "http://10.0.0.5:80/", "matched-at": "10.0.0.5:445"}
    Nuclei(monkeypatch, jsonl={"web": _line(web_shape), "network": _line(REAL_SMB_RECORD)})

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates), out)

    assert len(result["findings"]) == 1 and result["coverage"]["network"]["duplicates_of_sweep"] == 1


def test_the_dedup_key_ignores_the_case_of_the_host():
    from scanner.pipeline.nuclei_scan import _finding_key

    assert _finding_key({"template_id": "t", "host": "FD00::5A", "port": "1"}) == _finding_key(
        {"template_id": "t", "host": "fd00::5a", "port": "1"}
    )
    assert _finding_key({"template_id": "t", "host": "Host.Example", "port": "1"})[1] == "host.example"


def test_switching_the_pass_off_also_drops_the_row_of_a_match_the_sweep_made(stand, monkeypatch):
    """The sweep still reaches 445 of a host with a web port; its finding stays in nuclei.json, the row does not."""
    templates, out = stand
    Nuclei(monkeypatch, jsonl={"web": _line(REAL_SMB_RECORD)})

    result = run_nuclei_scan(["10.0.0.5:445/tcp", "10.0.0.5:80/tcp"], _config(templates, network_templates=False), out)

    assert len(result["findings"]) == 1
    assert result["network_vulnerabilities"] == []


def test_a_stale_file_that_cannot_be_removed_does_not_break_the_stage(stand, monkeypatch):
    templates, out = stand
    Nuclei(monkeypatch)
    (out / "nuclei_network_smb_raw.jsonl").write_text("x", encoding="utf-8")
    real_unlink = Path.unlink

    def refuse(self, *args, **kwargs):
        if self.name.startswith("nuclei_network_"):
            raise PermissionError("read-only")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)

    result = run_nuclei_scan(["10.0.0.5:80/tcp"], _config(templates), out)

    assert result["coverage"]["ran"] is True
