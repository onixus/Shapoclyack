"""Rhai plugins for Pulse: the adapter side (#544, ADR 0002).

What is pinned here, and why each one is a test of its own:

* ``--script-dir`` is passed when plugins are on and never otherwise, and Pulse
  runs in the same empty directory as its ``HOME`` -- ``--script-dir`` makes it
  load ``./scripts`` and ``$HOME/.pulse/scripts`` too;
* the run's receipt names every plugin with its sha256, which of them
  ``pulse plugin check`` accepted, and the errors Pulse printed, per chunk;
* the plugin set is part of the chunk key and of the resume decision;
* a plugin finding is not a CVE: severity normalised, stamped with the file's
  sha, keyed by ``script_id`` in the report, and judged by its own detector
  when a verification asks whether it was re-checked.

No Pulse binary is needed. The tests that run the plugins against stub servers
are in ``test_pulse_plugins_live.py``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from api.services import verification_coverage as vc
from api.services import vulnerabilities as vulns
from scanner.pipeline import evidence_artifacts, pulse_plugins
from scanner.pipeline import pulse_probe as pp
from scanner.pipeline.config_schema import ProfilePulseConfig, PulseProbeConfig, merge_pulse_config
from scanner.pipeline.scan_policy import apply_policy
from scanner.pipeline.service_schema import CveRecord, cves_to_extra_vulnerabilities
from tests.test_scanner_scan_policy import _config, _policy

PLUGIN_A = "fn name() { \"shapo_ssh_algorithms\" }\nfn description() { \"a\" }\nfn ports() { [] }\nfn run() { }\n"
PLUGIN_B = "fn name() { \"shapo_ftp_anonymous\" }\nfn description() { \"b\" }\nfn ports() { [] }\nfn run() { }\n"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _flag(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def _plugin_row(plugin: str = "shapo_ssh_algorithms", *, ip: str = "10.0.0.1", port: int = 22, severity: str = "HIGH") -> dict:
    return {
        "cve_id": f"SCRIPT-{plugin.upper()}", "ip": ip, "port": port, "service": "ssh", "severity": severity,
        "title": "t", "summary": "s", "evidence": "e\r", "source": "rhai_script",
        "finding_class": "plugin_script", "match_reason": f"rhai script {plugin}", "confidence": 90,
        "ruleset_version": "2026.07.29-h1", "requires_confirmation": False,
    }


@pytest.fixture
def plugin_dir(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "plugins"
    directory.mkdir()
    (directory / "shapo_ssh_algorithms.rhai").write_text(PLUGIN_A, encoding="utf-8")
    (directory / "shapo_ftp_anonymous.rhai").write_text(PLUGIN_B, encoding="utf-8")
    monkeypatch.setattr(pulse_plugins, "PLUGINS_DIR", directory)
    return directory


class Pulse:
    """A stand-in for the pulse process: records how it was spawned."""

    def __init__(self, monkeypatch):
        self.spawns: list[dict] = []
        self.checked: list[str] = []
        self.stderr = ""
        self.findings: list[dict] = []
        self.reject: dict[str, str] = {}
        monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "fixture")
        monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
        monkeypatch.setattr(pp.time, "sleep", lambda _: None)
        monkeypatch.setattr(pp, "run_command", self._run)
        monkeypatch.setattr(pulse_plugins, "check_plugin", self._check)

    def _check(self, pulse_bin, path, *, env, cwd):
        self.checked.append(Path(path).stem)
        return self.reject.get(Path(path).stem)

    @staticmethod
    def _script_dir_files(command):
        if "--script-dir" not in command:
            return None
        directory = Path(_flag(command, "--script-dir"))
        return sorted(p.name for p in directory.iterdir()) if directory.is_dir() else "missing"

    def _run(self, command, **kwargs):
        cwd = kwargs.get("cwd")
        env = kwargs["env"]
        hosts = Path(command[command.index("--targets-file") + 1]).read_text().splitlines()
        ports = [int(p) for p in _flag(command, "-p").split(",")]
        self.spawns.append({
            "command": command, "cwd": cwd, "home": env["HOME"], "timeout": kwargs["timeout"],
            # Snapshot at spawn time: the directory is removed once the process is done.
            "cwd_entries": sorted(p.name for p in Path(cwd).iterdir()) if cwd else None,
            "cwd_is_dir": bool(cwd) and Path(cwd).is_dir(),
            "script_dir_files": self._script_dir_files(command),
        })
        rows = [{"ip": h, "port": p, "protocol": "tcp", "service": "ssh"} for h in hosts for p in ports]
        body = {"open": rows, "cves": list(self.findings), "findings": list(self.findings),
                "meta": {"ruleset": "2026.07.29-h1", "version": "1.3.0"}}
        return subprocess.CompletedProcess(command, 0, json.dumps(body), self.stderr)


@pytest.fixture
def pulse(monkeypatch) -> Pulse:
    return Pulse(monkeypatch)


def _run(tmp_path, endpoints=("10.0.0.1:22/tcp",), **kwargs) -> Path:
    out = tmp_path / "out"
    pp.run_pulse_probe(list(endpoints), output_dir=out, retry_settle_seconds=0, **kwargs)
    return out


def _raw(out: Path) -> dict:
    return json.loads((out / "pulse" / "raw.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The command and the process
# --------------------------------------------------------------------------


def test_script_dir_is_passed_when_plugins_are_on(tmp_path, plugin_dir, pulse):
    _run(tmp_path, plugins=True)
    spawn = pulse.spawns[0]
    directory = Path(_flag(spawn["command"], "--script-dir"))
    # Pulse is given a directory of copies, not the shipped one.
    assert directory.is_absolute() and directory != plugin_dir
    assert spawn["script_dir_files"] == ["shapo_ftp_anonymous.rhai", "shapo_ssh_algorithms.rhai"]
    assert not directory.exists()  # removed when the run is over
    assert "--scripts" not in spawn["command"]  # bare --scripts would read ./scripts of the cwd


def test_script_dir_is_not_passed_when_plugins_are_off(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=False)
    assert "--script-dir" not in pulse.spawns[0]["command"]
    assert pulse.checked == []
    receipt = _raw(out)["adapter"]["plugins"]
    assert receipt["requested"] is False and receipt["active"] is False and receipt["loaded"] == []


def test_pulse_runs_in_the_empty_directory_that_is_also_home(tmp_path, plugin_dir, pulse):
    _run(tmp_path, plugins=True)
    spawn = pulse.spawns[0]
    assert spawn["cwd"] == spawn["home"]
    assert spawn["cwd_entries"] == []  # no ./scripts, no .pulse/scripts to be added by pulse
    assert not Path(spawn["cwd"]).exists()  # removed with the process


def test_cwd_is_private_even_without_plugins(tmp_path, plugin_dir, pulse):
    _run(tmp_path, plugins=False)
    spawn = pulse.spawns[0]
    assert spawn["cwd"] == spawn["home"] and spawn["cwd_entries"] == []


def test_relative_pulse_binary_is_made_absolute(tmp_path, plugin_dir, pulse, monkeypatch):
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "./bin/pulse")
    _run(tmp_path, plugins=False)
    assert Path(pulse.spawns[0]["command"][0]).is_absolute()


def test_process_timeout_grows_by_the_plugin_budget(tmp_path, plugin_dir, pulse):
    _run(tmp_path, ["10.0.0.1:22/tcp", "10.0.0.1:21/tcp"], plugins=True, timeout_seconds=100)
    assert pulse.spawns[0]["timeout"] == 100 + 2 * pulse_plugins.PLUGIN_SECONDS_PER_ENDPOINT


def test_process_timeout_is_untouched_without_plugins(tmp_path, plugin_dir, pulse):
    _run(tmp_path, ["10.0.0.1:22/tcp", "10.0.0.1:21/tcp"], plugins=False, timeout_seconds=100)
    assert pulse.spawns[0]["timeout"] == 100


# --------------------------------------------------------------------------
# The receipt
# --------------------------------------------------------------------------


def test_receipt_names_each_plugin_with_the_sha256_of_its_file(tmp_path, plugin_dir, pulse):
    receipt = _raw(_run(tmp_path, plugins=True))["adapter"]["plugins"]
    assert receipt["loaded"] == [
        {"name": "shapo_ftp_anonymous", "sha256": _sha(PLUGIN_B)},
        {"name": "shapo_ssh_algorithms", "sha256": _sha(PLUGIN_A)},
    ]
    assert receipt["active"] is True and receipt["rejected"] == []
    assert receipt["digest"] and receipt["dir"] == str(plugin_dir)
    assert pulse.checked == ["shapo_ftp_anonymous", "shapo_ssh_algorithms"]


def test_a_plugin_pulse_check_rejects_is_not_loaded(tmp_path, plugin_dir, pulse):
    pulse.reject = {"shapo_ftp_anonymous": "Compilation error: x"}
    receipt = _raw(_run(tmp_path, plugins=True))["adapter"]["plugins"]
    assert [p["name"] for p in receipt["loaded"]] == ["shapo_ssh_algorithms"]
    assert receipt["rejected"] == [{"name": "shapo_ftp_anonymous", "sha256": _sha(PLUGIN_B), "reason": "Compilation error: x"}]


def test_pulse_is_only_given_the_files_the_check_accepted(tmp_path, plugin_dir, pulse):
    """Pulse loads every script of the directory it is given that compiles."""
    pulse.reject = {"shapo_ftp_anonymous": "Compilation error: x"}
    _run(tmp_path, plugins=True)
    assert pulse.spawns[0]["script_dir_files"] == ["shapo_ssh_algorithms.rhai"]


def test_loaded_sha256_is_that_of_the_copy_pulse_reads(tmp_path, plugin_dir, pulse, monkeypatch):
    seen = {}

    def check(pulse_bin, path, *, env, cwd):
        seen[Path(path).stem] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        return None

    monkeypatch.setattr(pulse_plugins, "check_plugin", check)
    receipt = _raw(_run(tmp_path, plugins=True))["adapter"]["plugins"]
    assert {p["name"]: p["sha256"] for p in receipt["loaded"]} == seen


def test_when_every_plugin_is_rejected_no_script_dir_is_passed(tmp_path, plugin_dir, pulse):
    pulse.reject = {"shapo_ssh_algorithms": "bad", "shapo_ftp_anonymous": "bad"}
    receipt = _raw(_run(tmp_path, plugins=True))["adapter"]["plugins"]
    assert "--script-dir" not in pulse.spawns[0]["command"]
    assert receipt["active"] is False and receipt["loaded"] == []


def test_missing_plugin_directory_degrades_and_says_so(tmp_path, pulse, monkeypatch, caplog):
    monkeypatch.setattr(pulse_plugins, "PLUGINS_DIR", tmp_path / "gone")
    receipt = _raw(_run(tmp_path, plugins=True))["adapter"]["plugins"]
    assert "--script-dir" not in pulse.spawns[0]["command"]
    assert receipt["active"] is False and "no .rhai plugins" in receipt["unavailable"]
    assert "Pulse runs without plugins" in caplog.text


def test_plugin_errors_are_recorded_with_the_chunks_hosts_and_ports(tmp_path, plugin_dir, pulse):
    pulse.stderr = (
        "adaptive  concurrency\n"
        "  \x1b[1m\x1b[33mwarn\x1b[39m\x1b[0m  plugin error — shapo_ssh_algorithms: Runtime error: the server closed (line 3, position 9)\n"
    )
    raw = _raw(_run(tmp_path, ["10.0.0.1:22/tcp", "10.0.0.2:22/tcp"], plugins=True))
    receipt = raw["adapter"]["plugins"]
    assert len(receipt["errors"]) == 1
    error = receipt["errors"][0]
    assert error["plugin"] == "shapo_ssh_algorithms" and "server closed" in error["message"]
    assert error["hosts"] == ["10.0.0.1", "10.0.0.2"] and error["ports"] == [22]
    assert error["chunk"] == raw["chunks"][0]["key"]


def test_errors_are_not_collected_when_plugins_are_off(tmp_path, plugin_dir, pulse):
    pulse.stderr = "  warn  plugin error — shapo_ssh_algorithms: boom\n"
    assert _raw(_run(tmp_path, plugins=False))["adapter"]["plugins"]["errors"] == []


def test_parse_plugin_errors_reads_pulses_stderr_line():
    stderr = (
        "x\n  \x1b[33mwarn\x1b[0m  plugin error — shapo_ssh_algorithms: Runtime error: boom (line 1) (line 3, position 9)\n"
        "plugin error — a.b-c: x\n"
    )
    assert pulse_plugins.parse_plugin_errors(stderr) == [
        {"plugin": "shapo_ssh_algorithms", "message": "Runtime error: boom (line 1)", "position": "line 3, position 9"},
        {"plugin": "a.b-c", "message": "x"},
    ]
    assert pulse_plugins.parse_plugin_errors("warn  something else\n") == []


# --------------------------------------------------------------------------
# Chunk key and resume
# --------------------------------------------------------------------------


def test_chunk_key_depends_on_the_plugin_set_and_only_when_there_is_one():
    plain = pp.chunk_key(["10.0.0.1"], [22])
    assert pp.chunk_key(["10.0.0.1"], [22], "connect", "") == plain  # old keys stay valid
    with_a = pp.chunk_key(["10.0.0.1"], [22], "connect", "a" * 64)
    assert with_a != plain
    assert with_a != pp.chunk_key(["10.0.0.1"], [22], "connect", "b" * 64)


def test_chunk_file_name_carries_the_plugin_digest(tmp_path, plugin_dir, pulse):
    with_plugins = _run(tmp_path / "a", plugins=True)
    without = _run(tmp_path / "b", plugins=False)
    assert _raw(with_plugins)["chunks"][0]["key"] != _raw(without)["chunks"][0]["key"]


def _resume(out: Path, **kwargs) -> None:
    pp.run_pulse_probe(["10.0.0.1:22/tcp"], output_dir=out, done_hosts={"10.0.0.1"}, retry_settle_seconds=0, **kwargs)


def test_resume_reuses_a_run_made_with_the_same_plugins(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=True)
    pulse.findings = [_plugin_row()]
    spawns = len(pulse.spawns)
    _resume(out, plugins=True)
    assert len(pulse.spawns) == spawns  # nothing re-probed
    receipt = _raw(out)["adapter"]["plugins"]
    assert [p["name"] for p in receipt["loaded"]] == ["shapo_ftp_anonymous", "shapo_ssh_algorithms"]  # the receipt survived


def test_resume_reprobes_when_a_plugin_was_edited(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=True)
    (plugin_dir / "shapo_ssh_algorithms.rhai").write_text(PLUGIN_A + "// edited\n", encoding="utf-8")
    spawns = len(pulse.spawns)
    _resume(out, plugins=True)
    assert len(pulse.spawns) == spawns + 1


def test_resume_reprobes_when_plugins_were_off_and_are_on_now(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=False)
    spawns = len(pulse.spawns)
    _resume(out, plugins=True)
    assert len(pulse.spawns) == spawns + 1


def test_resume_reprobes_when_plugins_were_on_and_are_off_now(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=True)
    spawns = len(pulse.spawns)
    _resume(out, plugins=False)
    assert len(pulse.spawns) == spawns + 1


# --------------------------------------------------------------------------
# Parsing a plugin's finding
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [("HIGH", "high"), ("Medium", "medium"), ("critical", "critical"), ("LOW", "low"),
     ("INFO", "info"), ("informational", "info"), ("", "info"), (None, "info"), ("urgent!", "info")],
)
def test_plugin_severity_is_normalised(given, expected):
    records = pp.parse_pulse_json({"cves": [{**_plugin_row(), "severity": given}]})[2]
    assert records[0].severity == expected


def test_plugin_finding_is_stamped_with_the_files_sha_and_cleaned():
    row = _plugin_row()
    _, _, records = pp.parse_pulse_json({"cves": [row]}, plugin_shas={"shapo_ssh_algorithms": "ab" * 32})
    assert records[0].finding_class == "plugin_script"
    assert records[0].ruleset_version == "sha256:" + "ab" * 32
    assert records[0].evidence == "e"


def test_finding_from_a_plugin_nobody_offered_is_dropped(caplog):
    payload = {"cves": [_plugin_row("shapo_ssh_algorithms"), _plugin_row("stranger")]}
    _, _, records = pp.parse_pulse_json(payload, plugin_shas={"shapo_ssh_algorithms": "ab" * 32})
    assert [r.match_reason for r in records] == ["rhai script shapo_ssh_algorithms"]
    assert "not in the set" in caplog.text
    # Without plugins offered, every plugin finding is a stranger.
    assert pp.parse_pulse_json(payload, plugin_shas={})[2] == []
    # Recorded output read by tooling (no set) passes untouched.
    assert len(pp.parse_pulse_json(payload)[2]) == 2


def test_run_drops_findings_when_plugins_are_off(tmp_path, plugin_dir, pulse):
    pulse.findings = [_plugin_row()]
    out = _run(tmp_path, plugins=False)
    assert json.loads((out / "pulse_cves.json").read_text(encoding="utf-8")) == []


def test_run_keeps_and_stamps_findings_of_loaded_plugins(tmp_path, plugin_dir, pulse):
    pulse.findings = [_plugin_row("shapo_ssh_algorithms")]
    out = _run(tmp_path, plugins=True)
    (record,) = json.loads((out / "pulse_cves.json").read_text(encoding="utf-8"))
    assert record["ruleset_version"] == "sha256:" + _sha(PLUGIN_A)
    shape = json.loads((out / "pulse" / "findings_report_shape.json").read_text(encoding="utf-8"))
    (row,) = shape["vulnerabilities"]
    assert row["script_id"] == "pulse-plugin:shapo_ssh_algorithms" and row["source"] == "pulse-plugin"


def test_report_row_has_no_fake_cve():
    record = CveRecord(**{**_plugin_row(), "severity": "info", "refs": []})
    (row,) = cves_to_extra_vulnerabilities([record])
    assert row["cve"] == "" and row["script_id"] == "pulse-plugin:shapo_ssh_algorithms"
    assert row["severity"] == "unknown" and row["finding_class"] == "plugin_script"
    assert row["epss"] is None and row["in_kev"] is False


def test_plugin_finding_reaches_the_evidence_projection(tmp_path, plugin_dir, pulse):
    pulse.findings = [_plugin_row("shapo_ssh_algorithms")]
    out = _run(tmp_path, plugins=True)
    result = evidence_artifacts.write_evidence_artifact(out, tenant_id="t", run_id="r")
    assert not [d for d in result["diagnostics"] if d["code"] == "invalid_observation"]
    text = json.dumps(result)
    assert "plugin:shapo_ssh_algorithms" in text and "plugin_report" in text
    assert "sha256:" + _sha(PLUGIN_A) in text


# --------------------------------------------------------------------------
# The detector: what a verification may credit
# --------------------------------------------------------------------------


def _coverage(tmp_path, plugin_dir, pulse, *, findings=True) -> tuple[vc.RunCoverage, str]:
    pulse.findings = [_plugin_row("shapo_ssh_algorithms")] if findings else []
    out = _run(tmp_path, ["10.0.0.1:22/tcp", "10.0.0.2:22/tcp"], plugins=True)
    return vc.RunCoverage(out), "sha256:" + _sha(PLUGIN_A)


def _entry(ref="shapo_ssh_algorithms", ruleset="x", host="10.0.0.1", port="22") -> dict:
    return {"detector": vc.PULSE_PLUGIN, "ref": ref, "host": host, "port": port, "ruleset": ruleset}


def _gaps(coverage, entry, host="10.0.0.1"):
    return [g["reason"] for g in coverage.gaps([entry], port="22", asset_hosts={host})]


def test_plugin_is_covered_by_a_run_that_loaded_the_same_file_and_finished_the_endpoint(tmp_path, plugin_dir, pulse):
    coverage, sha = _coverage(tmp_path, plugin_dir, pulse)
    assert _gaps(coverage, _entry(ruleset=sha)) == []


def test_plugin_edited_since_the_finding_is_not_covered(tmp_path, plugin_dir, pulse):
    coverage, _ = _coverage(tmp_path, plugin_dir, pulse)
    assert _gaps(coverage, _entry(ruleset="sha256:" + "0" * 64)) == ["plugin_changed"]


def test_finding_without_a_recorded_version_is_not_covered(tmp_path, plugin_dir, pulse):
    coverage, _ = _coverage(tmp_path, plugin_dir, pulse)
    assert _gaps(coverage, _entry(ruleset=None)) == ["plugin_version_not_recorded"]


def test_plugin_that_was_not_loaded_is_not_covered(tmp_path, plugin_dir, pulse):
    pulse.reject = {"shapo_ssh_algorithms": "bad"}
    coverage, sha = _coverage(tmp_path, plugin_dir, pulse, findings=False)
    assert _gaps(coverage, _entry(ruleset=sha)) == ["plugin_not_loaded"]
    assert _gaps(coverage, _entry(ref="gamma", ruleset=sha)) == ["plugin_not_loaded"]


def test_endpoint_without_a_success_receipt_is_not_covered(tmp_path, plugin_dir, pulse):
    coverage, sha = _coverage(tmp_path, plugin_dir, pulse)
    assert _gaps(coverage, _entry(ruleset=sha, host="10.0.0.9"), host="10.0.0.9") == ["endpoint_not_probed"]
    assert _gaps(coverage, _entry(ruleset=sha, port="2222")) == ["endpoint_not_probed"]


def test_plugin_error_on_the_endpoints_chunk_is_not_covered(tmp_path, plugin_dir, pulse):
    pulse.stderr = "  warn  plugin error — shapo_ssh_algorithms: Runtime error: boom\n"
    coverage, sha = _coverage(tmp_path, plugin_dir, pulse)
    assert _gaps(coverage, _entry(ruleset=sha)) == ["plugin_error"]


def test_error_of_another_plugin_does_not_block_this_one(tmp_path, plugin_dir, pulse):
    pulse.stderr = "  warn  plugin error — shapo_ftp_anonymous: Runtime error: boom\n"
    coverage, sha = _coverage(tmp_path, plugin_dir, pulse)
    assert _gaps(coverage, _entry(ruleset=sha)) == []


def test_error_without_its_endpoints_reads_as_covering_everything(tmp_path, plugin_dir, pulse):
    pulse.stderr = "  warn  plugin error — shapo_ssh_algorithms: Runtime error: boom\n"
    coverage, sha = _coverage(tmp_path, plugin_dir, pulse)
    for error in coverage.pulse["adapter"]["plugins"]["errors"]:
        error.pop("hosts"), error.pop("ports")
    assert _gaps(coverage, _entry(ruleset=sha)) == ["plugin_error"]


def test_run_without_a_plugin_receipt_covers_nothing(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=False)
    raw = _raw(out)
    del raw["adapter"]["plugins"]
    (out / "pulse" / "raw.json").write_text(json.dumps(raw), encoding="utf-8")
    assert _gaps(vc.RunCoverage(out), _entry(ruleset="sha256:" + _sha(PLUGIN_A))) == ["plugin_receipt_not_recorded"]


def test_no_pulse_run_covers_nothing(tmp_path):
    assert _gaps(vc.RunCoverage(tmp_path), _entry(ruleset="sha256:x")) == ["pulse_not_run"]


def test_plugin_detector_is_a_known_one_and_tcp_only():
    assert vc.PULSE_PLUGIN in vc.KNOWN_DETECTORS
    assert vc.detector_protocol({"detector": vc.PULSE_PLUGIN}) == "tcp"


def test_tracker_derives_the_plugin_detector_from_script_id_and_keeps_the_sha():
    assert vulns._detector_of("pulse-plugin", "pulse-plugin:shapo_ssh_algorithms") == (vc.PULSE_PLUGIN, "shapo_ssh_algorithms")
    assert vulns._detector_of("", "pulse-plugin:shapo_ssh_algorithms") == (vc.PULSE_PLUGIN, "shapo_ssh_algorithms")
    from datetime import UTC, datetime

    sha = "sha256:" + "ab" * 32
    (entry,) = vulns._observed_detectors(
        {"host": "10.0.0.1", "source": "pulse-plugin", "script_id": "pulse-plugin:shapo_ssh_algorithms",
         "protocol": "tcp", "ruleset_version": sha},
        port="22", run_id="r1", now=datetime.now(UTC),
    )
    assert entry["detector"] == vc.PULSE_PLUGIN and entry["ref"] == "shapo_ssh_algorithms" and entry["ruleset"] == sha


# --------------------------------------------------------------------------
# Config and scan policy
# --------------------------------------------------------------------------


def test_plugins_are_on_by_default_and_the_profile_can_turn_them_off():
    assert PulseProbeConfig().plugins is True
    merged = merge_pulse_config(PulseProbeConfig(), ProfilePulseConfig(plugins=False))
    assert merged.plugins is False
    assert merge_pulse_config(PulseProbeConfig(), ProfilePulseConfig()).plugins is True


def _plugins_after(policy: dict) -> set[bool]:
    tightened = apply_policy(_config(), policy)
    return {merge_pulse_config(tightened.service_probe.pulse, p.pulse).plugins for p in tightened.profiles.values()}


def test_per_host_rate_ceiling_turns_plugins_off_in_every_profile():
    assert _plugins_after(_policy(per_host_rate=25)) == {False}


def test_no_policy_and_non_rate_ceilings_leave_plugins_on():
    # The plugins are serial: a host-concurrency ceiling holds without help.
    assert _plugins_after(_policy()) == {True}
    assert _plugins_after(_policy(max_host_concurrency=2)) == {True}
    assert _plugins_after(_policy(max_port_rate=100, max_discover_rate=100)) == {True}


# --------------------------------------------------------------------------
# The set itself
# --------------------------------------------------------------------------


def test_set_ignores_symlinks_and_other_files(tmp_path):
    directory = tmp_path / "p"
    directory.mkdir()
    (directory / "a.rhai").write_text(PLUGIN_A, encoding="utf-8")
    (directory / "notes.txt").write_text("x", encoding="utf-8")
    (directory / "link.rhai").symlink_to(directory / "a.rhai")
    plugin_set = pulse_plugins.resolve_plugin_set(enabled=True, directory=directory)
    assert [f.name for f in plugin_set.files] == ["a"]


def test_set_digest_changes_with_content_and_is_empty_for_an_empty_set(tmp_path):
    directory = tmp_path / "p"
    directory.mkdir()
    (directory / "a.rhai").write_text(PLUGIN_A, encoding="utf-8")
    first = pulse_plugins.resolve_plugin_set(enabled=True, directory=directory).digest
    (directory / "a.rhai").write_text(PLUGIN_A + " ", encoding="utf-8")
    assert pulse_plugins.resolve_plugin_set(enabled=True, directory=directory).digest != first
    assert pulse_plugins.resolve_plugin_set(enabled=False).digest == ""


def test_check_plugin_reports_a_missing_binary_instead_of_raising(tmp_path):
    reason = pulse_plugins.check_plugin("/nonexistent/pulse", tmp_path / "a.rhai", env={}, cwd=tmp_path)
    assert reason and "could not run" in reason


# --------------------------------------------------------------------------
# Review round: relative paths, active digest, applicability, timeouts
# --------------------------------------------------------------------------

STUB_PULSE = """#!/bin/sh
# A pulse that insists every path it is given exists *from its own cwd*.
if [ "$1" = plugin ]; then exit 0; fi
while [ $# -gt 0 ]; do
  case "$1" in
    --targets-file) targets="$2" ;;
    --services-db) db="$2" ;;
    --script-dir) scripts="$2" ;;
  esac
  shift
done
[ -f "$targets" ] || { echo "no targets file '$targets' from $(pwd)" >&2; exit 2; }
[ -f "$db" ] || { echo "no services db '$db' from $(pwd)" >&2; exit 2; }
if [ -n "$scripts" ] && [ ! -d "$scripts" ]; then echo "no script dir '$scripts'" >&2; exit 2; fi
echo '{"open": [{"ip": "10.0.0.1", "port": 22, "service": "ssh"}]}'
"""


@pytest.mark.parametrize("plugins", [False, True])
def test_a_relative_output_dir_still_reaches_pulse_in_its_private_cwd(tmp_path, plugin_dir, monkeypatch, plugins):
    """The default runtime.output_dir is relative (scanner/output); pulse runs elsewhere."""
    binary = tmp_path / "pulse-stub"
    binary.write_text(STUB_PULSE, encoding="utf-8")
    binary.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: str(binary))
    monkeypatch.setattr(pp, "SERVICES_DB", Path("relative-services.tsv"))
    Path("relative-services.tsv").write_text("x\n", encoding="utf-8")
    pp.run_pulse_probe(["10.0.0.1:22/tcp"], output_dir=Path("rel/out"), plugins=plugins, retry_settle_seconds=0)
    raw = json.loads(Path("rel/out/pulse/raw.json").read_text(encoding="utf-8"))
    assert raw["chunks"][0]["returncode"] == 0 and raw["chunks"][0]["resolved"] is True
    assert "10.0.0.1" in raw["completion"]["hosts"]


def test_every_path_argument_of_the_command_is_absolute():
    command = pp.build_pulse_command(
        bin_path="pulse", hosts_file=Path("rel/hosts.txt"), ports=[22], concurrency=1, rate=0, adaptive=False,
        host_parallel=0, timeout_ms=800, banner=True, os_detect=False, cve=False, cve_online=False, syn=False,
        checkpoint=Path("rel/cp.json"), max_hosts=1, services_db="rel/services.tsv", script_dir="rel/plugins",
    )
    for flag in ("--targets-file", "--services-db", "--checkpoint", "--script-dir"):
        assert Path(_flag(command, flag)).is_absolute(), flag


def test_plugins_requested_but_all_rejected_do_not_vouch_for_a_later_run_that_accepts_them(
    tmp_path, plugin_dir, pulse
):
    """Run 1 probes without plugins (every check fails); on resume the check passes."""
    pulse.reject = {"shapo_ssh_algorithms": "bad", "shapo_ftp_anonymous": "bad"}
    out = _run(tmp_path, plugins=True)
    assert _raw(out)["adapter"]["plugins"]["digest"] == ""
    pulse.reject = {}
    spawns = len(pulse.spawns)
    _resume(out, plugins=True)
    assert len(pulse.spawns) == spawns + 1  # probed again, now with the plugins
    receipt = _raw(out)["adapter"]["plugins"]
    assert [p["name"] for p in receipt["loaded"]] == ["shapo_ftp_anonymous", "shapo_ssh_algorithms"]


def test_resume_compares_the_plugins_that_run_not_the_files_on_disk(tmp_path, plugin_dir, pulse):
    out = _run(tmp_path, plugins=True)
    pulse.reject = {"shapo_ftp_anonymous": "bad"}  # same files, one no longer accepted
    spawns = len(pulse.spawns)
    _resume(out, plugins=True)
    assert len(pulse.spawns) == spawns + 1


def test_resume_without_a_pulse_binary_trusts_a_receipt_made_with_the_same_files(tmp_path, plugin_dir, pulse, monkeypatch):
    out = _run(tmp_path, plugins=True)
    monkeypatch.setattr(pp, "_pulse_available", lambda _: False)
    spawns = len(pulse.spawns)
    _resume(out, plugins=True)
    assert len(pulse.spawns) == spawns
    assert len(_raw(out)["adapter"]["plugins"]["loaded"]) == 2
    (plugin_dir / "shapo_ssh_algorithms.rhai").write_text(PLUGIN_A + "// edited\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError):  # edited files and nobody to ask: probe again, which cannot happen
        _resume(out, plugins=True)


# --- applicability -------------------------------------------------------


def _coverage_for(tmp_path, pulse, rows):
    pulse.findings = []
    out = _run(tmp_path, plugins=True)
    raw = _raw(out)
    raw["open"] = rows
    (out / "pulse" / "raw.json").write_text(json.dumps(raw), encoding="utf-8")
    return vc.RunCoverage(out)


def test_a_plugin_that_does_not_handle_the_endpoint_covers_nothing(tmp_path, plugin_dir, pulse):
    rows = [{"ip": "10.0.0.1", "port": 22, "service": "ssh", "banner": "SSH-2.0-x"}]
    coverage = _coverage_for(tmp_path, pulse, rows)
    assert _gaps(coverage, _entry(ref="shapo_ftp_anonymous", ruleset="sha256:" + _sha(PLUGIN_B))) == ["plugin_not_applicable"]
    assert _gaps(coverage, _entry(ruleset="sha256:" + _sha(PLUGIN_A))) == []


def test_a_service_the_scan_renamed_since_the_finding_is_not_a_look(tmp_path, plugin_dir, pulse):
    rows = [{"ip": "10.0.0.1", "port": 22, "service": "http", "banner": "HTTP/1.1 200 OK"}]
    coverage = _coverage_for(tmp_path, pulse, rows)
    assert _gaps(coverage, _entry(ruleset="sha256:" + _sha(PLUGIN_A))) == ["plugin_not_applicable"]


def test_a_missing_open_row_is_not_applicable(tmp_path, plugin_dir, pulse):
    coverage = _coverage_for(tmp_path, pulse, [])
    assert _gaps(coverage, _entry(ruleset="sha256:" + _sha(PLUGIN_A))) == ["plugin_not_applicable"]


@pytest.mark.parametrize(
    ("plugin", "service", "port", "banner", "expected"),
    [
        ("shapo_ssh_algorithms", "ssh", 22, "", True),
        # Compared as the plugin compares (`service == "ssh"`): a looser reading here would
        # call an endpoint looked at that the plugin skipped.
        ("shapo_ssh_algorithms", "SSH", 22, "", False),
        ("shapo_ssh_algorithms", " ssh", 22, "", False),
        ("shapo_smb_exposure", "SMB", 445, "", False),
        ("shapo_ssh_algorithms", "unknown", 2222, "SSH-2.0-x", True),
        ("shapo_ssh_algorithms", "unknown", 22, "", False),  # no port rule: only service or banner
        ("shapo_ftp_anonymous", "unknown", 21, "220 vsFTPd", True),
        ("shapo_ftp_anonymous", "unknown", 25, "220 mail ESMTP", False),
        ("shapo_cleartext_services", "", 23, "", True),
        ("shapo_cleartext_services", "http", 23, "", False),  # a named service beats the port number
        ("shapo_cleartext_services", "unknown", 110, "+OK ready", True),
        ("shapo_smb_exposure", "smb", 4455, "", True),
        ("shapo_smb_exposure", "http", 445, "", False),
        ("shapo_smb_exposure", "", 445, "", True),
        ("shapo_remote_admin_exposure", "unknown", 5901, "RFB 003.008", True),
        ("shapo_remote_admin_exposure", "http", 3389, "", False),
        ("nonexistent", "ssh", 22, "SSH-", False),
    ],
)
def test_applicability_table(plugin, service, port, banner, expected):
    assert pulse_plugins.applies(plugin, service=service, port=port, banner=banner) is expected


# --- time ----------------------------------------------------------------


def test_the_plugin_time_allowance_is_capped():
    cap = pulse_plugins.PLUGIN_BUDGET_CAP_SECONDS
    assert pulse_plugins.plugin_budget_seconds(10**6) == cap
    assert pulse_plugins.plugin_budget_seconds(64 * 10) <= cap
    assert pulse_plugins.plugin_budget_seconds(1) == pulse_plugins.PLUGIN_SECONDS_PER_ENDPOINT


class _Slow(Pulse):
    """pulse that overruns its timeout on the chunks named in ``slow`` (by host)."""

    slow: set[str] = set()
    timeouts = 0

    def _run(self, command, **kwargs):
        hosts = Path(command[command.index("--targets-file") + 1]).read_text().splitlines()
        if set(hosts) & self.slow:
            self.timeouts += 1
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return super()._run(command, **kwargs)


def test_a_pulse_timeout_leaves_the_chunk_unresolved_instead_of_failing_the_stage(tmp_path, plugin_dir, monkeypatch):
    slow = _Slow(monkeypatch)
    slow.slow = {"10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5"}  # runs of two: under the loop limit
    unresolved: list[str] = []
    done: list[str] = []
    endpoints = [f"10.0.0.{i}:22/tcp" for i in range(1, 7)]
    out = tmp_path / "out"
    pp.run_pulse_probe(endpoints, output_dir=out, plugins=True, chunk_hosts=1, retry_settle_seconds=0,
                       on_unresolved=unresolved.extend, on_host_done=done.append)
    raw = _raw(out)
    assert sorted(unresolved) == ["10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5"]
    assert done == ["10.0.0.3", "10.0.0.6"]  # the chunks that finished are still credited
    assert set(raw["completion"]["hosts"]) == {"10.0.0.3", "10.0.0.6"}
    timed = [c for c in raw["chunks"] if c["timed_out"]]
    assert len(timed) == 4 and all(not c["resolved"] for c in timed)
    # A slow process is not retried at once like a crashed one: one attempt per chunk.
    assert slow.timeouts == 4
    # No success receipt, so nothing a verification could credit.
    coverage = vc.RunCoverage(out)
    gaps = _gaps(coverage, _entry(ruleset="sha256:" + _sha(PLUGIN_A), host="10.0.0.1"))
    assert gaps == ["endpoint_not_probed"]


def test_timeouts_do_not_hide_a_real_crash_loop(tmp_path, plugin_dir, pulse, monkeypatch):
    def crash(command, **kwargs):
        return subprocess.CompletedProcess(command, 2, "", "boom")

    monkeypatch.setattr(pp, "run_command", crash)
    with pytest.raises(pp.PulseCrashLoopError) as raised:
        pp.run_pulse_probe([f"10.0.0.{i}:22/tcp" for i in range(1, 6)], output_dir=tmp_path / "o",
                           plugins=True, chunk_hosts=1, retry_settle_seconds=0)
    assert not isinstance(raised.value, pp.PulseTimeoutLoopError)


def test_a_run_of_timeouts_stops_the_stage_with_a_message_that_says_what_to_change(tmp_path, plugin_dir, monkeypatch):
    slow = _Slow(monkeypatch)
    slow.slow = {f"10.0.0.{i}" for i in range(1, 8)}
    with pytest.raises(pp.PulseTimeoutLoopError, match="3 chunks in a row") as raised:
        pp.run_pulse_probe([f"10.0.0.{i}:22/tcp" for i in range(1, 8)], output_dir=tmp_path / "o", plugins=True,
                           chunk_hosts=1, retry_settle_seconds=0)
    assert isinstance(raised.value, pp.PulseCrashLoopError)
    assert "chunk_hosts" in str(raised.value) and "plugins" in str(raised.value)
    assert slow.timeouts == pp.MAX_CONSECUTIVE_TIMED_OUT_CHUNKS  # not one more chunk is paid for
