"""Unit tests for Pulse probe adapter (no live network / no pulse binary)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from scanner.pipeline.pulse_probe import (
    build_pulse_command,
    chunk_key,
    load_service_artifacts,
    parse_pulse_json,
    write_pulse_artifacts,
)
from scanner.pipeline.service_schema import (
    ServiceRecord,
    cves_to_extra_vulnerabilities,
    finding_key,
)


SAMPLE_PULSE = {
    "open": [
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "port": 22,
            "protocol": "tcp",
            "open": True,
            "service": "ssh",
            "latency_ms": 3,
            "banner": "SSH-2.0-OpenSSH_8.9",
        },
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "port": 80,
            "protocol": "tcp",
            "open": True,
            "service": "http",
            "latency_ms": 1,
            "banner": None,
        },
    ],
    "os": [
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "family": "Linux",
            "detail": "Linux 3.x",
            "confidence": 72,
            "source": "nmap-os-db-low",
            "ttl": 64,
            "matches": [{"name": "Linux 3.x", "accuracy": 0.72, "family": "Linux"}],
        }
    ],
    "cves": [
        {
            "cve_id": "CVE-2023-0001",
            "ip": "10.0.0.5",
            "port": 22,
            "service": "ssh",
            "cvss": 7.5,
            "severity": "HIGH",
            "title": "CVE-2023-0001",
            "summary": "example",
            "match_reason": "banner",
            "source": "local",
            "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
        }
    ],
    "stats": {"total": 2, "open": 2, "closed": 0, "elapsed_ms": 10, "rate_pps": 200.0},
}


def test_parse_pulse_json_services_os_cves():
    services, os_recs, cves = parse_pulse_json(SAMPLE_PULSE)
    assert len(services) == 2
    assert services[0].port == 22
    assert services[0].banner.startswith("SSH")
    assert len(os_recs) == 1
    assert os_recs[0].source == "nmap-os-db-low"
    assert os_recs[0].confidence == 72
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-0001"


# Pulse's full finding taxonomy (pulse.scan.v2): a confirmed version match, an
# unverified NVD keyword hit, and a CVE-less exposure observation.
SAMPLE_FINDINGS = {
    "meta": {"scanner": "pulse", "schema": "pulse.scan.v2", "ruleset": "2026.07.29-h1"},
    "open": [],
    "findings": [
        {
            "cve_id": "CVE-2021-44228",
            "ip": "10.0.0.5",
            "port": 8080,
            "service": "http",
            "cvss": 10.0,
            "severity": "critical",
            "title": "Log4Shell",
            "finding_class": "version_cve",
            "confidence": 90,
            "requires_confirmation": False,
            "evidence": "Server: Apache/2.4 log4j/2.14",
            "ruleset_version": "2026.07.29-h1",
            "epss": 0.97,
            "in_kev": True,
        },
        {
            "cve_id": "CVE-2019-0708",
            "ip": "10.0.0.5",
            "port": 3389,
            "service": "rdp",
            "cvss": 9.8,
            "severity": "critical",
            "title": "BlueKeep",
            "finding_class": "keyword_cve",
            "confidence": 40,
            "requires_confirmation": True,
        },
        {
            "cve_id": "",
            "ip": "10.0.0.5",
            "port": 445,
            "service": "smb",
            "cvss": 5.0,
            "severity": "medium",
            "title": "EternalBlue (SMBv1 RCE)",
            "summary": "SMBv1 remote code execution.",
            "finding_class": "exposure",
            "confidence": 45,
            "requires_confirmation": True,
        },
    ],
    "stats": {},
}


# Pulse v1.1.0 JSON (probe-DB product/version, port state, JARM on tls[],
# and Stage 12.6 tls-class findings that tls_posture already classifies).
SAMPLE_V110 = {
    "meta": {"scanner": "pulse", "schema": "pulse.scan.v2", "version": "1.1.0"},
    "open": [
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "port": 443,
            "protocol": "tcp",
            "open": True,
            "state": "open",
            "service": "https",
            "product": "nginx",
            "version": "1.24.0",
            "banner": "Server: nginx/1.24.0",
            "detection_method": "probe",
            "jarm": "21d19d00021d21d21c21d19d21d21d1a9c3e8e8e8e8e8e8e8e8e8e8e8e8e8e",
        }
    ],
    "tls": [
        {
            "ip": "10.0.0.5",
            "host": "10.0.0.5",
            "port": 443,
            "subject_cn": "app.local",
            "issuer_cn": "R3",
            "expired": False,
            "expires_in_days": 10,
            "self_signed": False,
            "negotiated_protocol": "TLSv1_3",
            "accepts_weak_protocols": ["TLSv1.0"],
            "jarm": "21d19d00021d21d21c21d19d21d21d1a9c3e8e8e8e8e8e8e8e8e8e8e8e8e8e",
            "source": "pulse-tls",
        }
    ],
    "findings": [
        {
            "cve_id": "CVE-2023-44487",
            "ip": "10.0.0.5",
            "port": 443,
            "service": "https",
            "cvss": 7.5,
            "severity": "HIGH",
            "title": "HTTP/2 Rapid Reset",
            "finding_class": "version_cve",
            "confidence": 80,
            "requires_confirmation": False,
            "epss": 0.55,
            "in_kev": True,
        },
        {
            "cve_id": "",
            "ip": "10.0.0.5",
            "port": 443,
            "service": "https",
            "severity": "medium",
            "title": "TLS certificate expiring soon",
            "finding_class": "tls",
            "confidence": 80,
            "requires_confirmation": False,
            "evidence": "expires_in_days=10",
            "source": "pulse-tls",
        },
        {
            "cve_id": "",
            "ip": "10.0.0.5",
            "port": 443,
            "service": "https",
            "severity": "high",
            "title": "Server accepts weak TLS protocol",
            "finding_class": "tls",
            "confidence": 82,
            "requires_confirmation": True,
            "evidence": "accepts=TLSv1.0",
            "source": "pulse-tls",
        },
    ],
    "stats": {},
}


def test_v110_json_parses_and_keeps_tls_findings(tmp_path: Path):
    """v1.1.0 extra keys (state, product/version, jarm) must not break the
    adapter. tls-class findings stay extra vulnerabilities because
    tls_posture is opt-in and a separate artifact."""
    services, _, cves = parse_pulse_json(SAMPLE_V110)
    assert len(services) == 1
    assert services[0].product == "nginx"
    assert services[0].version == "1.24.0"
    assert services[0].state == "open"
    assert [c.finding_class for c in cves] == ["version_cve", "tls", "tls"]
    assert cves[0].cve_id == "CVE-2023-44487"

    write_pulse_artifacts(tmp_path, services, [], cves, raw=SAMPLE_V110)
    tls_artifact = json.loads((tmp_path / "pulse" / "tls.json").read_text(encoding="utf-8"))
    assert tls_artifact["tls"][0]["jarm"].startswith("21d19d")
    assert len(tls_artifact["findings"]) == 2

    loaded = load_service_artifacts(tmp_path)
    assert loaded is not None
    _, _, vulns = loaded
    classes = [v["finding_class"] for v in vulns]
    assert classes.count("tls") == 2
    assert "CVE-2023-44487" in [v["cve"] for v in vulns]


def test_exposure_findings_survive_parsing():
    """CVE-less classes used to be dropped outright, losing every
    reachable-service observation Pulse makes."""
    _, _, cves = parse_pulse_json(SAMPLE_FINDINGS)
    assert [c.finding_class for c in cves] == ["version_cve", "keyword_cve", "exposure"]

    exposure = cves[2]
    assert exposure.cve_id == ""
    assert exposure.requires_confirmation is True
    assert exposure.confidence == 45


def test_hypothesis_metadata_and_enrichment_reach_the_report_shape():
    _, _, cves = parse_pulse_json(SAMPLE_FINDINGS)
    rows = cves_to_extra_vulnerabilities(cves)

    confirmed = rows[0]
    assert confirmed["cve"] == "CVE-2021-44228"
    assert confirmed["epss"] == 0.97
    assert confirmed["in_kev"] is True
    assert confirmed["requires_confirmation"] is False
    assert confirmed["evidence"].startswith("Server:")

    unverified = rows[1]
    assert unverified["finding_class"] == "keyword_cve"
    assert unverified["confidence"] == 40
    assert unverified["requires_confirmation"] is True

    # A CVE-less finding keeps an empty `cve` and is identified by a synthetic
    # script_id, so the report dedupe and ClickHouse key stay distinct per
    # port/title instead of collapsing every exposure on a host into one row.
    exposure = rows[2]
    assert exposure["cve"] == ""
    assert exposure["script_id"] == "pulse:exposure:445:eternalblue-smbv1-rce"
    assert exposure["severity"] == "medium"


def test_finding_key_is_stable_and_distinct_per_port():
    _, _, cves = parse_pulse_json(SAMPLE_FINDINGS)
    exposure = cves[2]
    assert finding_key(exposure) == finding_key(exposure.model_copy())
    other_port = exposure.model_copy(update={"port": 139})
    assert finding_key(other_port) != finding_key(exposure)
    # A finding with a real CVE keys on the CVE itself.
    assert finding_key(cves[0]) == "CVE-2021-44228"


def test_rows_without_cve_or_class_are_still_skipped():
    _, _, cves = parse_pulse_json({"findings": [{"ip": "10.0.0.5", "port": 22}]})
    assert cves == []


def test_write_and_load_artifacts(tmp_path: Path):
    services, os_recs, cves = parse_pulse_json(SAMPLE_PULSE)
    write_pulse_artifacts(tmp_path, services, os_recs, cves, raw=SAMPLE_PULSE)
    assert (tmp_path / "services.json").exists()
    assert (tmp_path / "os.json").exists()
    assert (tmp_path / "pulse_cves.json").exists()
    assert (tmp_path / "pulse" / "raw.json").exists()

    loaded = load_service_artifacts(tmp_path)
    assert loaded is not None
    findings, os_matches, vulns = loaded
    assert len(findings) == 2
    assert findings[0]["host"] == "10.0.0.5"
    assert findings[0]["service"] == "ssh"
    assert len(os_matches) == 1
    assert os_matches[0]["accuracy"] == "72"
    assert len(vulns) == 1
    assert vulns[0]["cve"] == "CVE-2023-0001"
    assert vulns[0]["severity"] == "high"
    assert vulns[0]["source"] == "pulse"
    assert vulns[0]["script_id"].startswith("pulse:")


def test_load_missing_returns_none(tmp_path: Path):
    assert load_service_artifacts(tmp_path) is None


def test_build_pulse_command_flags():
    hosts = Path("/tmp/hosts.txt")
    cmd = build_pulse_command(
        bin_path="pulse",
        hosts_file=hosts,
        ports=[22, 80, 443],
        concurrency=100,
        rate=500,
        adaptive=True,
        host_parallel=4,
        timeout_ms=800,
        banner=True,
        os_detect=True,
        os_mode="auto",
        cve=True,
        cve_online=False,
        syn=False,
        checkpoint=Path("/tmp/x.ckpt"),
        max_hosts=1000,
    )
    assert cmd[0] == "pulse"
    assert "--targets-file" in cmd
    assert "-p" in cmd
    assert "22,80,443" in cmd
    assert "--adaptive" in cmd
    assert "--host-parallel" in cmd
    assert "-b" in cmd
    assert "--os" in cmd
    assert "--cve" in cmd
    assert "--checkpoint" in cmd
    assert "-f" in cmd and "json" in cmd
    # Product features that duplicate Shapoclyack stay off the adapter CLI.
    joined = " ".join(cmd)
    assert "--jarm" not in cmd
    assert "--scripts" not in cmd
    assert "--inventory" not in cmd
    assert "--server" not in cmd
    assert "--alert-" not in joined
    assert "monitor" not in cmd


def test_service_record_roundtrip():
    s = ServiceRecord(ip="1.2.3.4", port=443, service="https", banner="x")
    d = s.model_dump(mode="json")
    assert d["schema_version"] == "octo.service.v1"
    again = ServiceRecord.model_validate(d)
    assert again.port == 443


class _FakeCompleted:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout: str, returncode: int = 0, stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


_ONE_SERVICE = '{"open": [{"ip": "10.0.0.1", "port": 22, "service": "ssh"}]}'
_ALL_CLOSED = '{"open": [], "os": [], "cves": []}'
# What GenDec's ensure_os_capable() prints when --os cannot open raw sockets
# (src/scanner/osdetect.rs); pulse exits 1 without any JSON.
_NO_RAW_SOCKETS = _FakeCompleted(
    "",
    returncode=1,
    stderr="Error: OS detection needs raw sockets (run as root/sudo, or setcap cap_net_raw+ep on Linux)\n\n"
    "Caused by:\n    Operation not permitted (os error 1)",
)


def _ckpt_arg(command: list[str]) -> Path:
    return Path(command[command.index("--checkpoint") + 1])


def _run_probe(tmp_path, monkeypatch, outputs, open_ports=("10.0.0.1:22/tcp",), **kwargs):
    """Drive run_pulse_probe with a scripted sequence of pulse outputs.

    ``outputs`` items are either a stdout string (exit 0) or a ready-made
    ``_FakeCompleted``. Returns the commands issued, the checkpoint path of the
    single default chunk, and whether that checkpoint existed at each call.
    """
    from scanner.pipeline import pulse_probe as pp

    calls: list[list[str]] = []
    ckpt_alive_at_call: list[bool] = []
    ckpt = tmp_path / "pulse" / f"chunk_{chunk_key(['10.0.0.1'], [22])}.ckpt"

    def fake_run_command(command, **_):
        calls.append(command)
        ckpt_alive_at_call.append(ckpt.exists())
        scripted = outputs[min(len(calls) - 1, len(outputs) - 1)]
        completed = scripted if isinstance(scripted, _FakeCompleted) else _FakeCompleted(scripted)
        # pulse writes its checkpoint as it goes; mimic that so the test can
        # tell whether the retry cleared it first. A refused --os never gets
        # that far (the capability check runs before the checkpoint is created).
        if completed is not _NO_RAW_SOCKETS:
            target = _ckpt_arg(command)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('{"status": "done"}', encoding="utf-8")
        return completed

    monkeypatch.setattr(pp, "run_command", fake_run_command)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    monkeypatch.setattr(pp.time, "sleep", lambda _: None)

    pp.run_pulse_probe(list(open_ports), output_dir=tmp_path, **kwargs)
    return calls, ckpt, ckpt_alive_at_call


def test_all_closed_chunk_is_reprobed(tmp_path, monkeypatch):
    """naabu proved the port open, so all-closed is a contradiction, not a result."""
    calls, _, _ = _run_probe(tmp_path, monkeypatch, [_ALL_CLOSED, _ONE_SERVICE])
    assert len(calls) == 2, "expected one re-probe after the empty chunk"


def test_reprobe_clears_checkpoint_first(tmp_path, monkeypatch):
    """pulse honours its own 'status: done' and would replay the zero offline."""
    _, _, ckpt_alive = _run_probe(tmp_path, monkeypatch, [_ALL_CLOSED, _ONE_SERVICE])
    assert ckpt_alive[1] is False, "retry ran against a stale done-checkpoint"


def test_successful_chunk_is_not_reprobed(tmp_path, monkeypatch):
    calls, ckpt, _ = _run_probe(tmp_path, monkeypatch, [_ONE_SERVICE])
    assert len(calls) == 1
    assert ckpt.exists(), "a chunk that found services must keep its checkpoint"


def test_persistently_empty_chunk_leaves_no_checkpoint(tmp_path, monkeypatch):
    """Otherwise --resume trusts the zero and never re-probes these hosts."""
    calls, ckpt, _ = _run_probe(tmp_path, monkeypatch, [_ALL_CLOSED])
    assert len(calls) == 2
    assert not ckpt.exists()


def test_retry_can_be_disabled(tmp_path, monkeypatch):
    calls, _, _ = _run_probe(tmp_path, monkeypatch, [_ALL_CLOSED], retry_settle_seconds=0)
    assert len(calls) == 1


def test_persistently_empty_chunk_leaves_hosts_unmarked(tmp_path, monkeypatch):
    """Deleting pulse's checkpoint is not enough on its own.

    The hosts would still be marked done and the caller would still mark the
    whole stage done, so --resume would skip the stage and keep the zero. The
    chunk has to stay visibly unfinished at every level.
    """
    done: list[str] = []
    unresolved: list[str] = []
    _run_probe(
        tmp_path,
        monkeypatch,
        [_ALL_CLOSED],
        on_host_done=done.append,
        on_unresolved=unresolved.extend,
    )

    assert done == [], "an unresolved chunk must not mark its hosts done"
    assert unresolved == ["10.0.0.1"], "the caller must learn the chunk is unresolved"


def test_resolved_chunk_marks_hosts_done(tmp_path, monkeypatch):
    done: list[str] = []
    unresolved: list[str] = []
    _run_probe(
        tmp_path,
        monkeypatch,
        [_ONE_SERVICE],
        on_host_done=done.append,
        on_unresolved=unresolved.extend,
    )

    assert done == ["10.0.0.1"]
    assert unresolved == []


# --- checkpoint identity -----------------------------------------------------


def test_chunk_key_depends_on_content_not_order():
    assert chunk_key(["b", "a"], [443, 22]) == chunk_key(["a", "b"], [22, 443])
    assert chunk_key(["a"], [22]) != chunk_key(["b"], [22])
    assert chunk_key(["a"], [22]) != chunk_key(["a"], [22, 80])
    assert len(chunk_key(["a"], [22])) == 16


def test_checkpoint_is_named_after_the_chunk_not_its_position(tmp_path, monkeypatch):
    """A --resume re-cuts chunks from the pending hosts, so position 0 is a
    different host set every time. pulse trusts an existing checkpoint file
    over --targets-file, so an index-named file would make it answer for the
    previous run's hosts and let the new ones be marked done unscanned."""
    two_hosts = ("10.0.0.1:22/tcp", "10.0.0.2:22/tcp")
    first_run, _, _ = _run_probe(
        tmp_path, monkeypatch, [_ONE_SERVICE], open_ports=two_hosts, chunk_hosts=1
    )
    by_host = {Path(c[c.index("--targets-file") + 1]).read_text().split()[0]: _ckpt_arg(c) for c in first_run}
    assert set(by_host) == {"10.0.0.1", "10.0.0.2"}
    assert by_host["10.0.0.1"] != by_host["10.0.0.2"]
    assert "chunk_0000" not in str(by_host["10.0.0.1"])

    # Resume with the first host already done: the second host is now at
    # position 0 but must keep *its own* checkpoint from the first run.
    resumed, _, _ = _run_probe(
        tmp_path,
        monkeypatch,
        [_ONE_SERVICE],
        open_ports=two_hosts,
        chunk_hosts=1,
        done_hosts={"10.0.0.1"},
    )
    assert len(resumed) == 1
    assert _ckpt_arg(resumed[0]) == by_host["10.0.0.2"]


# --- failure is not "all closed" ----------------------------------------------


def test_os_detection_degrades_when_raw_sockets_are_unavailable(tmp_path, monkeypatch):
    """pulse aborts the whole run when --os cannot open raw sockets; the
    adapter must keep services/banners/CVEs rather than lose the stage."""
    calls, _, _ = _run_probe(tmp_path, monkeypatch, [_NO_RAW_SOCKETS, _ONE_SERVICE])
    assert len(calls) == 2, "expected one immediate re-run without --os"
    assert "--os" in calls[0]
    assert "--os" not in calls[1]
    assert "--os-mode" not in calls[1]

    raw = json.loads((tmp_path / "pulse" / "raw.json").read_text(encoding="utf-8"))
    assert raw["adapter"]["os_detect"] is False
    assert "raw sockets" in raw["adapter"]["os_detect_degraded"]
    assert [row["ip"] for row in raw["open"]] == ["10.0.0.1"]


def test_os_degrade_sticks_for_later_chunks(tmp_path, monkeypatch):
    """Every later chunk would hit the same refusal; do not pay it per chunk."""
    calls, _, _ = _run_probe(
        tmp_path,
        monkeypatch,
        [_NO_RAW_SOCKETS, _ONE_SERVICE, _ONE_SERVICE],
        open_ports=("10.0.0.1:22/tcp", "10.0.0.2:22/tcp"),
        chunk_hosts=1,
    )
    assert len(calls) == 3
    assert "--os" in calls[0]
    assert all("--os" not in c for c in calls[1:])


def test_os_degrade_is_not_triggered_by_other_failures(tmp_path, monkeypatch):
    """A crash for any other reason keeps --os: the settle retry handles it."""
    crash = _FakeCompleted("", returncode=101, stderr="thread 'main' panicked at src/x.rs")
    calls, _, _ = _run_probe(tmp_path, monkeypatch, [crash, _ONE_SERVICE])
    assert len(calls) == 2
    assert all("--os" in c for c in calls)


def test_syn_capability_failure_is_not_downgraded(tmp_path, monkeypatch):
    """--syn is an explicit opt-in; the adapter must not silently switch it off."""
    refused = _FakeCompleted("", returncode=1, stderr="Error: SYN scan needs raw sockets (root)")
    calls, _, _ = _run_probe(tmp_path, monkeypatch, [refused, _ONE_SERVICE], syn=True)
    assert all("--syn" in c and "--os" in c for c in calls)


def test_pulse_crash_is_logged_as_a_crash_not_as_zero_services(tmp_path, monkeypatch, caplog):
    crash = _FakeCompleted("", returncode=2, stderr="error: unexpected argument '--bogus'")
    with caplog.at_level(logging.WARNING, logger=None):
        _run_probe(tmp_path, monkeypatch, [crash, _ONE_SERVICE])
    text = caplog.text
    assert "exited 2 without JSON" in text
    assert "unexpected argument" in text
    assert "0 services across" not in text


def test_missing_binary_fails_fast_with_an_install_hint(tmp_path, monkeypatch):
    from scanner.pipeline import pulse_probe as pp

    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: False)
    monkeypatch.setattr(pp, "run_command", lambda *a, **k: pytest.fail("pulse must not be invoked"))
    with pytest.raises(FileNotFoundError, match="install-pulse.sh"):
        pp.run_pulse_probe(["10.0.0.1:22/tcp"], output_dir=tmp_path)


def test_missing_binary_is_fine_when_there_is_nothing_to_probe(tmp_path, monkeypatch):
    """No TCP ports → empty artifacts, no pulse needed."""
    from scanner.pipeline import pulse_probe as pp

    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: False)
    pp.run_pulse_probe(["10.0.0.1:53/udp"], output_dir=tmp_path)
    assert json.loads((tmp_path / "services.json").read_text(encoding="utf-8")) == []


# --- merged raw ---------------------------------------------------------------


def test_stats_are_summed_across_chunks_and_rate_recomputed(tmp_path, monkeypatch):
    chunk = json.dumps(
        {
            "open": [{"ip": "10.0.0.1", "port": 22, "service": "ssh"}],
            "stats": {"total": 10, "open": 1, "closed": 9, "elapsed_ms": 500, "rate_pps": 20.0},
        }
    )
    _run_probe(
        tmp_path,
        monkeypatch,
        [chunk],
        open_ports=("10.0.0.1:22/tcp", "10.0.0.2:22/tcp"),
        chunk_hosts=1,
    )
    raw = json.loads((tmp_path / "pulse" / "raw.json").read_text(encoding="utf-8"))
    assert raw["stats"] == {"total": 20, "open": 2, "closed": 18, "elapsed_ms": 1000, "rate_pps": 20.0}
    assert [c["key"] for c in raw["chunks"]] == [chunk_key(["10.0.0.1"], [22]), chunk_key(["10.0.0.2"], [22])]


def test_finished_checkpoint_is_rescanned_not_replayed(tmp_path, monkeypatch):
    """pulse replays a done checkpoint without --os/--cve/TLS; the adapter
    must not resume from one. An in-progress checkpoint is a real resume."""
    ckpt = tmp_path / "pulse" / f"chunk_{chunk_key(['10.0.0.1'], [22])}.ckpt"
    ckpt.parent.mkdir(parents=True)
    ckpt.write_text('{"version": 1, "status": "done", "open": []}', encoding="utf-8")
    _, _, alive_at_call = _run_probe(tmp_path, monkeypatch, [_ONE_SERVICE])
    assert alive_at_call == [False], "a finished checkpoint must be dropped before pulse runs"

    ckpt.write_text('{"version": 1, "status": "in_progress", "open": []}', encoding="utf-8")
    _, _, alive_at_call = _run_probe(tmp_path, monkeypatch, [_ONE_SERVICE])
    assert alive_at_call == [True], "an unfinished checkpoint is a genuine resume"
