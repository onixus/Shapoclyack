"""A verification may only close what it demonstrably looked for (#451, #450).

``POST /vulnerabilities/{id}/verify`` used to dispatch ``intent=vuln`` at the
asset's first IP and close the finding as ``machine_verified`` whenever that
run did not report it. Four ways that run could not have reported it, each of
which closed a finding as verified-fixed:

* a **medium** nuclei finding — ``intent=vuln`` loads critical and high
  templates only;
* nuclei **not there** — ``nuclei.json`` says ``skipped_reason`` and the run
  succeeds all the same;
* a finding seen on a **name** re-checked on the address behind it;
* an **NSE** finding re-checked on the Pulse backend, which runs no NSE.

The evidence these tests feed the closure is written by the scanner's own
stages (``run_nuclei_scan``, ``run_pulse_probe``, with the binaries stubbed),
so they also pin the artifact contract between the two sides.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import run_completion
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from scanner.pipeline import nuclei_scan
from scanner.pipeline import pulse_probe
from scanner.pipeline.config_schema import NucleiConfig
from tests.conftest import approve_scan_scope, requires_postgres
from tests.test_vuln_lifecycle import _seed, _write_run
from tests.test_vuln_verification import _advance_to_fixing, _job_for_run, _park_in_verifying

pytestmark = requires_postgres

HOST = "10.0.0.5"
NAME = "app.example.com"
HOSTS = [{"host": HOST, "hostname": NAME}]
CVE = "CVE-2024-0001"
TEMPLATE = CVE


def _row(source: str, script_id: str, *, host: str = HOST, port: str = "443", **extra) -> dict:
    return {
        "host": host,
        "port": port,
        "cve": CVE,
        "cvss": 5.3,
        "severity": "medium",
        "source": source,
        "script_id": script_id,
        **extra,
    }


NUCLEI_MEDIUM = _row("nuclei", f"nuclei:{TEMPLATE}")
PULSE = _row("pulse", "pulse:local")
NSE = _row("nmap-nse", "vulners")


# --------------------------------------------------------------------------
# The scanner stages, as they write their artifacts
# --------------------------------------------------------------------------


def _templates(tmp_path: Path) -> Path:
    templates = tmp_path / "nuclei-templates"
    (templates / "http" / "cves").mkdir(parents=True, exist_ok=True)
    (templates / "http" / "cves" / f"{TEMPLATE}.yaml").write_text(
        f"id: {TEMPLATE}\n\ninfo:\n  name: x\n  severity: medium\n  tags: cve\n",
        encoding="utf-8",
    )
    return templates


def _nuclei_stub(*, loaded: int | None = None, skipped: tuple[str, ...] = ()):
    """nuclei exiting 0 with the INFO lines v3.11.1 prints (checked live):
    templates loaded (default: every pinned id) and targets it dropped."""

    def run(command, **kwargs):
        Path(command[command.index("-jsonl-export") + 1]).write_text("", encoding="utf-8")
        ids = command[command.index("-id") + 1].split(",") if "-id" in command else []
        count = len(ids) if loaded is None else loaded
        stderr = f"[INF] Templates loaded for current scan: {count}\n" + "".join(
            f"[INF] Skipped {target} from target list as found unresponsive permanently: x\n"
            for target in skipped
        )
        return subprocess.CompletedProcess(command, 0, "", stderr)

    return run


def _nuclei(
    monkeypatch, run_dir: Path, tmp_path: Path, *, binary: bool = True, stub=None, **config
) -> dict:
    """Run the real nuclei stage over ``run_dir`` with the binary stubbed."""
    monkeypatch.setattr(
        nuclei_scan.shutil,
        "which",
        lambda name: "/usr/local/bin/nuclei" if binary and name == "nuclei" else None,
    )

    clean_exit = _nuclei_stub()

    monkeypatch.setattr(nuclei_scan, "run_command", stub or clean_exit)
    config.setdefault("templates_dir", str(_templates(tmp_path)))
    return nuclei_scan.run_nuclei_scan([f"{HOST}:443/tcp"], NucleiConfig(**config), run_dir)


#: What pulse 1.1.0 reports in ``meta`` (checked against the real binary).
RULESET = "2026.07.29-h1"


def _pulse(
    monkeypatch,
    run_dir: Path,
    *,
    cve: bool = True,
    cve_online: bool = False,
    ports: tuple[int, ...] = (443,),
    ruleset: str | None = RULESET,
) -> None:
    """Run the real Pulse stage over ``run_dir`` with the binary stubbed."""
    document: dict = {"open": [{"ip": HOST, "port": port, "service": "https"} for port in ports]}
    if ruleset:
        document["meta"] = {"ruleset": ruleset, "scanner": "pulse", "schema": "pulse.scan.v2", "version": "1.1.0"}
    payload = json.dumps(document)
    monkeypatch.setattr(
        pulse_probe, "run_command", lambda command, **_: subprocess.CompletedProcess(command, 0, payload, "")
    )
    monkeypatch.setattr(pulse_probe, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pulse_probe, "_pulse_available", lambda _: True)
    pulse_probe.run_pulse_probe(
        [f"{HOST}:{port}/tcp" for port in ports], output_dir=run_dir, cve=cve, cve_online=cve_online
    )


#: The NSE scripts a verification re-scan really runs: it is a ``safe`` mode
#: scan, whose shipped NSE profile is ``baseline`` (scanner/config/default.yaml,
#: k8s/shapoclyack/base/config/k8s.yaml) — two categories, no script by name.
SAFE_MODE_SCRIPTS = "default,safe"


def _nmap(run_dir: Path, *, scripts: str = SAFE_MODE_SCRIPTS, port: int = 443, exit: str = "success") -> None:
    nmap_dir = run_dir / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True, exist_ok=True)
    (nmap_dir / f"tcp_{HOST}.xml").write_text(
        '<?xml version="1.0"?>\n'
        f'<nmaprun scanner="nmap" args="nmap -n -Pn -T4 -sV --script {scripts} -p {port} {HOST} '
        f'-oA /out/tcp_{HOST}">'
        f'<host><status state="up"/><address addr="{HOST}" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/></port></ports></host>'
        f'<runstats><finished exit="{exit}"/></runstats></nmaprun>\n',
        encoding="utf-8",
    )


def _port_stage(
    monkeypatch,
    run_dir: Path,
    *,
    asked: tuple[int, ...] = (443,),
    open_ports: tuple[int, ...] = (),
    explicit: bool = True,
    fails: bool = False,
) -> None:
    """Run the real port stage (naabu stubbed) over ``run_dir`` for HOST."""
    from scanner.pipeline import ports as ports_stage

    def naabu(command, **kwargs):
        if fails:
            raise subprocess.CalledProcessError(1, command)
        stdout = "".join(f"{HOST}:{p}\n" for p in open_ports)
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(ports_stage, "run_command", naabu)
    custom = run_dir / "ports_input.txt"
    custom.write_text(",".join(str(p) for p in asked) + "\n" if explicit else "", encoding="utf-8")
    try:
        found = ports_stage.fast_port_scan(
            [HOST],
            output_dir=run_dir,
            rate=100,
            top_ports=100,
            top_udp_ports=0,
            timeout=5,
            retries=0,
            protocol_mode="tcp",
            custom_ports_file=custom,
            custom_udp_ports_file=run_dir / "none.txt",
            udp_probes=False,
            tag="b0",
            scan_type="connect",
        )
    except subprocess.CalledProcessError:
        found = []
    (run_dir / "open_ports.txt").write_text("".join(f"{e}\n" for e in found), encoding="utf-8")


def _discovered(run_dir: Path, *, probed: bool = True) -> None:
    """discover/<tag>.* as host_discovery leaves them; without the probe
    stats when discovery was skipped and every target written alive."""
    discover = run_dir / "discover"
    discover.mkdir(parents=True, exist_ok=True)
    (discover / "all.alive.txt").write_text(f"{HOST}\n", encoding="utf-8")
    if probed:
        (discover / "all.probe_stats.json").write_text('{"icmp": 1, "tcp": 0, "naabu": 0}', encoding="utf-8")


EXPOSURE = {
    "host": HOST,
    "port": "443",
    "cve": None,
    "severity": "medium",
    "source": "pulse",
    "script_id": "pulse:exposure:443:admin-panel-reachable",
}


# --------------------------------------------------------------------------
# Helpers around the tracker
# --------------------------------------------------------------------------


def _tracked(settings, tenant_id, findings, run_id: str = "run-1") -> dict:
    _write_run(settings.output_dir, run_id, HOSTS, findings)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, limit=50)
    assert total == 1, items
    return items[0]


def _verification_run(settings, tenant_id, vuln_id, findings=()) -> Path:
    """Park the finding behind ``job-verify`` and give that job a run."""
    _park_in_verifying(settings, tenant_id, vuln_id, "job-verify")
    _write_run(settings.output_dir, "run-verify", HOSTS, list(findings))
    _job_for_run(settings, tenant_id, "job-verify", "run-verify")
    return settings.output_dir / "runs" / "run-verify"


def _fold(settings, tenant_id):
    return vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-verify")


def _last_event(settings, tenant_id, vuln_id) -> dict:
    events, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id, limit=1)
    return events[0]


def _assert_inconclusive(settings, tenant_id, vuln_id, *reasons: str) -> dict:
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    # State first: on the code before #451 this is CLOSED.
    assert after["state"] == vuln_states.FIXING
    assert after["machine_verified"] is False
    assert after["closure_reason"] is None
    event = _last_event(settings, tenant_id, vuln_id)
    assert event["kind"] == "verification_inconclusive"
    assert event["from_state"] == vuln_states.VERIFYING
    assert event["to_state"] == vuln_states.FIXING
    assert sorted(gap["reason"] for gap in event["detail"]["gaps"]) == sorted(reasons)
    return event


# --------------------------------------------------------------------------
# The four false closures
# --------------------------------------------------------------------------


def test_a_medium_nuclei_finding_is_not_closed_by_a_sweep_that_never_loaded_it(
    tmp_path, monkeypatch
):
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    # What intent=vuln ran before #451: critical and high, nothing pinned.
    _nuclei(monkeypatch, run_dir, tmp_path, severities=["critical", "high"])

    stats = _fold(settings, tenant_id)

    event = _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "template_not_pinned")
    assert stats.verification_passed == 0
    assert stats.verification_inconclusive == 1
    assert event["detail"]["gaps"][0]["ref"] == TEMPLATE
    assert TEMPLATE in event["note"]


def test_a_verification_run_without_nuclei_does_not_close_a_nuclei_finding(tmp_path, monkeypatch):
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "nuclei_not_run")


def test_a_skipped_nuclei_does_not_close_a_nuclei_finding(tmp_path, monkeypatch):
    """The binary missing on the sensor: the run succeeds, nuclei.json says why
    it did nothing, and nothing used to read it."""
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    written = _nuclei(monkeypatch, run_dir, tmp_path, binary=False, template_ids=[TEMPLATE])
    assert written["skipped_reason"] == "nuclei_binary_missing"

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "nuclei_skipped:nuclei_binary_missing")


def test_a_pinned_template_missing_on_the_sensor_does_not_close(tmp_path, monkeypatch):
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    empty = tmp_path / "empty-templates"
    empty.mkdir()
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE], templates_dir=str(empty))

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "nuclei_skipped:template_ids_missing")


@pytest.mark.parametrize(
    ("stub", "reason"),
    [
        # The index found the template; nuclei loaded none of it (a template
        # it refused to parse, say).
        (lambda: _nuclei_stub(loaded=0), "nuclei_templates_not_loaded"),
        (lambda: _nuclei_stub(skipped=(f"{HOST}:443",)), "nuclei_target_skipped"),
    ],
)
def test_nuclei_s_own_account_can_deny_coverage(tmp_path, monkeypatch, stub, reason):
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE], stub=stub())

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], reason)


def test_a_finding_seen_on_a_name_is_not_closed_by_a_run_against_the_address(
    tmp_path, monkeypatch
):
    on_name = _row("nuclei", f"nuclei:{TEMPLATE}", host=NAME)
    settings, tenant_id = _seed(tmp_path, findings=[on_name])
    vuln = _tracked(settings, tenant_id, [on_name])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    # The pinned template ran -- against the bare address.
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE])

    _fold(settings, tenant_id)

    event = _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "endpoint_not_targeted")
    assert event["detail"]["gaps"][0]["host"] == NAME


def test_an_nse_finding_is_not_closed_by_a_pulse_only_run(tmp_path, monkeypatch):
    settings, tenant_id = _seed(tmp_path, findings=[NSE])
    vuln = _tracked(settings, tenant_id, [NSE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "nse_not_run")


@pytest.mark.parametrize(
    ("scripts", "exit", "reason"),
    [
        ("vuln", "success", "script_not_run"),  # a category: not provably the script
        ("vulners", "error", "nse_not_run"),  # nmap did not finish
    ],
)
def test_nse_coverage_needs_the_script_by_name_in_a_finished_run(
    tmp_path, monkeypatch, scripts, exit, reason
):
    settings, tenant_id = _seed(tmp_path, findings=[NSE])
    vuln = _tracked(settings, tenant_id, [NSE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _nmap(run_dir, scripts=scripts, exit=exit)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], reason)


@pytest.mark.parametrize(("cve", "reason"), [(False, "pulse_cve_matching_off"), (None, "pulse_cve_matching_not_recorded")])
def test_a_legacy_finding_needs_pulse_with_cve_matching(tmp_path, monkeypatch, cve, reason):
    """No source, no script id: the legacy rule, what intent=vuln always ran."""
    legacy = {"host": HOST, "port": "443", "cve": CVE, "severity": "high"}
    settings, tenant_id = _seed(tmp_path, findings=[legacy])
    vuln = _tracked(settings, tenant_id, [legacy])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, cve=bool(cve))
    if cve is None:
        # A sensor from before #451 wrote no ``adapter.cve`` at all.
        raw_path = run_dir / "pulse" / "raw.json"
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        raw["adapter"].pop("cve", None)
        raw_path.write_text(json.dumps(raw), encoding="utf-8")

    _fold(settings, tenant_id)

    event = _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], reason)
    assert event["detail"]["gaps"][0]["legacy_rule"] is True
    assert vuln["detectors"] == []


def test_a_cve_pulse_found_online_is_not_closed_by_offline_rules(tmp_path, monkeypatch):
    """Pulse's offline rules never contained it; their silence is no answer."""
    online = _row("pulse", "pulse:nvd")
    settings, tenant_id = _seed(tmp_path, findings=[online])
    vuln = _tracked(settings, tenant_id, [online])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, cve_online=False)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "pulse_cve_online_off")


def test_a_cve_pulse_found_online_closes_when_the_run_looked_online(tmp_path, monkeypatch):
    online = _row("pulse", "pulse:nvd")
    settings, tenant_id = _seed(tmp_path, findings=[online])
    vuln = _tracked(settings, tenant_id, [online])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, cve_online=True)

    assert _fold(settings, tenant_id).verification_passed == 1


@pytest.mark.parametrize(
    ("verify_ruleset", "reason"),
    [("2026.07.29-h1", "pulse_ruleset_older"), (None, "pulse_ruleset_not_recorded")],
)
def test_a_verification_with_an_older_ruleset_proves_nothing(tmp_path, monkeypatch, verify_ruleset, reason):
    """Found by a rule added in 2026.08.02; a sensor still on 2026.07.29 cannot
    match it, so its silence closes nothing."""
    newer = _row("pulse", "pulse:local", ruleset_version="2026.08.02-h0")
    settings, tenant_id = _seed(tmp_path, findings=[newer])
    vuln = _tracked(settings, tenant_id, [newer])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, ruleset=verify_ruleset)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], reason)
    assert vuln["detectors"][0]["ruleset"] == "2026.08.02-h0"


def test_a_verification_with_the_same_or_newer_ruleset_closes(tmp_path, monkeypatch):
    found = _row("pulse", "pulse:local", ruleset_version="2026.07.29-h1")
    settings, tenant_id = _seed(tmp_path, findings=[found])
    vuln = _tracked(settings, tenant_id, [found])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, ruleset="2026.07.29-h2")

    assert _fold(settings, tenant_id).verification_passed == 1


def test_a_port_that_did_not_answer_proves_nothing(tmp_path, monkeypatch):
    """Absence on a port that was not open this time is the module docstring's
    firewalled-during-the-window case, not a fix."""
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    vuln = _tracked(settings, tenant_id, [PULSE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, ports=(80,))

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "endpoint_not_probed")


# --------------------------------------------------------------------------
# Host up, port closed: endpoint_unreachable
# --------------------------------------------------------------------------


def _closed_unreachable(settings, tenant_id, vuln_id) -> dict:
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert after["state"] == vuln_states.CLOSED
    assert after["closure_reason"] == "endpoint_unreachable"
    event = _last_event(settings, tenant_id, vuln_id)
    assert event["kind"] == "verification_unreachable"
    assert event["detail"]["evidence"]["endpoints"][0]["host"] == HOST
    return after


def test_a_pulse_exposure_whose_port_is_closed_is_verified_gone(tmp_path, monkeypatch):
    """The finding *is* "this port is reachable": a live host with the port
    provably closed is that finding gone, and machine-verified."""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked(settings, tenant_id, [EXPOSURE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _discovered(run_dir)
    _port_stage(monkeypatch, run_dir)

    stats = _fold(settings, tenant_id)

    assert stats.verification_unreachable == 1
    assert _closed_unreachable(settings, tenant_id, vuln["vuln_id"])["machine_verified"] is True


def test_a_cve_whose_port_is_closed_is_closed_but_not_verified_fixed(tmp_path, monkeypatch):
    """The vulnerable service is out of reach; nothing showed it patched."""
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    vuln = _tracked(settings, tenant_id, [PULSE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _discovered(run_dir)
    _port_stage(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    after = _closed_unreachable(settings, tenant_id, vuln["vuln_id"])
    assert after["machine_verified"] is False
    assert vulns.summary(settings, tenant_id=tenant_id)["machine_verified_closed"] == 0


def test_another_open_port_is_proof_of_life_too(tmp_path, monkeypatch):
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked(settings, tenant_id, [EXPOSURE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    # No discovery evidence: 22 answering is the proof of life.
    _port_stage(monkeypatch, run_dir, asked=(443, 22), open_ports=(22,))

    _fold(settings, tenant_id)

    event = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert event["kind"] == "verification_unreachable"
    assert event["detail"]["evidence"]["endpoints"][0]["alive_by"] == "open_port"


@pytest.mark.parametrize(
    ("setup", "why"),
    [
        (lambda m, d: (_discovered(d, probed=False), _port_stage(m, d)), "discovery skipped: alive unproven"),
        (lambda m, d: _port_stage(m, d), "no liveness signal at all"),
        (lambda m, d: (_discovered(d), _port_stage(m, d, explicit=False)), "port only in -top-ports"),
        (lambda m, d: (_discovered(d), _port_stage(m, d, fails=True)), "port batch did not finish"),
        (lambda m, d: (_discovered(d), _port_stage(m, d), _pulse(m, d, ports=(443,), cve=False)), "Pulse saw it open"),
    ],
)
def test_short_of_every_condition_a_closed_port_stays_inconclusive(tmp_path, monkeypatch, setup, why):
    """A host that is down, a port never asked about, a batch that died, a
    probe that disagrees: the firewalled-during-the-window case, not a fix."""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked(settings, tenant_id, [EXPOSURE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    setup(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING, why
    assert _last_event(settings, tenant_id, vuln["vuln_id"])["kind"] == "verification_inconclusive", why


# --------------------------------------------------------------------------
# What still closes, and what still bounces
# --------------------------------------------------------------------------


def test_full_coverage_and_not_observed_closes_machine_verified(tmp_path, monkeypatch):
    """The positive control: every detector re-checked the endpoint, the
    finding was not there, and that is a verified fix."""
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nuclei", "script_id": f"nuclei:{TEMPLATE}"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE])

    stats = _fold(settings, tenant_id)

    assert stats.verification_passed == 1
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.CLOSED
    assert after["machine_verified"] is True
    assert after["closure_reason"] == "verified_remediated"
    event = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert event["kind"] == "verification_passed"
    # What #451 adds to the closure, checked after it so that the code before
    # it fails only here: both detectors were held to their evidence.
    assert {d["detector"] for d in vuln["detectors"]} == {"pulse", "nuclei"}
    assert event["detail"]["coverage_rule"] == "detectors"


def test_one_detector_short_of_full_coverage_is_still_inconclusive(tmp_path, monkeypatch):
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nuclei", "script_id": f"nuclei:{TEMPLATE}"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "nuclei_not_run")


def test_an_nse_only_finding_is_inconclusive_under_what_safe_mode_runs(tmp_path, monkeypatch):
    """The honest dead end: ``--script default,safe`` may well have run
    vulners, but nmap's XML lists a script only when it printed something, so
    a silent category run is no evidence about one script."""
    settings, tenant_id = _seed(tmp_path, findings=[NSE])
    vuln = _tracked(settings, tenant_id, [NSE])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _nmap(run_dir)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "script_not_run")


def test_a_pulse_finding_vulners_also_saw_closes_on_pulse_coverage(tmp_path, monkeypatch):
    """Hybrid or nmap backend: Pulse and vulners report one CVE, the report
    keeps Pulse's row and names vulners in also_detected_by. The safe-mode
    re-scan cannot be asked for vulners by name — the NSE detector is stood
    in for by Pulse, which re-checked the same address and did not see it.
    Before, this finding could never be closed."""
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nmap-nse", "script_id": "vulners"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)
    _nmap(run_dir)

    assert _fold(settings, tenant_id).verification_passed == 1
    event = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert [(w["detector"], w["ref"], w["covered_by"]) for w in event["detail"]["waived"]] == [
        ("nmap-nse", "vulners", "pulse")
    ]


def test_an_nse_detector_is_not_stood_in_for_by_an_uncovered_one(tmp_path, monkeypatch):
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nmap-nse", "script_id": "vulners"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, cve=False)
    _nmap(run_dir)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "pulse_cve_matching_off", "script_not_run")


def test_an_nse_detector_on_another_address_is_not_stood_in_for(tmp_path, monkeypatch):
    """vulners saw it on 10.0.0.6, Pulse on 10.0.0.5: Pulse covering .5
    says nothing about what vulners found on .6."""
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nmap-nse", "script_id": "vulners"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln["vuln_id"])
        row.detectors = [
            {**entry, "host": "10.0.0.6"} if entry["detector"] == "nmap-nse" else entry
            for entry in row.detectors
        ]
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)
    _nmap(run_dir)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "script_not_run")


def _second_address(settings, tenant_id, vuln_id, address: str = "10.0.0.6") -> None:
    """Give the finding's asset a second IP, as an identity merge would."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        session.add(
            models.AssetIdentifier(
                asset_id=row.asset_id, tenant_id=tenant_id, identifier_type="ip", identifier_value=address
            )
        )


def _forget_host(settings, vuln_id, detector: str) -> None:
    """Make one detector a migrated, host-less entry (0079's backfill)."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        row.detectors = [
            {**entry, "host": None} if entry["detector"] == detector else entry for entry in row.detectors
        ]


def test_a_hostless_detector_needs_coverage_on_every_address_of_the_asset(tmp_path, monkeypatch):
    """A migrated nuclei entry never said where it looked. "Some address
    answered" would let a re-scan of the address the finding was not on close
    it, so each address has to be covered."""
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nuclei", "script_id": f"nuclei:{TEMPLATE}"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    _second_address(settings, tenant_id, vuln["vuln_id"])
    _forget_host(settings, vuln["vuln_id"], "nuclei")
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)
    # nuclei looked at 10.0.0.5 only.
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE])

    _fold(settings, tenant_id)

    event = _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "endpoint_not_targeted")
    assert event["detail"]["gaps"][0]["host"] == "10.0.0.6"


def test_a_hostless_detector_puts_every_address_of_the_asset_in_the_scan(tmp_path):
    both = _row("pulse", "pulse:local", also_detected_by=[{"source": "nuclei", "script_id": f"nuclei:{TEMPLATE}"}])
    settings, tenant_id = _seed(tmp_path, findings=[both])
    approve_scan_scope(settings)
    vuln = _tracked(settings, tenant_id, [both])
    _second_address(settings, tenant_id, vuln["vuln_id"])
    _forget_host(settings, vuln["vuln_id"], "nuclei")

    job = _dispatch(settings, tenant_id, vuln["vuln_id"])

    assert _inputs(settings, job.job_id, "ranges.txt") == [HOST, "10.0.0.6"]


def test_still_observed_bounces_whatever_the_coverage(tmp_path, monkeypatch):
    """Unchanged: a run that sees the finding needs no proof that it looked."""
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    _verification_run(settings, tenant_id, vuln["vuln_id"], findings=[NUCLEI_MEDIUM])

    stats = _fold(settings, tenant_id)

    assert stats.verification_failed == 1
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING
    assert after["machine_verified"] is False
    assert _last_event(settings, tenant_id, vuln["vuln_id"])["kind"] == "verification_failed"


def test_a_failed_verification_run_gives_the_finding_back(tmp_path):
    """Only a succeeded run is folded, so a failed verification used to leave
    its finding in VERIFYING with nothing looking at it."""
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    _verification_run(settings, tenant_id, vuln["vuln_id"])

    run_completion.project_published_run(
        settings, "job-verify", run_id="run-verify", tenant_id=tenant_id, status="failed"
    )

    event = _assert_inconclusive(settings, tenant_id, vuln["vuln_id"])
    assert event["detail"]["job_status"] == "failed"
    # And once is enough: a replayed publication finds nothing to move.
    assert vulns.release_unfinished_verification(
        settings, tenant_id=tenant_id, job_id="job-verify", run_id="run-verify", status="failed"
    ) == 0


# --------------------------------------------------------------------------
# Provenance
# --------------------------------------------------------------------------


def test_one_cve_seen_by_pulse_then_nuclei_records_both_on_one_row(tmp_path):
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    first = _tracked(settings, tenant_id, [PULSE])
    assert [(d["detector"], d["ref"], d["host"]) for d in first["detectors"]] == [("pulse", "local", HOST)]

    second = _tracked(settings, tenant_id, [NUCLEI_MEDIUM], run_id="run-2")

    assert second["vuln_id"] == first["vuln_id"]
    assert second["finding_key"] == first["finding_key"]
    # Newest first; the first observer's script id is unchanged.
    assert [(d["detector"], d["ref"], d["last_run_id"]) for d in second["detectors"]] == [
        ("nuclei", TEMPLATE, "run-2"),
        ("pulse", "local", "run-1"),
    ]
    assert second["script_id"] == "pulse:local"

    third = _tracked(settings, tenant_id, [PULSE], run_id="run-3")
    assert [(d["detector"], d["last_run_id"]) for d in third["detectors"]] == [
        ("pulse", "run-3"),
        ("nuclei", "run-2"),
    ]


def test_the_detector_list_is_bounded(tmp_path):
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    _tracked(settings, tenant_id, [PULSE])
    for index in range(vulns.MAX_DETECTORS + 3):
        row = _row("nuclei", f"nuclei:template-{index}")
        latest = _tracked(settings, tenant_id, [row], run_id=f"run-n{index}")
    assert len(latest["detectors"]) == vulns.MAX_DETECTORS
    assert latest["detectors"][0]["ref"] == f"template-{vulns.MAX_DETECTORS + 2}"


def test_the_nse_rule_reads_script_names_as_nmap_takes_them():
    from api.services import verification_coverage as coverage

    assert coverage._script_names("nmap -sV --script vulners,ssl-cert -p 443 h") == {"vulners", "ssl-cert"}
    assert coverage._script_names("nmap --script=vulscan/vulscan.nse h") == {"vulscan"}
    # Categories are names too, and never match a script id.
    assert coverage._script_names("nmap --script default,safe h") == {"default", "safe"}
    assert coverage._script_names("nmap -sV h") == set()
    assert coverage.normalize_host("[2001:DB8::1]") == "2001:db8::1"
    assert coverage.normalize_host("App.Example.COM.") == "app.example.com"


def test_over_the_cap_a_repeated_detector_goes_before_a_lone_one():
    """A template seen on one address long ago, and Pulse seen on many since:
    dropping the oldest outright would drop the template's only entry, and a
    verification would then close the finding without nuclei ever looking."""
    lone = {"detector": "nuclei", "ref": TEMPLATE, "host": HOST, "port": "443"}
    pulse_on = [
        {"detector": "pulse", "ref": "local", "host": f"10.0.1.{n}", "port": "443"}
        for n in range(vulns.MAX_DETECTORS)
    ]
    merged = vulns.merge_detectors([lone], pulse_on)
    assert len(merged) == vulns.MAX_DETECTORS
    assert lone in merged
    # The newest Pulse entries stay; the oldest repeat made room.
    assert merged[: vulns.MAX_DETECTORS - 1] == pulse_on[: vulns.MAX_DETECTORS - 1]


def test_a_nuclei_template_on_another_port_is_not_this_endpoint(tmp_path, monkeypatch):
    """The finding is on 443; nuclei was given the host's port 80 only."""
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    monkeypatch.setattr(
        nuclei_scan.shutil, "which", lambda name: "/usr/local/bin/nuclei" if name == "nuclei" else None
    )

    clean_exit = _nuclei_stub()

    monkeypatch.setattr(nuclei_scan, "run_command", clean_exit)
    nuclei_scan.run_nuclei_scan(
        [f"{HOST}:80/tcp"],
        NucleiConfig(templates_dir=str(_templates(tmp_path)), template_ids=[TEMPLATE]),
        run_dir,
    )

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "endpoint_not_targeted")


def test_a_failed_verification_job_releases_only_its_own_findings(tmp_path):
    """Two findings in VERIFYING behind two jobs; one job fails. The other
    finding's verification is still running and must stay where it is."""
    two = [NUCLEI_MEDIUM, {**PULSE, "cve": "CVE-2024-0002", "port": "80"}]
    settings, tenant_id = _seed(tmp_path, findings=two)
    _write_run(settings.output_dir, "run-1", HOSTS, two)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, limit=50)
    by_cve = {item["cve"]: item["vuln_id"] for item in items}
    _park_in_verifying(settings, tenant_id, by_cve[CVE], "job-a")
    _park_in_verifying(settings, tenant_id, by_cve["CVE-2024-0002"], "job-b")

    moved = vulns.release_unfinished_verification(
        settings, tenant_id=tenant_id, job_id="job-a", run_id="run-a", status="failed"
    )

    assert moved == 1
    assert vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=by_cve[CVE])["state"] == vuln_states.FIXING
    other = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=by_cve["CVE-2024-0002"])
    assert other["state"] == vuln_states.VERIFYING
    assert other["verification_job_id"] == "job-b"


# --------------------------------------------------------------------------
# The dispatch is built from the detectors
# --------------------------------------------------------------------------


def _sensor(settings, tenant_id, capabilities=("scan_policy", "config_overlay.v1", "config_overlay.v2")):
    """A live scanner sensor of the tenant declaring ``capabilities``."""
    from api.services import agents as agents_service

    agents_service.configure(settings)
    agents_service.register_agent(
        hostname=f"sensor-{len(capabilities)}", tenant_id=tenant_id, capabilities=list(capabilities)
    )


def _agent_mode(settings, tenant_id, **sensor) -> None:
    settings.job_execution_mode = "agent"
    _sensor(settings, tenant_id, **sensor)


def _dispatch(settings, tenant_id, vuln_id) -> models.Job:
    _agent_mode(settings, tenant_id)
    _advance_to_fixing(settings, tenant_id, vuln_id)
    result = vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln_id, actor="alice")
    assert result["state"] == vuln_states.VERIFYING
    with get_session(settings.postgres_url) as session:
        job = session.get(models.Job, result["verification_job_id"])
        session.expunge(job)
    return job


def _inputs(settings, job_id: str, name: str) -> list[str]:
    path = settings.state_dir / "job_inputs" / job_id / name
    return path.read_text(encoding="utf-8").split() if path.is_file() else []


def test_a_finding_seen_on_a_name_is_re_scanned_on_that_name_with_its_template(tmp_path):
    on_name = _row("nuclei", f"nuclei:{TEMPLATE}", host=NAME)
    settings, tenant_id = _seed(tmp_path, findings=[on_name])
    approve_scan_scope(settings)
    vuln = _tracked(settings, tenant_id, [on_name])

    job = _dispatch(settings, tenant_id, vuln["vuln_id"])

    assert _inputs(settings, job.job_id, "domains.txt") == [NAME]
    assert _inputs(settings, job.job_id, "ranges.txt") == []
    assert _inputs(settings, job.job_id, "ports.txt") == ["443"]
    overlay = job.scan_options["config_overlay"]
    assert overlay["nuclei"]["template_ids"] == [TEMPLATE]
    assert overlay["nuclei"]["enabled"] is True
    assert job.scan_options["config_overlay_capability"] == "config_overlay.v2"
    started = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert started["detail"]["plan"]["template_ids"] == [TEMPLATE]


def test_a_name_out_of_scope_is_refused_not_swapped_for_the_address(tmp_path):
    on_name = _row("nuclei", f"nuclei:{TEMPLATE}", host=NAME)
    settings, tenant_id = _seed(tmp_path, findings=[on_name])
    approve_scan_scope(settings, entries=[{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}])
    vuln = _tracked(settings, tenant_id, [on_name])
    _agent_mode(settings, tenant_id)
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError, match=NAME):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING
    assert after["verification_job_id"] is None
    with get_session(settings.postgres_url) as session:
        assert session.query(models.Job).filter(models.Job.tenant_id == tenant_id).count() == 0


def test_an_nse_finding_is_re_scanned_with_nse_on(tmp_path):
    settings, tenant_id = _seed(tmp_path, findings=[NSE])
    approve_scan_scope(settings)
    vuln = _tracked(settings, tenant_id, [NSE])

    job = _dispatch(settings, tenant_id, vuln["vuln_id"])

    assert _inputs(settings, job.job_id, "ranges.txt") == [HOST]
    assert job.scan_options["config_overlay"]["service_probe"] == {"backend": "hybrid"}
    # Nothing to pin, and still a verification: asked for v2 explicitly.
    assert "template_ids" not in job.scan_options["config_overlay"]["nuclei"]
    assert job.scan_options["config_overlay_capability"] == "config_overlay.v2"
    assert job.scan_options["verification_of"] == vuln["vuln_id"]


def test_a_verification_no_live_sensor_can_run_is_refused_not_parked(tmp_path):
    """Sensor execution, and only sensors from before #451 online: the job
    would wait for one that never comes while the finding sat in VERIFYING."""
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    approve_scan_scope(settings)
    vuln = _tracked(settings, tenant_id, [PULSE])
    _agent_mode(settings, tenant_id, capabilities=("scan_policy", "config_overlay.v1"))
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError, match="config_overlay.v2"):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING
    with get_session(settings.postgres_url) as session:
        assert session.query(models.Job).filter(models.Job.tenant_id == tenant_id).count() == 0


def test_a_template_id_a_sensor_would_refuse_is_refused_at_dispatch(tmp_path):
    odd = _row("nuclei", "nuclei:bad,id")
    settings, tenant_id = _seed(tmp_path, findings=[odd])
    approve_scan_scope(settings)
    vuln = _tracked(settings, tenant_id, [odd])
    _agent_mode(settings, tenant_id)
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError, match="bad,id"):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")
