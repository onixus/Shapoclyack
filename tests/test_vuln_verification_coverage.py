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
    exclude: tuple[int, ...] = (),
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
            exclude_ports=list(exclude),
        )
    except subprocess.CalledProcessError:
        found = []
    (run_dir / "open_ports.txt").write_text("".join(f"{e}\n" for e in found), encoding="utf-8")


def _reach(monkeypatch, run_dir: Path, outcomes: dict[str, list[str]], *, port: int = 443) -> None:
    """Run the real reachability stage with each host's connect outcomes
    scripted (``{"10.0.0.5": ["refused", "refused"]}``)."""
    from scanner.pipeline import reachability
    from scanner.pipeline.config_schema import ReachabilityConfig

    script = {host: list(results) for host, results in outcomes.items()}
    monkeypatch.setattr(reachability, "_attempt", lambda host, _port, _timeout: script[host].pop(0))
    attempts = max(len(results) for results in outcomes.values())
    reachability.run_reachability_probe(
        list(outcomes),
        {port},
        ReachabilityConfig(enabled=True, attempts=attempts, attempt_interval_seconds=0),
        run_dir,
    )


REFUSED = ["refused", "refused"]


def _job_from(settings, tenant_id, job_id: str, run_id: str, *, agent: str | None = None, group: str | None = None):
    """A job that produced ``run_id``: local, or a sensor (in ``group``)."""
    from datetime import UTC, datetime

    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id=job_id,
                tenant_id=tenant_id,
                status="succeeded",
                run_id=run_id,
                queued_at=now,
                finished_at=now,
                execution="agent" if agent else "local",
                assigned_agent_id=agent,
                agent_group=group,
            )
        )


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
        # One more than expected is no better than one fewer.
        (lambda: _nuclei_stub(loaded=2), "nuclei_templates_not_loaded"),
    ],
)
def test_nuclei_s_own_account_can_deny_coverage(tmp_path, monkeypatch, stub, reason):
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE], stub=stub())

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], reason)


def test_two_pinned_templates_need_both_loaded(tmp_path, monkeypatch):
    """Two nuclei detectors, two pinned templates; nuclei reports one loaded
    (the other did not parse): neither is shown to have been checked."""
    second = "CVE-2024-0009"
    both = _row(
        "nuclei", f"nuclei:{TEMPLATE}", also_detected_by=[{"source": "nuclei", "script_id": f"nuclei:{second}"}]
    )
    settings, tenant_id = _seed(tmp_path, findings=[both])
    vuln = _tracked(settings, tenant_id, [both])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    templates = _templates(tmp_path)
    (templates / "http" / "cves" / f"{second}.yaml").write_text(
        f"id: {second}\n\ninfo:\n  name: x\n  severity: medium\n  tags: cve\n", encoding="utf-8"
    )
    _nuclei(
        monkeypatch,
        run_dir,
        tmp_path,
        template_ids=[TEMPLATE, second],
        templates_dir=str(templates),
        stub=_nuclei_stub(loaded=1),
    )

    _fold(settings, tenant_id)

    _assert_inconclusive(
        settings, tenant_id, vuln["vuln_id"], "nuclei_templates_not_loaded", "nuclei_templates_not_loaded"
    )


def test_an_ambiguous_template_id_is_a_gap(tmp_path, monkeypatch):
    settings, tenant_id = _seed(tmp_path, findings=[NUCLEI_MEDIUM])
    vuln = _tracked(settings, tenant_id, [NUCLEI_MEDIUM])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    copy = tmp_path / "custom"
    copy.mkdir()
    (copy / f"{TEMPLATE}.yaml").write_text(
        f"id: {TEMPLATE}\n\ninfo:\n  name: copy\n  severity: medium\n  tags: cve\n", encoding="utf-8"
    )
    _nuclei(monkeypatch, run_dir, tmp_path, template_ids=[TEMPLATE], custom_templates_dir=str(copy))

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], "nuclei_template_ambiguous")


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


@pytest.mark.parametrize(
    ("found_with", "verified_with", "reason"),
    [
        ("2026.07.29-h10", "2026.07.29-h9", "pulse_ruleset_older"),  # numbers, not strings
        ("2026-08-02", "2026.07.29-h1", "pulse_ruleset_unparseable"),  # used to sort oldest
        ("2026.08.02-h0", "nightly", "pulse_ruleset_unparseable"),
    ],
)
def test_a_ruleset_is_compared_only_when_both_sides_read(tmp_path, monkeypatch, found_with, verified_with, reason):
    found = _row("pulse", "pulse:local", ruleset_version=found_with)
    settings, tenant_id = _seed(tmp_path, findings=[found])
    vuln = _tracked(settings, tenant_id, [found])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, ruleset=verified_with)

    _fold(settings, tenant_id)

    _assert_inconclusive(settings, tenant_id, vuln["vuln_id"], reason)


def test_a_ruleset_without_its_hotfix_is_not_a_dead_end(tmp_path, monkeypatch):
    found = _row("pulse", "pulse:local", ruleset_version="2026.07.29")
    settings, tenant_id = _seed(tmp_path, findings=[found])
    vuln = _tracked(settings, tenant_id, [found])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir, ruleset="2026.07.29-H0")

    assert _fold(settings, tenant_id).verification_passed == 1


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
# Refused from the observing vantage: endpoint_unreachable, never verified
# --------------------------------------------------------------------------


def _closed_unreachable(settings, tenant_id, vuln_id) -> dict:
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert after["state"] == vuln_states.CLOSED
    assert after["closure_reason"] == "endpoint_unreachable"
    event = _last_event(settings, tenant_id, vuln_id)
    assert event["kind"] == "verification_unreachable"
    assert event["detail"]["evidence"]["endpoints"][0]["probe"] == REFUSED
    return after


def _tracked_from(settings, tenant_id, finding, **vantage) -> dict:
    """Track ``finding`` from a run-1 a known job produced (local by default)."""
    _job_from(settings, tenant_id, "job-observe", "run-1", **vantage)
    return _tracked(settings, tenant_id, [finding])


def _still_open(settings, tenant_id, vuln_id) -> dict:
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    assert after["state"] == vuln_states.FIXING
    assert after["machine_verified"] is False
    assert _last_event(settings, tenant_id, vuln_id)["kind"] == "verification_inconclusive"
    return after


def test_icmp_liveness_and_an_empty_naabu_close_nothing(tmp_path, monkeypatch):
    """The delta review's P0: naabu reports open ports only, so a port a
    firewall dropped and one that refused look alike — absent — and a host
    that answered ping was enough to close the exposure machine-verified.
    Without the connect probe's refusal there is no closure."""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked_from(settings, tenant_id, EXPOSURE)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _discovered(run_dir)
    _port_stage(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    _still_open(settings, tenant_id, vuln["vuln_id"])


@pytest.mark.parametrize(
    "finding",
    [
        EXPOSURE,  # "this port is reachable": a REJECT rule makes it look gone
        PULSE,  # a CVE: the vulnerable service out of reach, not shown patched
        {**EXPOSURE, "script_id": "pulse:tls:443:weak-cipher"},
    ],
    ids=["exposure", "cve", "tls"],
)
def test_a_refused_port_closes_but_is_never_machine_verified(tmp_path, monkeypatch, finding):
    """The round-3 decision: an iptables/kube-proxy REJECT, a tcp-reset rule or
    a fail2ban ban in front of a listening port is refused on every attempt
    just like a closed one. So a refusal closes the finding as not reachable
    from where the run looked — for an exposure as much as for a CVE — and is
    not a verified fix, nor counted as one."""
    settings, tenant_id = _seed(tmp_path, findings=[finding])
    vuln = _tracked_from(settings, tenant_id, finding)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})

    stats = _fold(settings, tenant_id)

    assert stats.verification_unreachable == 1
    assert _closed_unreachable(settings, tenant_id, vuln["vuln_id"])["machine_verified"] is False
    assert vulns.summary(settings, tenant_id=tenant_id)["machine_verified_closed"] == 0
    event = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert event["detail"]["machine_verified"] is False
    assert "not reachable from local" in event["note"]
    assert "not machine-verified" in event["note"]


@pytest.mark.parametrize("finding", [EXPOSURE, PULSE], ids=["exposure", "cve"])
@pytest.mark.parametrize(
    ("observed", "why"),
    [
        ({"agent": "sensor-int", "group": "internal"}, "another sensor group"),
        ({"agent": "sensor-solo"}, "another, ungrouped sensor"),
        (None, "observing sensor unknown (a run no job owns)"),
    ],
)
def test_a_port_refused_from_elsewhere_is_inconclusive(tmp_path, monkeypatch, finding, observed, why):
    """A DMZ sensor's refusal says nothing about the path the internal one
    saw the finding on — exposure or CVE alike."""
    settings, tenant_id = _seed(tmp_path, findings=[finding])
    vuln = (
        _tracked_from(settings, tenant_id, finding, **observed)
        if observed
        else _tracked(settings, tenant_id, [finding])
    )
    _park_in_verifying(settings, tenant_id, vuln["vuln_id"], "job-verify")
    _write_run(settings.output_dir, "run-verify", HOSTS, [])
    _job_from(settings, tenant_id, "job-verify", "run-verify", agent="sensor-dmz", group="dmz")
    run_dir = settings.output_dir / "runs" / "run-verify"
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})

    _fold(settings, tenant_id)

    _still_open(settings, tenant_id, vuln["vuln_id"])
    gaps = _last_event(settings, tenant_id, vuln["vuln_id"])["detail"]["gaps"]
    assert any(gap["reason"] == "vantage_differs" for gap in gaps), why


@pytest.mark.parametrize("verify_from", ["dmz", "internal"])
def test_a_later_observer_does_not_erase_an_earlier_one(tmp_path, monkeypatch, verify_from):
    """The round-2 delta review's probe: the internal sensors saw the
    exposure, then the DMZ sensor saw it too. The detector entry used to
    take the DMZ vantage over, and a DMZ refusal then closed what the
    internal path still reached. Seen from two places, a refusal from
    either one closes nothing."""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    _job_from(settings, tenant_id, "job-int", "run-1", agent="sensor-int", group="internal")
    first = _tracked(settings, tenant_id, [EXPOSURE], run_id="run-1")
    _job_from(settings, tenant_id, "job-dmz", "run-2", agent="sensor-dmz", group="dmz")
    second = _tracked(settings, tenant_id, [EXPOSURE], run_id="run-2")
    assert second["detectors"][0]["vantages"] == ["group:dmz", "group:internal"]

    _park_in_verifying(settings, tenant_id, first["vuln_id"], "job-verify")
    _write_run(settings.output_dir, "run-verify", HOSTS, [])
    _job_from(settings, tenant_id, "job-verify", "run-verify", agent=f"sensor-{verify_from}", group=verify_from)
    run_dir = settings.output_dir / "runs" / "run-verify"
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})

    _fold(settings, tenant_id)

    _still_open(settings, tenant_id, first["vuln_id"])
    gap = next(
        gap
        for gap in _last_event(settings, tenant_id, first["vuln_id"])["detail"]["gaps"]
        if gap["reason"] == "vantage_differs"
    )
    assert gap["observed_from"] == ["group:dmz", "group:internal"]
    assert gap["verified_from"] == f"group:{verify_from}"


def test_two_detectors_seen_from_two_places_close_nothing_by_refusal(tmp_path, monkeypatch):
    """Pulse from the internal group, nuclei from the DMZ: the refusal from
    the DMZ matches one of them and not the other."""
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    _job_from(settings, tenant_id, "job-int", "run-1", agent="sensor-int", group="internal")
    vuln = _tracked(settings, tenant_id, [PULSE], run_id="run-1")
    _job_from(settings, tenant_id, "job-dmz", "run-2", agent="sensor-dmz", group="dmz")
    _tracked(settings, tenant_id, [NUCLEI_MEDIUM], run_id="run-2")
    _park_in_verifying(settings, tenant_id, vuln["vuln_id"], "job-verify")
    _write_run(settings.output_dir, "run-verify", HOSTS, [])
    _job_from(settings, tenant_id, "job-verify", "run-verify", agent="sensor-dmz", group="dmz")
    run_dir = settings.output_dir / "runs" / "run-verify"
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})

    _fold(settings, tenant_id)

    _still_open(settings, tenant_id, vuln["vuln_id"])


def test_a_row_without_detectors_is_never_closed_by_refusal(tmp_path, monkeypatch):
    """A row with no detector recorded none of where it was seen, nor over
    which protocol: a refusal from the verifying run's own place says nothing
    about it. (Two locks hold here — no protocol, no vantage — so a mutant
    that loosens either one alone survives this test; each is pinned on its
    own by the protocol and vantage tests.)"""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked_from(settings, tenant_id, EXPOSURE)
    with get_session(settings.postgres_url) as session:
        session.get(models.Vulnerability, vuln["vuln_id"]).detectors = None
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})

    _fold(settings, tenant_id)

    _still_open(settings, tenant_id, vuln["vuln_id"])


def test_the_detector_records_where_it_was_seen_from(tmp_path):
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    vuln = _tracked_from(settings, tenant_id, PULSE, agent="sensor-int", group="internal")
    entry = vuln["detectors"][0]
    assert (entry["agent_id"], entry["agent_group"], entry["vantage"]) == ("sensor-int", "internal", "group:internal")
    assert entry["vantages"] == ["group:internal"]


def test_vantages_survive_the_detector_cap_and_the_hostless_backfill():
    """Whatever the merge drops, the vantages it was seen from stay on the
    row: the entry the cap evicts hands them to the newest one, and the
    host-less entry 0079 backfilled (seen from nobody knows where) leaves
    ``unknown`` behind when a located one replaces it."""
    backfilled = {"detector": "pulse", "ref": "local", "host": None, "port": "443"}
    located = {"detector": "pulse", "ref": "local", "host": HOST, "port": "443", "vantage": "local", "vantages": ["local"]}
    assert vulns.merge_detectors([backfilled], [located])[0]["vantages"] == ["local", "unknown"]

    old = {"detector": "nuclei", "ref": "t-old", "host": HOST, "port": "443", "vantages": ["group:internal"]}
    repeat = {**old, "host": "10.0.0.9", "vantages": ["group:dmz"]}
    newer = [
        {"detector": "nuclei", "ref": f"t-{n}", "host": HOST, "port": "443", "vantages": ["group:dmz"]}
        for n in range(vulns.MAX_DETECTORS - 1)
    ]
    merged = vulns.merge_detectors([repeat, old], newer)
    assert len(merged) == vulns.MAX_DETECTORS
    assert {v for entry in merged for v in entry["vantages"]} == {"group:dmz", "group:internal"}


def test_the_verification_goes_out_from_the_observing_group(tmp_path):
    from api.services import agent_groups

    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    approve_scan_scope(settings)
    agent_groups.create_group(settings, tenant_id=tenant_id, name="internal")
    vuln = _tracked_from(settings, tenant_id, PULSE, agent="sensor-int", group="internal")

    job = _dispatch(settings, tenant_id, vuln["vuln_id"], sensor_group="internal")

    assert job.agent_group == "internal"


@pytest.mark.parametrize(
    ("setup", "why"),
    [
        (lambda m, d: (_port_stage(m, d), _reach(m, d, {HOST: ["timeout", "timeout"]})), "dropped: timeout"),
        (lambda m, d: (_port_stage(m, d), _reach(m, d, {HOST: ["refused", "timeout"]})), "one answer lost"),
        (lambda m, d: (_port_stage(m, d), _reach(m, d, {HOST: ["unreachable", "unreachable"]})), "no route"),
        (lambda m, d: (_port_stage(m, d), _reach(m, d, {HOST: ["refused", "open"]})), "the probe got in"),
        (lambda m, d: (_port_stage(m, d, explicit=False), _reach(m, d, {HOST: REFUSED})), "-top-ports only"),
        (lambda m, d: (_port_stage(m, d, fails=True), _reach(m, d, {HOST: REFUSED})), "batch did not finish"),
        (lambda m, d: (_port_stage(m, d, exclude=(443,)), _reach(m, d, {HOST: REFUSED})), "port excluded"),
        (lambda m, d: _reach(m, d, {HOST: REFUSED}), "no port-stage record"),
        (
            lambda m, d: (
                _port_stage(m, d),
                _reach(m, d, {HOST: REFUSED}),
                _pulse(m, d, ports=(443,), cve=False),
            ),
            "Pulse saw it open",
        ),
    ],
)
def test_short_of_every_condition_a_closed_port_stays_inconclusive(tmp_path, monkeypatch, setup, why):
    """A dropped packet, a port never explicitly asked about, a batch that
    died, a probe that disagrees: the firewalled-during-the-window case."""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked_from(settings, tenant_id, EXPOSURE)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    setup(monkeypatch, run_dir)

    _fold(settings, tenant_id)

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING, why


def test_a_name_is_never_judged_by_refusal(tmp_path, monkeypatch):
    """Even with a refusal and a finished port batch recorded under the name
    itself: which address the name led to is not recorded, so a name is never
    closed this way."""
    import json as _json

    on_name = {**EXPOSURE, "host": NAME}
    settings, tenant_id = _seed(tmp_path, findings=[on_name])
    vuln = _tracked_from(settings, tenant_id, on_name)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    ports = run_dir / "ports"
    ports.mkdir(parents=True, exist_ok=True)
    (ports / "b0.scan.json").write_text(
        _json.dumps(
            {"protocol": "tcp", "hosts": [NAME], "port_args": ["-p", "443"], "exclude_ports": [], "complete": True}
        ),
        encoding="utf-8",
    )
    _reach(monkeypatch, run_dir, {NAME: REFUSED})

    _fold(settings, tenant_id)

    _still_open(settings, tenant_id, vuln["vuln_id"])


def test_a_hostless_exposure_needs_refusal_on_every_address(tmp_path, monkeypatch):
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked_from(settings, tenant_id, EXPOSURE)
    _second_address(settings, tenant_id, vuln["vuln_id"])
    _forget_host(settings, vuln["vuln_id"], "pulse")
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir)  # HOST only
    _reach(monkeypatch, run_dir, {HOST: REFUSED})  # nothing about 10.0.0.6

    _fold(settings, tenant_id)

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING


def test_a_hostless_detector_beside_a_located_one_still_needs_every_address(tmp_path, monkeypatch):
    """Pulse saw it on 10.0.0.5; a migrated nuclei entry never said where.
    A refusal on .5 alone would close it while .6 was never asked."""
    exposure_both = {**EXPOSURE, "also_detected_by": [{"source": "nuclei", "script_id": "nuclei:panel-detect"}]}
    settings, tenant_id = _seed(tmp_path, findings=[exposure_both])
    vuln = _tracked_from(settings, tenant_id, exposure_both)
    _second_address(settings, tenant_id, vuln["vuln_id"])
    _forget_host(settings, vuln["vuln_id"], "nuclei")
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})

    _fold(settings, tenant_id)

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING


def test_a_reopen_after_an_unreachable_closure_keeps_the_sla_clock(tmp_path, monkeypatch):
    """Verify → closed unreachable → seen again → reopened: the deadline is
    the original one, so the cycle cannot reset an overdue exposure."""
    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked_from(settings, tenant_id, EXPOSURE)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})
    _fold(settings, tenant_id)
    _closed_unreachable(settings, tenant_id, vuln["vuln_id"])

    again = _tracked(settings, tenant_id, [EXPOSURE], run_id="run-3")

    assert again["state"] == vuln_states.OPEN
    assert again["sla_started_at"] == vuln["sla_started_at"]
    assert again["due_at"] == vuln["due_at"]
    reopened = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert reopened["kind"] == "reopened"
    assert reopened["detail"]["sla_continued"] is True


@pytest.mark.parametrize(("later", "continued"), [("in_window", True), ("180_days", False)])
def test_the_sla_clock_continues_only_within_one_window_of_the_closure(tmp_path, monkeypatch, later, continued):
    """The round-2 delta review's probe: an exposure closed as unreachable,
    and the port opened again 180 days later by a new deployment. That is a
    new exposure, and it reopened already overdue on its first observation.
    Within one SLA window of the closure it is the same one, and continues."""
    from datetime import datetime, timedelta

    settings, tenant_id = _seed(tmp_path, findings=[EXPOSURE])
    vuln = _tracked_from(settings, tenant_id, EXPOSURE)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir)
    _reach(monkeypatch, run_dir, {HOST: REFUSED})
    _fold(settings, tenant_id)
    _closed_unreachable(settings, tenant_id, vuln["vuln_id"])
    assert vuln["sla_days"] < 180
    offset = timedelta(days=vuln["sla_days"] - 1) if later == "in_window" else timedelta(days=180)
    moment = vulns._now() + offset
    monkeypatch.setattr(vulns, "_now", lambda: moment)

    again = _tracked(settings, tenant_id, [EXPOSURE], run_id="run-later")

    assert again["state"] == vuln_states.OPEN
    reopened = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert reopened["kind"] == "reopened"
    if continued:
        assert again["due_at"] == vuln["due_at"]
        assert reopened["detail"]["sla_continued"] is True
    else:
        assert datetime.fromisoformat(again["sla_started_at"].replace("Z", "")) == moment
        assert again["due_at"] != vuln["due_at"]
        assert "sla_continued" not in reopened["detail"]


def test_a_reopen_after_a_verified_fix_still_restarts_the_clock(tmp_path, monkeypatch):
    """The control: a regression after a real fix is measured from its return."""
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    vuln = _tracked_from(settings, tenant_id, PULSE)
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _pulse(monkeypatch, run_dir)
    assert _fold(settings, tenant_id).verification_passed == 1

    again = _tracked(settings, tenant_id, [PULSE], run_id="run-3")

    assert again["state"] == vuln_states.OPEN
    assert again["sla_started_at"] != vuln["sla_started_at"]
    assert "sla_continued" not in _last_event(settings, tenant_id, vuln["vuln_id"])["detail"]


@pytest.mark.parametrize(
    "protocol",
    [
        "udp",  # NTP's vulners finding is on UDP 123
        None,  # an NSE detector from before the protocol was recorded
    ],
)
def test_a_closed_tcp_port_says_nothing_about_a_udp_or_unknown_finding(tmp_path, monkeypatch, protocol):
    """The delta review's probe: a vulners CVE on UDP 123, re-checked by a
    TCP port stage that saw 123 closed, was closed as endpoint_unreachable."""
    ntp = _row("nmap-nse", "vulners", port="123", **({"protocol": protocol} if protocol else {}))
    settings, tenant_id = _seed(tmp_path, findings=[ntp])
    vuln = _tracked(settings, tenant_id, [ntp])
    run_dir = _verification_run(settings, tenant_id, vuln["vuln_id"])
    _port_stage(monkeypatch, run_dir, asked=(123,))
    _reach(monkeypatch, run_dir, {HOST: REFUSED}, port=123)

    stats = _fold(settings, tenant_id)

    assert stats.verification_unreachable == 0
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING
    if protocol:
        assert vuln["detectors"][0]["protocol"] == protocol


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


@pytest.mark.parametrize(
    ("detectors", "protocol"),
    [
        ([{"detector": "pulse"}], "tcp"),
        ([{"detector": "nmap-nse", "protocol": "udp"}], "udp"),
        # TCP evidence for a finding one of whose detectors saw it on UDP.
        ([{"detector": "pulse"}, {"detector": "nmap-nse", "protocol": "udp"}], None),
        # An NSE entry from before the protocol was recorded: unknown, and
        # Pulse being TCP does not make it TCP.
        ([{"detector": "pulse"}, {"detector": "nmap-nse"}], None),
        ([], None),
    ],
    ids=["pulse", "nse-udp", "tcp-and-udp", "tcp-and-unknown", "none"],
)
def test_a_finding_is_tcp_only_when_every_detector_says_so(detectors, protocol):
    """The delta review's surviving mutants: "any detector is TCP" and
    "ignore the unknown ones" each let a refused TCP port close a finding a
    UDP or protocol-unknown detector also stands behind."""
    from api.services import verification_coverage as coverage

    assert coverage.finding_protocol(detectors) == protocol


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
    assert [
        {key: value for key, value in entry.items() if key != "vantages"}
        for entry in merged[: vulns.MAX_DETECTORS - 1]
    ] == pulse_on[: vulns.MAX_DETECTORS - 1]


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


def _sensor(
    settings,
    tenant_id,
    capabilities=("scan_policy", "config_overlay.v1", "config_overlay.v2"),
    group: str | None = None,
):
    """A live scanner sensor of the tenant declaring ``capabilities``, in ``group``."""
    from api.services import agent_groups
    from api.services import agents as agents_service

    agents_service.configure(settings)
    agent = agents_service.register_agent(
        hostname=f"sensor-{len(capabilities)}-{group}", tenant_id=tenant_id, capabilities=list(capabilities)
    )
    if group:
        agent_groups.set_agent_group(settings, tenant_id=tenant_id, agent_id=agent.agent_id, name=group)


def _agent_mode(settings, tenant_id, **sensor) -> None:
    settings.job_execution_mode = "agent"
    _sensor(settings, tenant_id, **sensor)


def _dispatch(settings, tenant_id, vuln_id, *, sensor_group: str | None = None) -> models.Job:
    _agent_mode(settings, tenant_id, group=sensor_group)
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
    # The connect probe a refusal is judged on, on every verification.
    assert overlay["reachability"] == {"enabled": True}
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
    assert job.scan_options["config_overlay"]["reachability"] == {"enabled": True}
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


def _dmz_scope(settings, tenant_id) -> None:
    from api.services import agent_groups

    agent_groups.create_group(settings, tenant_id=tenant_id, name="dmz")
    approve_scan_scope(
        settings, entries=[{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8", "agent_groups": ["dmz"]}]
    )


def test_a_scope_pinned_group_without_a_v2_sensor_is_refused(tmp_path):
    """The delta review's probe: a v2 sensor outside any group, a v1 sensor
    in ``dmz``, a scope that sends 10.0.0.0/8 to ``dmz``. The tenant-wide
    check passed, the job went to ``dmz``, every claim was a 426 and the
    finding sat in VERIFYING with nothing on screen."""
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    _dmz_scope(settings, tenant_id)
    vuln = _tracked(settings, tenant_id, [PULSE])
    _agent_mode(settings, tenant_id)  # v2, ungrouped
    _sensor(settings, tenant_id, capabilities=("scan_policy", "config_overlay.v1"), group="dmz")
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError, match="dmz"):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING
    with get_session(settings.postgres_url) as session:
        assert session.query(models.Job).filter(models.Job.tenant_id == tenant_id).count() == 0


def test_a_scope_pinned_group_with_a_v2_sensor_gets_the_job(tmp_path):
    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    _dmz_scope(settings, tenant_id)
    vuln = _tracked(settings, tenant_id, [PULSE])

    job = _dispatch(settings, tenant_id, vuln["vuln_id"], sensor_group="dmz")

    assert job.agent_group == "dmz"


@pytest.mark.parametrize("regroup", ["deleted", "no_live_sensor"])
def test_an_observing_group_that_cannot_take_it_sends_the_verification_tenant_wide(tmp_path, regroup):
    """The round-2 delta review's probes: the sensors of ``internal`` moved
    to ``msk``, and ``internal`` deleted — or kept, empty. Pinning the job to
    ``internal`` was a 409 forever (unknown group) or one telling the
    operator to upgrade a sensor in a group that has none. It goes out to
    any sensor of the tenant instead, and says so."""
    from api.services import agent_groups

    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    approve_scan_scope(settings)
    agent_groups.create_group(settings, tenant_id=tenant_id, name="internal")
    agent_groups.create_group(settings, tenant_id=tenant_id, name="msk")
    vuln = _tracked_from(settings, tenant_id, PULSE, agent="sensor-int", group="internal")
    if regroup == "deleted":
        agent_groups.delete_group(settings, tenant_id=tenant_id, name="internal")

    job = _dispatch(settings, tenant_id, vuln["vuln_id"], sensor_group="msk")

    assert job.agent_group is None
    started = _last_event(settings, tenant_id, vuln["vuln_id"])
    assert started["detail"]["regrouped"] == {"from": "internal", "reason": regroup, "dispatched_group": None}
    assert "observing sensor group 'internal'" in started["note"]
    assert "vantage differs" in started["note"]


@pytest.mark.parametrize(
    "member",
    [
        {"agent_kind": "endpoint"},  # refused every scan job on claim (403)
        {"version": "1.0"},  # below the floor: refused on claim (426)
    ],
    ids=["endpoint-agent", "below-floor"],
)
def test_a_group_of_agents_the_claim_refuses_is_no_sensor_for_a_verification(tmp_path, member):
    """The round-2 delta review's probes: the observing group's only member
    declares v2 but could never claim the job. The verification was queued
    there and the finding parked in VERIFYING. Now the group counts as having
    no live sensor; with none elsewhere either, it is refused — and the
    refusal does not tell anyone to upgrade a sensor that does not exist."""
    from api.services import agent_groups
    from api.services import agents as agents_service

    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    approve_scan_scope(settings)
    agent_groups.create_group(settings, tenant_id=tenant_id, name="dmz")
    vuln = _tracked_from(settings, tenant_id, PULSE, agent="sensor-dmz", group="dmz")
    settings.job_execution_mode = "agent"
    settings.agent_min_version = "9.0"
    agents_service.configure(settings)
    agent = agents_service.register_agent(
        hostname="dmz-member",
        tenant_id=tenant_id,
        capabilities=["scan_policy", "config_overlay.v1", "config_overlay.v2"],
        **{"version": "9.1", **member},
    )
    agent_groups.set_agent_group(settings, tenant_id=tenant_id, agent_id=agent.agent_id, name="dmz")
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError) as refused:
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")

    assert "Upgrade" not in str(refused.value)
    assert "observing group 'dmz' has no live sensor" in str(refused.value)
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"])
    assert after["state"] == vuln_states.FIXING
    with get_session(settings.postgres_url) as session:
        # Only the job that observed it: no verification was queued.
        assert [job.job_id for job in session.query(models.Job).filter(models.Job.tenant_id == tenant_id)] == [
            "job-observe"
        ]


def test_a_group_with_only_old_sensors_is_told_to_upgrade_one(tmp_path):
    """The control: live v1 sensors in the observing group — there is
    something to upgrade, and the job stays pinned to where it was seen."""
    from api.services import agent_groups

    settings, tenant_id = _seed(tmp_path, findings=[PULSE])
    approve_scan_scope(settings)
    agent_groups.create_group(settings, tenant_id=tenant_id, name="dmz")
    vuln = _tracked_from(settings, tenant_id, PULSE, agent="sensor-dmz", group="dmz")
    _agent_mode(settings, tenant_id, capabilities=("scan_policy", "config_overlay.v1"), group="dmz")
    _sensor(settings, tenant_id)  # a v2 sensor elsewhere does not take it
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError, match="sensor group 'dmz'.*Upgrade a sensor there"):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")


def test_a_template_id_a_sensor_would_refuse_is_refused_at_dispatch(tmp_path):
    odd = _row("nuclei", "nuclei:bad,id")
    settings, tenant_id = _seed(tmp_path, findings=[odd])
    approve_scan_scope(settings)
    vuln = _tracked(settings, tenant_id, [odd])
    _agent_mode(settings, tenant_id)
    _advance_to_fixing(settings, tenant_id, vuln["vuln_id"])

    with pytest.raises(vulns.VerificationDispatchError, match="bad,id"):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=vuln["vuln_id"], actor="alice")
