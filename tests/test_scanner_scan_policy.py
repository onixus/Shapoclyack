"""The scanner half of the tenant scan policy (#362).

The API decides the ceiling; this is the code that has to make the packets obey
it. Every test below pins the one property the whole feature rests on — the
policy can lower a rate and never raise one — plus the two ways that could
silently go wrong: a config that spells "unlimited" as 0, and a policy version
this build does not understand.

They run against ``scanner/config/default.yaml``'s own shape rather than a
hand-made minimal config where that matters, because the number this issue
starts from is a real one: ``safe`` discovery at 2000 packets per second.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.pipeline.config_schema import load_config
from scanner.pipeline.scan_policy import (
    ScanPolicyError,
    apply_policy,
    load_policy,
)


def _config(**runtime: object):
    """A valid config whose ``safe`` profile carries the shipped rates."""
    return load_config(
        {
            "runtime": {"mode": "safe", **runtime},
            "profiles": {
                "safe": {
                    "discover_rate": 2000,
                    "port_rate": 1000,
                    "top_ports": 100,
                    "nse_profile": "baseline",
                    "nse_concurrency": 2,
                    "nse_max_rate": 500,
                    "pulse": {"concurrency": 300, "rate": 500, "host_parallel": 4},
                },
                "balanced": {
                    "discover_rate": 4000,
                    "port_rate": 3000,
                    "top_ports": 1000,
                    "nse_profile": "baseline",
                },
                "fast": {
                    "discover_rate": 10000,
                    "port_rate": 7000,
                    "top_ports": 1000,
                    "nse_profile": "baseline",
                },
            },
            "nse_profiles": {"baseline": {"scripts": "default,safe"}},
        }
    )


def _policy(**fields: object) -> dict:
    return {
        "policy_version": 1,
        "profile": "standard",
        "safe_only": False,
        "skip_service_probe": False,
        "avoid_ports": [],
        "max_discover_rate": None,
        "max_port_rate": None,
        "max_host_concurrency": None,
        "per_host_rate": None,
        **fields,
    }


def test_a_policy_lowers_the_configured_rate():
    """The number the issue starts from: safe discovery at 2000 pps, on the
    agent's own config, with the platform operator unable to say otherwise."""
    tightened = apply_policy(_config(), _policy(max_discover_rate=100, max_port_rate=50))
    assert tightened.profiles["safe"].discover_rate == 100
    assert tightened.profiles["safe"].port_rate == 50
    # Every profile, not only the active one: which profile runs is decided
    # elsewhere, and a ceiling that only applied to ``safe`` would be lifted by
    # a scan that asked for ``fast``.
    assert tightened.profiles["fast"].discover_rate == 100


def test_a_policy_never_raises_a_rate_the_config_already_lowered():
    """The local file stays the fallback: an installation that hardened its own
    config keeps the hardening, and the policy only ever tightens it."""
    tightened = apply_policy(_config(), _policy(max_discover_rate=50_000))
    assert tightened.profiles["safe"].discover_rate == 2000
    assert tightened.profiles["fast"].discover_rate == 10_000


def test_an_unlimited_rate_is_not_read_as_the_strictest_one():
    """``nse_max_rate: 0`` means *unlimited* in this config, so a naive min()
    would compute 0 and turn a 25 pps ceiling into no ceiling at all — the one
    mistake here that would be silent and would show up as a dead PLC."""
    tightened = apply_policy(_config(nse_max_rate=0), _policy(per_host_rate=25))
    assert tightened.runtime.nse_max_rate == 25


def test_concurrency_is_held_down_everywhere_a_batch_can_widen():
    tightened = apply_policy(_config(), _policy(max_host_concurrency=1))
    assert tightened.runtime.discover_concurrency == 1
    assert tightened.runtime.ports_concurrency == 1
    assert tightened.runtime.nse_concurrency == 1
    assert tightened.profiles["safe"].pulse.host_parallel == 1


def test_the_fragile_profile_turns_the_service_probe_stage_off():
    """NSE scripts and banner grabs are the packets that fault a controller."""
    tightened = apply_policy(_config(), _policy(skip_service_probe=True))
    assert tightened.runtime.skip_nse is True


def test_the_policy_cannot_turn_the_service_probe_stage_back_on():
    """One direction only — a policy is a set of ceilings, not of values."""
    tightened = apply_policy(_config(skip_nse=True), _policy(skip_service_probe=False))
    assert tightened.runtime.skip_nse is True


def test_avoided_ports_are_added_to_the_exclusions_the_config_already_has():
    config = _config()
    config = config.model_copy(update={"ports": config.ports.model_copy(update={"exclude_ports": [9100]})})
    tightened = apply_policy(config, _policy(avoid_ports=[502, 20000]))
    assert tightened.ports.exclude_ports == [502, 9100, 20000]


def test_a_policy_version_this_build_cannot_apply_stops_the_run(tmp_path: Path):
    """Rather than being ignored: a ceiling half-understood reads as enforced
    and is not, and the scan it would not have paced is on a plant network."""
    path = tmp_path / "scan_policy.json"
    path.write_text(json.dumps(_policy(policy_version=99)), encoding="utf-8")
    with pytest.raises(ScanPolicyError) as excinfo:
        load_policy(path)
    assert "version" in str(excinfo.value)


def test_a_malformed_policy_file_stops_the_run(tmp_path: Path):
    path = tmp_path / "scan_policy.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ScanPolicyError):
        load_policy(path)


def test_avoided_ports_reach_naabu(tmp_path, monkeypatch):
    """The port stage decides which ports exist for every stage after it, so
    an avoid-list that did not reach naabu would not exist at all."""
    from scanner.pipeline import ports as ports_mod

    ports_mod._reset_syn_state()
    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    monkeypatch.setattr(
        ports_mod,
        "run_command",
        lambda command, **kwargs: (captured.append(command), _Result())[1],
    )
    try:
        ports_mod.fast_port_scan(
            alive_hosts=["10.0.0.1"],
            output_dir=tmp_path,
            rate=1000,
            top_ports=100,
            top_udp_ports=100,
            timeout=60,
            retries=1,
            protocol_mode="tcp",
            custom_ports_file=tmp_path / "absent.txt",
            custom_udp_ports_file=tmp_path / "absent-udp.txt",
            udp_probes=False,
            exclude_ports=[502, 20000],
        )
    finally:
        ports_mod._reset_syn_state()

    assert captured, "naabu was never invoked"
    command = captured[0]
    assert command[command.index("-exclude-ports") + 1] == "502,20000"


# ---------------------------------------------------------------------------
# The stages that read a rate of their own
# ---------------------------------------------------------------------------


def _fragile_run_config():
    """The config a fragile scan actually runs on, assembled as ``main`` does.

    ``scanner/config/default.yaml`` → the discovery preset for the mode → the
    policy, in that order (see ``scanner/main.py``). Hand-made configs are no
    use for these three: the defect was never in ``apply_policy`` refusing to
    lower a number, it was in the shipped YAML carrying rates that nothing
    lowered.
    """
    from scanner.pipeline.discovery_profiles import apply_discovery_profile
    from scanner.pipeline.utils import load_yaml

    config = load_config(load_yaml(Path("scanner/config/default.yaml")))
    # ``fragile`` forces mode ``safe``, whose discovery preset is ``thorough``:
    # adaptive wave 2 and the verify pass both on.
    config = apply_discovery_profile(config, active_mode="safe")
    return apply_policy(
        config,
        _policy(
            profile="fragile",
            safe_only=True,
            skip_service_probe=True,
            avoid_ports=[502, 20000],
            max_discover_rate=100,
            max_port_rate=50,
            max_host_concurrency=1,
            per_host_rate=25,
        ),
    )


def test_the_discovery_ceiling_reaches_the_passes_after_wave_one():
    """A ceiling of 100 pps that only holds for wave 1 is not a ceiling.

    Wave 2 re-probes the hosts that stayed silent — on a plant network the
    PLCs and relays this profile exists for — and the verify pass re-probes the
    alive hosts with no open ports. The shipped config gives them 2500 and 1250
    pps, and neither number went anywhere near ``discover_rate``.
    """
    from scanner.pipeline.discovery_runner import _wave2_rate

    tightened = _fragile_run_config()
    profile = tightened.profiles["safe"]
    assert profile.discover_rate == 100
    assert tightened.discovery.adaptive.enabled is True
    assert _wave2_rate(profile, tightened.discovery.adaptive.wave2_rate) == 100
    assert tightened.discovery.verify.enabled is True
    assert tightened.discovery.verify.rate == 100
    assert tightened.discovery.tcp_probe.rate == 100


def test_the_derived_rate_of_the_later_passes_has_no_floor_of_its_own():
    """With the YAML rates removed the passes derive their own, and that
    derivation used to be ``max(500, …)``: any policy under 500 pps silently
    became 500 on exactly the hosts that had not answered."""
    from scanner.pipeline.config_schema import ProfileConfig
    from scanner.pipeline.discovery_runner import _wave2_rate

    profile = ProfileConfig(
        discover_rate=100, port_rate=50, top_ports=100, nse_profile="baseline"
    )
    assert _wave2_rate(profile, None) == 100
    # A config that never had a ceiling keeps the coarse figure it always had.
    fast = ProfileConfig(discover_rate=10_000, port_rate=7000, top_ports=100, nse_profile="baseline")
    assert _wave2_rate(fast, None) == 2500


def test_nuclei_is_inside_the_policy_like_every_other_stage():
    """Nuclei is the one stage that sends HTTP payloads rather than counting
    SYN/ACKs, ~8.9k templates of them at whatever web interface the estate has.
    It used to run at its configured 150 rps and 10 at a time no matter what
    the policy said, on a scan whose whole point was that the devices are
    fragile."""
    from scanner.pipeline.config_schema import merge_nuclei_config

    tightened = _fragile_run_config()
    # ``skip_service_probe`` is "inventory the ports, do not talk to the
    # devices", and nuclei is talking to the devices.
    assert tightened.nuclei.enabled is False
    # The ceilings hold for a tenant that is only throttled, not silenced:
    # the per-profile overlay is merged over the global block at run time, so
    # both have to be lowered.
    throttled = apply_policy(
        _fragile_run_config().model_copy(
            update={"nuclei": tightened.nuclei.model_copy(update={"enabled": True})}
        ),
        _policy(per_host_rate=25, max_host_concurrency=1),
    )
    merged = merge_nuclei_config(throttled.nuclei, throttled.profiles["safe"].nuclei)
    assert merged.rate_limit == 25
    assert merged.concurrency == 1


def test_the_policy_cannot_turn_nuclei_back_on():
    config = _config().model_copy(
        update={"nuclei": _config().nuclei.model_copy(update={"enabled": False})}
    )
    assert apply_policy(config, _policy(skip_service_probe=False)).nuclei.enabled is False


# ---------------------------------------------------------------------------
# "25 pps at any single host", which is what the operator was promised
# ---------------------------------------------------------------------------


def test_a_port_batch_of_one_host_is_held_to_the_per_host_ceiling(tmp_path, monkeypatch):
    """naabu's ``-rate`` is a budget for the whole batch, so a batch of one
    device hands that device all of it: a fragile scan of one PLC was 50 pps of
    port scanning at a policy that promised 25."""
    from scanner.pipeline import ports as ports_mod

    ports_mod._reset_syn_state()
    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    monkeypatch.setattr(
        ports_mod,
        "run_command",
        lambda command, **kwargs: (captured.append(command), _Result())[1],
    )

    def _scan(hosts: list[str]) -> list[str]:
        captured.clear()
        ports_mod.fast_port_scan(
            alive_hosts=hosts,
            output_dir=tmp_path,
            rate=50,
            top_ports=100,
            top_udp_ports=100,
            timeout=60,
            retries=1,
            protocol_mode="tcp",
            custom_ports_file=tmp_path / "absent.txt",
            custom_udp_ports_file=tmp_path / "absent-udp.txt",
            udp_probes=False,
            per_host_rate=25,
        )
        return captured[0]

    try:
        one = _scan(["10.0.0.7"])
        assert one[one.index("-rate") + 1] == "25"
        # A batch of many hosts keeps the batch budget: lowering it to the
        # per-host figure would make a large scan take as many times longer as
        # it has hosts, which is not what the ceiling says.
        many = _scan(["10.0.0.7", "10.0.0.8"])
        assert many[many.index("-rate") + 1] == "50"
    finally:
        ports_mod._reset_syn_state()


def test_a_discovery_batch_of_one_host_is_held_to_the_per_host_ceiling(tmp_path, monkeypatch):
    from scanner.pipeline import probe_ladder as ladder_mod
    from scanner.pipeline.discover import host_discovery

    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    monkeypatch.setattr(
        ladder_mod,
        "run_command",
        lambda command, **kwargs: (captured.append(command), _Result())[1],
    )
    host_discovery(
        ["10.0.0.7"],
        output_dir=tmp_path,
        rate=100,
        timeout=60,
        retries=1,
        skip_discovery=False,
        discovery=_config().discovery,
        tag="one",
        per_host_rate=25,
    )
    assert captured, "naabu was never invoked"
    assert captured[0][captured[0].index("-rate") + 1] == "25"


# ---------------------------------------------------------------------------
# The avoid-list, in the stage that picks ports of its own
# ---------------------------------------------------------------------------


def _tcp_probe_config(tightened, ports: list[int]):
    """The tightened config with discovery's TCP probe on, scanning ``ports``.

    The step ships disabled and on 80/443/22, so the hole it leaves is only
    reachable on an installation that turned it on with a port list of its
    own — which is exactly the installation that has OT ports to avoid.
    """
    return tightened.model_copy(
        update={
            "discovery": tightened.discovery.model_copy(
                update={
                    "probe_order": ["tcp"],
                    "icmp": tightened.discovery.icmp.model_copy(update={"enabled": False}),
                    "tcp_probe": tightened.discovery.tcp_probe.model_copy(
                        update={"enabled": True, "ports": ports}
                    ),
                }
            )
        }
    )


def _capture_naabu(monkeypatch) -> list[list[str]]:
    from scanner.pipeline import probe_ladder as ladder_mod

    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    monkeypatch.setattr(
        ladder_mod,
        "run_command",
        lambda command, **kwargs: (captured.append(command), _Result())[1],
    )
    return captured


def test_the_avoid_list_reaches_the_discovery_tcp_probe(tmp_path, monkeypatch):
    """``ports.exclude_ports`` is documented as "ports no scan started from this
    config may touch", and the probe that decides whether a host is alive is a
    scan started from this config: it used to SYN its own port list — a field
    bus port among them, if the installation had configured one — while the
    port stage next door honoured the very same avoid-list."""
    from scanner.pipeline.discover import host_discovery

    tightened = _tcp_probe_config(_fragile_run_config(), [80, 502])
    assert 502 in tightened.ports.exclude_ports
    captured = _capture_naabu(monkeypatch)
    host_discovery(
        ["10.0.0.7"],
        output_dir=tmp_path,
        rate=100,
        timeout=60,
        retries=1,
        skip_discovery=False,
        discovery=tightened.discovery,
        tag="one",
        exclude_ports=tightened.ports.exclude_ports,
    )
    assert captured, "naabu was never invoked"
    command = captured[0]
    assert command[command.index("-p") + 1] == "80"
    assert command[command.index("-exclude-ports") + 1] == "502,20000"


def test_a_tcp_probe_of_nothing_but_avoided_ports_sends_no_packets(tmp_path, monkeypatch):
    """The ladder falls through to the next step instead of running naabu with
    a port list the exclusions have emptied."""
    from scanner.pipeline.discover import host_discovery

    tightened = _tcp_probe_config(_fragile_run_config(), [502, 20000])
    captured = _capture_naabu(monkeypatch)
    alive = host_discovery(
        ["10.0.0.7"],
        output_dir=tmp_path,
        rate=100,
        timeout=60,
        retries=1,
        skip_discovery=False,
        discovery=tightened.discovery,
        tag="one",
        exclude_ports=tightened.ports.exclude_ports,
    )
    assert captured == []
    assert alive == []


def test_the_verify_pass_carries_the_avoid_list_too(tmp_path, monkeypatch):
    """Wiring, not intent: the probe reads the avoid-list from what its caller
    hands it, so a caller that passed nothing would leave it as it was. The
    verify pass is the one that re-probes the hosts that answered nothing,
    which on an OT estate are the devices the list exists for."""
    from scanner.pipeline.discovery_runner import verify_alive_without_ports

    tightened = _tcp_probe_config(_fragile_run_config(), [80, 502])
    captured = _capture_naabu(monkeypatch)
    verify_alive_without_ports(
        alive_hosts=["10.0.0.7"],
        open_ports=[],
        config=tightened,
        profile=tightened.profiles["safe"],
        output_dir=tmp_path,
        timeout=60,
        retries=1,
    )
    assert captured, "naabu was never invoked"
    command = captured[0]
    assert command[command.index("-p") + 1] == "80"
    assert command[command.index("-exclude-ports") + 1] == "502,20000"


# ---------------------------------------------------------------------------
# The other fields that can hold a 0
# ---------------------------------------------------------------------------


def test_pulse_host_parallel_zero_stays_one_host_at_a_time():
    """The other place a 0 lives, and the one that must *not* be read as
    "unlimited": ``host_parallel: 0`` reaches pulse as ``--host-first``, which
    is one host at a time — already stricter than any ceiling. Reading it as
    unlimited would raise it to the policy's figure, which is this file
    loosening a config."""
    from scanner.pipeline.config_schema import merge_pulse_config
    from scanner.pipeline.pulse_probe import build_pulse_command

    config = _config()
    safe = config.profiles["safe"]
    config = config.model_copy(
        update={
            "profiles": {
                **config.profiles,
                "safe": safe.model_copy(
                    update={"pulse": safe.pulse.model_copy(update={"host_parallel": 0})}
                ),
            }
        }
    )
    tightened = apply_policy(config, _policy(max_host_concurrency=4))
    pulse_cfg = merge_pulse_config(
        tightened.service_probe.pulse, tightened.profiles["safe"].pulse
    )
    assert pulse_cfg.host_parallel == 0
    command = build_pulse_command(
        bin_path="pulse",
        hosts_file=Path("hosts.txt"),
        ports=[80],
        concurrency=pulse_cfg.concurrency,
        rate=pulse_cfg.rate,
        adaptive=pulse_cfg.adaptive,
        host_parallel=pulse_cfg.host_parallel,
        timeout_ms=pulse_cfg.timeout_ms,
        banner=pulse_cfg.banner,
        os_detect=False,
        os_mode=pulse_cfg.os_mode,
        cve=False,
        cve_online=False,
        syn=False,
        checkpoint=None,
        max_hosts=pulse_cfg.max_hosts,
    )
    assert "--host-parallel" not in command
    assert "--host-first" in command


# ---------------------------------------------------------------------------
# The pace the tool is actually handed, and the two ladder steps the first
# round of this work left out (review of #397)
# ---------------------------------------------------------------------------


def _capture_probes(monkeypatch) -> list[list[str]]:
    """Every command the probe ladder runs — naabu *and* fping.

    The assertions below are on the argv the tool receives, not on the config
    object: the whole defect class this file is about is a ceiling that is
    correct in the config and lost on its way to the command line.
    """
    from scanner.pipeline import icmp_discover as icmp_mod
    from scanner.pipeline import probe_ladder as ladder_mod

    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    def _record(command, **kwargs):  # noqa: ANN001, ANN003
        captured.append(list(command))
        return _Result()

    monkeypatch.setattr(ladder_mod, "run_command", _record)
    monkeypatch.setattr(icmp_mod, "run_command", _record)
    return captured


def _naabu_calls(captured: list[list[str]]) -> list[list[str]]:
    return [command for command in captured if command and command[0] == "naabu"]


def _flag(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def test_the_tcp_probe_of_one_host_is_held_to_the_per_host_ceiling(tmp_path, monkeypatch):
    """The ceiling the policy put on ``discovery.tcp_probe.rate`` is a *batch*
    ceiling like every other one here, and the per-host correction is applied
    to the batch rate before the ladder ever sees it. Reading the field as "a
    rate that replaces the batch rate" threw that correction away and sent a
    fragile tenant's one PLC 100 pps under a policy promising 25."""
    from scanner.pipeline.discover import host_discovery

    tightened = _tcp_probe_config(_fragile_run_config(), [80])
    assert tightened.discovery.tcp_probe.rate == 100
    captured = _capture_probes(monkeypatch)
    host_discovery(
        ["10.0.0.7"],
        output_dir=tmp_path,
        rate=tightened.profiles["safe"].discover_rate,
        timeout=60,
        retries=1,
        skip_discovery=False,
        discovery=tightened.discovery,
        tag="one",
        per_host_rate=tightened.runtime.per_host_rate,
        exclude_ports=tightened.ports.exclude_ports,
    )
    command = _naabu_calls(captured)[0]
    assert _flag(command, "-rate") == "25"


def test_the_last_ladder_step_never_pings_an_avoided_port(tmp_path, monkeypatch):
    """``naabu -sn`` with no probe flags pings TCP 80 and 443 (SYN and ACK) on
    top of ICMP — ``configureHostDiscovery`` in naabu v2.6.1, the version the
    image pins. It is the step a default ladder ends on, so a tenant who put
    the HMI's web port on the avoid-list was getting a SYN to it from the very
    stage that decides who is alive."""
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    captured = _capture_probes(monkeypatch)
    naabu_host_discovery(
        ["10.0.0.7"],
        tmp_path,
        rate=25,
        timeout=60,
        retries=1,
        tag="one",
        scope_members=["10.0.0.7"],
        exclude_ports=[80, 502],
    )
    command = _naabu_calls(captured)[0]
    assert "-pe" in command and "-pp" in command
    assert _flag(command, "-ps") == "443"
    assert _flag(command, "-pa") == "443"


def test_the_last_ladder_step_keeps_both_probe_ports_when_neither_is_avoided(
    tmp_path, monkeypatch
):
    """The fix narrows the probe set, it does not replace naabu's defaults with
    something weaker: an avoid-list that touches neither port leaves both."""
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    captured = _capture_probes(monkeypatch)
    naabu_host_discovery(
        ["10.0.0.7"],
        tmp_path,
        rate=25,
        timeout=60,
        retries=1,
        tag="one",
        scope_members=["10.0.0.7"],
        exclude_ports=[502, 20000],
    )
    command = _naabu_calls(captured)[0]
    assert _flag(command, "-ps") == "80,443"
    assert _flag(command, "-pa") == "80,443"


def test_the_ladder_hands_the_last_step_the_avoid_list(tmp_path, monkeypatch):
    """Wiring, not intent — the half of the previous round's lesson that still
    applied: the step reads the list from what the ladder hands it, and a
    ladder that passed nothing would leave it probing 80."""
    from scanner.pipeline.discover import host_discovery

    tightened = _fragile_run_config()
    tightened = tightened.model_copy(
        update={
            "discovery": tightened.discovery.model_copy(update={"probe_order": ["naabu"]}),
            "ports": tightened.ports.model_copy(
                update={"exclude_ports": sorted({*tightened.ports.exclude_ports, 80})}
            ),
        }
    )
    captured = _capture_probes(monkeypatch)
    host_discovery(
        ["10.0.0.7"],
        output_dir=tmp_path,
        rate=tightened.profiles["safe"].discover_rate,
        timeout=60,
        retries=1,
        skip_discovery=False,
        discovery=tightened.discovery,
        tag="one",
        per_host_rate=tightened.runtime.per_host_rate,
        exclude_ports=tightened.ports.exclude_ports,
    )
    command = _naabu_calls(captured)[0]
    assert "-sn" in command
    assert _flag(command, "-ps") == "443"


def test_the_icmp_step_uses_the_fping_flag_that_paces_it(tmp_path, monkeypatch):
    """``-p`` is the interval between packets *to one target*, and fping applies
    it only in loop and count modes, neither of which this command asks for:
    measured on fping 5.x, ``-p 200`` over 20 addresses took the same 1.51s as
    no flag at all, while ``-i 200`` took 6.82s. The knob was a no-op and the
    step ran at fping's default 10ms — 100 pps, whatever the policy said."""
    from scanner.pipeline.icmp_discover import icmp_ping_filter

    tightened = _fragile_run_config()
    assert tightened.discovery.icmp.enabled is True
    captured = _capture_probes(monkeypatch)
    icmp_ping_filter(["10.0.0.7"], tmp_path, tightened.discovery.icmp, timeout=60, retries=1, tag="one")
    command = captured[0]
    assert "-p" not in command
    # 100 pps is the ceiling, so 10ms between packets is the fastest allowed.
    assert _flag(command, "-i") == "10"


def test_the_icmp_step_is_paced_by_the_discovery_ceiling(tmp_path, monkeypatch):
    """The ladder's first step is a discovery probe like the other two, and it
    was the one pass no ``max_discover_rate`` reached."""
    from scanner.pipeline.discovery_profiles import apply_discovery_profile
    from scanner.pipeline.icmp_discover import icmp_ping_filter

    config = apply_discovery_profile(_config(), active_mode="safe")
    tightened = apply_policy(config, _policy(max_discover_rate=20))
    captured = _capture_probes(monkeypatch)
    icmp_ping_filter(["10.0.0.7"], tmp_path, tightened.discovery.icmp, timeout=60, retries=1, tag="one")
    assert _flag(captured[0], "-i") == "50"


def _run_wave_one(tmp_path, monkeypatch, config, targets: list[str]):
    from scanner.pipeline.checkpoint import CheckpointStore
    from scanner.pipeline.discovery_runner import run_discovery_stage

    captured = _capture_probes(monkeypatch)
    run_discovery_stage(
        all_targets=targets,
        config=config,
        profile=config.profiles["safe"],
        output_dir=tmp_path,
        alive_file=tmp_path / "alive.txt",
        timeout=60,
        retries=1,
        checkpoint=CheckpointStore(tmp_path / "checkpoint.json"),
        resume=False,
    )
    return captured


def test_wave_one_carries_the_avoid_list(tmp_path, monkeypatch):
    """The pass every scan runs, and the one the first round of this work left
    untested: verify and delta-refresh are optional, wave 1 is not."""
    tightened = _tcp_probe_config(_fragile_run_config(), [80, 502])
    captured = _run_wave_one(tmp_path, monkeypatch, tightened, ["10.0.0.7"])
    command = _naabu_calls(captured)[0]
    assert _flag(command, "-p") == "80"
    assert _flag(command, "-exclude-ports") == "502,20000"


def test_the_delta_refresh_pass_carries_the_avoid_list(tmp_path, monkeypatch):
    """The third caller. It re-probes the hosts a previous run found alive —
    on an OT estate, the controllers — and it picks its own rate, so it is the
    one most easily forgotten."""
    tightened = _tcp_probe_config(_fragile_run_config(), [80, 502])
    tightened = tightened.model_copy(
        update={
            "discovery": tightened.discovery.model_copy(
                update={"delta": tightened.discovery.delta.model_copy(update={"enabled": True})}
            )
        }
    )
    from scanner.pipeline.checkpoint import CheckpointStore
    from scanner.pipeline.discovery_runner import run_discovery_stage

    captured = _capture_probes(monkeypatch)
    run_discovery_stage(
        all_targets=["10.0.0.7"],
        config=tightened,
        profile=tightened.profiles["safe"],
        output_dir=tmp_path,
        alive_file=tmp_path / "alive.txt",
        timeout=60,
        retries=1,
        checkpoint=CheckpointStore(tmp_path / "checkpoint.json"),
        resume=False,
        previous_alive={"10.0.0.7"},
    )
    refresh = [c for c in _naabu_calls(captured) if "delta-refresh" in " ".join(c)]
    assert refresh, "the delta refresh pass never probed"
    assert _flag(refresh[0], "-exclude-ports") == "502,20000"


def test_a_fragile_scan_of_a_range_walks_one_host_at_a_time(tmp_path, monkeypatch):
    """What ``max_host_concurrency: 1`` is documented to mean. Lowering the
    worker counts alone left the *batch* at 4096 targets, so a ``/24`` reached
    naabu as one invocation of 254 hosts at the batch rate — with the per-host
    ceiling not applied at all, because it only applies to a batch of one."""
    from scanner.pipeline.utils import read_lines

    tightened = _tcp_probe_config(_fragile_run_config(), [80])
    assert tightened.batching.max_targets_per_batch == 1
    assert tightened.batching.ipv4_prefix == 32
    captured = _run_wave_one(tmp_path, monkeypatch, tightened, ["10.10.0.0/24"])
    calls = _naabu_calls(captured)
    probed: set[str] = set()
    for command in calls:
        members = read_lines(Path(_flag(command, "-list")))
        assert len(members) == 1, f"{len(members)} hosts in one naabu invocation"
        assert _flag(command, "-rate") == "25"
        probed.update(members)
    assert len(probed) == 256, "a /24 is 256 addresses, and each one got its own invocation"


def test_a_ceiling_without_a_per_host_rate_leaves_the_batch_size_alone(tmp_path):
    """The batch budget is spent across the batch, so shrinking a batch without
    a per-host figure to hold it to would *raise* what one host receives — this
    file's one forbidden direction. 4096 hosts at 2500 pps is 0.6 pps each; one
    host at 2500 pps is 2500."""
    tightened = apply_policy(_config(), _policy(max_host_concurrency=1))
    assert tightened.batching.max_targets_per_batch == _config().batching.max_targets_per_batch
    assert tightened.batching.ipv4_prefix == _config().batching.ipv4_prefix
