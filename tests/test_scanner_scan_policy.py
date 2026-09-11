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
    # 100 pps is the ceiling and 100 pps is what fping does unasked, so the
    # fragile policy leaves the field unset rather than restating the default.
    assert tightened.discovery.icmp.period_ms is None
    paced = tightened.discovery.icmp.model_copy(update={"period_ms": 200})
    captured = _capture_probes(monkeypatch)
    icmp_ping_filter(["10.0.0.7"], tmp_path, paced, timeout=60, retries=1, tag="one")
    command = captured[0]
    assert "-p" not in command
    assert _flag(command, "-i") == "200"


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


def test_a_ceiling_no_stricter_than_the_config_leaves_the_icmp_command_alone(
    tmp_path, monkeypatch
):
    """The first policy an operator writes is "no faster than what is already
    configured", and it has to change nothing.

    ``max_discover_rate: 2000`` is exactly ``profiles.safe.discover_rate`` in
    the shipped config. Reading an unset ``period_ms`` as 0 made the ceiling
    compute ``-i 1`` for it, and fping 5.1 over 254 addresses takes 1.58s with
    ``-i 1`` against 5.86s with no flag at all: the one knob in this file that
    ran *faster* under a ceiling — 100 pps to 1000 — because the tool's own
    default is part of the config whether or not the YAML spells it out.
    """
    from scanner.pipeline.discovery_profiles import apply_discovery_profile
    from scanner.pipeline.icmp_discover import icmp_ping_filter
    from scanner.pipeline.utils import load_yaml

    shipped = load_config(load_yaml(Path("scanner/config/default.yaml")))
    assert shipped.profiles["safe"].discover_rate == 2000, "the figure the operator copies"
    config = apply_discovery_profile(shipped, active_mode="safe")
    assert config.discovery.icmp.period_ms is None, "the shipped config sets no pace"

    captured = _capture_probes(monkeypatch)
    icmp_ping_filter(["10.0.0.7"], tmp_path, config.discovery.icmp, timeout=60, retries=1, tag="one")
    tightened = apply_policy(config, _policy(max_discover_rate=2000))
    icmp_ping_filter(
        ["10.0.0.7"], tmp_path, tightened.discovery.icmp, timeout=60, retries=1, tag="one"
    )

    before, after = captured
    assert after == before, "a ceiling at the configured rate rewrote the fping command"


def test_a_pace_fping_refuses_cannot_be_configured():
    """``-i 0`` is not "fping's own default": fping 5.1 answers "these options
    are too risky for mere mortals ... You need -i >= 1" and exits 1, and the
    step reads that empty stdout as nobody being alive. The smallest gap the
    tool accepts is the smallest one the schema accepts."""
    from pydantic import ValidationError

    from scanner.pipeline.config_schema import IcmpDiscoveryConfig

    assert IcmpDiscoveryConfig(period_ms=1).period_ms == 1
    with pytest.raises(ValidationError):
        IcmpDiscoveryConfig(period_ms=0)


def test_a_policy_does_not_resize_batches():
    """A ceiling picks the pace, not the shape of the work.

    Narrowing batches to one address per batch is how "one host at a time"
    would become literally true, and it costs more than it buys: a ``/8`` in
    scope expands to 16.7M batches (~12 GB in ``expand_batches`` alone), the
    checkpoint rewrites its whole JSON after every batch, and each batch leaves
    its own artefact files behind — a ``/22`` produced 12276 of them. The
    promise is documented for what it is instead (``docs/operations.md``): the
    worker counts are batches in flight, and the per-host ceiling lands when a
    batch happens to be one host."""
    baseline = _config().batching
    tightened = apply_policy(
        _config(), _policy(max_host_concurrency=1, per_host_rate=25, max_discover_rate=100)
    )
    assert tightened.batching.max_targets_per_batch == baseline.max_targets_per_batch
    assert tightened.batching.ipv4_prefix == baseline.ipv4_prefix


def test_a_fragile_scan_of_a_range_spares_the_network_and_broadcast_addresses(
    tmp_path, monkeypatch
):
    """A batch is a subnet, and a subnet's own address and its directed
    broadcast are not hosts.

    Splitting a ``/24`` into 256 batches of ``x.x.x.y/32`` lost that:
    ``ip_network(...).hosts()`` on a ``/32`` returns the address itself, so
    ``x.x.x.0`` and ``x.x.x.255`` picked up an ICMP echo and a SYN — the
    directed broadcast being exactly the packet an old stack answers in a
    pile."""
    from scanner.pipeline.utils import read_lines

    tightened = _tcp_probe_config(_fragile_run_config(), [80])
    captured = _run_wave_one(tmp_path, monkeypatch, tightened, ["10.10.0.0/24"])
    probed: set[str] = set()
    for command in _naabu_calls(captured):
        probed.update(read_lines(Path(_flag(command, "-list"))))
    assert len(probed) == 254, "a /24 is 254 hosts between its network and broadcast address"
    assert "10.10.0.0" not in probed
    assert "10.10.0.255" not in probed


def test_an_ipv6_range_reaches_naabu_the_way_the_document_says_it_does(tmp_path, monkeypatch):
    """Batching splits IPv4 networks by prefix and leaves everything else as
    one entry (``batching.expand_batches``), so an IPv6 range is one batch and
    one naabu invocation at the batch rate — with the per-host ceiling not
    applied, because that ceiling only lands on a batch of one host.

    This pins the shape the documentation now describes. It is also why
    ``docs/operations.md`` no longer promises a walk device by device: half a
    promise, kept for IPv4 and not for IPv6, reads as a ceiling and is not
    one."""
    from scanner.pipeline.utils import read_lines

    tightened = _tcp_probe_config(_fragile_run_config(), [80])
    captured = _run_wave_one(tmp_path, monkeypatch, tightened, ["2001:db8::/120"])
    calls = _naabu_calls(captured)
    assert calls, "the IPv6 range was never probed"
    for command in calls:
        assert len(read_lines(Path(_flag(command, "-list")))) == 255, "one batch, whole range"
        assert _flag(command, "-rate") == "100", "the batch rate, not the per-host rate"
