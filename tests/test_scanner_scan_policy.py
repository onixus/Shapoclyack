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
