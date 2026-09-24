"""Apply the tenant scan policy the API pushed onto this run (#362).

The pace a scan runs at used to be decided entirely by the config file on the
host executing it — ``scanner/config/default.yaml``, or whatever an agent's
operator had edited it to. The platform sent ``--mode`` and hoped. This module
is the other half: the API writes the tenant's policy next to the run's target
files (``scan_policy.json``) and the pipeline is handed it as
``--scan-policy``, exactly like the approved scope of #244.

**Every knob here can only ever go down.** The policy is a set of ceilings, not
a set of values: a rate is applied as ``min(config, policy)``, the avoid-list
is unioned with whatever the config already excludes, and ``skip_service_probe``
can turn the service-probe stage off but never on. That is what makes the local
file the fallback it is documented to be — an installation that has hardened
its own config keeps the hardening, and the policy only ever tightens it.

An unknown ``policy_version`` is a hard error rather than a best-effort
application: a ceiling half-understood is a ceiling that reads as enforced and
is not, and the scan that would have run under it is on somebody's plant
network.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .config_schema import AppConfig

#: The shape this build understands. Mirrors
#: ``api.services.scan_policy.POLICY_VERSION``; the two move together and a
#: mismatch stops the run (see :func:`load_policy`).
SUPPORTED_POLICY_VERSION = 1


class ScanPolicyError(ValueError):
    """The policy file is missing, malformed, or of a version this build cannot apply."""


#: Secondary stages that open fresh network connections after discovery.
#:
#: The value is ``(concurrency_field, active_work_field)``. A host-concurrency
#: ceiling lowers the first field. ``skip_service_probe`` sets the second one
#: to false. For fingerprint/screenshots that disables the whole stage; for
#: TLS posture it disables only the direct-handshake fallback and preserves
#: passive parsing of NSE/Pulse evidence already collected by another stage.
#:
#: Pipeline call sites go through :func:`require_secondary_active_stage_policy`,
#: which stops the run on a name missing here. That runtime guard only sees the
#: names handed to it, though: what makes a new stage impossible to add without
#: a decision is that every stage in ``scanner/main.py`` must appear either here
#: or in :data:`NON_SECONDARY_ACTIVE_STAGES`, and a regression test enforces it.
SECONDARY_ACTIVE_STAGE_POLICIES: dict[str, tuple[str, str]] = {
    "tls_posture": ("probe_concurrency", "probe_fallback"),
    "fingerprint": ("concurrency", "enabled"),
    "screenshots": ("concurrency", "enabled"),
}

#: Every other pipeline stage, with the reason it is not a secondary active
#: stage. A stage name in ``scanner/main.py`` that is in neither registry fails
#: ``tests/test_scanner_scan_policy.py``: the author has to say which kind of
#: stage it is before it can ship.
#:
#: The reasons are claims about what the stage puts on the wire, checked
#: against its module. "Not secondary active" is not "sends nothing to the
#: target's infrastructure" — ``dns_hygiene`` and ``mail_posture`` below each
#: have one such request, bounded by count rather than by the tenant policy.
NON_SECONDARY_ACTIVE_STAGES: dict[str, str] = {
    # Primary stages: each is held by policy fields of its own in apply_policy.
    "discover": "primary: discover_rate, wave2/verify/tcp_probe rates, icmp period, discover_concurrency",
    "discover-l2": (
        "primary, opt-in: nmap ARP --max-rate held to max_discover_rate; "
        "mDNS/NetBIOS name probes off with skip_service_probe"
    ),
    "ports": "primary: port_rate, per_host_rate, ports_concurrency, avoid_ports",
    "verify_alive": "primary: discovery.verify.rate held to max_discover_rate",
    "pulse": "primary: pulse rate/concurrency/host_parallel; off with skip_service_probe",
    "nse": "primary: nse_max_rate, nse_concurrency; off with skip_service_probe",
    "nuclei": "primary: rate_limit, concurrency; off with skip_service_probe",
    # Third-party sources and DNS: no connection to an address in scope.
    "cloudflare": "Cloudflare API zone export",
    "ct": "CT log APIs (crt.sh, certspotter, OTX) and DNS lookups through resolvers",
    "asn": "DNS lookups and a public BGP/ASN API",
    "ownership": "RDAP servers through safe_http",
    "cloud": "HTTP to cloud storage provider endpoints, not to in-scope addresses",
    "resolve": "dnsx lookups through resolvers",
    "discover-hostnames": "dnsx PTR lookups through resolvers",
    "domain_monitor": "DNS lookups only; never contacts the flagged service",
    "dns_hygiene": (
        "DNS queries through resolvers; the opt-in axfr_probe makes one TCP/53 "
        "transfer per public nameserver, gated by the scanner config (docs/operations.md)"
    ),
    "mail_posture": (
        "DNS TXT/MX lookups plus one HTTPS GET of mta-sts.<domain> per seed domain "
        "through safe_http (public addresses only, no redirects)"
    ),
    "related_domains": "crt.sh organisation search",
    "credential_leaks": "breach-database provider API",
    # Artifact-only: read what earlier stages wrote, open no connection.
    "pulse_shadow": "diff of pulse and nmap artifacts",
    "report": "report build from stage artifacts and local enrichment databases",
    "controls": "controls matrix from stage artifacts",
}


def require_secondary_active_stage_policy(stage: str) -> None:
    """Fail closed when a network-active secondary stage has no policy contract."""
    if stage in SECONDARY_ACTIVE_STAGE_POLICIES:
        return
    known = ", ".join(sorted(SECONDARY_ACTIVE_STAGE_POLICIES))
    raise ScanPolicyError(
        f"network-active secondary stage {stage!r} has no scan-policy contract; "
        f"register its concurrency and disable fields (known: {known})"
    )


def load_policy(path: Path) -> dict[str, Any]:
    """Read and sanity-check one policy document written by the API."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScanPolicyError(f"could not read scan policy {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ScanPolicyError(f"scan policy {path} is not an object")
    version = raw.get("policy_version")
    if version != SUPPORTED_POLICY_VERSION:
        raise ScanPolicyError(
            f"scan policy {path} is version {version!r}, and this scanner applies "
            f"version {SUPPORTED_POLICY_VERSION}: upgrade the scanner rather than "
            "running the scan without the policy"
        )
    return raw


def _ceiling(current: int | None, limit: int | None, *, zero_is_unlimited: bool = False) -> int | None:
    """``min`` over two ceilings, where None — and sometimes 0 — mean "no limit".

    ``zero_is_unlimited`` is for the config fields that spell "unlimited" as 0
    (``runtime.nse_max_rate``, ``pulse.rate``). Without it a policy of 50 pps
    would compute ``min(0, 50) == 0`` and read as *unlimited*, which is the one
    mistake in this file that would be silent and catastrophic.
    """
    if limit is None:
        return current
    if current is None:
        return limit
    if zero_is_unlimited and current == 0:
        return limit
    return min(current, limit)


def _secondary_active_stage_updates(
    config: AppConfig,
    *,
    max_concurrency: int | None,
    skip_service_probe: bool,
) -> dict[str, Any]:
    """Tighten every registered secondary stage that can open a connection.

    The registry is deliberately data rather than three nearby assignments:
    the pipeline guard and the tests consume the same list, so a fourth active
    stage needs an explicit policy decision before it is allowed to run.
    """
    updates: dict[str, Any] = {}
    for stage, (concurrency_field, active_work_field) in SECONDARY_ACTIVE_STAGE_POLICIES.items():
        require_secondary_active_stage_policy(stage)
        stage_config = getattr(config, stage, None)
        if stage_config is None:
            raise ScanPolicyError(
                f"scan-policy contract names missing AppConfig field {stage!r}"
            )
        for field in (concurrency_field, active_work_field):
            if not hasattr(stage_config, field):
                raise ScanPolicyError(
                    f"scan-policy contract for {stage!r} names missing field {field!r}"
                )

        stage_updates: dict[str, Any] = {}
        if max_concurrency is not None:
            stage_updates[concurrency_field] = _ceiling(
                getattr(stage_config, concurrency_field), max_concurrency
            )
        if skip_service_probe:
            stage_updates[active_work_field] = False
        if stage_updates:
            updates[stage] = stage_config.model_copy(update=stage_updates)
    return updates


def _nuclei_ceilings(
    rate_limit: int | None,
    concurrency: int | None,
    per_host_rate: int | None,
    max_concurrency: int | None,
) -> dict[str, Any]:
    """The nuclei knobs a policy lowers, for the global block or a profile's.

    ``rate_limit`` is nuclei's requests per second and it is not divided
    between targets, so ``per_host_rate`` — "packets aimed at any single host"
    — is the ceiling it belongs under; ``concurrency`` is how many endpoints it
    works on at once, which is what ``max_host_concurrency`` means everywhere
    else in this file.
    """
    updates: dict[str, Any] = {}
    if per_host_rate is not None:
        updates["rate_limit"] = _ceiling(rate_limit, per_host_rate)
    if max_concurrency is not None:
        updates["concurrency"] = _ceiling(concurrency, max_concurrency)
    return updates


def single_host_rate(rate: int, host_count: int, per_host_rate: int | None) -> int:
    """The naabu rate for one batch, held to the per-host ceiling when it can be.

    ``-rate`` is a budget naabu spends across everything in the batch, so for a
    batch of 1024 hosts it says little about what any one of them receives —
    but for a batch of *one* host the two numbers are the same. Without this, a
    policy promising "25 pps at any single host" put 100 pps of discovery and
    50 pps of port scanning into that one PLC.

    It is the batch shape that decides whether this applies, and the policy
    does not change that shape: batching is the config's (a ``/24`` per batch
    and up to 1024 addresses, as shipped), so this lands on the targets
    that arrive as single addresses and not on a range. Batches of several
    hosts keep the batch budget — lowering the whole batch to the per-host
    figure would make a large scan take as many times longer as it has hosts,
    which is not what the ceiling says. ``docs/operations.md`` says the same
    thing to the operator rather than promising a walk device by device.
    """
    if per_host_rate is None or host_count != 1:
        return rate
    return min(rate, per_host_rate)


#: The gap fping leaves between packets when ``-i`` is not given: 10ms, 100 pps.
#: It is a configured value like any other — the config just spells it by saying
#: nothing — so a ceiling has to be measured against it (:func:`_icmp_period_ms`).
FPING_DEFAULT_PERIOD_MS = 10


def _icmp_period_ms(current: int | None, max_discover_rate: int) -> int | None:
    """The gap between fping packets that holds the ICMP step to a pps ceiling.

    fping has no rate flag: ``-i`` is the interval between the packets it
    sends, so ``max_discover_rate`` pps is ``1000 // rate`` milliseconds,
    rounded up so the ceiling is never exceeded.

    An unset ``period_ms`` is not "no pace", and reading it as 0 made this the
    one knob in this file that a ceiling could *raise*: a policy of 2000 pps —
    the figure already in ``profiles.safe`` — computed a 1ms gap and took the
    step from fping's 100 pps to 1000 (measured on fping 5.1, 254 addresses:
    5.86s with no flag, 5.71s with ``-i 10``, 1.58s with ``-i 1``). So a
    ceiling looser than the tool's own default leaves the field unset and the
    command is the one the step ran before any policy existed.
    """
    floor = -(-1000 // max(1, max_discover_rate))
    if current is None:
        return floor if floor > FPING_DEFAULT_PERIOD_MS else None
    return max(current, floor)


def apply_policy(config: AppConfig, policy: dict[str, Any]) -> AppConfig:
    """Return ``config`` tightened by ``policy``. Never loosens anything."""
    max_discover = policy.get("max_discover_rate")
    max_port = policy.get("max_port_rate")
    max_concurrency = policy.get("max_host_concurrency")
    per_host_rate = policy.get("per_host_rate")
    avoid_ports = sorted({int(p) for p in (policy.get("avoid_ports") or [])})

    profiles = {}
    for name, profile in config.profiles.items():
        updates: dict[str, Any] = {}
        if max_discover is not None:
            updates["discover_rate"] = _ceiling(profile.discover_rate, max_discover)
        if max_port is not None:
            updates["port_rate"] = _ceiling(profile.port_rate, max_port)
        if max_concurrency is not None:
            updates["nse_concurrency"] = _ceiling(profile.nse_concurrency, max_concurrency)
        if per_host_rate is not None:
            # The NSE budget is shared by every parallel nmap, so holding the
            # whole stage to the per-host ceiling is stricter than the policy
            # asks for and never looser — which is the direction this file is
            # allowed to be wrong in.
            updates["nse_max_rate"] = _ceiling(
                profile.nse_max_rate, per_host_rate, zero_is_unlimited=True
            )
        pulse_updates: dict[str, Any] = {}
        if per_host_rate is not None:
            pulse_updates["rate"] = _ceiling(
                profile.pulse.rate, per_host_rate, zero_is_unlimited=True
            )
        if max_concurrency is not None:
            # ``host_parallel`` is the third field in this file that can hold a
            # 0, and it is the one that must *not* get ``zero_is_unlimited``:
            # the adapter spells 0 as ``--host-first`` rather than as a missing
            # flag (``pulse_probe.build_pulse_command``), and pulse reads
            # ``--host-first`` without ``--host-parallel`` as one host at a
            # time. So 0 already is the strictest setting, and reading it as
            # "unlimited" would raise it to the policy's figure — a ceiling
            # loosening a config, which is the one thing this file may not do.
            pulse_updates["host_parallel"] = _ceiling(profile.pulse.host_parallel, max_concurrency)
            pulse_updates["concurrency"] = _ceiling(profile.pulse.concurrency, max_concurrency)
        if pulse_updates:
            updates["pulse"] = profile.pulse.model_copy(update=pulse_updates)
        # The per-profile nuclei overlay is merged over the global block at run
        # time (``merge_nuclei_config``), so a ceiling applied only to the
        # global one would be lifted by whichever profile happened to run.
        profile_nuclei = _nuclei_ceilings(
            profile.nuclei.rate_limit, profile.nuclei.concurrency, per_host_rate, max_concurrency
        )
        if profile_nuclei:
            updates["nuclei"] = profile.nuclei.model_copy(update=profile_nuclei)
        profiles[name] = profile.model_copy(update=updates) if updates else profile

    runtime_updates: dict[str, Any] = {}
    if per_host_rate is not None:
        # Read back by the discovery and port stages, which lower naabu's own
        # ``-rate`` for a batch that is a single host: the batch budget and the
        # per-host budget are the same number when the batch is one device, and
        # a fragile estate is scanned one device at a time.
        runtime_updates["per_host_rate"] = _ceiling(config.runtime.per_host_rate, per_host_rate)
    if max_concurrency is not None:
        runtime_updates["discover_concurrency"] = _ceiling(
            config.runtime.discover_concurrency, max_concurrency
        )
        runtime_updates["ports_concurrency"] = _ceiling(
            config.runtime.ports_concurrency, max_concurrency
        )
        runtime_updates["nse_concurrency"] = _ceiling(
            config.runtime.nse_concurrency, max_concurrency
        )
    if per_host_rate is not None:
        runtime_updates["nse_max_rate"] = _ceiling(
            config.runtime.nse_max_rate, per_host_rate, zero_is_unlimited=True
        )
    if policy.get("skip_service_probe"):
        # One direction only: a policy can turn the stage that sends
        # protocol-specific payloads off, and nothing here turns it back on.
        runtime_updates["skip_nse"] = True

    discovery_updates: dict[str, Any] = {}
    l2_updates: dict[str, Any] = {}
    if max_discover is not None:
        # nmap's ARP sweep is a discovery stage too. --max-rate is the only
        # portable ceiling it exposes, so the tenant ceiling lowers that
        # explicit command-line value just like it lowers naabu/fping.
        l2_updates["max_rate"] = _ceiling(config.discovery.l2.max_rate, max_discover)
        # Discovery is three passes, not one. Wave 2 re-probes the hosts that
        # stayed silent in wave 1 — on an OT estate exactly the PLCs and relays
        # the ceiling exists for — and the verify pass re-probes the alive
        # hosts that showed no open ports. Both read a rate of their own, so a
        # ceiling put only on ``discover_rate`` was 100 pps for one pass and
        # whatever the YAML said (2500 and 1250 in the shipped config) for the
        # other two.
        discovery_updates["adaptive"] = config.discovery.adaptive.model_copy(
            update={"wave2_rate": _ceiling(config.discovery.adaptive.wave2_rate, max_discover)}
        )
        discovery_updates["verify"] = config.discovery.verify.model_copy(
            update={"rate": _ceiling(config.discovery.verify.rate, max_discover)}
        )
        discovery_updates["tcp_probe"] = config.discovery.tcp_probe.model_copy(
            update={"rate": _ceiling(config.discovery.tcp_probe.rate, max_discover)}
        )
        # The ladder's first step is a discovery probe too, and it was the one
        # pass no rate ceiling reached: fping paces itself by the gap between
        # packets, so the ceiling has to be inverted into milliseconds. A
        # config that already waits longer keeps its own figure, and so does a
        # config that said nothing and gets fping's 10ms — ``max`` over an
        # interval is the same direction as ``min`` over a rate only as long as
        # the tool's default is counted as the configured value it is.
        discovery_updates["icmp"] = config.discovery.icmp.model_copy(
            update={"period_ms": _icmp_period_ms(config.discovery.icmp.period_ms, max_discover)}
        )
    if policy.get("skip_service_probe"):
        # ARP remains host discovery. mDNS and NetBIOS are protocol-specific
        # UDP requests and therefore follow the same "ports only" decision as
        # pulse/NSE/nuclei; a fragile policy can turn them off, never on.
        l2_updates["mdns"] = False
        l2_updates["netbios"] = False
    if l2_updates:
        discovery_updates["l2"] = config.discovery.l2.model_copy(update=l2_updates)

    nuclei_updates = _nuclei_ceilings(
        config.nuclei.rate_limit, config.nuclei.concurrency, per_host_rate, max_concurrency
    )
    skip_service_probe = bool(policy.get("skip_service_probe"))
    if skip_service_probe:
        # Nuclei is the other stage that sends payloads rather than counting
        # SYN/ACKs: ~8.9k templates of HTTP requests aimed at an engineering
        # station's web interface. ``skip_service_probe`` is the policy saying
        # "inventory the ports, do not talk to the devices", and a run that
        # honoured it for pulse and NSE while nuclei kept going would honour it
        # in name only. One direction, like ``skip_nse``: never turned back on.
        nuclei_updates["enabled"] = False

    secondary_updates = _secondary_active_stage_updates(
        config,
        max_concurrency=max_concurrency,
        skip_service_probe=skip_service_probe,
    )

    # Batching is deliberately not among the knobs above. Narrowing a batch to
    # one address is the only way "one host at a time" becomes literally true,
    # and the cost is out of all proportion to the promise: a ``/8`` in scope
    # expands to 16.7M batches (~12 GB before a packet is sent), the checkpoint
    # rewrites its whole JSON after every one of them, and each batch leaves its
    # own artefact files behind. What the ceilings actually buy is written down
    # as such in ``docs/operations.md`` instead.
    updates: dict[str, Any] = {"profiles": profiles}
    if discovery_updates:
        updates["discovery"] = config.discovery.model_copy(update=discovery_updates)
    if nuclei_updates:
        updates["nuclei"] = config.nuclei.model_copy(update=nuclei_updates)
    if runtime_updates:
        updates["runtime"] = config.runtime.model_copy(update=runtime_updates)
    updates.update(secondary_updates)
    if avoid_ports:
        updates["ports"] = config.ports.model_copy(
            update={"exclude_ports": sorted(set(config.ports.exclude_ports) | set(avoid_ports))}
        )

    tightened = config.model_copy(update=updates)
    logging.info(
        "Scan policy applied (profile=%s, version=%s): discover<=%s pps, ports<=%s pps, "
        "concurrency<=%s, per-host<=%s pps, %d avoided port(s), service probe %s",
        policy.get("profile", "standard"),
        policy.get("policy_version"),
        max_discover if max_discover is not None else "config",
        max_port if max_port is not None else "config",
        max_concurrency if max_concurrency is not None else "config",
        per_host_rate if per_host_rate is not None else "config",
        len(avoid_ports),
        "off" if tightened.runtime.skip_nse else "on",
    )
    if config.nuclei.enabled and not tightened.nuclei.enabled:
        logging.info("Scan policy: nuclei stage turned off (skip_service_probe)")
    if skip_service_probe:
        disabled_secondary = [
            stage
            for stage, (_, active_work_field) in SECONDARY_ACTIVE_STAGE_POLICIES.items()
            if getattr(getattr(config, stage), active_work_field)
            and not getattr(getattr(tightened, stage), active_work_field)
        ]
        if disabled_secondary:
            logging.info(
                "Scan policy: active secondary network work turned off for %s",
                ", ".join(disabled_secondary),
            )
    return tightened
