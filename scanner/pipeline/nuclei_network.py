"""Which non-HTTP endpoints get which Nuclei network/javascript templates (#547).

The web sweep in ``nuclei_scan.py`` only ever receives ``http(s)://`` URLs of
the configured web ports, so a ``javascript:`` or ``tcp:`` template (SMB, RDP,
FTP ...) can never run there: nuclei would hand it a URL for a port it does not
speak. This module is the other half: a small curated table that says, per
service, which templates answer which Nmap ``vuln``/``safe`` script, and the
pure functions that turn ``open_ports`` plus ``services.json`` into
``(rule, host, port)`` targets. It does no I/O beyond reading ``services.json``
and calls no tool; ``nuclei_scan.run_nuclei_scan`` runs the plan and records,
next to the web coverage, what it did.

The table is policy, not discovery. Each id was checked against the pinned
``nuclei-templates`` (``NUCLEI_TEMPLATES_REF`` in ``Dockerfile.allinone``) by
reading the template: what it sends, its severity and its tags. The reasons
for what is *not* here are in ``docs/nse-vuln-coverage.md``. An id the host's
template directory does not have is recorded as missing, never assumed.

Ports are matched by service name first (Pulse's ``services.json``) and by the
default port only for an endpoint whose service is unnamed, the rule the
plugins' gates use (``pulse_plugins.APPLICABILITY``): a service on a
non-standard port is still checked, and an unrelated service on port 445 is
not. Nuclei v3.11.1 takes the port from the input ``host:port`` for these
templates even where the template hardcodes one (``Port: "445"``,
``port: 3389``); checked live against a relay on 1445 and 13389.

Planning by Pulse service for the web sweep is #450; this table is shaped so
that work can read the same ``services.json`` map (:func:`load_service_names`)
without a second source of truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .protocol import format_host_port, parse_endpoint


@dataclass(frozen=True)
class NetworkRule:
    """One service family and the templates that stand in for its NSE scripts.

    ``services`` are Pulse/Nmap service names (lower case). ``ports`` are the
    defaults, used only when the endpoint's service is unnamed. ``nse`` names
    the scripts the templates answer, for the report and the docs.
    """

    name: str
    services: frozenset[str]
    ports: frozenset[int]
    template_ids: tuple[str, ...]
    nse: tuple[str, ...]


#: Deliberately short. Every id here runs on every matching endpoint of every
#: default scan, so it must be read-only, must not send credentials and must
#: not need an out-of-band server.
#:
#: ``smb-signing-not-required`` (javascript, medium, tags ``js,network,smb,enum``)
#: does an SMB2 negotiate and the first NTLMSSP message (type 1) and reads the
#: signing flags from the reply; the challenge it gets back is the end of the
#: exchange, no message type 3 is ever sent, so no logon is attempted (checked
#: on a relay that logs NTLMSSP message types). Its args carry ``User: test`` /
#: ``Pass: test``; they are not used on the wire.
NETWORK_RULES: tuple[NetworkRule, ...] = (
    NetworkRule(
        name="smb",
        services=frozenset({"smb", "microsoft-ds"}),
        ports=frozenset({445}),
        template_ids=("smb-signing-not-required",),
        nse=("smb2-security-mode",),
    ),
)

_UNNAMED = frozenset({"", "unknown"})


def load_service_names(output_dir: Path) -> dict[tuple[str, int], str]:
    """``{(host, port): service}`` of the TCP rows of ``services.json``, lower case.

    Empty when the file is missing or unreadable (a ports-only run, a
    chunk Pulse did not finish): the planner then falls back to default ports.
    Never raises.
    """
    path = output_dir / "services.json"
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    names: dict[tuple[str, int], str] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or str(row.get("protocol") or "tcp").lower() != "tcp":
            continue
        host = str(row.get("ip") or row.get("host") or "").strip()
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        if host:
            names[(host, port)] = str(row.get("service") or "").strip().lower()
    return names


def rule_applies(rule: NetworkRule, service: str, port: int) -> bool:
    """Whether ``rule`` covers an endpoint with this detected ``service``."""
    name = (service or "").strip().lower()
    if name in rule.services:
        return True
    return name in _UNNAMED and port in rule.ports


def plan_network_targets(
    open_ports: list[str],
    services: dict[tuple[str, int], str],
    rules: tuple[NetworkRule, ...] = NETWORK_RULES,
) -> dict[str, list[tuple[str, int]]]:
    """``{rule name: sorted [(host, port)]}`` for the open TCP endpoints each rule covers.

    Only rules with at least one endpoint appear. Deterministic: the same
    ports, services and table give the same plan.
    """
    seen: set[tuple[str, int]] = set()
    plan: dict[str, set[tuple[str, int]]] = {}
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is None or parsed.protocol != "tcp":
            continue
        try:
            endpoint = (parsed.host, int(parsed.port))
        except ValueError:
            continue
        if endpoint in seen:
            continue
        seen.add(endpoint)
        service = services.get(endpoint, "")
        for rule in rules:
            if rule_applies(rule, service, endpoint[1]):
                plan.setdefault(rule.name, set()).add(endpoint)
    return {name: sorted(endpoints) for name, endpoints in sorted(plan.items())}


def target_string(host: str, port: int) -> str:
    """``host:port`` as nuclei reads it, IPv6 bracketed."""
    return format_host_port(host, str(port))


def rule_by_name(name: str, rules: tuple[NetworkRule, ...] = NETWORK_RULES) -> NetworkRule:
    for rule in rules:
        if rule.name == name:
            return rule
    raise LookupError(name)
