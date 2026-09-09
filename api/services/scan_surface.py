"""Whether a scan faces the internet or the tenant's own network.

The console shows external and internal scans apart, because they answer
different questions: an external run is the attack surface a stranger sees,
an internal one is what an intruder already inside would. The scanner has no
opinion on this — it scans what it is given — so the classification is made
here, from the targets, at the moment the job is created, and carried on the
job's ``scan_options`` and in the run's ``tenant.json`` marker. No column and
no migration: the value is a property of the request, not a new entity.

The operator's own declaration wins over the derived one (``resolve``). A
tenant whose "internal" estate is a block of public addresses is not wrong,
and no address-based rule can know that.

Not to be confused with ``risk_scoring.resolve_network_exposure``, which asks
whether one *host in a finding* is internet-reachable and deliberately treats a
public address as no evidence either way. This one is about the scan an
operator asked for, so a public target is exactly the evidence that matters.
"""

from __future__ import annotations

import ipaddress
from typing import Literal

from api.services.targets import split_target_lines
from scanner.pipeline.utils import is_fqdn

Surface = Literal["external", "internal", "mixed"]

SURFACES: tuple[Surface, ...] = ("external", "internal", "mixed")

# Spelled out rather than deferred to ``ip_network.is_private``: that property
# answers "is this address special" and its membership has moved between
# CPython releases (RFC 6598 shared space, the 192.0.0.0/24 assignments), which
# would silently reclassify jobs on a base-image bump. These are the ranges a
# scan of which is an *internal* scan, and nothing else.
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",  # RFC1918
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local
        "100.64.0.0/10",  # RFC6598 carrier-grade NAT
        "fc00::/7",  # IPv6 unique local
        "fe80::/10",  # IPv6 link-local
        "::1/128",  # IPv6 loopback
    )
)


def _is_internal(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """True when every address in ``network`` is in private space.

    Containment, not overlap: ``0.0.0.0/0`` covers RFC1918 too, and a scan of
    the whole address space is an internet-facing scan that happens to sweep
    some private ranges on the way.
    """
    return any(
        network.version == private.version and network.subnet_of(private)  # type: ignore[arg-type]
        for private in _PRIVATE_NETWORKS
    )


def classify(ranges_text: str | None, domains_text: str | None) -> Surface | None:
    """Derive the surface from a scan's targets, or ``None`` when it has none.

    ``None`` means "unknown", not "neither": a request with empty target fields
    runs the installation's default input files, whose contents this module
    never sees. Malformed entries are skipped rather than refused —
    ``targets.parse_target_payload`` is the one that validates them, and a
    classification that raised would turn a target typo into two error
    messages, the second of them about the wrong thing.
    """
    external = False
    internal = False

    for name in split_target_lines(domains_text):
        # A name is resolved over public DNS from wherever the scanner runs;
        # it is external evidence even when it happens to answer with an
        # RFC1918 address, because that is a split-horizon detail no parser
        # here can see.
        if is_fqdn(name):
            external = True

    for item in split_target_lines(ranges_text):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if _is_internal(network):
            internal = True
        else:
            external = True

    if external and internal:
        return "mixed"
    if external:
        return "external"
    if internal:
        return "internal"
    return None


def resolve(
    requested: Surface | None, ranges_text: str | None, domains_text: str | None
) -> Surface | None:
    """The surface to record for a scan: the operator's choice, else derived."""
    if requested:
        return requested
    return classify(ranges_text, domains_text)


def declared_surface_for_job(scan_options: dict | None) -> Surface | None:
    """The surface an operator *declared* on a job, for risk scoring.

    ``None`` for anything the server worked out on its own. A derived surface
    is the address-space rule applied to the targets, and handing it to
    ``risk_scoring.resolve_network_exposure`` would make a routing fact score as
    a decision — the one thing that function refuses to do. ``mixed`` is a
    declaration, but it names both answers at once, so it is no evidence about
    any single finding either.
    """
    options = scan_options or {}
    if options.get("surface_source") != "operator":
        return None
    surface = options.get("surface")
    return surface if surface in ("external", "internal") else None
