"""Which address a request is attributed to (#157).

The login limiter keys on the client's address, so *how* that address is
decided is a security property rather than a convenience: if the client can
choose it, the limit is one attempt per header value the client cares to
invent, which is no limit at all.

``X-Forwarded-For`` is therefore read **only** when the immediate peer is a
configured trusted proxy (``OCTO_TRUSTED_PROXIES``). With none configured — the
default — the socket peer is used and forwarding headers are ignored entirely.
That is the safe direction of the trade: an installation behind an unconfigured
ingress rate-limits the ingress's address (too coarse, visible, fixable by
setting the variable), while trusting the header by default would silently
rate-limit nobody.

When the peer *is* trusted, the header is walked from the right and trusted
hops are skipped: the rightmost entry is the one the nearest proxy appended and
the only one it can vouch for, and anything further left may have been sent by
the client.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, Sequence

logger = logging.getLogger(__name__)

FORWARDED_FOR_HEADER = "x-forwarded-for"

# A forwarding chain longer than this is not parsed past the trusted hops it
# starts with; a client can otherwise send thousands of entries and make every
# login attempt do the parsing work.
MAX_FORWARDED_HOPS = 32


def parse_trusted_proxies(raw: str | Iterable[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma-separated list of proxy IPs/CIDRs. Invalid entries are dropped.

    A bare address is accepted and read as a single-host network, so
    ``10.0.0.7`` and ``10.0.0.7/32`` mean the same thing.
    """
    parts: Iterable[str]
    if isinstance(raw, str):
        parts = raw.split(",")
    else:
        parts = raw
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in parts:
        cleaned = part.strip()
        if not cleaned:
            continue
        try:
            networks.append(ipaddress.ip_network(cleaned, strict=False))
        except ValueError:
            # Dropped rather than fatal: a typo in this list must not take the
            # API down, and the effect of dropping it is a *stricter* limiter
            # (one fewer trusted hop), never a looser one.
            logger.warning("Ignoring unparsable OCTO_TRUSTED_PROXIES entry: %r", cleaned)
    return networks


def _is_trusted(address: str, networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def resolve_client_ip(
    peer: str | None,
    forwarded_for: str | None,
    trusted_proxies: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str:
    """Return the address to attribute the request to.

    ``peer`` is the socket address (``request.client.host``), ``forwarded_for``
    the raw header value. Returns ``"unknown"`` when there is no peer at all —
    an ASGI transport without a client, which the limiter then treats as one
    key rather than as an absent one.
    """
    peer_ip = (peer or "").strip()
    if not trusted_proxies or not _is_trusted(peer_ip, trusted_proxies):
        return peer_ip or "unknown"

    hops = [hop.strip() for hop in (forwarded_for or "").split(",") if hop.strip()]
    for hop in reversed(hops[-MAX_FORWARDED_HOPS:]):
        candidate = _strip_port(hop)
        if _is_trusted(candidate, trusted_proxies):
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            # A garbage hop ends the walk: continuing past it would step onto
            # entries the client wrote itself.
            break
        return candidate
    return peer_ip or "unknown"


def _strip_port(value: str) -> str:
    """``203.0.113.5:41234`` → ``203.0.113.5``; ``[2001:db8::1]:443`` → ``2001:db8::1``.

    Some proxies append the source port. An IPv6 address without brackets is
    left alone — its colons are part of the address.
    """
    cleaned = value.strip()
    if cleaned.startswith("["):
        end = cleaned.find("]")
        if end > 0:
            return cleaned[1:end]
        return cleaned
    if cleaned.count(":") == 1:
        return cleaned.split(":", 1)[0]
    return cleaned
