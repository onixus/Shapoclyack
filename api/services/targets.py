"""Parse and validate scan target text from the API / web UI."""

from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.pipeline.utils import is_fqdn, is_ip_or_cidr

_PORT_TOKEN_RE = re.compile(r"^(?:u:)?(\d{1,5})(?:-(\d{1,5}))?$")


@dataclass(frozen=True)
class ParsedTargets:
    """Validated target overrides. ``None`` fields keep the server default file."""

    ranges: list[str] | None
    domains: list[str] | None
    ports: list[str] | None
    ports_udp: list[str] | None


def _split_lines(text: str | None) -> list[str]:
    if text is None:
        return []
    values: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for part in line.split(","):
            part = part.strip()
            if part and not part.startswith("#"):
                values.append(part)
    return values


def _valid_port_token(token: str) -> bool:
    match = _PORT_TOKEN_RE.fullmatch(token)
    if not match:
        return False
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    return 1 <= start <= 65535 and 1 <= end <= 65535 and end >= start


def _normalize_port_token(token: str, *, udp: bool) -> str:
    """Store plain port/range tokens; strip optional ``u:`` for UDP lists."""
    if udp and token.startswith("u:"):
        return token[2:]
    return token


def parse_target_payload(
    *,
    ranges_text: str | None,
    domains_text: str | None,
    ports_text: str | None,
    ports_udp_text: str | None = None,
) -> ParsedTargets | None:
    """Return parsed overrides, or None when all fields are empty (server defaults).

    Raises ValueError with a human-readable message when validation fails.
    """
    ranges_raw = _split_lines(ranges_text)
    domains_raw = _split_lines(domains_text)
    ports_raw = _split_lines(ports_text)
    ports_udp_raw = _split_lines(ports_udp_text)

    host_override = bool(ranges_raw or domains_raw)
    port_override = bool(ports_raw)
    port_udp_override = bool(ports_udp_raw)
    if not host_override and not port_override and not port_udp_override:
        return None

    rejected: list[str] = []
    ranges: list[str] = []
    domains: list[str] = []
    ports: list[str] = []
    ports_udp: list[str] = []

    for item in ranges_raw:
        if is_ip_or_cidr(item):
            ranges.append(item)
        else:
            rejected.append(item)

    for item in domains_raw:
        if is_fqdn(item):
            domains.append(item.rstrip("."))
        else:
            rejected.append(item)

    for item in ports_raw:
        if _valid_port_token(item):
            ports.append(_normalize_port_token(item, udp=False))
        else:
            rejected.append(item)

    for item in ports_udp_raw:
        if _valid_port_token(item):
            ports_udp.append(_normalize_port_token(item, udp=True))
        else:
            rejected.append(item)

    if rejected:
        sample = ", ".join(rejected[:8])
        more = f" (+{len(rejected) - 8} more)" if len(rejected) > 8 else ""
        raise ValueError(f"invalid scan targets: {sample}{more}")

    return ParsedTargets(
        ranges=sorted(set(ranges)) if host_override else None,
        domains=sorted(set(domains)) if host_override else None,
        ports=sorted(set(ports)) if port_override else None,
        ports_udp=sorted(set(ports_udp)) if port_udp_override else None,
    )
