from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

ScanProtocol = Literal["tcp", "udp"]
ProtocolMode = Literal["tcp", "udp", "tcp_udp"]

# Common UDP ports (nmap-style ordering) used when no custom UDP list is provided.
TOP_UDP_PORTS: tuple[int, ...] = (
    7,
    9,
    17,
    19,
    49,
    53,
    67,
    68,
    69,
    88,
    111,
    123,
    135,
    137,
    138,
    161,
    162,
    177,
    389,
    427,
    443,
    464,
    500,
    502,
    514,
    515,
    520,
    523,
    548,
    554,
    563,
    593,
    623,
    626,
    631,
    646,
    664,
    685,
    700,
    750,
    751,
    752,
    753,
    754,
    758,
    760,
    761,
    762,
    763,
    764,
    765,
    771,
    777,
    780,
    786,
    787,
    800,
    808,
    873,
    902,
    903,
    912,
    921,
    996,
    997,
    998,
    999,
    1000,
    1025,
    1026,
    1027,
    1028,
    1029,
    1030,
    1433,
    1434,
    1645,
    1646,
    1701,
    1719,
    1812,
    1813,
    1900,
    2000,
    2048,
    2049,
    2222,
    3283,
    3456,
    3703,
    4444,
    4500,
    5000,
    5060,
    5351,
    5353,
    5355,
    5500,
    5900,
    6000,
    6001,
    6346,
    6347,
    7001,
    8080,
    8888,
    9100,
    9876,
    10000,
)


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: str
    protocol: ScanProtocol = "tcp"


def is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def format_host_port(host: str, port: str) -> str:
    if is_ipv6(host):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def format_endpoint(host: str, port: str, protocol: ScanProtocol) -> str:
    return f"{format_host_port(host, port)}/{protocol}"


def endpoint_checkpoint_key(host: str, protocol: ScanProtocol) -> str:
    return f"{host}/{protocol}"


def parse_endpoint(value: str) -> Endpoint | None:
    """Parse ``host:port[/protocol]`` including bracketed IPv6."""
    raw = value.strip()
    if not raw:
        return None

    protocol: ScanProtocol = "tcp"
    if raw.endswith("/tcp"):
        protocol = "tcp"
        raw = raw[: -len("/tcp")]
    elif raw.endswith("/udp"):
        protocol = "udp"
        raw = raw[: -len("/udp")]

    if raw.startswith("[") and "]" in raw:
        host, _, rest = raw.partition("]")
        host = host[1:]
        port = rest.lstrip(":")
    else:
        host, sep, port = raw.rpartition(":")
        if not sep:
            return None

    if not host or not port.isdigit():
        return None
    return Endpoint(host=host, port=port, protocol=protocol)


def top_udp_port_list(count: int) -> list[int]:
    size = max(1, min(count, len(TOP_UDP_PORTS)))
    return list(TOP_UDP_PORTS[:size])


def naabu_udp_port_spec(ports: list[str]) -> str:
    """Build naabu ``-p`` value for UDP (``u:53,u:123``)."""
    normalized: list[str] = []
    for item in ports:
        value = item.strip()
        if not value:
            continue
        if value.startswith("u:"):
            normalized.append(value)
        elif re.fullmatch(r"\d+", value):
            normalized.append(f"u:{value}")
        else:
            normalized.append(value)
    return ",".join(normalized)
