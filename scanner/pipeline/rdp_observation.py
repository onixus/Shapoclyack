"""Bounded, scanner-owned RDP X.224 negotiation observation.

This module deliberately has no dependency on Pulse/Rhai. It sends exactly one
request to an already-scoped TCP endpoint and returns only decoded protocol
facts (or an inconclusive reason) for the separate observation receipt.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import time
from typing import Any

# TPKT + X.224 Connection Request + RDP_NEG_REQ(type=1,length=8,flags=0,mask=0x0b).
REQUEST = bytes.fromhex("030000130ee00000000000010008000b000000")
VARIANT = "rdp-negotiation-ssl-hybrid-hybrid-ex-v1"
PROTOCOLS = {
    0x00000001: "PROTOCOL_SSL",
    0x00000002: "PROTOCOL_HYBRID",
    0x00000008: "PROTOCOL_HYBRID_EX",
}
MAX_RESPONSE = 64


class RdpNegotiationError(ValueError):
    """Peer reply is malformed, unsupported or unoffered."""


def parse_reply(data: bytes) -> dict[str, Any]:
    """Decode one strict TPKT/X.224/RDP_NEG_RSP or RDP_NEG_FAILURE."""
    if not isinstance(data, bytes) or len(data) < 19 or len(data) > MAX_RESPONSE:
        raise RdpNegotiationError("malformed_response_length")
    if data[0] != 3 or data[1] != 0 or data[4] != 0x0E:
        raise RdpNegotiationError("malformed_tpkt_header")
    length = struct.unpack(">H", data[2:4])[0]
    if length != len(data) or data[4] != 0x0E:
        raise RdpNegotiationError("malformed_tpkt_length")
    if data[5:11] != bytes.fromhex("d00000000000"):
        raise RdpNegotiationError("malformed_x224_confirm")
    # RDP_NEG_RSP and RDP_NEG_FAILURE are exactly 8 bytes; X.224 CR has no user data.
    if data[11] not in (0x02, 0x03) or data[12] != 0 or data[13:15] != b"\x08\x00":
        raise RdpNegotiationError("malformed_negotiation_structure")
    value = struct.unpack("<I", data[15:19])[0]
    if len(data) != 19:
        raise RdpNegotiationError("unexpected_trailing_data")
    if data[11] == 0x03:
        return {"result": "explicit_failure", "failure_code": value}
    protocol = PROTOCOLS.get(value)
    if protocol is None:
        # Includes standard RDP (0), RDSTLS, unknown, and any unoffered value.
        raise RdpNegotiationError("unoffered_protocol")
    return {"result": "selected", "selected_protocol": protocol}


def observe(host: str, port: int = 3389, *, timeout: float = 1.5) -> tuple[str, dict[str, Any] | None]:
    """Make one bounded TCP exchange; return responded/failed/unknown and facts."""
    if (not isinstance(host, str) or not host or port != 3389
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 5):
        raise ValueError("RDP observation requires scoped TCP port 3389 and bounded timeout")
    try:
        # Connect to the previously scoped address only; never re-resolve a
        # hostname after admission, where DNS could move outside the scope.
        host = str(ipaddress.ip_address(host))
    except ValueError:
        return "unknown", None
    try:
        deadline = time.monotonic() + timeout
        with socket.create_connection((host, port), timeout=timeout) as connection:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "unknown", None
            connection.settimeout(remaining)
            connection.sendall(REQUEST)
            chunks = bytearray()
            while len(chunks) < MAX_RESPONSE:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "unknown", None
                connection.settimeout(remaining)
                part = connection.recv(min(1024, MAX_RESPONSE - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
                if len(chunks) >= 4:
                    expected = struct.unpack(">H", chunks[2:4])[0]
                    if expected < 4 or expected > MAX_RESPONSE:
                        return "failed", None
                    if len(chunks) > expected:
                        # Exactly one negotiation response is permitted.
                        return "failed", None
                    if len(chunks) == expected:
                        break
            try:
                outcome = parse_reply(bytes(chunks))
            except RdpNegotiationError:
                return "failed", None
            return "responded", outcome
    except socket.timeout:
        return "unknown", None
    except OSError:
        return "failed", None
