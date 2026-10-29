from __future__ import annotations

import socket
import struct
import threading

import pytest

from scanner.pipeline import rdp_observation as rdp


def reply(kind: int, value: int) -> bytes:
    return b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x00\x00\x00" + bytes([kind, 0, 8, 0]) + struct.pack("<I", value)


@pytest.mark.parametrize(("value", "name"), [
    (1, "PROTOCOL_SSL"), (2, "PROTOCOL_HYBRID"), (8, "PROTOCOL_HYBRID_EX"),
])
def test_parse_offered_protocols(value, name):
    assert rdp.parse_reply(reply(2, value)) == {"result": "selected", "selected_protocol": name}


def test_parse_explicit_request_failure():
    assert rdp.parse_reply(reply(3, 2)) == {"result": "explicit_failure", "failure_code": 2}


@pytest.mark.parametrize("value", [0, 4, 0x10, 0xffffffff])
def test_unoffered_selection_is_inconclusive(value):
    with pytest.raises(rdp.RdpNegotiationError, match="unoffered_protocol"):
        rdp.parse_reply(reply(2, value))


@pytest.mark.parametrize("data", [b"", b"x" * 19, reply(2, 1)[:-1], reply(2, 1) + b"x"])
def test_rejects_malformed_or_trailing_response(data):
    with pytest.raises(rdp.RdpNegotiationError):
        rdp.parse_reply(data)


def test_loopback_sends_exactly_one_request_and_stops_after_response(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    fixture_port = listener.getsockname()[1]
    received: list[bytes] = []
    create_connection = socket.create_connection

    def connect_scoped(address, *, timeout):
        assert address == ("127.0.0.1", 3389)
        return create_connection(("127.0.0.1", fixture_port), timeout=timeout)

    monkeypatch.setattr(rdp.socket, "create_connection", connect_scoped)

    def serve():
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(1)
            received.append(conn.recv(4096))
            conn.sendall(reply(2, 1))
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        state, outcome = rdp.observe("127.0.0.1", port=3389)
    finally:
        if thread.is_alive():
            listener.close()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert received == [rdp.REQUEST]
    assert state == "responded" and outcome == {"result": "selected", "selected_protocol": "PROTOCOL_SSL"}


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (socket.timeout("late"), ("unknown", None)),
        (OSError("connection refused"), ("failed", None)),
    ],
)
def test_socket_failures_have_distinct_states(monkeypatch, failure, expected):
    def connect(*args, **kwargs):
        raise failure

    monkeypatch.setattr(rdp.socket, "create_connection", connect)
    assert rdp.observe("127.0.0.1") == expected


def test_eof_without_reply_is_failed(monkeypatch):
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def settimeout(self, value): pass
        def sendall(self, data): assert data == rdp.REQUEST
        def recv(self, size): return b""

    def connect(*args, **kwargs):
        return Connection()
    monkeypatch.setattr(rdp.socket, "create_connection", connect)
    # EOF before any response is a malformed/failed response, not a timeout.
    assert rdp.observe("127.0.0.1") == ("failed", None)


@pytest.mark.parametrize("partial", [b"", b"\x03\x00\x00\x13\x0e"])
def test_eof_with_partial_reply_is_failed(monkeypatch, partial):
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def settimeout(self, value): pass
        def sendall(self, data): assert data == rdp.REQUEST
        def recv(self, size):
            if not hasattr(self, "sent"):
                self.sent = True
                return partial
            return b""

    monkeypatch.setattr(rdp.socket, "create_connection", lambda *args, **kwargs: Connection())
    assert rdp.observe("127.0.0.1") == ("failed", None)


def test_scope_guard_requires_tcp_rdp_port():
    with pytest.raises(ValueError):
        rdp.observe("127.0.0.1", port=3388)


def test_trickled_response_cannot_extend_total_deadline(monkeypatch):
    clock = iter([0.0, 0.1, 0.2, 0.9, 1.6])
    monkeypatch.setattr(rdp.time, "monotonic", lambda: next(clock))

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): return None
        def settimeout(self, value): assert 0 < value <= 1.5
        def sendall(self, data): assert data == rdp.REQUEST
        def recv(self, size): return b"\x03"

    monkeypatch.setattr(rdp.socket, "create_connection", lambda *args, **kwargs: Connection())
    assert rdp.observe("127.0.0.1", timeout=1.5) == ("unknown", None)
