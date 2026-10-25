"""Observation must retain routing metadata, never packet contents."""
import importlib.util
from pathlib import Path
import socket
import struct

spec = importlib.util.spec_from_file_location("operator_observe", Path(__file__).parents[1] / "scripts/operator-observe.py")
observe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observe)


def test_ipv4_dns_metadata_discards_question_and_payload():
    ethernet = bytes(12) + struct.pack("!H", 0x0800)
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 17
    ip[12:16], ip[16:20] = socket.inet_aton("172.30.83.2"), socket.inet_aton("127.0.0.1")
    packet = ethernet + ip + struct.pack("!HH", 40000, 53) + b"private-dns-question-and-secret"
    result = observe.packet_metadata(packet)
    assert result == {"family": "ipv4", "source": "172.30.83.2", "destination": "127.0.0.1",
                      "protocol": 17, "source_port": 40000, "destination_port": 53}
    assert "private" not in repr(result)


def test_later_fragment_cannot_invent_ports_from_payload():
    ip = bytearray(20)
    ip[0], ip[9], ip[7] = 0x45, 6, 1
    result = observe.packet_metadata(bytes(12) + b"\x08\x00" + ip + b"secret")
    assert "source_port" not in result


def test_truncated_frames_and_ipv6():
    assert observe.packet_metadata(b"short") is None
    assert observe.packet_metadata(bytes(12) + b"\x08\x00" + b"\x4f" * 20) is None
    ip = bytearray(40)
    ip[0], ip[6] = 0x60, 6
    ip[8:24] = socket.inet_pton(socket.AF_INET6, "::1")
    ip[24:40] = socket.inet_pton(socket.AF_INET6, "::1")
    value = observe.packet_metadata(bytes(12) + b"\x86\xdd" + ip + struct.pack("!HH", 20000, 8082))
    assert value["destination"] == "::1"
    assert value["destination_port"] == 8082
