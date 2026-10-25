"""Observation must retain routing metadata, never packet contents."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import signal
from types import SimpleNamespace

import pytest

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


def test_capture_signal_flushes_cumulative_packet_and_kernel_drop_counts(monkeypatch):
    stop = observe.StopRequest()
    class Handle:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, _seconds):
            pass
        def recv(self, _size):
            stop.request(signal.SIGTERM)
            return bytes(12) + b"\x08\x06"  # one metadata-only ARP frame
        def getsockopt(self, *args):
            assert args == (263, 6, 8)
            return struct.pack("II", 4, 2)
    monkeypatch.setattr(observe.socket, "AF_PACKET", 17, raising=False)
    monkeypatch.setattr(observe.socket, "socket", lambda *args: Handle())
    result = observe.capture(3600, ["127.0.0.0/8"], stop)
    assert result["stopped_early"] and result["stop_signal"] == signal.SIGTERM
    assert result["packets"] == 1 and result["flows"] == {"arp": 1}
    assert result["kernel_packets"] == 4 and result["kernel_drops"] == 2
    assert result["duration_seconds"] < result["planned_seconds"]


def test_real_process_signal_sets_flag_and_restores_handlers():
    stop = observe.StopRequest()
    previous = signal.getsignal(signal.SIGTERM)
    with observe.graceful_signals(stop):
        os.kill(os.getpid(), signal.SIGTERM)
        assert stop.event.is_set() and stop.signal == signal.SIGTERM
    assert signal.getsignal(signal.SIGTERM) == previous


@pytest.mark.parametrize("capture_fails", [False, True])
def test_parent_signal_stops_only_owned_helper_and_retains_endstate(tmp_path, monkeypatch, capture_fails):
    stop = observe.StopRequest()
    calls = []
    value = {"Image": "sha256:" + "b" * 64, "RestartCount": 0,
        "NetworkSettings": {"Networks": {"private": {}}}, "HostConfig": {"Memory": 1024, "Dns": []},
        "State": {"Status": "running", "OOMKilled": False, "StartedAt": "fixture"}}
    def command(argv, timeout=15):
        calls.append(argv)
        if argv[0] in {"vm_stat", "sysctl"}:
            return "metadata"
        if argv[1:3] == ["inspect", "observed-runtime"]:
            return json.dumps([value])
        if argv[1:3] == ["network", "inspect"]:
            return json.dumps([{"Internal": True, "IPAM": {"Config": [{"Subnet": "172.30.83.0/24"}]}}])
        if argv[1] == "run":
            return "own-helper-id"
        if argv[1] == "stats":
            stop.request(signal.SIGINT)
            return "{}"
        if argv[1] == "kill":
            return "own-helper-id"
        if argv[1] == "wait":
            if capture_fails:
                raise observe.subprocess.TimeoutExpired(argv, timeout)
            return "0"
        if argv[1] == "logs":
            return json.dumps({"packets": 3, "kernel_packets": 4, "kernel_drops": 1, "stopped_early": True})
        if argv[1] == "exec":
            return "512\noom 0\noom_kill 0\n"
        raise AssertionError(argv)
    monkeypatch.setattr(observe, "command", command)
    monkeypatch.setattr(observe.subprocess, "run", lambda argv, **kwargs: calls.append(argv))
    args = SimpleNamespace(image="sha256:" + "a" * 64, container=["observed-runtime"], ingress_container=[], seconds=3600, output=tmp_path / "report.json")
    observe.observe(args, stop)
    report = json.loads(args.output.read_text())
    assert report["stopped_early"] and report["stop_signal"] == signal.SIGINT
    assert report["duration_seconds"] < report["planned_seconds"]
    metadata = report["containers"]["observed-runtime"]
    assert metadata["ended_status"] == "running" and metadata["cgroup_memory_events"]["oom_kill"] == 0
    if capture_fails:
        assert any(row["type"] == "network_capture_unavailable" for row in report["sampling_errors"])
        assert "network_observation" not in metadata
    else:
        assert metadata["network_observation"]["kernel_drops"] == 1
    mutation_calls = [argv for argv in calls if argv[0] == "docker" and argv[1] in {"kill", "rm"}]
    assert len(mutation_calls) == 2
    assert all(argv[-1].startswith("shapo-observe-") for argv in mutation_calls)
    assert all("observed-runtime" not in argv for argv in mutation_calls)
