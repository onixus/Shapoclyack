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
    ip[4:6] = struct.pack("!H", 4)
    ip[8:24] = socket.inet_pton(socket.AF_INET6, "::1")
    ip[24:40] = socket.inet_pton(socket.AF_INET6, "::1")
    value = observe.packet_metadata(bytes(12) + b"\x86\xdd" + ip + struct.pack("!HH", 20000, 8082))
    assert value["destination"] == "::1"
    assert value["destination_port"] == 8082


def ipv6_frame(source, destination, payload, protocol=58, hop_limit=255):
    ip = bytearray(40)
    ip[0], ip[6], ip[7] = 0x60, protocol, hop_limit
    ip[4:6] = struct.pack("!H", len(payload))
    ip[8:24] = socket.inet_pton(socket.AF_INET6, source)
    ip[24:40] = socket.inet_pton(socket.AF_INET6, destination)
    return bytes(12) + b"\x86\xdd" + ip + payload


def dad_frame(source="::", destination="ff02::1:ff84:75b5", kind=135, hop_limit=255, target="fe80::5441:1cff:fe84:75b5"):
    return ipv6_frame(source, destination, bytes([kind, 0]) + bytes(6) + socket.inet_pton(socket.AF_INET6, target), hop_limit=hop_limit)


def mld_frame(source="fe80::1", destination="ff02::16", kind=143, hop_limit=1, alert=0):
    hbh = bytes([58, 0, 5, 2, 0, alert, 1, 0])
    return ipv6_frame(source, destination, hbh + bytes([kind, 0]) + bytes(6), protocol=0, hop_limit=hop_limit)


def test_control_candidates_require_positive_protocol_scope_metadata():
    dad = observe.packet_metadata(dad_frame())
    mld = observe.packet_metadata(mld_frame())
    assert dad["link_local_control_candidate"] == "duplicate_address_detection_ns"
    assert mld["link_local_control_candidate"] == "mldv2_listener_report"
    assert mld["protocol"] == 58 and mld["extension_headers"] == [0]
    assert mld["icmpv6_type"] == 143 and mld["hop_limit"] == 1
    assert not any("payload" in key for key in dad | mld)


@pytest.mark.parametrize("packet", [
    dad_frame(kind=128), dad_frame(hop_limit=64), dad_frame(source="2001:db8::1"),
    dad_frame(destination="ff02::16"), dad_frame(target="fe80::2"), dad_frame(target="2001:db8::8475:b5"),
    mld_frame(kind=128), mld_frame(hop_limit=64), mld_frame(source="2001:db8::1"),
    mld_frame(destination="ff05::16"), mld_frame(alert=1),
])
def test_no_blanket_icmpv6_or_multicast_exemption(packet):
    assert "link_local_control_candidate" not in observe.packet_metadata(packet)


@pytest.mark.parametrize("frame,payload_size", [(dad_frame(), 4), (mld_frame(), 12)])
def test_ethernet_padding_cannot_supply_control_message_body(frame, payload_size):
    frame = bytearray(frame)
    frame[18:20] = struct.pack("!H", payload_size)
    assert "link_local_control_candidate" not in observe.packet_metadata(frame)


def test_ethernet_padding_cannot_invent_dns_ports():
    frame = bytearray(ipv6_frame("fe80::1", "ff02::16", struct.pack("!HH", 40000, 53), protocol=17))
    frame[18:20] = struct.pack("!H", 2)
    value = observe.packet_metadata(frame)
    assert value["decode_error"] == "truncated_transport"
    assert "destination_port" not in value


def capture_frames(monkeypatch, frames):
    stop = observe.StopRequest()
    pending = iter(enumerate(frames))
    class Handle:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, _seconds): pass
        def recv(self, _size):
            index, frame = next(pending)
            if index == len(frames) - 1:
                stop.request(signal.SIGTERM)
            return frame
        def getsockopt(self, *args): return struct.pack("II", len(frames), 2)
    monkeypatch.setattr(observe.socket, "AF_PACKET", 17, raising=False)
    monkeypatch.setattr(observe.socket, "socket", lambda *args: Handle())
    return observe.capture(3600, ["127.0.0.0/8", "172.30.83.0/24"], stop)


def test_control_candidates_remain_unexpected_and_drop_dns_checks_unchanged(monkeypatch):
    dns = ipv6_frame("fe80::1", "2001:db8::53", bytes([17, 0]) + bytes(6) + struct.pack("!HH", 41000, 53), protocol=0)
    result = capture_frames(monkeypatch, [dad_frame(), mld_frame(), dns])
    assert result["link_local_control_candidates"] == {"duplicate_address_detection_ns": 1, "mldv2_listener_report": 1}
    assert sum(result["unexpected_destinations"].values()) == 3
    assert result["dns_packets"] == 1 and result["kernel_drops"] == 2
    assert result["receive_errors"] == {} and not result["payload_retained"]


@pytest.mark.parametrize("payload,protocol,error", [
    (bytes([17, 2]) + bytes(6), 0, "truncated_extension"),
    (bytes([17, 0, 5, 9]) + bytes(4), 0, "malformed_hop_options"),
    ((bytes([0, 0]) + bytes(6)) * 9, 0, "extension_limit"),
    (bytes([17, 0]) + bytes(6), 44, "fragmented_transport"),
    (bytes([17, 0, 0, 8]) + bytes(4), 44, "later_fragment"),
    (bytes(8), 50, "opaque_encapsulation"),
    (b"\x00", 17, "truncated_transport"),
])
def test_undecodable_ipv6_fails_closed_in_existing_receive_error_gate(monkeypatch, payload, protocol, error):
    frame = ipv6_frame("fe80::1", "ff02::16", payload, protocol=protocol)
    metadata = observe.packet_metadata(frame)
    assert metadata["decode_error"] == error
    assert "source_port" not in metadata and "link_local_control_candidate" not in metadata
    result = capture_frames(monkeypatch, [frame])
    assert result["receive_errors"] == {"ipv6_decode_" + error: 1}
    assert sum(result["unexpected_destinations"].values()) == 1


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


def cgroup_sample(start=100, end=None):
    values = [f"1 (llama server) S {'0 ' * 18}{start}\n", "7510000000\n", "7516192768\n",
        "low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\n", "anon 7000000000\nfile 100\nslab 200\npgscan 999\n",
        f"1 (llama server) S {'0 ' * 18}{start if end is None else end}\n"]
    names = ["/proc/1/stat", "/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.peak",
             "/sys/fs/cgroup/memory.events", "/sys/fs/cgroup/memory.stat", "/proc/1/stat"]
    return "".join(f"\n__file__{name}\n{value}" for name, value in zip(names, values))


def test_cgroup_sample_retains_pre_restart_oom_and_selected_memory_only():
    first = observe.parse_cgroup_sample(cgroup_sample())
    second = observe.parse_cgroup_sample(cgroup_sample(start=200).replace("oom_kill 1", "oom_kill 0"))
    assert first["pid1_start_ticks"] != second["pid1_start_ticks"]
    assert first["memory_events"]["oom_kill"] == 1 and second["memory_events"]["oom_kill"] == 0
    assert first["memory_current_bytes"] == 7510000000
    assert first["memory_peak_bytes"] == 7516192768
    assert first["memory_stat_bytes"] == {"anon": 7000000000, "file": 100, "slab": 200}


@pytest.mark.parametrize("mode", ["restart", "missing", "negative", "duplicate", "oversized", "bad_stat", "truncated"])
def test_cgroup_sample_rejects_mixed_epochs_and_invalid_counters(mode):
    raw = cgroup_sample(end=200 if mode == "restart" else None)
    if mode == "missing":
        raw = raw.replace("slab 200\n", "")
    elif mode == "negative":
        raw = raw.replace("file 100", "file -1")
    elif mode == "duplicate":
        raw = raw.replace("slab 200", "slab 200\nslab 201")
    elif mode == "oversized":
        raw += "x" * 16385
    elif mode == "bad_stat":
        raw = raw.replace("1 (llama server) S", "bad")
    elif mode == "truncated":
        raw = raw[:raw.rindex("\n__file__")]
    with pytest.raises((ValueError, IndexError)):
        observe.parse_cgroup_sample(raw)


@pytest.mark.parametrize("capture_fails", [False, True])
@pytest.mark.parametrize("cgroup_fails", [False, True])
def test_parent_signal_stops_only_owned_helper_and_retains_endstate(tmp_path, monkeypatch, capture_fails, cgroup_fails):
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
            if "sh" in argv:
                assert timeout == 5
                if cgroup_fails:
                    raise observe.subprocess.TimeoutExpired(argv, timeout)
                return cgroup_sample()
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
    if cgroup_fails:
        assert report["samples"][0]["cgroup_memory"] == {}
        assert any(row["type"] == "cgroup_sample_unavailable" for row in report["sampling_errors"])
    else:
        assert report["samples"][0]["cgroup_memory"]["observed-runtime"]["memory_events"]["oom_kill"] == 1
    if capture_fails:
        assert any(row["type"] == "network_capture_unavailable" for row in report["sampling_errors"])
        assert "network_observation" not in metadata
    else:
        assert metadata["network_observation"]["kernel_drops"] == 1
    mutation_calls = [argv for argv in calls if argv[0] == "docker" and argv[1] in {"kill", "rm"}]
    assert len(mutation_calls) == 2
    assert all(argv[-1].startswith("shapo-observe-") for argv in mutation_calls)
    assert all("observed-runtime" not in argv for argv in mutation_calls)
