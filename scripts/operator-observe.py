#!/usr/bin/env python3
"""Metadata-only network and bounded resource observation for local acceptance.

No packet payload, HTTP body, credential or DNS question is retained. A helper
shares each observed container's network namespace, never the Docker socket.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
import errno
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import signal
import struct
import subprocess
import time
from threading import Event
from uuid import uuid4


class StopRequest:
    """Signal handlers only notify; Docker commands and report IO stay outside."""
    def __init__(self):
        self.event = Event()
        self.signal = None
        self.requested_at = None

    def request(self, signum, _frame=None):
        if self.signal is None:
            self.signal = signum
            self.requested_at = time.monotonic()
        self.event.set()


@contextmanager
def graceful_signals(stop):
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, stop.request)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def packet_metadata(frame):
    if len(frame) < 14:
        return None
    kind = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if kind == 0x8100 and len(frame) >= 18:
        kind, offset = struct.unpack("!H", frame[16:18])[0], 18
    if kind == 0x0806:
        return {"family": "arp"}
    if kind == 0x0800 and len(frame) >= offset + 20:
        ihl = (frame[offset] & 15) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            return None
        src = socket.inet_ntop(socket.AF_INET, frame[offset + 12:offset + 16])
        dst = socket.inet_ntop(socket.AF_INET, frame[offset + 16:offset + 20])
        protocol, transport = frame[offset + 9], offset + ihl
        # Later fragments do not contain transport headers.
        fragmented = bool(struct.unpack("!H", frame[offset + 6:offset + 8])[0] & 8191)
        family = "ipv4"
    elif kind == 0x86DD and len(frame) >= offset + 40:
        src = socket.inet_ntop(socket.AF_INET6, frame[offset + 8:offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, frame[offset + 24:offset + 40])
        protocol, transport, fragmented, family = frame[offset + 6], offset + 40, False, "ipv6"
    else:
        return None
    value = {"family": family, "source": src, "destination": dst, "protocol": protocol}
    if not fragmented and protocol in (6, 17) and len(frame) >= transport + 4:
        value["source_port"], value["destination_port"] = struct.unpack("!HH", frame[transport:transport + 4])
    return value


def capture(seconds, allowed, stop=None):
    stop = stop or StopRequest()
    networks = [ipaddress.ip_network(value) for value in allowed]
    counts = Counter()
    unexpected = Counter()
    packets = 0
    dns = 0
    receive_errors = Counter()
    started = time.monotonic()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as handle:
        handle.settimeout(0.5)
        while not stop.event.is_set() and time.monotonic() - started < seconds:
            try:
                frame = handle.recv(256)
            except TimeoutError:
                continue
            except OSError as exc:
                receive_errors[str(exc.errno)] += 1
                if exc.errno == errno.ENOBUFS:
                    continue
                break
            value = packet_metadata(frame)
            if value is None:
                continue
            packets += 1
            if value["family"] == "arp":
                counts["arp"] += 1
                continue
            key = f'{value["source"]}>{value["destination"]}/ip{value["protocol"]}/dst{value.get("destination_port", "none")}'
            counts[key] += 1
            if 53 in (value.get("source_port"), value.get("destination_port")):
                dns += 1
            destination = ipaddress.ip_address(value["destination"])
            if not any(destination.version == network.version and destination in network for network in networks):
                unexpected[key] += 1
        # Linux PACKET_STATISTICS counts receive drops even when recv itself
        # succeeds. A zero observed external count with drops is inconclusive.
        seen, dropped = struct.unpack("II", handle.getsockopt(263, 6, 8))
    return {"duration_seconds": time.monotonic() - started, "packets": packets,
            "planned_seconds": seconds, "stopped_early": stop.requested_at is not None and stop.requested_at < started + seconds,
            "stop_signal": stop.signal,
            "dns_packets": dns, "flows": dict(counts), "unexpected_destinations": dict(unexpected),
            "kernel_packets": seen, "kernel_drops": dropped, "receive_errors": dict(receive_errors),
            "payload_retained": False, "capture_limitations": "AF_PACKET metadata, both directions; IPv6 extension transport ports not decoded"}


def command(arguments, timeout=15):
    return subprocess.check_output(arguments, timeout=timeout, text=True)


def observe(args, stop=None):
    stop = stop or StopRequest()
    if not args.image.startswith("sha256:") or len(args.image) != 71:
        raise ValueError("Supply an existing local Python image by immutable image ID")
    started = datetime.now(UTC).isoformat()
    began = time.monotonic()
    helper_names = []
    containers = {}
    samples = []
    errors = []
    script = str(Path(__file__).resolve())
    # Snapshot public collector code into argv. Docker Desktop file bind caches
    # can retain an old inode after an atomic source edit; a stale collector
    # cannot establish evidence about the code the controller actually ran.
    collector_code = Path(script).read_text()
    collector_sha256 = hashlib.sha256(collector_code.encode()).hexdigest()
    names = list(dict.fromkeys(args.container + args.ingress_container))
    deadline = began + args.seconds
    try:
        for index, name in enumerate(names):
            if stop.event.is_set():
                break
            value = json.loads(command(["docker", "inspect", name]))[0]
            networks = {}
            internal = {}
            for network in value["NetworkSettings"]["Networks"]:
                net = json.loads(command(["docker", "network", "inspect", network]))[0]
                if not net["Internal"] and name not in args.ingress_container:
                    raise ValueError(f"Observed container has non-internal network: {name}")
                internal[network] = net["Internal"]
                networks[network] = [item["Subnet"] for item in net["IPAM"]["Config"] if "Subnet" in item]
            allowed = ["127.0.0.0/8", "::1/128"] + [cidr for subnets in networks.values() for cidr in subnets]
            containers[name] = {"image_id": value["Image"], "networks": networks, "network_internal": internal,
                "ingress_observation_only": name in args.ingress_container,
                "dns": value["HostConfig"].get("Dns"), "memory_limit": value["HostConfig"]["Memory"],
                "restart_count_before": value["RestartCount"], "started_at": value["State"]["StartedAt"]}
            helper = f"shapo-observe-{uuid4().hex}-{index}"
            helper_names.append((name, helper))
            command(["docker", "run", "-d", "--name", helper, "--network", "container:" + name,
                "--read-only", "--user=0:0", "--cap-drop=ALL", "--cap-add=NET_RAW", "--security-opt=no-new-privileges",
                "--memory=64m", "--pids-limit=32",
                "--entrypoint", "python", args.image, "-c", collector_code, "--capture-seconds", str(args.seconds),
                *["--allow=" + item for item in allowed]])
        while not stop.event.is_set() and time.monotonic() < deadline:
            cycle_started = time.monotonic()
            sample = {"at": datetime.now(UTC).isoformat()}
            try:
                sample["docker"] = [json.loads(row) for row in command([
                    "docker", "stats", "--no-stream", "--format", "{{json .}}", *names], timeout=12).splitlines()]
                sample["host_vm_stat"] = command(["vm_stat"], timeout=3)
                sample["host_swap"] = command(["sysctl", "vm.swapusage"], timeout=3).strip()
            except (subprocess.SubprocessError, ValueError) as exc:
                errors.append({"at": sample["at"], "type": type(exc).__name__})
            samples.append(sample)
            stop.event.wait(max(0, min(5 - (time.monotonic() - cycle_started), deadline - time.monotonic())))
        # Helpers are our UUID-named metadata collectors only. SIGTERM lets
        # Python emit its accumulated counts and kernel drops before exiting.
        for name, helper in helper_names:
            try:
                command(["docker", "kill", "--signal", "SIGTERM", helper], timeout=10)
            except subprocess.SubprocessError as exc:
                errors.append({"container": name, "type": "helper_signal_unavailable", "exception": type(exc).__name__})
        for name, helper in helper_names:
            try:
                exit_code = command(["docker", "wait", helper], timeout=30).strip()
                logs = command(["docker", "logs", helper], timeout=10)
                if exit_code != "0":
                    errors.append({"container": name, "type": "network_capture_failed", "exit_code": exit_code,
                                   "diagnostic": logs[-1500:]})
                else:
                    containers[name]["network_observation"] = json.loads(logs)
            except (subprocess.SubprocessError, ValueError) as exc:
                errors.append({"container": name, "type": "network_capture_unavailable", "exception": type(exc).__name__})
        for name in containers:
            try:
                current = json.loads(command(["docker", "inspect", name]))[0]
            except (subprocess.SubprocessError, ValueError, KeyError, IndexError) as exc:
                errors.append({"container": name, "type": "endstate_unavailable", "exception": type(exc).__name__})
                continue
            containers[name].update(oom_killed=current["State"]["OOMKilled"],
                restart_count_after=current["RestartCount"], ended_status=current["State"]["Status"],
                ended_started_at=current["State"]["StartedAt"])
            if current["State"]["Status"] == "running":
                try:
                    lines = command(["docker", "exec", name, "cat", "/sys/fs/cgroup/memory.peak",
                                     "/sys/fs/cgroup/memory.events"], timeout=10).splitlines()
                    containers[name]["cgroup_memory_peak_bytes"] = int(lines[0])
                    containers[name]["cgroup_memory_events"] = {
                        key: int(value) for key, value in (line.split() for line in lines[1:])}
                except (subprocess.SubprocessError, ValueError, IndexError):
                    errors.append({"container": name, "type": "cgroup_memory_counters_unavailable"})
    except BaseException as exc:
        errors.append({"type": "collector_failed", "exception": type(exc).__name__})
        raise
    finally:
        for _, helper in helper_names:
            try:
                subprocess.run(["docker", "rm", "-f", helper], capture_output=True, timeout=15)
            except subprocess.SubprocessError as exc:
                errors.append({"type": "helper_cleanup_failed", "exception": type(exc).__name__})
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"schema_version": 1, "started_at": started,
            "ended_at": datetime.now(UTC).isoformat(), "planned_seconds": args.seconds,
            "duration_seconds": time.monotonic() - began,
            "stopped_early": stop.requested_at is not None and stop.requested_at < deadline,
            "stop_signal": stop.signal,
            "collector_sha256": collector_sha256,
            "containers": containers, "samples": samples, "sampling_errors": errors}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-seconds", type=int)
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--seconds", type=int, default=3600)
    parser.add_argument("--container", action="append", default=[])
    parser.add_argument("--ingress-container", action="append", default=[],
                        help="Explicit metadata observation of a fixed ingress proxy; does not attest network deny")
    parser.add_argument("--image")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    stop = StopRequest()
    if args.capture_seconds:
        if not 1 <= args.capture_seconds <= 14400:
            parser.error("capture duration out of bounds")
        with graceful_signals(stop):
            print(json.dumps(capture(args.capture_seconds, args.allow, stop)), flush=True)
    else:
        if not (args.container or args.ingress_container) or args.image is None or args.output is None or not 1 <= args.seconds <= 14400:
            parser.error("observation requires containers, local image, output and bounded duration")
        with graceful_signals(stop):
            observe(args, stop)


if __name__ == "__main__":
    main()
