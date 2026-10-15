"""Real pinned Pulse comparison; all traffic constrained to container loopback."""

import fcntl
import argparse
import collections
import hashlib
import json
import os
import platform
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import re
import resource
from pathlib import Path

HOSTS = ["127.20.0.1", "127.20.0.2", "127.20.0.3"]


def verify_binary(expected):
    if (
        hashlib.sha256(Path("/usr/local/bin/pulse").read_bytes()).hexdigest()
        != expected
    ):
        raise ValueError("Pulse binary SHA-256 does not match reviewed expected digest")
    # This harness needs a Linux container with --network none. Refuse a
    # namespace with external interfaces even when fixtures use loopback.
    if platform.system() != "Linux":
        raise ValueError("Linux network namespace required")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        active = set()
        for _, name in socket.if_nameindex():
            flags = fcntl.ioctl(
                control.fileno(), 0x8913, struct.pack("256s", name.encode())
            )
            if struct.unpack_from("H", flags, 16)[0] & 1:
                active.add(name)
    if active != {"lo"}:
        raise ValueError("run in a Linux container with --network none")


def driver(args):
    verify_binary(args.binary_sha256)
    sys.path.insert(0, args.source)
    from scanner.pipeline import pulse_probe as pp

    if args.legacy_plan:
        from scanner.pipeline.pulse_plan import TcpProbeChunk

        def union_plan(grouped, *, chunk_hosts=64, done_hosts=()):
            hosts = sorted(set(grouped) - set(done_hosts))
            return tuple(
                TcpProbeChunk(
                    tuple(hosts[i : i + chunk_hosts]),
                    tuple(
                        sorted(
                            {p for h in hosts[i : i + chunk_hosts] for p in grouped[h]}
                        )
                    ),
                )
                for i in range(0, len(hosts), chunk_hosts)
            )

        pp.plan_tcp_probe = union_plan
    original = subprocess.run
    calls = []

    def observed(command, *a, **kw):
        if isinstance(command, list) and command[0] == "/usr/local/bin/pulse":
            row = {"argv": command, "start": time.monotonic()}
            if "--targets-file" in command:
                row["hosts"] = (
                    Path(command[command.index("--targets-file") + 1])
                    .read_text()
                    .splitlines()
                )
            calls.append(row)
            try:
                result = original(command, *a, **kw)
                row["returncode"] = result.returncode
                return result
            finally:
                row["duration_sec"] = time.monotonic() - row.pop("start")
        return original(command, *a, **kw)

    subprocess.run = observed
    endpoints = json.loads(args.endpoints)
    allowed = {f"{host}:{port}/tcp" for host in HOSTS for port in (8080, 8443, 2222)}
    if not endpoints or any(endpoint not in allowed for endpoint in endpoints):
        raise ValueError("only fixed numeric loopback fixture endpoints are allowed")
    done = []
    unresolved = []
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    adapter_cpu_start = time.process_time()
    start = time.monotonic()
    pp.run_pulse_probe(
        endpoints,
        output_dir=Path(args.output),
        bin_path="/usr/local/bin/pulse",
        concurrency=16,
        rate=100,
        adaptive=False,
        host_parallel=3,
        timeout_ms=300,
        banner=True,
        os_detect=True,
        cve=False,
        cve_online=False,
        syn=False,
        timeout_seconds=90,
        retries=0,
        retry_settle_seconds=0,
        on_host_done=done.append,
        on_unresolved=unresolved.extend,
    )
    raw = json.loads((Path(args.output) / "pulse/raw.json").read_text())
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    data = {
        "duration_sec": time.monotonic() - start,
        "pulse_child_cpu_sec": (usage_after.ru_utime + usage_after.ru_stime)
        - (usage_before.ru_utime + usage_before.ru_stime),
        "pulse_peak_rss_kib": usage_after.ru_maxrss,
        "adapter_cpu_sec": time.process_time() - adapter_cpu_start,
        "calls": calls,
        "done_hosts": done,
        "unresolved_hosts": unresolved,
        "adapter": raw.get("adapter"),
        "services": json.loads((Path(args.output) / "services.json").read_text()),
        "os": json.loads((Path(args.output) / "os.json").read_text()),
        "tls": raw.get("tls", []),
    }
    (Path(args.output) / "sample.json").write_text(json.dumps(data, indent=2))


class Server:
    def __init__(self, host, port, kind, ctx):
        self.host, self.port, self.kind, self.ctx = host, port, kind, ctx
        self.count = 0
        self.stop = False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(128)
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def handle(self, conn):
        try:
            conn.settimeout(0.5)
            if self.kind == "tls":
                conn = self.ctx.wrap_socket(conn, server_side=True)
            if self.kind == "ssh":
                conn.sendall(b"SSH-2.0-OpenSSH_9.2\r\n")
            else:
                conn.recv(8192)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                )
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def serve(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.count += 1
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def close(self):
        self.stop = True
        self.sock.close()
        self.thread.join(1)


def pcap_stats(path):
    data = path.read_bytes()
    magic = data[:4]
    if len(data) < 24 or magic not in {
        b"\xd4\xc3\xb2\xa1",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\xa1\xb2\x3c\x4d",
    }:
        raise ValueError("invalid or truncated PCAP header")
    endian = "<" if magic in [b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"] else ">"
    link = struct.unpack(endian + "I", data[20:24])[0]
    if link != 1:
        raise ValueError(f"Expected Ethernet linktype, got {link}")
    pos = 24
    count = 0
    total = 0
    syn = collections.Counter()
    flags = collections.Counter()
    while pos + 16 <= len(data):
        _, _, caplen, wirelen = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        if pos + caplen > len(data):
            raise ValueError("truncated PCAP packet")
        packet = data[pos : pos + caplen]
        pos += caplen
        count += 1
        total += wirelen
        if len(packet) < 54 or packet[12:14] != b"\x08\x00" or packet[23] != 6:
            continue
        off = 14 + (packet[14] & 15) * 4
        if len(packet) < off + 14:
            continue
        flag = packet[off + 13]
        flags[str(flag)] += 1
        if flag & 2 and not flag & 16:
            dst = socket.inet_ntoa(packet[30:34])
            port = struct.unpack("!H", packet[off + 2 : off + 4])[0]
            syn[f"{dst}:{port}"] += 1
    if pos != len(data):
        raise ValueError("truncated PCAP record header")
    return {
        "packets": count,
        "wire_bytes": total,
        "tcp_syn": dict(syn),
        "tcp_flags": dict(flags),
    }


def main(args):
    if not 5 <= args.repeats <= 100:
        raise ValueError("repeats must be 5..100")
    verify_binary(args.binary_sha256)
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=pulse-loopback-fixture",
            "-keyout",
            str(root / "key.pem"),
            "-out",
            str(root / "cert.pem"),
        ],
        check=True,
        capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(root / "cert.pem", root / "key.pem")
    results = []
    for scenario in ["heterogeneous", "homogeneous", "partial_closed"]:
        ports = [8080] * 3 if scenario == "homogeneous" else [8080, 8443, 2222]
        kinds = ["http"] * 3 if scenario == "homogeneous" else ["http", "tls", "ssh"]
        servers = [
            Server(h, p, k, ctx)
            for i, (h, p, k) in enumerate(zip(HOSTS, ports, kinds))
            if not (scenario == "partial_closed" and i == 2)
        ]
        endpoints = [f"{h}:{p}/tcp" for h, p in zip(HOSTS, ports)]
        try:
            for repeat in range(args.repeats):
                for variant in (
                    ["before", "after"] if repeat % 2 == 0 else ["after", "before"]
                ):
                    out = root / f"{scenario}-{repeat}-{variant}"
                    out.mkdir()
                    capture = out / "traffic.pcap"
                    with (out / "capture.log").open("w") as log:
                        cap = subprocess.Popen(
                            [
                                "tcpdump",
                                "-i",
                                "lo",
                                "-U",
                                "-nn",
                                "-w",
                                str(capture),
                                "net",
                                "127.20.0.0/16",
                            ],
                            stdout=log,
                            stderr=log,
                        )
                        time.sleep(0.3)
                        if cap.poll() is not None:
                            raise RuntimeError((out / "capture.log").read_text())
                        counts = [s.count for s in servers]
                        try:
                            r = subprocess.run(
                                [
                                    sys.executable,
                                    __file__,
                                    "--driver",
                                    "--source",
                                    args.before_source
                                    if variant == "before"
                                    else args.after_source,
                                    "--output",
                                    str(out),
                                    "--endpoints",
                                    json.dumps(endpoints),
                                    "--binary-sha256",
                                    args.binary_sha256,
                                ]
                                + (
                                    ["--legacy-plan"]
                                    if args.legacy_before and variant == "before"
                                    else []
                                ),
                                capture_output=True,
                                text=True,
                                timeout=240,
                            )
                            (out / "driver.stdout").write_text(r.stdout)
                            (out / "driver.stderr").write_text(r.stderr)
                        finally:
                            time.sleep(1.0)
                            cap.send_signal(signal.SIGINT)
                            cap.wait(timeout=10)
                    if r.returncode:
                        raise RuntimeError(f"{scenario}/{variant}: {r.stderr[-1500:]}")
                    sample = json.loads((out / "sample.json").read_text())
                    sample.update(
                        scenario=scenario,
                        repeat=repeat,
                        variant=variant,
                        packets=pcap_stats(capture),
                        accepted_connections=sum(
                            s.count - c for s, c in zip(servers, counts)
                        ),
                    )
                    sample["probe_processes"] = sum(
                        "--targets-file" in c["argv"] for c in sample["calls"]
                    )
                    expected = {(s.host, s.port) for s in servers}
                    found = {(s["ip"], s["port"]) for s in sample["services"]}
                    assert found == expected, (
                        scenario,
                        variant,
                        "service mismatch",
                        found,
                        expected,
                    )
                    known_os = {
                        r["ip"]
                        for r in sample["os"]
                        if r.get("confidence", 0) > 0 and r.get("family") != "Unknown"
                    }
                    assert known_os <= {h for h, p in expected}, (
                        scenario,
                        variant,
                        "OS coverage",
                        known_os,
                    )
                    tls_endpoints = {(r["ip"], r["port"]) for r in sample["tls"]}
                    expected_tls = {
                        (s.host, s.port) for s in servers if s.kind == "tls"
                    }
                    assert tls_endpoints == expected_tls, (
                        scenario,
                        variant,
                        "TLS coverage",
                        tls_endpoints,
                    )
                    assert (
                        sample["adapter"]["os_detect"]
                        and not sample["adapter"]["os_detect_degraded"]
                    )
                    capture_log = (out / "capture.log").read_text()
                    assert re.search(r"0 packets dropped by kernel", capture_log), (
                        capture_log
                    )
                    assert sample["packets"]["packets"] > 0
                    command_pairs = []
                    for call in sample["calls"]:
                        if "--targets-file" not in call["argv"]:
                            continue
                        ports_arg = call["argv"][call["argv"].index("-p") + 1]
                        command_pairs.extend(
                            (h, int(p))
                            for h in call["hosts"]
                            for p in ports_arg.split(",")
                        )
                    sample["planned_command_pairs"] = command_pairs
                    sample["known_os_hosts"] = sorted(known_os)
                    sample["capture_dropped_packets"] = 0
                    sample["coverage_assertions_passed"] = True
                    if variant == "after":
                        assert (
                            set(command_pairs) == set(zip(HOSTS, ports))
                            and len(command_pairs) == 3
                        )
                        assert set(sample["done_hosts"]) == {h for h, p in expected}
                    results.append(sample)
                    (root / "results.json").write_text(json.dumps(results, indent=2))
                    print(
                        json.dumps(
                            {
                                k: sample[k]
                                for k in [
                                    "scenario",
                                    "repeat",
                                    "variant",
                                    "duration_sec",
                                    "probe_processes",
                                    "accepted_connections",
                                ]
                            }
                        ),
                        flush=True,
                    )
        finally:
            for server in servers:
                server.close()
    metadata = {
        "platform": platform.platform(),
        "pulse_version": subprocess.check_output(
            ["/usr/local/bin/pulse", "--version"], text=True
        ).strip(),
        "binary_sha256": hashlib.sha256(
            Path("/usr/local/bin/pulse").read_bytes()
        ).hexdigest(),
        "repeats": args.repeats,
        "capture_settle_seconds": 1.0,
        "network": "none; numeric loopback only",
        "uid": os.getuid(),
        "pulse_install_record": (
            Path("/usr/local/share/shapoclyack/pulse-install.txt").read_text()
            if Path("/usr/local/share/shapoclyack/pulse-install.txt").exists()
            else None
        ),
        "legacy_union_before": args.legacy_before,
    }
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-source", default="/bench/before")
    parser.add_argument("--after-source", default="/bench/after")
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument(
        "--legacy-before",
        action="store_true",
        help="Compare legacy union planner in the same current adapter (loopback only)",
    )
    parser.add_argument("--legacy-plan", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--driver", action="store_true")
    parser.add_argument("--source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--endpoints")
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    driver(args) if args.driver else main(args)
