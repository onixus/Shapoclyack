#!/usr/bin/env python3
"""Loopback-only endpoint-plan fixture. NOT a benchmark of the Pulse binary."""
from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scanner.pipeline.pulse_plan import TcpProbeChunk, plan_tcp_probe  # noqa: E402


def probe_fixture(chunk: dict[str, Any]) -> dict[str, Any]:
    """One TCP connect/banner read per pair, numeric loopback addresses only."""
    hosts, ports = chunk["hosts"], chunk["ports"]
    if not hosts or not ports or any(not ipaddress.ip_address(h).is_loopback for h in hosts):
        raise ValueError("only non-empty numeric loopback targets are permitted")
    if any(not isinstance(p, int) or not 1 <= p <= 65535 for p in ports):
        raise ValueError("invalid TCP port")
    attempted, services = 0, []
    for host in hosts:
        for port in ports:
            attempted += 1
            try:
                with socket.create_connection((host, port), timeout=0.5) as conn:
                    banner = conn.recv(80).decode("ascii").strip()
                services.append([host, port, banner])
            except OSError:
                pass
    return {"attempted_connections": attempted, "services": services}


def serve(listener: socket.socket, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with conn:
            conn.settimeout(0.5)
            conn.sendall(b"fixture-service\n")


def old_plan(grouped: dict[str, list[int]]) -> tuple[TcpProbeChunk, ...]:
    hosts = sorted(grouped)
    return tuple(TcpProbeChunk(tuple(hosts[i:i + 64]), tuple(sorted({
        port for h in hosts[i:i + 64] for port in grouped[h]
    }))) for i in range(0, len(hosts), 64))


def measure(chunks: tuple[TcpProbeChunk, ...]) -> dict[str, Any]:
    started = time.perf_counter()
    attempts, services = 0, []
    for chunk in chunks:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker", json.dumps({
                "hosts": chunk.hosts, "ports": chunk.ports,
            })], text=True, capture_output=True, check=True, timeout=10,
        )
        data = json.loads(result.stdout)
        attempts += data["attempted_connections"]
        services.extend(data["services"])
    return {
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "processes": len(chunks), "attempted_connections": attempts,
        "established_connections": len(services), "services": sorted(services),
    }


def benchmark(repeats: int) -> dict[str, Any]:
    samples: dict[str, Any] = {}
    for scenario in ("heterogeneous", "homogeneous"):
        with ExitStack() as stack:
            stop = threading.Event()
            grouped: dict[str, list[int]] = {}
            # Reserve distinct ephemeral ports on 0.0.0.0 before binding the
            # loopback listeners. Reservations never listen or connect anywhere.
            reserved = []
            for _ in range(3):
                reserve = stack.enter_context(socket.socket())
                reserve.bind(("0.0.0.0", 0))
                reserved.append(reserve)
            ports = [s.getsockname()[1] for s in reserved]
            for reserve in reserved:
                reserve.close()
            threads = []
            for index in range(3):
                host = f"127.0.0.{index + 2}"
                port = ports[index] if scenario == "heterogeneous" else ports[0]
                listener = stack.enter_context(socket.socket())
                listener.bind((host, port))
                listener.listen(16)
                listener.settimeout(0.05)
                thread = threading.Thread(target=serve, args=(listener, stop), daemon=True)
                thread.start()
                threads.append(thread)
                grouped[host] = [port]
            def shutdown() -> None:
                stop.set()
                for thread in threads:
                    thread.join(timeout=1)
            stack.callback(shutdown)
            plans = {"before": old_plan(grouped), "after": plan_tcp_probe(grouped)}
            runs: dict[str, list[dict[str, Any]]] = {"before": [], "after": []}
            expected = sorted([[h, p, "fixture-service"] for h, values in grouped.items() for p in values])
            for repeat in range(repeats):
                # Alternate order to avoid always charging one plan the first run.
                for name in ("before", "after") if repeat % 2 == 0 else ("after", "before"):
                    measured = measure(plans[name])
                    if measured["services"] != expected:
                        raise RuntimeError(f"fixture coverage mismatch: {scenario}/{name}")
                    runs[name].append(measured)
            samples[scenario] = {"endpoints": grouped, "runs": runs, "summary": {
                name: {
                    "median_ms": round(statistics.median(r["duration_ms"] for r in rows), 3),
                    "min_ms": min(r["duration_ms"] for r in rows),
                    "max_ms": max(r["duration_ms"] for r in rows),
                    "processes_per_run": rows[0]["processes"],
                    "attempts_per_run": rows[0]["attempted_connections"],
                    "established_per_run": rows[0]["established_connections"],
                } for name, rows in runs.items()
            }}
    return {
        "kind": "loopback TCP fixture, not Pulse engine benchmark",
        "baseline": "eca0cc708e0fde9d9d08bd4dcfafee51a78f028d",
        "python": sys.version, "platform": platform.platform(), "repeats": repeats,
        "limitations": "No Pulse/OS/TLS/CVE, no packet/byte or CPU/RSS measurements; process startup included. No cache tuning.",
        "samples": samples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", help=argparse.SUPPRESS)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(probe_fixture(json.loads(args.worker))))
        return
    if not 5 <= args.repeats <= 100:
        parser.error("--repeats must be between 5 and 100")
    report = benchmark(args.repeats)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
