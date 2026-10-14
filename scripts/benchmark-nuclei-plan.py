"""Local Nuclei acceptance fixture. Run inside --network none Linux runtime.

The expected match is synthetic, not a real vulnerable application/CVE.
"""

import json
import hashlib
import platform
import signal
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import scanner.pipeline.nuclei_scan as adapter
from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_scan import run_nuclei_scan

interfaces = {
    line.split(":", 1)[0].strip()
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]
    if ":" in line
}
if interfaces != {"lo"}:
    raise RuntimeError(f"fixture requires network isolation; interfaces={interfaces}")
ROOT = Path("/evidence")
ROOT.mkdir(exist_ok=True)
TEMPLATES = ROOT / "templates"
TEMPLATES.mkdir(exist_ok=True)
(TEMPLATES / "fixture.yaml").write_text("""id: local-fixture-cve
info:
  name: Synthetic loopback fixture (not a vulnerability)
  author: issue450
  severity: high
  tags: cve,fixture
  classification:
    cve-id: CVE-2099-9999
http:
  - method: GET
    path:
      - '{{BaseURL}}/expected'
    matchers:
      - type: word
        words:
          - 'issue450_expected_match'
""")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"issue450_expected_match")

    def log_message(self, *args):
        pass


class Server(ThreadingHTTPServer):
    def get_request(self):
        self.connections += 1
        return super().get_request()


server = Server(("127.0.0.1", 0), Handler)
server.connections = server.requests = 0
threading.Thread(target=server.serve_forever, daemon=True).start()
port = server.server_port
os.environ["PATH"] = "/fixture-bin:" + os.environ["PATH"]

measurements = []


def command(argv, **kwargs):
    started = time.monotonic()
    out = ROOT / f"process-{len(measurements)}.stdout"
    err = ROOT / f"process-{len(measurements)}.stderr"
    with out.open("w") as stdout, err.open("w") as stderr:
        process = subprocess.Popen(
            argv, stdout=stdout, stderr=stderr, start_new_session=True
        )
        deadline = started + kwargs["timeout"]
        timed_out = False
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(process.pid, 0)
                    break
                time.sleep(0.01)
            process.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            os.wait4(process.pid, 0)
            raise
    measurements.append(
        {
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "peak_rss_kib": usage.ru_maxrss,
            "duration_seconds": time.monotonic() - started,
        }
    )
    if timed_out:
        raise subprocess.TimeoutExpired(
            argv, kwargs["timeout"], output=out.read_text(), stderr=err.read_text()
        )
    return subprocess.CompletedProcess(
        argv, process.returncode, out.read_text(), err.read_text()
    )


adapter.run_command = command
binary_digest = hashlib.sha256()
with Path("/fixture-bin/nuclei").open("rb") as binary:
    while chunk := binary.read(1024 * 1024):
        binary_digest.update(chunk)
source_digest = hashlib.sha256()
for source in (
    "scanner/pipeline/nuclei_plan.py",
    "scanner/pipeline/nuclei_scan.py",
    "scanner/pipeline/config_schema.py",
):
    source_digest.update(source.encode() + (Path("/work") / source).read_bytes())
report = {
    "fixture": "synthetic HTTP response; no real CVE acceptance",
    "network": "container --network none, loopback only",
    "interfaces_observed": sorted(interfaces),
    "engine_binary_sha256": binary_digest.hexdigest(),
    "architecture": platform.machine(),
    "source_snapshot_sha256": source_digest.hexdigest(),
    "engine": subprocess.run(
        ["nuclei", "-version"], capture_output=True, text=True
    ).stderr.strip(),
    "modes": {},
}
for mode in ("legacy", "directed"):
    directory = ROOT / mode
    directory.mkdir(exist_ok=True)
    (directory / "services.json").write_text(
        json.dumps(
            [{"ip": "127.0.0.1", "port": port, "service": "http", "confidence": 100}]
        )
    )
    started = time.monotonic()
    requests = server.requests
    connections = server.connections
    processes = len(measurements)
    cfg = NucleiConfig(
        templates_dir=str(TEMPLATES),
        planner_mode=mode,
        network_templates=False,
        http_ports=[port],
        https_ports=[port],
        retries=0,
        timeout_seconds=1,
        overall_timeout_seconds=60,
    )
    result = run_nuclei_scan([f"127.0.0.1:{port}/tcp"], cfg, directory)
    metrics = measurements[processes:]
    report["modes"][mode] = {
        "duration_seconds": time.monotonic() - started,
        "cpu_seconds": sum(m["cpu_seconds"] for m in metrics),
        "peak_rss_kib": max((m["peak_rss_kib"] for m in metrics), default=0),
        "processes": len(metrics),
        "connections": server.connections - connections,
        "requests": server.requests - requests,
        "selected_templates": 1,
        "expected_problem_matches": sum(
            f["template_id"] == "local-fixture-cve" for f in result["findings"]
        ),
        "checked_count": result["checked_count"],
        "coverage": result["coverage"],
    }
report["expected_matches_preserved"] = all(
    m["expected_problem_matches"] >= 1 for m in report["modes"].values()
)
(ROOT / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
print(
    json.dumps(
        {
            k: {kk: vv for kk, vv in v.items() if kk != "coverage"}
            for k, v in report["modes"].items()
        },
        indent=2,
    )
)
assert report["expected_matches_preserved"]
server.shutdown()
