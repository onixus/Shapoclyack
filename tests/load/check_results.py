"""Assert a synthetic load test produced expected scale and artifacts.

Usage:
  python tests/load/check_results.py <output_dir> <targets_file> [--min-fraction 0.95]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _read_targets(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate load-test scan results")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("targets_file", type=Path)
    parser.add_argument(
        "--min-fraction",
        type=float,
        default=0.95,
        help="Minimum fraction of targets that must be alive with port 80 open",
    )
    parser.add_argument("--metrics-out", type=Path, help="Write pass/fail metrics JSON here")
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    targets = _read_targets(args.targets_file)
    if not targets:
        print("no targets in targets file", file=sys.stderr)
        return 2

    summary_path = output_dir / "summary.json"
    open_ports_path = output_dir / "open_ports.txt"
    failures: list[str] = []

    if not summary_path.exists():
        failures.append(f"missing {summary_path}")
        _report(failures, args.metrics_out, targets, output_dir)
        return 1

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    open_ports = set(open_ports_path.read_text(encoding="utf-8").split()) if open_ports_path.exists() else set()

    min_alive = max(1, int(len(targets) * args.min_fraction + 0.999))
    alive_hosts = int(summary.get("alive_hosts", 0))
    if alive_hosts < min_alive:
        failures.append(f"expected >={min_alive} alive hosts, got {alive_hosts}")

    found_hosts = sum(
        1
        for ip in targets
        if f"{ip}:80" in open_ports or f"{ip}:80/tcp" in open_ports
    )
    min_ports = max(1, int(len(targets) * args.min_fraction + 0.999))
    if found_hosts < min_ports:
        missing = sorted(
            ip for ip in targets if f"{ip}:80" not in open_ports and f"{ip}:80/tcp" not in open_ports
        )[:5]
        failures.append(
            f"expected >={min_ports} hosts with :80 open, got {found_hosts} "
            f"(sample missing: {missing})"
        )

    if int(summary.get("nmap_open_services", 0)) < min_alive:
        failures.append(
            f"expected >={min_alive} nmap services, got {summary.get('nmap_open_services')}"
        )

    for artifact in ("findings.json", "vulnerabilities.json", "summary.md"):
        if not (output_dir / artifact).exists():
            failures.append(f"missing artifact {artifact}")

    if failures:
        print("LOAD TEST FAILED:\n  " + "\n  ".join(failures), file=sys.stderr)
        _report(failures, args.metrics_out, targets, output_dir, summary=summary, open_port_count=found_hosts)
        return 1

    print(
        f"LOAD TEST OK: targets={len(targets)} alive={alive_hosts} "
        f"open_ports={found_hosts} nmap_services={summary.get('nmap_open_services')}"
    )
    _report([], args.metrics_out, targets, output_dir, summary=summary, open_port_count=found_hosts)
    return 0


def _report(
    failures: list[str],
    metrics_out: Path | None,
    targets: list[str],
    output_dir: Path,
    *,
    summary: dict | None = None,
    open_port_count: int = 0,
) -> None:
    if metrics_out is None:
        return
    metrics = {
        "passed": not failures,
        "target_count": len(targets),
        "alive_hosts": summary.get("alive_hosts") if summary else None,
        "open_port_matches": open_port_count,
        "nmap_open_services": summary.get("nmap_open_services") if summary else None,
        "failures": failures,
        "output_dir": str(output_dir),
    }
    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_out.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
