"""Assert the end-to-end scan produced the expected artifacts and findings.

Usage: python tests/e2e/check_results.py <output_dir> <target_ip>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_results.py <output_dir> <target_ip>", file=sys.stderr)
        return 2

    output_dir = Path(sys.argv[1])
    target_ip = sys.argv[2]

    summary_path = output_dir / "summary.json"
    open_ports_path = output_dir / "open_ports.txt"

    failures: list[str] = []

    if not summary_path.exists():
        failures.append(f"missing {summary_path}")
        print("E2E FAILED:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    open_ports = open_ports_path.read_text(encoding="utf-8").split() if open_ports_path.exists() else []

    if summary.get("alive_hosts", 0) < 1:
        failures.append(f"expected >=1 alive host, got {summary.get('alive_hosts')}")
    if f"{target_ip}:80" not in open_ports and f"{target_ip}:80/tcp" not in open_ports:
        failures.append(f"expected {target_ip}:80 in open ports, got {open_ports}")
    if summary.get("nmap_open_services", 0) < 1:
        failures.append(f"expected >=1 nmap service, got {summary.get('nmap_open_services')}")

    for artifact in ("findings.json", "vulnerabilities.json", "summary.md"):
        if not (output_dir / artifact).exists():
            failures.append(f"missing artifact {artifact}")

    if failures:
        print("E2E FAILED:\n  " + "\n  ".join(failures), file=sys.stderr)
        return 1

    print(f"E2E OK: {json.dumps(summary)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
