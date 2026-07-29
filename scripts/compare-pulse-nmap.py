#!/usr/bin/env python3
"""Live comparative scan: Pulse vs Nmap on the same targets/ports.

Runs both tools, normalizes into the same shapes as a Shapoclyack run, then
invokes ``pulse_shadow.compare_pulse_nmap`` (endpoint Jaccard + OS family).

Usage:
  scripts/compare-pulse-nmap.py 127.0.0.1 scanme.nmap.org
  PULSE_BIN=./pulse NMAP_BIN=nmap scripts/compare-pulse-nmap.py --top 100 1.1.1.1
  scripts/compare-pulse-nmap.py --one-ip-per-host scanme.nmap.org example.com

Requires: pulse + nmap on PATH (or PULSE_BIN / NMAP_BIN).
"""

from __future__ import annotations

import argparse
import socket
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# Allow running from repo root without install
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.pipeline.pulse_probe import parse_pulse_json, write_pulse_artifacts  # noqa: E402
from scanner.pipeline.pulse_shadow import compare_pulse_nmap, write_pulse_nmap_diff  # noqa: E402


def _which(env_key: str, default: str) -> str:
    configured = os.environ.get(env_key, "").strip()
    if configured and Path(configured).exists():
        return configured
    found = shutil.which(default)
    if found:
        return found
    raise SystemExit(f"missing binary: set {env_key} or install `{default}`")



def resolve_targets(targets: list[str], *, one_ip_per_host: bool) -> list[str]:
    """Resolve hostnames for fair compare.

    When *one_ip_per_host* is True, each hostname collapses to a single IPv4
    (first getaddrinfo result). Bare IPs pass through. Multi-A expansion is
    the default Pulse behaviour and inflates endpoint Jaccard vs nmap.
    """
    if not one_ip_per_host:
        return list(targets)
    out: list[str] = []
    seen: set[str] = set()
    for t in targets:
        t = t.strip()
        if not t:
            continue
        # already IPv4/IPv6 literal?
        try:
            socket.inet_pton(socket.AF_INET, t)
            if t not in seen:
                seen.add(t)
                out.append(t)
            continue
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, t)
            if t not in seen:
                seen.add(t)
                out.append(t)
            continue
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(t, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise SystemExit(f"resolve failed for {t!r}: {exc}") from exc
        if not infos:
            raise SystemExit(f"no A records for {t!r}")
        ip = infos[0][4][0]
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
            print(f"    resolve {t} -> {ip} (one-ip)")
        else:
            print(f"    resolve {t} -> {ip} (dup skipped)")
    return out


def run_pulse(
    pulse_bin: str,
    targets: list[str],
    ports: str,
    out_dir: Path,
    timeout: int,
    *,
    os_detect: bool,
) -> dict:
    raw_path = out_dir / "pulse_raw.json"
    # Pulse takes one TARGET arg (comma-separated hosts) or --targets-file.
    target_arg = ",".join(targets)
    cmd = [
        pulse_bin,
        target_arg,
        "-p",
        ports,
        "-c",
        "200",
        "--rate",
        "500",
        "-b",
        "--cve",
        "-f",
        "json",
        "-q",
    ]
    # OS fingerprint needs raw sockets (root / setcap); skip when unprivileged.
    if os_detect:
        cmd.extend(["--os", "--os-mode", "sinfp"])
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    elapsed = time.perf_counter() - t0
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"pulse failed ({proc.returncode}): {proc.stderr[-500:]}")
    text = proc.stdout.strip()
    # pulse may wrap JSON or print only JSON object
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # last {...} block
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < 0:
            raise RuntimeError(f"pulse produced no JSON: {text[:300]!r}") from None
        payload = json.loads(text[start : end + 1])
    raw_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    services, os_recs, cves = parse_pulse_json(payload)
    write_pulse_artifacts(out_dir, services, os_recs, cves, raw=payload)
    return {
        "elapsed_s": round(elapsed, 3),
        "returncode": proc.returncode,
        "services": len(services),
        "os": len(os_recs),
        "cves": len(cves),
        "cmd": cmd,
    }


def run_nmap(
    nmap_bin: str,
    targets: list[str],
    ports: str,
    out_dir: Path,
    timeout: int,
    *,
    os_detect: bool = False,
) -> dict:
    nmap_dir = out_dir / "nmap" / "tcp"
    nmap_dir.mkdir(parents=True, exist_ok=True)
    base = nmap_dir / "compare"
    # -Pn: same as pipeline (targets already "alive" for compare)
    cmd = [
        nmap_bin,
        "-n",
        "-Pn",
        "-T4",
        "-sV",
        "--version-intensity",
        "2",
        "-p",
        ports,
        "-oX",
        str(base) + ".xml",
        *targets,
    ]
    if os_detect and hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd[4:4] = ["-O", "--osscan-guess"]
    return _run_nmap_cmd(cmd, base, timeout)


def _run_nmap_cmd(cmd: list[str], base: Path, timeout: int) -> dict:
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    elapsed = time.perf_counter() - t0
    xml_path = Path(str(base) + ".xml")
    if not xml_path.exists():
        raise RuntimeError(f"nmap wrote no XML: rc={proc.returncode} stderr={proc.stderr[-500:]}")
    open_ports = 0
    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8", errors="replace"))
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.attrib.get("state") == "open":
                open_ports += 1
    except ET.ParseError:
        pass
    return {
        "elapsed_s": round(elapsed, 3),
        "returncode": proc.returncode,
        "open_ports_xml": open_ports,
        "xml": str(xml_path),
        "cmd": cmd,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("targets", nargs="*", default=["127.0.0.1"], help="hosts/IPs")
    ap.add_argument(
        "--ports",
        default="22,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443",
        help="comma-separated ports for both tools",
    )
    ap.add_argument("--timeout", type=int, default=180, help="per-tool timeout seconds")
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output dir (default: temp under /tmp)",
    )
    ap.add_argument(
        "--os",
        action="store_true",
        help="enable OS detect (needs root/raw sockets on both tools)",
    )
    ap.add_argument(
        "--one-ip-per-host",
        action="store_true",
        help="resolve each hostname to a single IPv4 (fair Jaccard vs nmap)",
    )
    args = ap.parse_args()
    targets = args.targets or ["127.0.0.1"]
    if args.one_ip_per_host:
        print("==> resolving targets (--one-ip-per-host)")
        targets = resolve_targets(targets, one_ip_per_host=True)
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    os_detect = args.os or is_root

    # Prefer local GenDec build if present
    default_pulse = ROOT.parent / "GenA" / "pulse" / "target" / "release" / "pulse"
    if "PULSE_BIN" not in os.environ and default_pulse.is_file():
        os.environ["PULSE_BIN"] = str(default_pulse)

    pulse_bin = _which("PULSE_BIN", "pulse")
    nmap_bin = _which("NMAP_BIN", "nmap")

    out_dir = args.out or Path(tempfile.mkdtemp(prefix="pulse-nmap-compare-"))
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"==> compare Pulse vs Nmap")
    print(f"    targets: {targets}")
    print(f"    ports:   {args.ports}")
    print(f"    pulse:   {pulse_bin}")
    print(f"    nmap:    {nmap_bin}")
    print(f"    os:      {os_detect} (root={is_root})")
    print(f"    out:     {out_dir}")

    print("\n==> running Pulse…")
    pulse_meta = run_pulse(
        pulse_bin, targets, args.ports, out_dir, args.timeout, os_detect=os_detect
    )
    print(
        f"    done in {pulse_meta['elapsed_s']}s  "
        f"services={pulse_meta['services']} os={pulse_meta['os']} cves={pulse_meta['cves']}"
    )

    print("\n==> running Nmap…")
    nmap_meta = run_nmap(
        nmap_bin, targets, args.ports, out_dir, args.timeout, os_detect=os_detect
    )
    print(
        f"    done in {nmap_meta['elapsed_s']}s  "
        f"open_ports_xml={nmap_meta['open_ports_xml']} rc={nmap_meta['returncode']}"
    )

    print("\n==> shadow diff…")
    diff_path = write_pulse_nmap_diff(
        out_dir,
        out_dir / "nmap",
        extra={
            "targets": targets,
            "ports": args.ports,
            "pulse": {k: v for k, v in pulse_meta.items() if k != "cmd"},
            "nmap": {k: v for k, v in nmap_meta.items() if k != "cmd"},
            "pulse_cmd": pulse_meta["cmd"],
            "nmap_cmd": nmap_meta["cmd"],
        },
    )
    diff = json.loads(diff_path.read_text(encoding="utf-8"))
    ep = diff["endpoints"]
    os_ = diff["os"]

    # Human report
    report = {
        "targets": targets,
        "ports": args.ports,
        "timing": {
            "pulse_s": pulse_meta["elapsed_s"],
            "nmap_s": nmap_meta["elapsed_s"],
            "speedup_vs_nmap": (
                round(nmap_meta["elapsed_s"] / pulse_meta["elapsed_s"], 2)
                if pulse_meta["elapsed_s"] > 0
                else None
            ),
        },
        "endpoints": ep,
        "os": os_,
        "artifacts": {
            "dir": str(out_dir),
            "diff": str(diff_path),
            "services": str(out_dir / "services.json"),
            "os": str(out_dir / "os.json"),
            "nmap_xml": nmap_meta["xml"],
        },
    }
    summary_path = out_dir / "compare_summary.json"
    summary_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print()
    print("=== RESULT ===")
    print(f"  Endpoint Jaccard:  {ep['jaccard']}")
    print(f"  Pulse endpoints:   {ep['pulse_count']}")
    print(f"  Nmap endpoints:    {ep['nmap_count']}")
    print(f"  Both:              {ep['both_count']}")
    print(f"  Only Pulse:        {ep['only_pulse_count']}  {ep['only_pulse_sample'][:10]}")
    print(f"  Only Nmap:         {ep['only_nmap_count']}  {ep['only_nmap_sample'][:10]}")
    print(f"  OS family agree:   {os_['family_agree']} / both={os_['hosts_with_both']}")
    print(f"  Time Pulse/Nmap:   {pulse_meta['elapsed_s']}s / {nmap_meta['elapsed_s']}s")
    print(f"  Summary:           {summary_path}")
    print(f"  Full diff:         {diff_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired as exc:
        print(f"timeout: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
