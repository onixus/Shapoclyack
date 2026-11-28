#!/usr/bin/env python3
"""Little's-law / serial-enrichment models for the 10k hosts/hour OKR.

No network I/O. Re-run after changing defaults in docs/throughput-okr-10k.md.

With ``--calibration`` (from FTT-055 Measure harness), prints measured cohort
hosts/h beside the analytic rows so ADR 0009 acceptance can cite both.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

OKR = 10_000  # hosts / hour

#: Default path written by the Measure fixture pack (FTT-PULSE-2026-055).
DEFAULT_CALIBRATION = Path("docs/benchmarks/throughput-okr-estate-baseline/calibration.json")


def hosts_per_hour(seconds_per_host: float) -> float:
    if seconds_per_host <= 0:
        return float("inf")
    return 3600.0 / seconds_per_host


def l4_pps(concurrency: int, timeout_s: float, rate: float | None) -> float:
    window = concurrency / timeout_s
    return window if rate is None else min(rate, window)


def print_row(label: str, hph: float) -> None:
    mark = "OK" if hph >= OKR else "MISS"
    print(f"  [{mark:4}] {label:48} {hph:10.0f} hosts/h")


def load_calibration(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"calibration must be an object: {path}")
    return data


def print_calibration(cal: dict[str, Any]) -> None:
    print("=== Measure calibration (stage_timings + Pulse L4/enrich split) ===")
    print(f"  source: {cal.get('source') or 'unknown'}")
    cohorts = cal.get("cohorts") or {}
    if not isinstance(cohorts, dict) or not cohorts:
        print("  (no cohort coefficients)")
        return
    for name in ("inventory", "inventory_services", "enrichment", "full"):
        block = cohorts.get(name)
        if not isinstance(block, dict):
            continue
        hph = block.get("hosts_per_hour_median")
        sec = block.get("seconds_per_host")
        share = block.get("enrichment_share_median")
        if not isinstance(hph, (int, float)):
            continue
        extra = ""
        if isinstance(sec, (int, float)):
            extra += f", {sec:.2f}s/host"
        if isinstance(share, (int, float)):
            extra += f", enrich_share={share:.0%}"
        print_row(f"measured {name}{extra}", float(hph))
    print()
    print("  Path A check: inventory≈5k/h ⇒ need ≥2 sensors for OKR; mid-tier similar.")
    print("  Path B check: enrichment/full ≪ 10k/h ⇒ Stage2 / shards required (ADR 0009).")


def analytic_model() -> None:
    print(f"OKR = {OKR} hosts/hour\n")

    print("=== H3: L4 inventory (silent targets, no discovery) ===")
    for name, c, rate, ports in [
        ("default connect c=500 top-100", 500, None, 100),
        ("balanced c=800 rate=2000 top-100", 800, 2000.0, 100),
        ("fast c=1200 rate=5000 top-100", 1200, 5000.0, 100),
        ("default connect c=500 ports 1-1024", 500, None, 1024),
        ("adaptive floor c=16 top-100", 16, None, 100),
    ]:
        pps = l4_pps(c, 0.8, rate)
        hph = pps / ports * 3600.0
        print_row(f"{name} ({pps:.0f} pps)", hph)

    print("\n=== H1: serial enrichment (1 TLS open/host) ===")
    for label, sec in [
        ("handshake+JARM healthy ~2s", 2.0),
        ("+ legacy TLS ~4s", 4.0),
        ("+ tls-enum typical ~15s", 15.0),
        ("+ tls-enum worst ~35s", 35.0),
        ("+ plugins dense ~45s", 45.0),
    ]:
        print_row(label, hosts_per_hour(sec))

    print("\n=== S1: enrichment parallel (E workers, 15s serial baseline) ===")
    baseline = 15.0
    for e in (1, 4, 8, 16):
        t = 0.2 + baseline / e
        print_row(f"E={e}", hosts_per_hour(t))

    print("\n=== H2: host_parallel waves (T_wave seconds for hp hosts) ===")
    for hp, tw in [(8, 3.0), (8, 10.0), (16, 5.0), (32, 5.0)]:
        hph = hp / tw * 3600.0
        print_row(f"hp={hp}, T_wave={tw}s", hph)

    print("\n=== S2: shards × sensor throughput ===")
    for sensor_hph, n in [(500, 20), (2000, 5), (4000, 3), (800, 13)]:
        print_row(f"{sensor_hph}/h × {n} shards", sensor_hph * n)

    print("\n=== Combined inventory mid-tier (model) ===")
    for c_chunks, e, base in [(1, 1, 0.8), (2, 4, 0.8), (4, 8, 0.5)]:
        t = base / (c_chunks * e)
        print_row(f"C={c_chunks} E={e} base={base}s", hosts_per_hour(t))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Little's-law throughput OKR model (optional Measure calibration).",
    )
    parser.add_argument(
        "--calibration",
        type=Path,
        nargs="?",
        const=DEFAULT_CALIBRATION,
        default=None,
        help=(
            "JSON from throughput_measure / baseline pack "
            f"(default path if flag alone: {DEFAULT_CALIBRATION})"
        ),
    )
    parser.add_argument(
        "--calibration-only",
        action="store_true",
        help="print only the Measure calibration block",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cal = None
    if args.calibration is not None:
        path = args.calibration
        if not path.is_file():
            print(f"error: calibration file not found: {path}", file=sys.stderr)
            return 2
        cal = load_calibration(path)

    if not args.calibration_only:
        analytic_model()
        print()

    if cal is not None:
        print_calibration(cal)
    elif args.calibration_only:
        print("error: --calibration-only requires --calibration", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
