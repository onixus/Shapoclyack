#!/usr/bin/env python3
"""Little's-law / serial-enrichment models for the 10k hosts/hour OKR.

No network I/O. Re-run after changing defaults in docs/throughput-okr-10k.md.
"""

from __future__ import annotations

OKR = 10_000  # hosts / hour


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


def main() -> None:
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
        # hosts/h = pps / ports_per_host * 3600
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
        # L4 of opens assumed small (~0.2s/host); enrichment dominates
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
    # Light banner path: effective seconds/host ≈ base / (chunk_concurrency × enrich_factor)
    for c_chunks, e, base in [(1, 1, 0.8), (2, 4, 0.8), (4, 8, 0.5)]:
        t = base / (c_chunks * e)
        print_row(f"C={c_chunks} E={e} base={base}s", hosts_per_hour(t))


if __name__ == "__main__":
    main()
