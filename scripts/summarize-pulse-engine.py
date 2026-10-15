#!/usr/bin/env python3
"""Recompute descriptive Pulse benchmark metrics from recorded samples."""

import argparse
import json
import statistics
from pathlib import Path


def summarize(samples):
    result = []
    for scenario in sorted({row["scenario"] for row in samples}):
        scenario_rows = [r for r in samples if r["scenario"] == scenario]
        service_sets = {
            tuple(
                sorted(
                    (
                        x["ip"],
                        x["port"],
                        x.get("service"),
                        x.get("product"),
                        x.get("version"),
                    )
                    for x in r["services"]
                )
            )
            for r in scenario_rows
        }
        os_sets = {
            tuple(
                sorted(
                    (x["ip"], x.get("family"))
                    for x in r["os"]
                    if x.get("confidence", 0) > 0 and x.get("family") != "Unknown"
                )
            )
            for r in scenario_rows
        }
        tls_sets = {
            tuple(sorted((x["ip"], x["port"]) for x in r["tls"])) for r in scenario_rows
        }
        if any(len(values) != 1 for values in (service_sets, os_sets, tls_sets)):
            raise ValueError(
                "service/known OS/TLS coverage changed between measurements"
            )
        for variant in ("before", "after"):
            rows = [
                r
                for r in samples
                if r["scenario"] == scenario and r["variant"] == variant
            ]
            if len(rows) < 5 or len({r["repeat"] for r in rows}) != len(rows):
                raise ValueError(
                    "at least five distinct repetitions per variant required"
                )
            if not all(
                r["coverage_assertions_passed"] and r["capture_dropped_packets"] == 0
                for r in rows
            ):
                raise ValueError("incomplete coverage or dropped capture packets")
            result.append(
                {
                    "scenario": scenario,
                    "variant": variant,
                    "samples": len(rows),
                    "median_seconds": statistics.median(
                        r["duration_sec"] for r in rows
                    ),
                    "min_seconds": min(r["duration_sec"] for r in rows),
                    "max_seconds": max(r["duration_sec"] for r in rows),
                    "processes": sorted({r["probe_processes"] for r in rows}),
                    "command_pairs": sorted(
                        {len(r["planned_command_pairs"]) for r in rows}
                    ),
                    "median_packets": statistics.median(
                        r["packets"]["packets"] for r in rows
                    ),
                    "median_wire_bytes": statistics.median(
                        r["packets"]["wire_bytes"] for r in rows
                    ),
                    "median_accepted_connections": statistics.median(
                        r["accepted_connections"] for r in rows
                    ),
                    "median_child_cpu_seconds": statistics.median(
                        r["pulse_child_cpu_sec"] for r in rows
                    ),
                    "median_child_peak_rss_mib": statistics.median(
                        r["pulse_peak_rss_kib"] / 1024 for r in rows
                    ),
                    "services": sorted({len(r["services"]) for r in rows}),
                    "known_os": sorted({len(r["known_os_hosts"]) for r in rows}),
                    "tls": sorted({len(r["tls"]) for r in rows}),
                    "unresolved_hosts": sorted(
                        {tuple(r["unresolved_hosts"]) for r in rows}
                    ),
                }
            )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(json.loads(args.results.read_text())), indent=2))
