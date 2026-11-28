"""Estate throughput OKR baseline from ``stage_timings.json`` + Pulse stats.

Companion to ``docs/ftt-pulse-2026-055-estate-baseline-measure.md`` and
``scripts/throughput_okr_model.py``. Read-only against run directories; CI uses
committed synthetic fixtures under ``docs/benchmarks/throughput-okr-estate-baseline/``.

Pulse contract (GenDec report): ``stats.elapsed_ms`` is the **L4** wall clock.
The adapter's ``pulse`` stage duration in ``stage_timings.json`` covers L4 plus
in-process enrichment. Completeness: ``l4_complete`` vs ``complete`` when both
are present (Pulse scan.v3 / coverage path).

Usage::

    python -m tests.fixtures.throughput_measure runs-dir /path/to/runs \\
        --cohort inventory --out baseline.json

    python -m tests.fixtures.throughput_measure fixtures \\
        docs/benchmarks/throughput-okr-estate-baseline --out summary.json

    python -m tests.fixtures.scale_measure okr-baseline \\
        docs/benchmarks/throughput-okr-estate-baseline/fixtures
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: Cohorts the OKR Measure pack tracks. Product intent names may land later;
#: the harness treats these as labels, not as live ``scan_intents`` resolution.
COHORTS = ("inventory", "inventory_services", "enrichment", "full")

#: Marker written into synthetic fixture ``stage_timings.json`` so
#: ``scale_measure runs-dir`` and this harness skip them as live scans when
#: scanning a mixed volume.
SYNTHETIC_MARKER = "tests.fixtures.throughput_measure"

OKR_HOSTS_PER_HOUR = 10_000


def hosts_per_hour(hosts: int | float, wall_sec: float) -> float | None:
    """Hosts completed per hour of pipeline wall clock."""
    if hosts is None or wall_sec is None:
        return None
    if wall_sec <= 0 or hosts < 0:
        return None
    return round(float(hosts) * 3600.0 / float(wall_sec), 3)


def _json_load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _json_len(path: Path) -> int | None:
    data = _json_load(path)
    return len(data) if isinstance(data, list) else None


def _resumed(timings: dict[str, Any]) -> bool:
    return any(
        isinstance(stage, dict)
        and stage.get("status") == "skipped"
        and stage.get("detail") == "checkpoint"
        for stage in timings.get("stages", [])
    )


def environment() -> dict[str, Any]:
    env: dict[str, Any] = {
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }
    try:
        env["git_commit"] = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        env["git_commit"] = None
    return env


def pulse_stage_duration_sec(timings: dict[str, Any]) -> float | None:
    for stage in timings.get("stages", []):
        if not isinstance(stage, dict):
            continue
        if stage.get("name") != "pulse":
            continue
        if stage.get("status") not in {"ok", "incomplete"}:
            return None
        duration = stage.get("duration_sec")
        return float(duration) if isinstance(duration, (int, float)) else None
    return None


def l4_enrichment_split(
    *,
    pulse_stage_sec: float | None,
    stats: dict[str, Any] | None,
) -> dict[str, Any]:
    """Derive L4 vs enrichment walls from Pulse stats + timed pulse stage.

    ``stats.elapsed_ms`` is L4-only (Pulse sets it when the port scan finishes,
    before enrichment). Enrichment wall is the remainder of the adapter stage.
    """
    out: dict[str, Any] = {
        "l4_wall_sec": None,
        "enrichment_wall_sec": None,
        "pulse_stage_sec": pulse_stage_sec,
        "l4_share": None,
        "enrichment_share": None,
        "l4_complete": None,
        "complete": None,
        "rate_pps": None,
        "open": None,
        "total": None,
        "elapsed_ms": None,
    }
    if not isinstance(stats, dict):
        return out
    for key in ("l4_complete", "complete"):
        value = stats.get(key)
        if isinstance(value, bool):
            out[key] = value
    for key in ("open", "total"):
        value = stats.get(key)
        if isinstance(value, (int, float)):
            out[key] = int(value)
    rate = stats.get("rate_pps")
    if isinstance(rate, (int, float)):
        out["rate_pps"] = float(rate)
    elapsed_ms = stats.get("elapsed_ms")
    if isinstance(elapsed_ms, (int, float)) and elapsed_ms >= 0:
        out["elapsed_ms"] = int(elapsed_ms)
        l4 = elapsed_ms / 1000.0
        out["l4_wall_sec"] = round(l4, 3)
        if isinstance(pulse_stage_sec, (int, float)) and pulse_stage_sec >= 0:
            enrich = max(0.0, float(pulse_stage_sec) - l4)
            out["enrichment_wall_sec"] = round(enrich, 3)
            total = float(pulse_stage_sec)
            if total > 0:
                out["l4_share"] = round(l4 / total, 4)
                out["enrichment_share"] = round(enrich / total, 4)
    return out


def analyze_run(
    run_dir: Path,
    *,
    cohort: str | None = None,
    require_alive: bool = True,
) -> dict[str, Any] | None:
    """One run → throughput OKR fields, or ``None`` when it should be skipped."""
    timings_path = run_dir / "stage_timings.json"
    timings = _json_load(timings_path)
    if not isinstance(timings, dict):
        if require_alive and not (run_dir / "alive_hosts.json").is_file():
            return None
        timings = {}
    if timings.get("synthetic") and timings.get("synthetic") != SYNTHETIC_MARKER:
        # Other harness synthetics (scale_measure) are not OKR estate baselines.
        if not cohort:
            return None
    if _resumed(timings):
        return None

    hosts = _json_len(run_dir / "alive_hosts.json")
    summary = _json_load(run_dir / "summary.json")
    targets = None
    if isinstance(summary, dict):
        total = summary.get("total_targets")
        if isinstance(total, (int, float)):
            targets = int(total)
        meta_cohort = summary.get("throughput_cohort") or summary.get("intent")
        if cohort is None and isinstance(meta_cohort, str):
            cohort = meta_cohort

    wall = timings.get("pipeline_wall_sec")
    wall_sec = float(wall) if isinstance(wall, (int, float)) else None
    top = timings.get("top_stages")
    if not isinstance(top, list):
        ranked = sorted(
            (
                s
                for s in timings.get("stages", [])
                if isinstance(s, dict) and s.get("status") in {"ok", "incomplete"}
            ),
            key=lambda s: float(s.get("duration_sec") or 0),
            reverse=True,
        )
        top = [
            {"name": s.get("name"), "duration_sec": s.get("duration_sec")}
            for s in ranked[:8]
        ]

    pulse_raw = _json_load(run_dir / "pulse" / "raw.json")
    stats = pulse_raw.get("stats") if isinstance(pulse_raw, dict) else None
    if not isinstance(stats, dict):
        stats = None
    pulse_sec = pulse_stage_duration_sec(timings)
    split = l4_enrichment_split(pulse_stage_sec=pulse_sec, stats=stats)

    host_count = hosts if hosts is not None else targets
    hph = hosts_per_hour(host_count, wall_sec) if host_count is not None and wall_sec is not None else None

    meta_path = run_dir / "throughput_meta.json"
    meta = _json_load(meta_path)
    if isinstance(meta, dict) and cohort is None:
        label = meta.get("cohort") or meta.get("intent")
        if isinstance(label, str):
            cohort = label

    return {
        "run": str(run_dir),
        "cohort": cohort,
        "hosts": hosts,
        "targets": targets,
        "pipeline_wall_sec": wall_sec,
        "stages_sum_sec": timings.get("stages_sum_sec"),
        "hosts_per_hour": hph,
        "okr_hosts_per_hour": OKR_HOSTS_PER_HOUR,
        "meets_okr": None if hph is None else hph >= OKR_HOSTS_PER_HOUR,
        "top_stages": top,
        "pulse": split,
        "resources": timings.get("resources"),
        "synthetic": timings.get("synthetic"),
    }


def discover_run_dirs(root: Path) -> list[Path]:
    """Run dirs under ``root``: direct children, or ``fixtures/<cohort>/<run>``."""
    if (root / "stage_timings.json").is_file() or (root / "alive_hosts.json").is_file():
        return [root]
    found: list[Path] = []
    # Prefer explicit fixture layout cohort/run
    for cohort in COHORTS:
        cohort_dir = root / cohort
        if cohort_dir.is_dir():
            for child in sorted(cohort_dir.iterdir()):
                if child.is_dir() and (
                    (child / "stage_timings.json").is_file()
                    or (child / "alive_hosts.json").is_file()
                ):
                    found.append(child)
    if found:
        return found
    # Flat runs-dir: each child with alive_hosts or stage_timings
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if (child / "alive_hosts.json").is_file() or (child / "stage_timings.json").is_file():
            found.append(child)
    if found:
        return found
    # Nested like $OCTO_OUTPUT_DIR/runs/_tenants/.../run_id
    for timings in sorted(root.rglob("stage_timings.json")):
        found.append(timings.parent)
    return sorted(set(found), key=lambda p: str(p))


def analyze_tree(
    root: Path,
    *,
    default_cohort: str | None = None,
) -> dict[str, Any]:
    """Analyse every eligible run under ``root`` and roll up by cohort."""
    runs: list[dict[str, Any]] = []
    skipped = {"missing": 0, "resumed_or_foreign_synthetic": 0}
    for run_dir in discover_run_dirs(root):
        cohort = default_cohort
        # Fixture layout: .../<cohort>/<run>
        if cohort is None and run_dir.parent.name in COHORTS:
            cohort = run_dir.parent.name
        row = analyze_run(run_dir, cohort=cohort)
        if row is None:
            skipped["resumed_or_foreign_synthetic"] += 1
            continue
        if row.get("hosts") is None and row.get("pipeline_wall_sec") is None:
            skipped["missing"] += 1
            continue
        # Relative path when under root
        try:
            row["run"] = str(run_dir.relative_to(root))
        except ValueError:
            pass
        runs.append(row)

    by_cohort: dict[str, list[dict[str, Any]]] = {name: [] for name in COHORTS}
    unlabeled: list[dict[str, Any]] = []
    for row in runs:
        name = row.get("cohort")
        if name in by_cohort:
            by_cohort[name].append(row)
        else:
            unlabeled.append(row)

    def summarize(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not rows:
            return None
        hph_values = [r["hosts_per_hour"] for r in rows if r.get("hosts_per_hour") is not None]
        walls = [r["pipeline_wall_sec"] for r in rows if r.get("pipeline_wall_sec") is not None]
        hosts = [r["hosts"] for r in rows if r.get("hosts") is not None]
        enrich_shares = [
            r["pulse"]["enrichment_share"]
            for r in rows
            if isinstance(r.get("pulse"), dict) and r["pulse"].get("enrichment_share") is not None
        ]
        l4_ok = [
            r["pulse"]["l4_complete"]
            for r in rows
            if isinstance(r.get("pulse"), dict) and isinstance(r["pulse"].get("l4_complete"), bool)
        ]
        full_ok = [
            r["pulse"]["complete"]
            for r in rows
            if isinstance(r.get("pulse"), dict) and isinstance(r["pulse"].get("complete"), bool)
        ]
        return {
            "runs": len(rows),
            "hosts_total": sum(hosts) if hosts else None,
            "hosts_per_hour_median": _median(hph_values),
            "hosts_per_hour_min": min(hph_values) if hph_values else None,
            "hosts_per_hour_max": max(hph_values) if hph_values else None,
            "pipeline_wall_sec_median": _median(walls),
            "enrichment_share_median": _median(enrich_shares),
            "l4_complete_true": sum(1 for v in l4_ok if v) if l4_ok else None,
            "l4_complete_false": sum(1 for v in l4_ok if not v) if l4_ok else None,
            "complete_true": sum(1 for v in full_ok if v) if full_ok else None,
            "complete_false": sum(1 for v in full_ok if not v) if full_ok else None,
            "meets_okr_any": any(r.get("meets_okr") for r in rows),
            "top_stages_sample": rows[0].get("top_stages"),
        }

    cohorts = {name: summarize(rows) for name, rows in by_cohort.items() if rows}
    return {
        "schema": "shapoclyack.throughput_okr_baseline.v1",
        "environment": environment(),
        "root": str(root),
        "okr_hosts_per_hour": OKR_HOSTS_PER_HOUR,
        "runs": runs,
        "skipped": skipped,
        "cohorts": cohorts,
        "unlabeled_runs": len(unlabeled),
    }


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return round(ordered[mid], 3)
    return round((ordered[mid - 1] + ordered[mid]) / 2.0, 3)


def fixture_digest(root: Path) -> str:
    """Stable SHA-256 over sorted relative paths + file bytes (fixtures only)."""
    hasher = hashlib.sha256()
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    for path in files:
        rel = path.relative_to(root).as_posix()
        hasher.update(rel.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()


def calibration_coefficients(summary: dict[str, Any]) -> dict[str, Any]:
    """Map cohort medians into seconds/host coefficients for the OKR model."""
    out: dict[str, Any] = {"source": summary.get("schema"), "cohorts": {}}
    for name, block in (summary.get("cohorts") or {}).items():
        if not isinstance(block, dict):
            continue
        hph = block.get("hosts_per_hour_median")
        sec_per_host = None if not hph else round(3600.0 / float(hph), 4)
        out["cohorts"][name] = {
            "hosts_per_hour_median": hph,
            "seconds_per_host": sec_per_host,
            "enrichment_share_median": block.get("enrichment_share_median"),
            "meets_okr": bool(hph and hph >= OKR_HOSTS_PER_HOUR),
        }
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.fixtures.throughput_measure",
        description="Measure estate throughput OKR baselines from stage_timings + Pulse stats.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    runs = sub.add_parser("runs-dir", help="analyse sensor run directories (read-only)")
    runs.add_argument("root", type=Path)
    runs.add_argument("--cohort", choices=COHORTS, default=None)
    runs.add_argument("--out", type=Path, default=None)

    fixtures = sub.add_parser("fixtures", help="analyse committed benchmark fixtures")
    fixtures.add_argument(
        "root",
        type=Path,
        nargs="?",
        default=Path("docs/benchmarks/throughput-okr-estate-baseline"),
        help="benchmark pack root (contains fixtures/)",
    )
    fixtures.add_argument("--out", type=Path, default=None)

    one = sub.add_parser("run", help="analyse a single run directory")
    one.add_argument("run_dir", type=Path)
    one.add_argument("--cohort", choices=COHORTS, default=None)
    one.add_argument("--out", type=Path, default=None)

    return parser


def _emit(payload: dict[str, Any], out: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        row = analyze_run(args.run_dir, cohort=args.cohort)
        if row is None:
            print("error: run not eligible (missing artifacts, resumed, or foreign synthetic)", file=sys.stderr)
            return 2
        _emit({"environment": environment(), "run": row}, args.out)
        return 0
    if args.command == "runs-dir":
        _emit(analyze_tree(args.root, default_cohort=args.cohort), args.out)
        return 0
    if args.command == "fixtures":
        root: Path = args.root
        fixtures_root = root / "fixtures" if (root / "fixtures").is_dir() else root
        summary = analyze_tree(fixtures_root)
        summary["fixture_pack"] = str(root)
        summary["fixture_digest_sha256"] = fixture_digest(fixtures_root)
        summary["calibration"] = calibration_coefficients(summary)
        _emit(summary, args.out)
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
