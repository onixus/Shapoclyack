"""Read-only provenance/quality review for D3 stand calibration campaigns.

This never runs a scan, changes a store, or declares production capacity. Each
sample points to an existing ``scale_measure derive`` result AND its raw inputs;
the raw environment blocks survive instead of the last merged one winning.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_SAMPLES = 20
MAX_RAW_FILES = 16
MIN_REPETITIONS = 3


class CampaignError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CampaignError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read(path: Path) -> tuple[dict[str, Any], str]:
    # Bounded read also catches a file growing after stat().
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise CampaignError(f"JSON exceeds {MAX_JSON_BYTES} bytes: {path.name}")
    try:
        body = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CampaignError(f"invalid JSON: {path.name}: {exc}") from exc
    if not isinstance(body, dict):
        raise CampaignError(f"JSON object required: {path.name}")
    return body, hashlib.sha256(raw).hexdigest()


def _path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise CampaignError("artifact paths must be relative to the manifest directory")
    resolved = (root / value).resolve()
    if not resolved.is_relative_to(root):
        raise CampaignError("artifact path escapes the campaign directory (including symlinks)")
    if not resolved.is_file():
        raise CampaignError(f"artifact is not a file: {value}")
    return resolved


def _finite(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _environments(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key.startswith("environment")}


def audit_campaign(path: Path, *, known_coefficients: set[str]) -> dict[str, Any]:
    """Audit one deployment/mode; don't pool kind/Arch or local/executor costs."""
    path = path.resolve()
    manifest, manifest_sha = _read(path)
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise CampaignError("schema_version must be integer 1")
    if manifest.get("deployment") not in {"kind", "arch"}:
        raise CampaignError("deployment must be kind or arch")
    if manifest.get("scanner_mode") not in {"scanner-executor", "local"}:
        raise CampaignError("scanner_mode must distinguish scanner-executor from local")
    samples = manifest.get("samples")
    if not isinstance(samples, list) or not 1 <= len(samples) <= MAX_SAMPLES:
        raise CampaignError(f"samples must contain 1..{MAX_SAMPLES} repetitions")
    problems = []
    if len(samples) < MIN_REPETITIONS:
        problems.append(f"need at least {MIN_REPETITIONS} independent repetitions")
    ids, raw_seen, result_seen = set(), set(), set()
    provenance, measurements = [], []
    for sample in samples:
        if not isinstance(sample, dict) or not isinstance(sample.get("id"), str) or not sample["id"].strip():
            raise CampaignError("each sample needs a non-empty string id")
        name = sample["id"]
        if name in ids:
            raise CampaignError(f"duplicate sample id: {name}")
        ids.add(name)
        result, result_sha = _read(_path(path.parent, sample.get("result")))
        if result_sha in result_seen:
            problems.append(f"{name}: duplicate derived result; not an independent repetition")
        result_seen.add(result_sha)
        coefficients = result.get("coefficients")
        if not isinstance(coefficients, dict) or set(coefficients) - known_coefficients:
            raise CampaignError(f"{name}: coefficients missing or unknown fields")
        for key, value in coefficients.items():
            if key == "source":
                if not isinstance(value, str) or not value.strip() or value == "unset":
                    problems.append(f"{name}: coefficient source is missing")
            elif key == "run_dir_bytes_is_floor":
                if type(value) is not bool:
                    raise CampaignError(f"{name}: run_dir_bytes_is_floor must be boolean")
            elif value is not None and not _finite(value):
                raise CampaignError(f"{name}: {key} must be a finite non-negative number or null")
        if not coefficients.get("source") or coefficients.get("source") == "unset":
            problems.append(f"{name}: no coefficient provenance")
        if coefficients.get("run_dir_bytes_is_floor", True) is not False:
            problems.append(f"{name}: run storage still represents a report-only floor")
        measurements.append(coefficients)
        raw_files = sample.get("raw_results")
        if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= MAX_RAW_FILES:
            raise CampaignError(f"{name}: raw_results must contain 1..{MAX_RAW_FILES} source files")
        files, local_hashes, postgres_seen = [], set(), False\n        real_run_hosts, real_archive_hosts = set(), set()
        for relative in raw_files:
            document, digest = _read(_path(path.parent, relative))
            if digest in local_hashes or digest in raw_seen:
                problems.append(f"{name}: repeated raw artifact {relative}")
            local_hashes.add(digest)
            envs = _environments(document)
            files.append({"path": relative, "sha256": digest, "environments": envs})
            if not envs:
                problems.append(f"{name}: {relative} has no environment metadata")
            for env in envs.values():
                if not isinstance(env, dict):
                    raise CampaignError(f"{name}: environment must be an object")
                for key in ("measured_at", "git_commit", "platform", "cpu_count", "mem_total_bytes"):
                    if not env.get(key):
                        problems.append(f"{name}: {relative} environment lacks {key}")
                pg = env.get("postgres")
                if pg is not None:
                    if not isinstance(pg, dict):
                        raise CampaignError(f"{name}: postgres environment must be an object")
                    postgres_seen = True
                    for setting in ("fsync", "full_page_writes", "synchronous_commit", "autovacuum"):
                        if pg.get(setting) != "on":
                            problems.append(f"{name}: PostgreSQL {setting} is not explicitly on")
            runs_dir = document.get("runs_dir", {})
            if not isinstance(runs_dir, dict):
                raise CampaignError(f"{name}: runs_dir must be an object")
            runs = runs_dir.get("runs", [])
            if not isinstance(runs, list):
                raise CampaignError(f"{name}: runs must be an array")
            for run in runs:
                if not isinstance(run, dict):
                    raise CampaignError(f"{name}: run must be an object")
                resources = run.get("resources")
                hosts = run.get("hosts")
                if type(hosts) is int and hosts > 0 and isinstance(resources, dict):
                    fields = ("cpu_sec", "children_cpu_sec", "max_rss_mb", "children_max_rss_mb")
                    if all(_finite(resources.get(key)) for key in fields):
                        real_run_hosts.add(hosts)
            # Synthetic/resumed runs are already excluded by scale_measure's
            # collector; retain its exclusion counts for review, not as scans.
            if runs_dir:
                files[-1]["skipped_runs"] = runs_dir.get("skipped", {})
        raw_seen.update(local_hashes)
        if not postgres_seen:
            problems.append(f"{name}: no raw PostgreSQL durability settings")
        if len(real_run_hosts) < 2:
            problems.append(f"{name}: need resource-accounted real runs at two distinct host counts")
        provenance.append({"sample": name, "result": sample["result"], "result_sha256": result_sha, "raw": files})
    numeric = known_coefficients - {"source", "run_dir_bytes_is_floor"}
    comparison = {}
    for key in sorted(numeric):
        values = [sample[key] for sample in measurements if sample.get(key) is not None]
        complete = len(values) == len(samples)
        median = statistics.median(values) if values else None
        comparison[key] = {
            "measured_repetitions": len(values), "complete": complete,
            "median": median, "min": min(values) if values else None,
            "max": max(values) if values else None,
            "relative_span": (max(values) - min(values)) / median if median else None,
        }
    return {
        "schema_version": 1, "deployment": manifest["deployment"],
        "scanner_mode": manifest["scanner_mode"], "manifest_sha256": manifest_sha,
        "checks_passed": not problems, "problems": problems,
        "sources": provenance, "comparison": comparison,
        "missing_coefficients": [key for key, value in comparison.items() if not value["complete"]],
        "capacity_validated": False,
        "review_required": [
            "Re-derive results from the hashed raw inputs and review fit quality before publishing coefficients.",
            "Verify engine versions/digests, scan scope/profile, partial failures and overlapping-process RSS.",
            "Measure ClickHouse CPU and system-log growth separately for idle and ingest, with retention.",
            "Check JetStream aggregate reservations/PVC and per-run max_payload; review unbounded tables.",
            "Justify headroom, compare the separate kind/Arch and local/executor campaigns; DR is #333.",
        ],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    # Reuse the model's field names; never maintain a second coefficient schema.
    from dataclasses import fields
    from tests.fixtures.scale_sizing import Coefficients
    try:
        report = audit_campaign(args.manifest, known_coefficients={field.name for field in fields(Coefficients)})
        output = args.out.resolve()
        protected = {args.manifest.resolve()}
        for sample in report["sources"]:
            protected.add((args.manifest.resolve().parent / sample["result"]).resolve())
            protected.update((args.manifest.resolve().parent / raw["path"]).resolve() for raw in sample["raw"])
        if output in protected:
            raise CampaignError("output must not overwrite the manifest or any evidence file")
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        print(f"calibration: {exc}", file=sys.stderr)
        return 2
    return 0 if report["checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
