"""Lightweight scan scheduler for Phase 1.

Runs ``python -m scanner.main`` on a cron schedule or fixed interval.
Prefer host cron / systemd timers in production; this module is useful for
docker-compose one-container schedules and local labs.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from calendar import monthrange
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from scanner.pipeline.config_schema import AppConfig, format_validation_error, load_config
from scanner.pipeline.utils import load_yaml, setup_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Schedule Octo-man scan runs")
    parser.add_argument("--config", default="scanner/config/default.yaml", help="Path to YAML config")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan immediately (ignore cron/interval wait)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the next fire time / command without executing scans",
    )
    return parser.parse_args()


def _parse_cron_field(field: str, minimum: int, maximum: int) -> set[int]:
    values: set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "*":
            values.update(range(minimum, maximum + 1))
            continue
        step = 1
        base = part
        if "/" in part:
            base, step_s = part.split("/", 1)
            step = int(step_s)
            if step < 1:
                raise ValueError(f"invalid cron step in '{field}'")
        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            start_s, end_s = base.split("-", 1)
            start, end = int(start_s), int(end_s)
        else:
            start = end = int(base)
        if start < minimum or end > maximum or start > end:
            raise ValueError(f"cron field out of range: '{field}'")
        values.update(range(start, end + 1, step))
    if not values:
        raise ValueError(f"empty cron field: '{field}'")
    return values


def parse_cron(expr: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    """Parse a 5-field cron expression: minute hour day-of-month month day-of-week."""
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("cron must have 5 fields: minute hour dom month dow")
    minute, hour, dom, month, dow = parts
    return (
        _parse_cron_field(minute, 0, 59),
        _parse_cron_field(hour, 0, 23),
        _parse_cron_field(dom, 1, 31),
        _parse_cron_field(month, 1, 12),
        _parse_cron_field(dow, 0, 6),  # 0 = Sunday
    )


def _dow_sunday0(dt: datetime) -> int:
    # Python: Monday=0 … Sunday=6 → cron: Sunday=0 … Saturday=6
    return (dt.weekday() + 1) % 7


def next_cron_time(expr: str, after: datetime | None = None) -> datetime:
    """Return the next UTC datetime matching a 5-field cron expression."""
    minutes, hours, doms, months, dows = parse_cron(expr)
    start = (after or datetime.now(UTC)).astimezone(UTC).replace(second=0, microsecond=0) + timedelta(
        minutes=1
    )

    candidate = start
    for _ in range(60 * 24 * 366 * 2):
        last_day = monthrange(candidate.year, candidate.month)[1]
        if (
            candidate.month in months
            and candidate.day <= last_day
            and candidate.day in doms
            and candidate.hour in hours
            and candidate.minute in minutes
            and _dow_sunday0(candidate) in dows
        ):
            return candidate
        candidate += timedelta(minutes=1)
    raise ValueError(f"could not find next fire time for cron '{expr}'")


def build_scan_command(config: AppConfig, config_path: str) -> list[str]:
    sched = config.scheduler
    mode = sched.mode or config.runtime.mode
    command = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        config_path,
        "--mode",
        mode,
    ]
    if sched.delta:
        command.append("--delta")
    if sched.skip_nse:
        command.append("--skip-nse")
    if sched.notify:
        command.append("--notify")
    return command


def _sleep_until(target: datetime) -> None:
    while True:
        remaining = (target - datetime.now(UTC)).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 30.0))


def run_scheduler(
    config: AppConfig,
    *,
    config_path: str,
    once: bool = False,
    dry_run: bool = False,
) -> int:
    sched = config.scheduler
    if not sched.enabled and not once:
        logging.error("scheduler.enabled is false; set scheduler.enabled: true or pass --once")
        return 2

    command = build_scan_command(config, config_path)
    logging.info("Scheduler scan command: %s", " ".join(command))

    if dry_run:
        if sched.interval_seconds > 0:
            fire_at = datetime.now(UTC) + timedelta(seconds=sched.interval_seconds)
        else:
            fire_at = next_cron_time(sched.cron)
        print(fire_at.isoformat())
        print(" ".join(command))
        return 0

    runs = 0
    last_code = 0
    while True:
        if not once:
            if sched.interval_seconds > 0:
                fire_at = datetime.now(UTC) + timedelta(seconds=sched.interval_seconds)
            else:
                fire_at = next_cron_time(sched.cron)
            logging.info("Next scan at %s UTC", fire_at.isoformat())
            _sleep_until(fire_at)

        logging.info("Starting scheduled scan #%s", runs + 1)
        completed = subprocess.run(command, check=False)
        last_code = completed.returncode
        logging.info("Scheduled scan finished with exit code %s", last_code)
        runs += 1

        if once:
            return last_code
        if sched.max_runs > 0 and runs >= sched.max_runs:
            logging.info("Reached scheduler.max_runs=%s, exiting", sched.max_runs)
            return 0


def main() -> int:
    args = parse_args()
    raw = load_yaml(Path(args.config))
    try:
        config = load_config(raw)
    except ValidationError as exc:
        print(format_validation_error(exc), file=sys.stderr)
        return 2

    log_dir = Path(config.runtime.output_dir) / "logs"
    setup_logging(log_dir / "scheduler.log")
    if os.environ.get("OCTO_SCHEDULER_ENABLED", "").lower() in {"1", "true", "yes"}:
        config = config.model_copy(
            update={"scheduler": config.scheduler.model_copy(update={"enabled": True})}
        )

    return run_scheduler(config, config_path=args.config, once=args.once, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
