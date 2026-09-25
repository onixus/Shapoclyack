"""Per-stage wall-clock timing for scanner pipeline runs.

Writes machine-readable ``stage_timings.json`` and a ranked log line so
operators can see which stage dominates without OpenTelemetry.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")

logger = logging.getLogger(__name__)


def process_resources() -> dict[str, float] | None:
    """CPU-seconds and peak memory of this scan and of the tools it ran (#337).

    Per run, not per stage: stages overlap (Pulse and NSE run concurrently),
    and a child's usage is only credited once it has been waited for, so a
    per-stage split would be wrong in exactly the runs worth measuring. For
    the whole pipeline it is exact, and it is what sizing a sensor needs:
    ``scale_measure runs-dir`` fits CPU-seconds per host from it.

    ``children_max_rss_mb`` is the largest *single* tool process (one nmap,
    one nuclei), not the sum of those that ran side by side.
    """
    try:
        import resource
    except ImportError:  # pragma: no cover - no getrusage on Windows
        return None
    own = resource.getrusage(resource.RUSAGE_SELF)
    tools = resource.getrusage(resource.RUSAGE_CHILDREN)
    # ru_maxrss is KiB on Linux and bytes on macOS.
    unit = 1 if sys.platform == "darwin" else 1024
    return {
        "cpu_sec": round(own.ru_utime + own.ru_stime, 3),
        "children_cpu_sec": round(tools.ru_utime + tools.ru_stime, 3),
        "max_rss_mb": round(own.ru_maxrss * unit / 2**20, 1),
        "children_max_rss_mb": round(tools.ru_maxrss * unit / 2**20, 1),
    }


@dataclass
class StageRecord:
    name: str
    duration_sec: float
    status: str = "ok"  # ok | skipped | error
    detail: str = ""


@dataclass
class StageTimer:
    """Collect stage durations for one pipeline run."""

    records: list[StageRecord] = field(default_factory=list)
    _pipeline_t0: float = field(default_factory=time.perf_counter)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _append(self, record: StageRecord) -> None:
        with self._lock:
            self.records.append(record)

    def run(self, name: str, func: Callable[[], T], *, detail: str = "") -> T:
        """Time ``func``; re-raise after recording status=error on failure."""
        t0 = time.perf_counter()
        try:
            result = func()
        except Exception:
            self._append(
                StageRecord(
                    name=name,
                    duration_sec=round(time.perf_counter() - t0, 3),
                    status="error",
                    detail=detail,
                )
            )
            raise
        elapsed = round(time.perf_counter() - t0, 3)
        self._append(StageRecord(name=name, duration_sec=elapsed, status="ok", detail=detail))
        logger.info("stage %s finished in %.3fs%s", name, elapsed, f" ({detail})" if detail else "")
        return result

    def skip(self, name: str, reason: str = "checkpoint") -> None:
        self._append(StageRecord(name=name, duration_sec=0.0, status="skipped", detail=reason))
        logger.info("stage %s skipped (%s)", name, reason)

    def pipeline_elapsed_sec(self) -> float:
        return round(time.perf_counter() - self._pipeline_t0, 3)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            snapshot = list(self.records)
        total_stages = round(sum(r.duration_sec for r in snapshot if r.status != "skipped"), 3)
        ranked = sorted(
            [r for r in snapshot if r.status == "ok"],
            key=lambda r: r.duration_sec,
            reverse=True,
        )
        return {
            "pipeline_wall_sec": self.pipeline_elapsed_sec(),
            "stages_sum_sec": total_stages,
            "stages": [
                {
                    "name": r.name,
                    "duration_sec": r.duration_sec,
                    "status": r.status,
                    **({"detail": r.detail} if r.detail else {}),
                }
                for r in snapshot
            ],
            "top_stages": [
                {"name": r.name, "duration_sec": r.duration_sec} for r in ranked[:8]
            ],
            "resources": process_resources(),
        }

    def write(self, output_dir: Path) -> Path:
        path = output_dir / "stage_timings.json"
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = self.as_dict()
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        top = ", ".join(f"{t['name']}={t['duration_sec']:.1f}s" for t in payload["top_stages"][:5])
        logger.info(
            "stage timings: pipeline_wall=%.1fs stages_sum=%.1fs top=[%s] → %s",
            payload["pipeline_wall_sec"],
            payload["stages_sum_sec"],
            top or "none",
            path,
        )
        return path
