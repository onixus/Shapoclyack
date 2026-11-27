#!/usr/bin/env python3
"""CLI entry for the throughput OKR Measure harness (FTT-PULSE-2026-055).

Delegates to ``tests.fixtures.throughput_measure``. No packets are sent.

Examples::

    python3 scripts/throughput_okr_measure.py fixtures
    python3 scripts/throughput_okr_measure.py runs-dir /var/lib/shapoclyack/output/runs \\
        --cohort inventory --out /tmp/inventory-baseline.json
    python3 scripts/throughput_okr_model.py \\
        --calibration docs/benchmarks/throughput-okr-estate-baseline/calibration.json
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.fixtures.throughput_measure import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
