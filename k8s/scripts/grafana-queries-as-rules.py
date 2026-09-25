#!/usr/bin/env python3
"""Write every PromQL query of the Grafana dashboards as a rules file (#334).

promtool has no command that checks a bare expression, but ``promtool check
rules`` parses every expression in a rules file. Each panel query becomes one
recording rule, so ``validate-prometheus-rules.sh`` catches a dashboard query
that would not parse the same way it catches a broken alert — before an
operator opens a panel that says "parse error".

Grafana's own variables are not PromQL, so they are replaced by something of
the same kind first: the interval variables by a duration, the dashboard
variables (only ever used inside a ``=~"…"`` matcher) by ``.*``.

Stdlib only, and the output is JSON — which is YAML — so this runs on a CI
agent that has python3 and nothing else.

Usage: grafana-queries-as-rules.py OUT_FILE
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARDS = ROOT / "shapoclyack/base/grafana-dashboards"

_DURATIONS = {"__rate_interval": "5m", "__interval": "1m", "__range": "1h"}
_VARIABLE = re.compile(r"\$\{?(\w+)\}?")


def _substitute(expr: str) -> str:
    return _VARIABLE.sub(lambda match: _DURATIONS.get(match.group(1), ".*"), expr)


def queries() -> Iterator[tuple[str, int, str, str]]:
    """``(dashboard file, panel id, refId, expr)`` for every panel query."""
    for path in sorted(DASHBOARDS.glob("*.json")):
        board = json.loads(path.read_text(encoding="utf-8"))
        for panel in board["panels"]:
            for target in panel.get("targets", []):
                yield path.name, panel["id"], target["refId"], target["expr"]


def main(out: Path) -> None:
    rules = [
        {
            "record": f"dashboard_query_{index}",
            "expr": _substitute(expr),
            "labels": {"dashboard": name, "panel": str(panel_id), "ref_id": ref_id},
        }
        for index, (name, panel_id, ref_id, expr) in enumerate(queries())
    ]
    if not rules:
        raise SystemExit(f"no dashboard queries found under {DASHBOARDS}")
    out.write_text(
        json.dumps({"groups": [{"name": "grafana-dashboard-queries", "rules": rules}]}, indent=1),
        encoding="utf-8",
    )
    print(f"{len(rules)} dashboard queries written to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: grafana-queries-as-rules.py OUT_FILE")
    main(Path(sys.argv[1]))
