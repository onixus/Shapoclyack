"""CLI entry: ``python -m agent``."""

from __future__ import annotations

from agent.worker import main

if __name__ == "__main__":
    raise SystemExit(main())
