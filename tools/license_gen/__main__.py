"""Entry point for ``python -m tools.license_gen``."""

from __future__ import annotations

import sys

from tools.license_gen.cli import main

if __name__ == "__main__":
    sys.exit(main())
