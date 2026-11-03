#!/usr/bin/env python3
"""CLI entry point for the tenant artifact migration (#311)."""

from api.services.legacy_artifact_migration import main


if __name__ == "__main__":
    raise SystemExit(main())
