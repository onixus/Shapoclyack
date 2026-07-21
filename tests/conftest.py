"""Shared test fixtures/constants.

Phase 7 made the tenant store Postgres-backed (api/services/tenants.py) —
unlike the opt-in NATS/ClickHouse sidecars, any test that builds a FastAPI
app now needs a real, migrated Postgres reachable at OCTO_POSTGRES_URL. CI
provides this via a postgres:16-alpine service container (.github/workflows/
ci.yml); locally, tests needing it are skipped when the env var is unset,
matching how tests/test_nats_live.py gates on OCTO_NATS_URL.
"""

from __future__ import annotations

import os

import pytest

POSTGRES_URL = (os.environ.get("OCTO_POSTGRES_URL") or os.environ.get("POSTGRES_URL") or "").strip()

requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="OCTO_POSTGRES_URL not set — tenant store is Postgres-backed (Phase 7); "
    "run `alembic -c api/db/alembic.ini upgrade head` against a local Postgres first.",
)
