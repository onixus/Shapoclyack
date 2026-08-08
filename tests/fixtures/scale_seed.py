"""Bulk fixture generator for 1k / 10k / 50k-asset scale testing (ROADMAP P3.7).

Seeds the two stores that actually grow with asset count:

* **Postgres** — ``assets`` + ``asset_identifiers`` (the registry behind
  ``GET /api/assets`` and its pagination/search path).
* **ClickHouse** — ``shapoclyack_vulnerabilities`` + ``shapoclyack_open_ports``
  (the tables ``api/services/ch_diff.py`` scans unbounded today).

This is a *data* generator, not a traffic generator: ``tests/load/run.sh``
already covers network load against live targets, and it produces one run's
worth of hosts — nowhere near 50k assets, and nothing in ClickHouse. The two
are complementary and neither replaces the other.

Everything is derived from ``--seed`` and the asset index, so two runs with the
same arguments produce byte-identical rows: reruns are idempotent at the row
level (both stores are keyed/``ReplacingMergeTree``-deduped on what we emit),
and a profiling measurement can be reproduced later. The row-building half is
pure — no DB, no clock — so ``tests/test_scale_seed.py`` exercises it in CI
without either service running.

Usage::

    # 10k assets into a local dev stack
    python -m tests.fixtures.scale_seed --assets 10000 \\
        --postgres-url postgresql+psycopg://octo:octo@localhost:5432/shapoclyack \\
        --clickhouse-url http://localhost:8123

    # Postgres only, then clean up afterwards
    python -m tests.fixtures.scale_seed --assets 1000 --skip-clickhouse
    python -m tests.fixtures.scale_seed --purge --skip-clickhouse

URLs fall back to ``OCTO_POSTGRES_URL`` / ``OCTO_CLICKHOUSE_URL``. The default
tenant is ``scale-test`` rather than ``default`` on purpose — ``--purge`` is a
tenant-scoped delete, and pointing it at a tenant holding real scan data would
destroy it.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Iterator

# Weighted so a seeded registry exercises the status filter on /api/assets
# rather than being uniformly "active".
STATUS_WEIGHTS: tuple[tuple[str, float], ...] = (
    ("active", 0.85),
    ("stale", 0.12),
    ("decommissioned", 0.03),
)

# Ports a real external scan actually turns up, not a uniform 1–65535 draw:
# port cardinality drives the ReplacingMergeTree ORDER BY key, so a realistic
# distribution matters for the 3.8 profiling pass.
PORT_POOL: tuple[int, ...] = (
    21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
    8080, 8443, 8888, 9000, 9200, 11211, 27017,
)

PROTOCOLS: tuple[str, ...] = ("tcp", "tcp", "tcp", "udp")

# Matches the Enum8 in k8s/shapoclyack/base/clickhouse/init-local.sql — an
# out-of-range string is rejected by ClickHouse at insert time.
CISA_DECISIONS: tuple[str, ...] = ("Track", "Attend", "Act", "Immediate")

SCORING_MODEL_VERSION = "mvp-2"

DEFAULT_TENANT = "scale-test"
DEFAULT_CVE_POOL = 2000


@dataclass(frozen=True)
class SeedSpec:
    """Everything that determines the generated rows. Hash it, not the clock."""

    tenant_id: str = DEFAULT_TENANT
    assets: int = 1000
    vulns_per_asset: int = 3
    ports_per_asset: int = 4
    fqdn_ratio: float = 0.35
    cve_pool: int = DEFAULT_CVE_POOL
    days_back: int = 30
    seed: int = 1337
    # Injected rather than read from the clock so generated rows stay
    # reproducible; the CLI passes datetime.now(UTC).
    now: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=UTC)
    )


@dataclass(frozen=True)
class SeedStats:
    assets: int = 0
    identifiers: int = 0
    vulnerabilities: int = 0
    ports: int = 0
    postgres_seconds: float = 0.0
    clickhouse_seconds: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "assets": self.assets,
            "identifiers": self.identifiers,
            "vulnerabilities": self.vulnerabilities,
            "ports": self.ports,
            "postgres_seconds": round(self.postgres_seconds, 3),
            "clickhouse_seconds": round(self.clickhouse_seconds, 3),
        }


# --------------------------------------------------------------------------
# Pure row generation (no DB, no clock)
# --------------------------------------------------------------------------


def _rng(spec: SeedSpec, index: int, stream: str) -> random.Random:
    """Per-asset, per-stream RNG.

    Deriving from ``(seed, index, stream)`` instead of advancing one shared
    generator means the vulnerability rows for asset #9000 are identical
    whether or not ports were generated first, and whatever batch size the
    caller chose. That independence is what makes partial reruns comparable.
    """
    return random.Random(f"{spec.seed}:{stream}:{index}")


def asset_ip(index: int) -> str:
    """Map an asset index onto 10.0.0.0/8 — 16.7M addresses, ample for 50k.

    ``.0``/``.255`` hosts are not skipped: these are fixture rows, never
    routed, and skipping would break the index↔IP bijection that makes
    ``--purge``-free reruns idempotent.
    """
    if index < 0 or index >= 1 << 24:
        raise ValueError(f"asset index out of 10.0.0.0/8 range: {index}")
    return f"10.{(index >> 16) & 0xFF}.{(index >> 8) & 0xFF}.{index & 0xFF}"


def asset_fqdn(index: int) -> str:
    return f"host-{index:06d}.scale.example.net"


def cve_id(spec: SeedSpec, slot: int) -> str:
    """Deterministic CVE from a fixed-size pool.

    A shared pool (not a unique CVE per row) is the point: real tenants have
    the same CVE across many hosts, and that overlap is what makes
    ``fetch_tenant_cves`` set-building and any future GROUP BY behave
    realistically.
    """
    slot %= max(spec.cve_pool, 1)
    return f"CVE-{2015 + (slot % 11)}-{10000 + slot}"


def _seen_window(spec: SeedSpec, index: int) -> tuple[datetime, datetime]:
    rng = _rng(spec, index, "seen")
    last_seen = spec.now - timedelta(seconds=rng.randrange(spec.days_back * 86400))
    first_seen = last_seen - timedelta(days=rng.randrange(1, 365))
    return first_seen, last_seen


def _status(spec: SeedSpec, index: int) -> str:
    draw = _rng(spec, index, "status").random()
    cumulative = 0.0
    for status, weight in STATUS_WEIGHTS:
        cumulative += weight
        if draw < cumulative:
            return status
    return STATUS_WEIGHTS[-1][0]


def iter_asset_rows(spec: SeedSpec) -> Iterator[dict[str, Any]]:
    """Yield ``assets`` rows as dicts keyed by column name."""
    from scanner.pipeline.asset_identity import ip_identity_key

    for index in range(spec.assets):
        first_seen, last_seen = _seen_window(spec, index)
        rng = _rng(spec, index, "criticality")
        # ~70 % unset: criticality is operator-set (Phase 9.4), so most assets
        # legitimately have none and fall back to the port/severity heuristic.
        criticality = None if rng.random() < 0.7 else rng.randrange(0, 5)
        yield {
            "asset_id": ip_identity_key(spec.tenant_id, asset_ip(index)),
            "tenant_id": spec.tenant_id,
            "status": _status(spec, index),
            "first_seen": first_seen.replace(tzinfo=None),
            "last_seen": last_seen.replace(tzinfo=None),
            "owner_email": None,
            "business_unit": f"bu-{index % 12:02d}",
            "asset_criticality": criticality,
        }


def iter_identifier_rows(spec: SeedSpec) -> Iterator[dict[str, Any]]:
    """Yield ``asset_identifiers`` rows: always an IP, sometimes an FQDN.

    Both identifiers hang off the *same* ``asset_id`` (the IP-derived key),
    mirroring ``assets_service.upsert_assets_from_run`` — one asset per host
    record, not one per identifier.
    """
    from scanner.pipeline.asset_identity import ip_identity_key

    for index in range(spec.assets):
        ip = asset_ip(index)
        asset_id = ip_identity_key(spec.tenant_id, ip)
        yield {
            "asset_id": asset_id,
            "tenant_id": spec.tenant_id,
            "identifier_type": "ip",
            "identifier_value": ip,
        }
        if _rng(spec, index, "fqdn").random() < spec.fqdn_ratio:
            yield {
                "asset_id": asset_id,
                "tenant_id": spec.tenant_id,
                "identifier_type": "fqdn",
                "identifier_value": asset_fqdn(index),
            }


def iter_vulnerability_rows(spec: SeedSpec) -> Iterator[list[Any]]:
    """Yield ClickHouse rows in ``clickhouse_client.VULN_COLUMNS`` order."""
    from api.services.ch_transform import tenant_to_uuid

    tenant_uuid = tenant_to_uuid(spec.tenant_id)
    for index in range(spec.assets):
        ip = asset_ip(index)
        rng = _rng(spec, index, "vuln")
        ts = (spec.now - timedelta(seconds=rng.randrange(spec.days_back * 86400))).replace(
            tzinfo=None
        )
        emitted: set[str] = set()
        for _ in range(spec.vulns_per_asset):
            cve = cve_id(spec, rng.randrange(spec.cve_pool))
            # ReplacingMergeTree collapses duplicate (tenant, ip, cve) keys, so
            # emitting them would silently undershoot the requested row count.
            if cve in emitted:
                continue
            emitted.add(cve)
            base_cvss = round(rng.uniform(1.0, 10.0), 1)
            epss = round(rng.random() ** 3, 4)  # skewed low, like real EPSS
            exploit_active = 1 if rng.random() < 0.08 else 0
            yield [
                tenant_uuid,
                ip,
                cve,
                float(base_cvss),
                float(epss),
                rng.randrange(0, 5),
                exploit_active,
                CISA_DECISIONS[min(int(base_cvss / 2.6), 3)],
                round(min(base_cvss * (1.0 + epss), 10.0), 2),
                SCORING_MODEL_VERSION,
                ts,
            ]


def iter_port_rows(spec: SeedSpec, *, run_id: str) -> Iterator[list[Any]]:
    """Yield ClickHouse rows in ``clickhouse_client.PORT_COLUMNS`` order."""
    from api.services.ch_transform import tenant_to_uuid

    tenant_uuid = tenant_to_uuid(spec.tenant_id)
    for index in range(spec.assets):
        ip = asset_ip(index)
        rng = _rng(spec, index, "port")
        ts = (spec.now - timedelta(seconds=rng.randrange(spec.days_back * 86400))).replace(
            tzinfo=None
        )
        # Sampled without replacement: the ORDER BY key is (tenant, ip, port),
        # so a repeated port on one host would be deduped away.
        count = min(spec.ports_per_asset, len(PORT_POOL))
        for port in rng.sample(PORT_POOL, count):
            yield [tenant_uuid, ip, port, rng.choice(PROTOCOLS), run_id, ts]


def _batched(rows: Iterator[Any], size: int) -> Iterator[list[Any]]:
    batch: list[Any] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


# --------------------------------------------------------------------------
# Postgres
# --------------------------------------------------------------------------


def seed_postgres(url: str, spec: SeedSpec, *, batch_size: int = 5000) -> tuple[int, int]:
    """Bulk-insert assets + identifiers. Returns ``(assets, identifiers)``."""
    from sqlalchemy import insert as core_insert
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from api.db import models
    from api.db.engine import get_engine

    engine = get_engine(url)  # also create_all()s the schema
    _ensure_tenant(url, spec.tenant_id)

    def _statement(entity, conflict_index: list[str]):
        if engine.dialect.name == "postgresql":
            # Reruns must be idempotent rather than exploding on the primary
            # key / uq_asset_identifier. sqlite (the settings fallback) has no
            # portable equivalent here, so it is left to fail loudly instead of
            # silently diverging from what Postgres would have stored.
            return pg_insert(entity).on_conflict_do_nothing(index_elements=conflict_index)
        return core_insert(entity)

    asset_stmt = _statement(models.Asset, ["asset_id"])
    identifier_stmt = _statement(
        models.AssetIdentifier, ["tenant_id", "identifier_type", "identifier_value"]
    )

    assets = 0
    for batch in _batched(iter_asset_rows(spec), batch_size):
        with engine.begin() as conn:
            conn.execute(asset_stmt, batch)  # executemany
        assets += len(batch)

    identifiers = 0
    for batch in _batched(iter_identifier_rows(spec), batch_size):
        with engine.begin() as conn:
            conn.execute(identifier_stmt, batch)
        identifiers += len(batch)

    return assets, identifiers


def _ensure_tenant(url: str, tenant_id: str) -> None:
    """Create the tenant row if absent — ``assets.tenant_id`` is an FK."""
    from sqlalchemy import select

    from api.db import models
    from api.db.engine import get_session

    with get_session(url) as session:
        exists = session.execute(
            select(models.Tenant.tenant_id).where(models.Tenant.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if exists is None:
            session.add(
                models.Tenant(
                    tenant_id=tenant_id,
                    name=f"{tenant_id} (scale fixture)",
                    status="active",
                    created_at=datetime.now(UTC).replace(tzinfo=None),
                )
            )


def purge_postgres(url: str, tenant_id: str) -> dict[str, int]:
    """Delete every seeded row for ``tenant_id``. The tenant row itself stays."""
    from sqlalchemy import delete, select

    from api.db import models
    from api.db.engine import get_session

    with get_session(url) as session:
        asset_ids = select(models.Asset.asset_id).where(models.Asset.tenant_id == tenant_id)
        tags = session.execute(
            delete(models.AssetTag).where(models.AssetTag.asset_id.in_(asset_ids))
        ).rowcount
        identifiers = session.execute(
            delete(models.AssetIdentifier).where(models.AssetIdentifier.tenant_id == tenant_id)
        ).rowcount
        assets = session.execute(
            delete(models.Asset).where(models.Asset.tenant_id == tenant_id)
        ).rowcount
    return {"assets": assets or 0, "identifiers": identifiers or 0, "asset_tags": tags or 0}


# --------------------------------------------------------------------------
# ClickHouse
# --------------------------------------------------------------------------


def seed_clickhouse(
    url: str, spec: SeedSpec, *, batch_size: int = 50000, run_id: str = "scale-seed"
) -> tuple[int, int]:
    """Bulk-insert vulnerability + port rows. Returns ``(vulns, ports)``."""
    from api.services import clickhouse_client as ch

    client = ch.get_client(url)

    vulns = 0
    for batch in _batched(iter_vulnerability_rows(spec), batch_size):
        vulns += ch.insert_rows(client, ch.VULN_TABLE, ch.VULN_COLUMNS, batch)

    ports = 0
    for batch in _batched(iter_port_rows(spec, run_id=run_id), batch_size):
        ports += ch.insert_rows(client, ch.PORTS_TABLE, ch.PORT_COLUMNS, batch)

    return vulns, ports


def purge_clickhouse(url: str, tenant_id: str) -> None:
    """Delete a tenant's rows from both analytics tables.

    ``ALTER TABLE … DELETE`` is an asynchronous mutation: it returns before the
    parts are rewritten, so a ``SELECT count()`` immediately afterwards can
    still see rows. Poll ``system.mutations`` if you need to block on it.
    """
    from api.services import clickhouse_client as ch
    from api.services.ch_transform import tenant_to_uuid

    client = ch.get_client(url)
    tid = str(tenant_to_uuid(tenant_id))
    for table in (ch.VULN_TABLE, ch.PORTS_TABLE):
        client.command(
            f"ALTER TABLE {table} DELETE WHERE tenant_id = {{tid:UUID}}",
            parameters={"tid": tid},
        )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.fixtures.scale_seed",
        description="Seed Postgres + ClickHouse with N synthetic assets (ROADMAP P3.7).",
    )
    parser.add_argument("--assets", type=int, default=1000, help="asset count (1k/10k/50k)")
    parser.add_argument("--tenant", default=DEFAULT_TENANT, help=f"tenant id (default: {DEFAULT_TENANT})")
    parser.add_argument("--vulns-per-asset", type=int, default=3)
    parser.add_argument("--ports-per-asset", type=int, default=4)
    parser.add_argument("--fqdn-ratio", type=float, default=0.35, help="fraction of assets with an FQDN identifier")
    parser.add_argument("--cve-pool", type=int, default=DEFAULT_CVE_POOL, help="distinct CVEs to draw from")
    parser.add_argument("--days-back", type=int, default=30, help="spread timestamps over this many days")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--batch-size", type=int, default=5000, help="Postgres insert batch")
    parser.add_argument("--ch-batch-size", type=int, default=50000, help="ClickHouse insert batch")
    parser.add_argument("--run-id", default="scale-seed", help="run_id stamped on port rows")
    parser.add_argument("--postgres-url", default="", help="defaults to $OCTO_POSTGRES_URL")
    parser.add_argument("--clickhouse-url", default="", help="defaults to $OCTO_CLICKHOUSE_URL")
    parser.add_argument("--skip-postgres", action="store_true")
    parser.add_argument("--skip-clickhouse", action="store_true")
    parser.add_argument(
        "--purge",
        action="store_true",
        help="delete the tenant's seeded rows instead of inserting (destructive, tenant-scoped)",
    )
    parser.add_argument("--json", action="store_true", help="emit the summary as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    postgres_url = (args.postgres_url or os.environ.get("OCTO_POSTGRES_URL", "")).strip()
    clickhouse_url = (args.clickhouse_url or os.environ.get("OCTO_CLICKHOUSE_URL", "")).strip()

    use_postgres = not args.skip_postgres
    use_clickhouse = not args.skip_clickhouse

    if use_postgres and not postgres_url:
        print("error: no Postgres URL (--postgres-url or $OCTO_POSTGRES_URL)", file=sys.stderr)
        return 2
    if use_clickhouse and not clickhouse_url:
        print("error: no ClickHouse URL (--clickhouse-url or $OCTO_CLICKHOUSE_URL)", file=sys.stderr)
        return 2
    if not use_postgres and not use_clickhouse:
        print("error: both stores skipped — nothing to do", file=sys.stderr)
        return 2

    if args.purge:
        if use_postgres:
            deleted = purge_postgres(postgres_url, args.tenant)
            print(f"[purge] postgres tenant={args.tenant} {deleted}")
        if use_clickhouse:
            purge_clickhouse(clickhouse_url, args.tenant)
            print(f"[purge] clickhouse tenant={args.tenant} (mutation submitted, async)")
        return 0

    spec = SeedSpec(
        tenant_id=args.tenant,
        assets=args.assets,
        vulns_per_asset=args.vulns_per_asset,
        ports_per_asset=args.ports_per_asset,
        fqdn_ratio=args.fqdn_ratio,
        cve_pool=args.cve_pool,
        days_back=args.days_back,
        seed=args.seed,
        now=datetime.now(UTC),
    )

    assets = identifiers = vulns = ports = 0
    pg_seconds = ch_seconds = 0.0

    if use_postgres:
        started = time.monotonic()
        assets, identifiers = seed_postgres(postgres_url, spec, batch_size=args.batch_size)
        pg_seconds = time.monotonic() - started
        print(f"[postgres] assets={assets} identifiers={identifiers} in {pg_seconds:.1f}s")

    if use_clickhouse:
        started = time.monotonic()
        vulns, ports = seed_clickhouse(
            clickhouse_url, spec, batch_size=args.ch_batch_size, run_id=args.run_id
        )
        ch_seconds = time.monotonic() - started
        print(f"[clickhouse] vulnerabilities={vulns} ports={ports} in {ch_seconds:.1f}s")

    stats = SeedStats(
        assets=assets,
        identifiers=identifiers,
        vulnerabilities=vulns,
        ports=ports,
        postgres_seconds=pg_seconds,
        clickhouse_seconds=ch_seconds,
    )
    if args.json:
        print(json.dumps({"tenant_id": spec.tenant_id, "seed": spec.seed, **stats.as_dict()}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
