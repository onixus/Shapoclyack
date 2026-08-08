"""Profiling harness over the P3.7 scale fixtures (ROADMAP P3.8).

Times the query paths that grow with asset count — the ClickHouse tenant-wide
diff helpers and the Postgres-backed asset list — so the provisional targets in
[docs/slo.md](../../docs/slo.md) can be re-derived from a measurement instead of
a guess, and so a change to either path can be shown to have helped.

Seed first with ``tests/fixtures/scale_seed.py`` (same ``--tenant``/``--seed``),
then::

    python -m tests.fixtures.scale_profile --markdown \\
        --postgres-url "$OCTO_POSTGRES_URL" --clickhouse-url "$OCTO_CLICKHOUSE_URL"

Numbers are wall-clock medians over ``--repeat`` runs after ``--warmup``
discarded runs, measured in-process against a local server. They are useful for
*comparing* shapes — this query vs. that one, before vs. after a fix — and are
not a production latency budget: no network, no concurrency, no contention.
ClickHouse rows/bytes read come from ``system.query_log`` and are exact, so
those are the durable half of the output.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable

from tests.fixtures.scale_seed import DEFAULT_TENANT, SeedSpec, asset_fqdn, asset_ip


@dataclass
class Measurement:
    name: str
    group: str
    median_ms: float
    p95_ms: float
    min_ms: float
    rows: int
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "group": self.group,
            "median_ms": round(self.median_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "min_ms": round(self.min_ms, 2),
            "rows": self.rows,
            "note": self.note,
        }


def measure(
    name: str,
    group: str,
    fn: Callable[[], Any],
    *,
    repeat: int,
    warmup: int,
    rows_of: Callable[[Any], int] = len,
    note: str = "",
) -> Measurement:
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    result: Any = None
    for _ in range(repeat):
        started = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - started) * 1000.0)
    samples.sort()
    # p95 of a small sample is the top observation, not an interpolation —
    # honest for repeat=5..20, and it is labelled as such in the output.
    p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
    try:
        rows = rows_of(result)
    except TypeError:
        rows = 0
    return Measurement(
        name=name,
        group=group,
        median_ms=statistics.median(samples),
        p95_ms=p95,
        min_ms=samples[0],
        rows=rows,
        note=note,
    )


# --------------------------------------------------------------------------
# ClickHouse
# --------------------------------------------------------------------------


def profile_clickhouse(url: str, tenant_id: str, *, repeat: int, warmup: int) -> list[Measurement]:
    from api.services import ch_diff

    return [
        measure(
            "ch_diff.fetch_tenant_cves",
            "clickhouse",
            lambda: ch_diff.fetch_tenant_cves(url, tenant_id),
            repeat=repeat,
            warmup=warmup,
            note="tenant-wide, no LIMIT",
        ),
        measure(
            "ch_diff.fetch_tenant_ports",
            "clickhouse",
            lambda: ch_diff.fetch_tenant_ports(url, tenant_id),
            repeat=repeat,
            warmup=warmup,
            note="tenant-wide, no LIMIT",
        ),
        measure(
            "ch_diff.compute_clickhouse_diff",
            "clickhouse",
            lambda: ch_diff.compute_clickhouse_diff(
                url, tenant_id=tenant_id, previous_cves=set(), previous_ports=set()
            ),
            repeat=repeat,
            warmup=warmup,
            rows_of=lambda r: r["counts"]["events"],
            note="both fetches + set diff; every row is 'added' vs. empty baseline",
        ),
    ]


def clickhouse_read_stats(url: str, tenant_id: str) -> list[dict[str, Any]]:
    """Exact rows/bytes read per query, straight from ``system.query_log``.

    Wall-clock is machine- and cache-dependent; read amplification is not, so
    this is the number worth recording in docs and comparing across changes.
    """
    from api.services import ch_diff, clickhouse_client as ch

    client = ch.get_client(url)
    probes: dict[str, Callable[[], Any]] = {
        "fetch_tenant_cves": lambda: ch_diff.fetch_tenant_cves(url, tenant_id),
        "fetch_tenant_ports": lambda: ch_diff.fetch_tenant_ports(url, tenant_id),
    }

    out: list[dict[str, Any]] = []
    for name, fn in probes.items():
        # Each probe is isolated by timestamp rather than by parsing the SQL
        # back out of the log: the helpers build their own statements, so the
        # harness must not depend on their text.
        client.command("SYSTEM FLUSH LOGS")
        since = client.query("SELECT now()").result_rows[0][0]
        fn()
        client.command("SYSTEM FLUSH LOGS")
        rows = client.query(
            """
            SELECT read_rows, read_bytes, query_duration_ms, result_rows
            FROM system.query_log
            WHERE type = 'QueryFinish'
              AND query LIKE '%shapoclyack.shapoclyack_%'
              AND query NOT LIKE '%system.%'
              AND event_time >= {since:DateTime}
            ORDER BY event_time_microseconds DESC
            LIMIT 1
            """,
            parameters={"since": since},
        ).result_rows
        if rows:
            read_rows, read_bytes, duration, result_rows = rows[0]
            out.append(
                {
                    "probe": name,
                    "read_rows": read_rows,
                    "read_bytes": read_bytes,
                    "result_rows": result_rows,
                    "server_ms": duration,
                }
            )
    return out


def clickhouse_table_stats(url: str) -> list[dict[str, Any]]:
    """Rows, on-disk size, part count and partition key per analytics table.

    ``partition_key`` lives on ``system.tables``; ``system.parts`` only knows
    the resolved ``partition_id``. An empty key is what an unpartitioned
    ``ReplacingMergeTree`` reports, and is exactly what P3.8 evaluates.
    """
    from api.services import clickhouse_client as ch

    client = ch.get_client(url)
    rows = client.query(
        """
        SELECT
            t.name,
            sum(p.rows),
            sum(p.bytes_on_disk),
            count(),
            any(t.partition_key),
            any(t.sorting_key)
        FROM system.tables AS t
        LEFT JOIN system.parts AS p
            ON p.database = t.database AND p.table = t.name AND p.active
        WHERE t.database = 'shapoclyack'
        GROUP BY t.name
        ORDER BY t.name
        """
    ).result_rows
    return [
        {
            "table": table,
            "rows": rows_count,
            "bytes_on_disk": disk,
            "active_parts": parts,
            "partition_key": partition_key or "(none)",
            "sorting_key": sorting_key,
        }
        for table, rows_count, disk, parts, partition_key, sorting_key in rows
    ]


# --------------------------------------------------------------------------
# Postgres / API
# --------------------------------------------------------------------------


def profile_postgres(
    url: str, tenant_id: str, *, assets: int, repeat: int, warmup: int, seed: int
) -> list[Measurement]:
    import dataclasses

    from api.services import assets as assets_service
    from api.settings import load_settings

    settings = dataclasses.replace(load_settings(), postgres_url=url)
    spec = SeedSpec(tenant_id=tenant_id, assets=assets, seed=seed)

    # An FQDN the seeder actually emitted — searching for one it skipped would
    # measure the empty-result path and flatter the numbers.
    from tests.fixtures.scale_seed import iter_identifier_rows

    sample_fqdn = next(
        (r["identifier_value"] for r in iter_identifier_rows(spec) if r["identifier_type"] == "fqdn"),
        asset_fqdn(0),
    )
    deep_offset = max(assets - 100, 0)

    def page(**kwargs):
        return assets_service.list_assets(settings, tenant_id, **kwargs)[0]

    measurements = [
        measure(
            "list_assets first page (limit=100)",
            "postgres",
            lambda: page(limit=100),
            repeat=repeat,
            warmup=warmup,
            note="default page size",
        ),
        measure(
            f"list_assets deep page (offset={deep_offset})",
            "postgres",
            lambda: page(limit=100, offset=deep_offset),
            repeat=repeat,
            warmup=warmup,
            note="OFFSET scan cost at the end of the list",
        ),
        measure(
            "list_assets max page (limit=5000)",
            "postgres",
            lambda: page(limit=5000),
            repeat=repeat,
            warmup=warmup,
            note="what the dashboard requests (MAX_LIMIT)",
        ),
        measure(
            "list_assets status filter",
            "postgres",
            lambda: page(limit=100, status="stale"),
            repeat=repeat,
            warmup=warmup,
            note="ix_assets_tenant_status",
        ),
        measure(
            "list_assets search by IP",
            "postgres",
            lambda: page(limit=100, q=asset_ip(assets // 2)),
            repeat=repeat,
            warmup=warmup,
            note="EXISTS subquery, lower() LIKE",
        ),
        measure(
            "list_assets search by FQDN",
            "postgres",
            lambda: page(limit=100, q=sample_fqdn),
            repeat=repeat,
            warmup=warmup,
        ),
        measure(
            "list_assets search prefix (many hits)",
            "postgres",
            lambda: page(limit=100, q="10.0.1."),
            repeat=repeat,
            warmup=warmup,
            note="leading-wildcard LIKE, no index usable",
        ),
        measure(
            "list_assets sort by criticality",
            "postgres",
            lambda: page(limit=100, sort="asset_criticality", order="asc"),
            repeat=repeat,
            warmup=warmup,
            note="unindexed sort column",
        ),
    ]

    from scanner.pipeline.asset_identity import ip_identity_key

    asset_id = ip_identity_key(tenant_id, asset_ip(assets // 2))
    measurements.append(
        measure(
            "get_asset (single)",
            "postgres",
            lambda: assets_service.get_asset(settings, tenant_id, asset_id),
            repeat=repeat,
            warmup=warmup,
            rows_of=lambda r: 1 if r else 0,
        )
    )
    return measurements


def postgres_query_counts(url: str, tenant_id: str, *, limit: int) -> dict[str, int]:
    """Count SQL round-trips for one ``list_assets`` call.

    Wall-clock hides an N+1: against a local socket each extra round-trip is
    sub-millisecond, but across a real network it is the dominant cost. Counting
    statements makes the shape visible regardless of where the DB sits.
    """
    import dataclasses

    from sqlalchemy import event

    from api.db.engine import get_engine
    from api.services import assets as assets_service
    from api.settings import load_settings

    settings = dataclasses.replace(load_settings(), postgres_url=url)
    engine = get_engine(url)
    counts: dict[str, int] = {"total": 0, "select_identifiers": 0}

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        counts["total"] += 1
        if "asset_identifiers" in statement and statement.strip().upper().startswith("SELECT"):
            counts["select_identifiers"] += 1

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        rows, _total = assets_service.list_assets(settings, tenant_id, limit=limit)
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)
    counts["returned_rows"] = len(rows)
    return counts


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _thousands(value: int) -> str:
    """Space-separated thousands, applied per number — formatting the whole
    row would also strip the commas out of the note text."""
    return f"{value:,}".replace(",", " ")


def render_markdown(assets: int, measurements: list[Measurement]) -> str:
    lines = [
        f"### {_thousands(assets)} assets",
        "",
        "| Query | Median | p95 | Rows | Note |",
        "|---|---:|---:|---:|---|",
    ]
    for m in measurements:
        lines.append(
            f"| `{m.name}` | {m.median_ms:.1f} ms | {m.p95_ms:.1f} ms "
            f"| {_thousands(m.rows)} | {m.note} |"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.fixtures.scale_profile",
        description="Profile the diff/assets-list query paths over a seeded fixture (ROADMAP P3.8).",
    )
    parser.add_argument("--assets", type=int, default=10000, help="asset count already seeded")
    parser.add_argument("--tenant", default=DEFAULT_TENANT)
    parser.add_argument("--seed", type=int, default=1337, help="must match the seed run")
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--postgres-url", default="")
    parser.add_argument("--clickhouse-url", default="")
    parser.add_argument("--skip-postgres", action="store_true")
    parser.add_argument("--skip-clickhouse", action="store_true")
    parser.add_argument("--markdown", action="store_true", help="emit a Markdown table")
    parser.add_argument("--json", action="store_true", help="emit JSON")
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
        print("error: both stores skipped — nothing to profile", file=sys.stderr)
        return 2

    measurements: list[Measurement] = []
    extras: dict[str, Any] = {}

    if use_clickhouse:
        measurements.extend(
            profile_clickhouse(clickhouse_url, args.tenant, repeat=args.repeat, warmup=args.warmup)
        )
        extras["clickhouse_read_stats"] = clickhouse_read_stats(clickhouse_url, args.tenant)
        extras["clickhouse_tables"] = clickhouse_table_stats(clickhouse_url)

    if use_postgres:
        measurements.extend(
            profile_postgres(
                postgres_url,
                args.tenant,
                assets=args.assets,
                repeat=args.repeat,
                warmup=args.warmup,
                seed=args.seed,
            )
        )
        extras["postgres_query_counts"] = {
            "limit_100": postgres_query_counts(postgres_url, args.tenant, limit=100),
            "limit_5000": postgres_query_counts(postgres_url, args.tenant, limit=5000),
        }

    if args.json:
        print(
            json.dumps(
                {
                    "assets": args.assets,
                    "tenant_id": args.tenant,
                    "repeat": args.repeat,
                    "measurements": [m.as_dict() for m in measurements],
                    **extras,
                },
                indent=2,
            )
        )
    elif args.markdown:
        print(render_markdown(args.assets, measurements))
        print()
        for key, value in extras.items():
            print(f"<!-- {key}: {json.dumps(value)} -->")
    else:
        for m in measurements:
            print(f"{m.group:<11} {m.name:<44} {m.median_ms:8.1f} ms  rows={m.rows}")
        for key, value in extras.items():
            print(f"{key}: {json.dumps(value)}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
