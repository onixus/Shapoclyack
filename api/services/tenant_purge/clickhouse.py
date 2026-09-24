"""The ClickHouse half of a tenant purge (#325).

The analytics tables key a tenant by ``uuid5`` of its id
(``ch_transform.tenant_to_uuid``), and each is emptied with a mutation —
``ALTER TABLE … DELETE`` with ``mutations_sync = 2`` — rather than a lightweight
``DELETE``: a lightweight delete only masks the rows until a merge gets round to
them, and "deleted" has to mean the bytes are gone, not hidden. The mutation is
idempotent, so an attempt that died while one was running simply issues it
again; the step then counts what is left and fails if anything is.

Tables are the three the ingest worker writes (``clickhouse_client``). One that
does not exist — an installation whose controls table was never created —
holds nothing to delete. ``OCTO_CLICKHOUSE_URL`` unset skips the step, and the
tombstone says so.
"""

from __future__ import annotations

import uuid
from typing import Any

from api.services import ch_transform
from api.services import clickhouse_client
from api.services.tenant_purge.context import PurgeContext, StepSkipped

#: ``(short name for the tombstone, fully qualified table)``.
TABLES = (
    ("vulnerabilities", clickhouse_client.VULN_TABLE),
    ("open_ports", clickhouse_client.PORTS_TABLE),
    ("controls", clickhouse_client.CONTROLS_TABLE),
)


def _uuid_literal(tenant_id: str) -> str:
    """The tenant's key as a ClickHouse literal. Built from a parsed UUID, so
    the only characters that can reach the statement are hex digits and dashes."""
    return f"toUUID('{uuid.UUID(str(ch_transform.tenant_to_uuid(tenant_id)))}')"


def _count(client: Any, table: str, key: str) -> int:
    # Table names are module constants and ``key`` is _uuid_literal's output;
    # nothing here is caller-supplied text.
    return int(client.command(f"SELECT count() FROM {table} WHERE tenant_id = {key}") or 0)


def _exists(client: Any, table: str) -> bool:
    return bool(int(client.command(f"EXISTS TABLE {table}") or 0))


def run(ctx: PurgeContext) -> dict[str, Any]:
    url = (ctx.settings.clickhouse_url or "").strip()
    if not url:
        raise StepSkipped("ClickHouse is not configured (OCTO_CLICKHOUSE_URL)")
    client = clickhouse_client.get_client(url)
    key = _uuid_literal(ctx.tenant_id)
    for short, table in TABLES:
        ctx.checkpoint()
        if not _exists(client, table):
            continue
        before = _count(client, table, key)
        if before:
            client.command(
                f"ALTER TABLE {table} DELETE WHERE tenant_id = {key}",
                settings={"mutations_sync": 2},
            )
        after = _count(client, table, key)
        if after:
            raise RuntimeError(f"{after} row(s) remain in {table} after the delete")
        # Recorded per table as it is done, so an attempt that fails on the
        # next one does not lose what this one removed.
        with ctx.guard() as session:
            ctx.add_counts(session, {short: before})
    return {short: 0 for short, _table in TABLES}
