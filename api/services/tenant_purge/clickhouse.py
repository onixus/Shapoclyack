"""The ClickHouse half of a tenant purge (#325).

The analytics tables key a tenant by ``uuid5`` of its id
(``ch_transform.tenant_to_uuid``), and each is emptied with a mutation —
``ALTER TABLE … DELETE`` — rather than a lightweight ``DELETE``: a lightweight
delete only masks the rows until a merge gets round to them, and "deleted" has
to mean the bytes are gone, not hidden.

**Submitted, then watched.** A mutation on a large table runs for longer than
the client's five-minute read timeout, and waiting for it inside the statement
(``mutations_sync``) turned that into a step failure while the mutation went
on server-side — after which the retry submitted a second one beside it. So the
statement is submitted without waiting, and the step polls
``system.mutations`` for it, renewing the purge's lease between polls. A retry
first looks there: an unfinished mutation for this tenant on this table is
waited for, never submitted again. One that keeps failing (``latest_fail_reason``)
fails the step with ClickHouse's own reason; ClickHouse retries it by itself,
and an operator who wants it gone runs ``KILL MUTATION``. When nothing is
pending the step counts what is left, and fails if anything is.

Tables are the three the ingest worker writes (``clickhouse_client``). One that
does not exist — an installation whose controls table was never created —
holds nothing to delete. ``OCTO_CLICKHOUSE_URL`` unset on the replica running
the step is a failure, not a skip, unless the installation has declared that it
runs no ClickHouse (``OCTO_TENANT_PURGE_UNUSED_STORES=clickhouse``): a replica
whose configuration drifted must not decide for the whole installation that a
store holds nothing.

The account needs ``ALTER DELETE`` on the three tables and ``SELECT`` on
``system.mutations`` (docs/tenant-lifecycle.md).
"""

from __future__ import annotations

import time
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

#: Seconds between two looks at ``system.mutations``. Each look renews the lease.
POLL_SECONDS = 2.0
#: How long one attempt waits for a mutation before failing the step. The next
#: attempt waits for the *same* mutation rather than submitting another, so
#: this bounds an attempt, not the mutation.
MAX_WAIT_SECONDS = 3600.0

UNUSED_STORE = "clickhouse"


def _tenant_uuid(tenant_id: str) -> str:
    """The tenant's key as text, from a parsed UUID: hex digits and dashes only."""
    return str(uuid.UUID(str(ch_transform.tenant_to_uuid(tenant_id))))


def _uuid_literal(tenant_id: str) -> str:
    return f"toUUID('{_tenant_uuid(tenant_id)}')"


# Every statement below is built from module constants and _tenant_uuid's
# output; nothing in them is caller-supplied text.


def _count(client: Any, table: str, key: str) -> int:
    return int(client.command(f"SELECT count() FROM {table} WHERE tenant_id = {key}") or 0)


def _exists(client: Any, table: str) -> bool:
    return bool(int(client.command(f"EXISTS TABLE {table}") or 0))


def _pending(client: Any, table: str, tenant_uuid: str) -> list[tuple[str, str]]:
    """``(mutation_id, latest_fail_reason)`` of this tenant's unfinished mutations on ``table``."""
    database, name = table.split(".", 1)
    rows = client.query(
        "SELECT mutation_id, latest_fail_reason FROM system.mutations "
        f"WHERE database = '{database}' AND table = '{name}' AND is_done = 0 "
        f"AND position(command, '{tenant_uuid}') > 0"
    ).result_rows
    return [(str(mutation_id), str(reason or "")) for mutation_id, reason in rows]


def _wait(ctx: PurgeContext, client: Any, table: str, tenant_uuid: str) -> None:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    while True:
        pending = _pending(client, table, tenant_uuid)
        if not pending:
            return
        failing = [(mutation_id, reason) for mutation_id, reason in pending if reason]
        if failing:
            mutation_id, reason = failing[0]
            raise RuntimeError(
                f"mutation {mutation_id} on {table} is failing: {reason} "
                "(ClickHouse retries it; KILL MUTATION to give up on it)"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"mutation {pending[0][0]} on {table} is still running after "
                f"{int(MAX_WAIT_SECONDS)}s; the next attempt waits for it"
            )
        time.sleep(POLL_SECONDS)
        ctx.checkpoint()


def run(ctx: PurgeContext) -> dict[str, Any]:
    url = (ctx.settings.clickhouse_url or "").strip()
    if not url:
        if UNUSED_STORE in ctx.settings.tenant_purge_unused_stores:
            raise StepSkipped("ClickHouse declared unused (OCTO_TENANT_PURGE_UNUSED_STORES)")
        raise RuntimeError(
            "OCTO_CLICKHOUSE_URL is not set on this replica and ClickHouse is not "
            "declared unused (OCTO_TENANT_PURGE_UNUSED_STORES=clickhouse); the "
            "tenant's analytics may be in a store this replica cannot reach"
        )
    client = clickhouse_client.get_client(url)
    tenant_uuid = _tenant_uuid(ctx.tenant_id)
    key = _uuid_literal(ctx.tenant_id)
    for short, table in TABLES:
        ctx.checkpoint()
        if not _exists(client, table):
            continue
        before = _count(client, table, key)
        # Submitted only when no earlier attempt's mutation is still running,
        # and — counted again — when that one did not finish a moment ago.
        if (
            before
            and not _pending(client, table, tenant_uuid)
            and _count(client, table, key)
        ):
            # Not waited for here: see the module docstring.
            client.command(
                f"ALTER TABLE {table} DELETE WHERE tenant_id = {key}",
                settings={"mutations_sync": 0},
            )
        _wait(ctx, client, table, tenant_uuid)
        after = _count(client, table, key)
        if after:
            raise RuntimeError(f"{after} row(s) remain in {table} after the delete")
        # Recorded per table as it is done, so an attempt that fails on the
        # next one does not lose what this one removed.
        with ctx.guard() as session:
            ctx.add_counts(session, {short: before})
    return {short: 0 for short, _table in TABLES}
