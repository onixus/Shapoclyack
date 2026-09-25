"""The purge against live ClickHouse and object storage (#325).

Apart from tests/test_tenant_purge.py, which is gated on Postgres alone: the
integration gate (tests/integration_gate.py) counts every test in a module
marked ``requires_postgres`` as a Postgres test, and a skip for any other
reason — no ClickHouse here, no S3 gateway there — would count against the
Postgres suite on a run that declares Postgres available. Each test here needs
Postgres *and* its store, and its skip reason names only the store.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from api.services import artifact_store, tenant_purge
from api.services.artifact_store import workspace
from api.services.tenant_purge import clickhouse as purge_clickhouse
from tests.conftest import POSTGRES_URL
from tests.test_tenant_purge import (
    NEIGHBOUR,
    VICTIM,
    _approve,
    _deletion,
    _make_due,
    _purge_artifacts,
    _run_keys,
    _run_to_end,
    _step,
    purge_settings,
)

CLICKHOUSE_URL = os.environ.get("OCTO_TEST_CLICKHOUSE_URL", "").strip()
S3_ENDPOINT = os.environ.get("OCTO_TEST_S3_ENDPOINT", "").strip()

requires_clickhouse = pytest.mark.skipif(
    not (POSTGRES_URL and CLICKHOUSE_URL),
    reason="OCTO_TEST_CLICKHOUSE_URL not set (live ClickHouse; the purge journal also needs the test database)",
)
requires_s3 = pytest.mark.skipif(
    not (POSTGRES_URL and S3_ENDPOINT),
    reason="OCTO_TEST_S3_ENDPOINT not set (live S3 gateway; the purge journal also needs the test database)",
)


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    workspace.reset_marker_cache()


@pytest.fixture()
def settings(tmp_path):
    yield from purge_settings(tmp_path)


def _clickhouse_schema():
    """The schema a fresh installation boots with: the compose/k8s init script."""
    from api.services import clickhouse_client

    setup = clickhouse_client.get_client(CLICKHOUSE_URL, database="default")
    init = Path(__file__).resolve().parents[1] / "k8s/shapoclyack/base/clickhouse/init-local.sql"
    for statement in init.read_text(encoding="utf-8").split(";"):
        body = "\n".join(
            line for line in statement.splitlines() if not line.strip().startswith("--")
        ).strip()
        if body:
            setup.command(body)
    return clickhouse_client.get_client(CLICKHOUSE_URL)


def _seed_ports(client, rows: dict[str, int]) -> None:
    from api.services import ch_transform, clickhouse_client

    stamp = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    for tenant_id, count in rows.items():
        clickhouse_client.insert_rows(
            client,
            clickhouse_client.PORTS_TABLE,
            clickhouse_client.PORT_COLUMNS,
            [
                [ch_transform.tenant_to_uuid(tenant_id), f"10.0.0.{i}", 80 + i, "tcp", "r", stamp]
                for i in range(count)
            ],
        )


def _count_ports(client, tenant_id: str) -> int:
    from api.services import clickhouse_client

    return int(
        client.command(
            f"SELECT count() FROM {clickhouse_client.PORTS_TABLE} "
            f"WHERE tenant_id = {purge_clickhouse._uuid_literal(tenant_id)}"  # noqa: SLF001
        )
    )


@requires_clickhouse
def test_live_clickhouse_mutation_removes_the_tenant_and_only_the_tenant(settings):
    from api.services import clickhouse_client

    client = _clickhouse_schema()
    client.command(f"TRUNCATE TABLE {clickhouse_client.PORTS_TABLE}")
    _seed_ports(client, {VICTIM: 3, NEIGHBOUR: 2})
    settings.clickhouse_url = CLICKHOUSE_URL
    deletion_id = _approve(settings)
    assert _run_to_end(settings)[-1] == "completed"
    assert _count_ports(client, VICTIM) == 0
    assert _count_ports(client, NEIGHBOUR) == 2
    assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"]["open_ports"] == 3
    client.command(f"TRUNCATE TABLE {clickhouse_client.PORTS_TABLE}")


@requires_s3
def test_live_object_storage_purge_against_an_s3_gateway(settings, tmp_path):
    import boto3

    bucket = f"purge-{uuid.uuid4().hex[:8]}"
    boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    ).create_bucket(Bucket=bucket)
    settings.artifact_backend = "s3"
    settings.artifact_s3_bucket = bucket
    settings.artifact_s3_endpoint_url = S3_ENDPOINT
    settings.artifact_s3_region = "us-east-1"
    settings.artifact_s3_access_key_id = "test"
    settings.artifact_s3_secret_access_key = "test"
    settings.artifact_s3_addressing_style = "path"
    settings.artifact_cache_dir = str(tmp_path / "cache")
    counts = _purge_artifacts(settings)
    store = artifact_store.get_store(settings)
    assert _run_keys(store, VICTIM) == []
    assert len(_run_keys(store, NEIGHBOUR)) == 6
    assert counts["run_objects"] == 2 and counts["report_objects"] == 1


@requires_clickhouse
def test_live_a_neighbours_failing_mutation_is_named_as_what_holds_the_purge(
    settings, monkeypatch
):
    """On ClickHouse itself: the neighbour's failing ``UPDATE`` holds the
    victim's ``DELETE`` behind it, the step names the neighbour's mutation, and
    once that one is killed the retry finishes without a second ``DELETE``."""
    from api.services import clickhouse_client

    client = _clickhouse_schema()
    table = clickhouse_client.PORTS_TABLE
    database, name = table.split(".", 1)
    client.command(f"TRUNCATE TABLE {table}")
    _seed_ports(client, {VICTIM: 3, NEIGHBOUR: 2})
    neighbour = purge_clickhouse._uuid_literal(NEIGHBOUR)  # noqa: SLF001
    client.command(
        f"ALTER TABLE {table} UPDATE protocol = toString(throwIf(1)) "
        f"WHERE tenant_id = {neighbour}",
        settings={"mutations_sync": 0},
    )

    def unfinished(needle: str = "") -> list[tuple[str, str]]:
        return [
            (str(mutation_id), str(command))
            for mutation_id, command in client.query(
                "SELECT mutation_id, command FROM system.mutations "
                f"WHERE database = '{database}' AND table = '{name}' AND is_done = 0 "
                f"AND position(command, '{needle}') > 0 ORDER BY create_time, mutation_id"
            ).result_rows
        ]

    blocker = unfinished("throwIf")[0][0]
    monkeypatch.setattr(purge_clickhouse, "POLL_SECONDS", 0.5)
    monkeypatch.setattr(purge_clickhouse, "MAX_WAIT_SECONDS", 60)
    settings.clickhouse_url = CLICKHOUSE_URL
    deletion_id = _approve(settings)
    try:
        assert tenant_purge.run_once(settings, owner="replica-1")["outcome"] == "failed"
        error = _step(settings, deletion_id, "clickhouse")["last_error"]
        assert f"mutation_id = '{blocker}'" in error and "not this tenant's" in error, error
        assert "give up on it" not in error
        assert _count_ports(client, VICTIM) == 3

        client.command(
            f"KILL MUTATION WHERE database = '{database}' AND table = '{name}' "
            f"AND mutation_id = '{blocker}'"
        )
        deadline = time.monotonic() + 30
        while unfinished("throwIf") and time.monotonic() < deadline:
            time.sleep(0.2)
        _make_due(settings, deletion_id)
        assert _run_to_end(settings)[-1] == "completed"
        assert _count_ports(client, VICTIM) == 0
        assert _count_ports(client, NEIGHBOUR) == 2
        assert _deletion(settings, deletion_id)["outcome"]["stores"]["clickhouse"]["open_ports"] == 3
        victim_uuid = purge_clickhouse._tenant_uuid(VICTIM)  # noqa: SLF001
        submitted = client.query(
            "SELECT count() FROM system.mutations "
            f"WHERE database = '{database}' AND table = '{name}' "
            f"AND position(command, '{victim_uuid}') > 0"
        ).result_rows[0][0]
        assert submitted == 1
    finally:
        client.command(f"KILL MUTATION WHERE database = '{database}' AND table = '{name}'")
        client.command(f"TRUNCATE TABLE {table}")
