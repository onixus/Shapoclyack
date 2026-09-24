"""Scrape-time collectors on ``/metrics`` (#334): process, DB pool, cluster, tenants.

The HTTP and ingest series are pushed by the code paths they describe. These
are not: the process view comes from ``/proc``, the pool gauges from the live
SQLAlchemy pool, and the fleet, the job queue, the endpoint devices and the
opt-in per-tenant series from shared tables, all read when Prometheus asks.
What is pinned here is what an operator's dashboard depends on — that the
series exist, carry only bounded labels, say what the database and the pool
say, and that reading them cannot hurt the replica being scraped.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import exc as sa_exc
from sqlalchemy import update

from api.db import engine as db_engine
from api.db import models
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import ch_ingest_worker, job_store, metrics, metrics_sources
from api.services import tenants as tenants_service
from api.services.integrations import webhook_worker
from tests.conftest import (
    POSTGRES_URL,
    TEST_AGENT_TOKEN,
    configured_client,
    make_settings,
    requires_postgres,
)

# Never connected to: create_engine is lazy, so the gauges of a pool that has
# not opened a connection yet can be read without a database (tests/test_db_engine.py).
UNCONNECTED_POSTGRES_URL = "postgresql+psycopg://u:p@127.0.0.1:5432/shapoclyack"


def _samples(collector) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    """``{(sample name, sorted labels): value}`` for everything one collect() yields."""
    return {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in collector.collect()
        for sample in family.samples
    }


def _value(samples, name: str, **labels: str) -> float:
    return samples[(name, tuple(sorted(labels.items())))]


def _expire_scrape_caches() -> None:
    """Drop every scrape-time snapshot, so the next scrape reads the database."""
    # Private, but the registry has no public list of its collectors.
    for collector in list(metrics.REGISTRY._collector_to_names):  # noqa: SLF001
        reset = getattr(collector, "reset_for_tests", None)
        if reset is not None:
            reset()


# --- process view -----------------------------------------------------------


@pytest.mark.skipif(
    not Path("/proc/self/stat").exists(), reason="ProcessCollector reads /proc (Linux only)"
)
def test_metrics_expose_the_process_and_runtime_view():
    """``REGISTRY`` is a private ``CollectorRegistry``, so none of the
    collectors ``prometheus_client`` puts on its *default* registry were ever
    on ``/metrics``: no memory, CPU, file descriptors or GC — the first things
    a platform dashboard asks of a pod, and the only way to tell a leak from
    load without shelling into it."""
    text = metrics.render()[0].decode("utf-8")
    for name in (
        "process_resident_memory_bytes",
        "process_virtual_memory_bytes",
        "process_cpu_seconds_total",
        "process_open_fds",
        "process_max_fds",
        "process_start_time_seconds",
        "python_gc_objects_collected_total",
        "python_gc_collections_total",
        "python_info",
    ):
        assert f"\n{name}" in text, f"{name} missing from /metrics"


# --- DB pool ------------------------------------------------------------------


def test_pool_gauges_describe_the_live_engine(tmp_path):
    """Read off the pool at scrape time rather than kept in step with it: a
    gauge that events move drifts the first time an event is missed, and the
    pool's own counters are what SQLAlchemy decides with."""
    settings = make_settings(
        tmp_path,
        postgres_url=UNCONNECTED_POSTGRES_URL,
        db_pool_size=3,
        db_max_overflow=2,
        db_pool_timeout=7,
    )
    db_engine.reset_for_tests()
    try:
        db_engine.configure(settings)
        db_engine.get_engine(settings.postgres_url)
        samples = _samples(metrics.DB_POOL_COLLECTOR)
        assert _value(samples, "octo_db_pool_size") == 3
        assert _value(samples, "octo_db_pool_max_overflow") == 2
        assert _value(samples, "octo_db_pool_timeout_seconds") == 7
        assert _value(samples, "octo_db_pool_checked_out") == 0
        assert _value(samples, "octo_db_pool_checked_in") == 0
        # SQLAlchemy's own overflow() is -pool_size until the pool fills up;
        # a gauge reading -3 would say the opposite of "no overflow in use".
        assert _value(samples, "octo_db_pool_overflow") == 0
    finally:
        db_engine.reset_for_tests()


def test_pool_gauges_are_absent_before_there_is_an_engine():
    """No engine is not an empty pool: a zero there would draw a healthy line
    for a replica that has not opened its database yet."""
    db_engine.reset_for_tests()
    assert _samples(metrics.DB_POOL_COLLECTOR) == {}
    # The families are still described, so the registry reserves the names.
    assert {family.name for family in metrics.DB_POOL_COLLECTOR.describe()} >= {
        "octo_db_pool_size",
        "octo_db_pool_checked_out",
    }


def test_the_postgres_engine_times_its_checkouts(tmp_path):
    """Every engine the app builds for Postgres gets the instrumented pool, and
    keeps it across a dispose — ``Engine.dispose()`` rebuilds the pool with
    ``recreate()``, which is where a subclass is most easily lost."""
    settings = make_settings(tmp_path, postgres_url=UNCONNECTED_POSTGRES_URL)
    db_engine.reset_for_tests()
    try:
        db_engine.configure(settings)
        engine = db_engine.get_engine(settings.postgres_url)
        assert isinstance(engine.pool, db_engine.InstrumentedQueuePool)
        engine.dispose()
        assert isinstance(engine.pool, db_engine.InstrumentedQueuePool)
    finally:
        db_engine.reset_for_tests()


def test_the_sqlite_fallback_keeps_its_own_pool_class(tmp_path):
    """An in-memory SQLite URL gets a SingletonThreadPool: forcing a QueuePool
    on it would hand every thread its own empty database."""
    db_engine.reset_for_tests()
    try:
        engine = db_engine.get_engine("sqlite://")
        assert not isinstance(engine.pool, db_engine.InstrumentedQueuePool)
        # And its gauges are simply not reported, rather than guessed at.
        assert _samples(metrics.DB_POOL_COLLECTOR) == {}
    finally:
        db_engine.reset_for_tests()


@requires_postgres
def test_pool_reports_checkouts_overflow_and_timeouts(tmp_path):
    """The pressure a saturated pool puts on requests, end to end against a real
    server: two connections held on a 1+1 pool is one of overflow and none
    free, and the third caller waits OCTO_DB_POOL_TIMEOUT and gets a
    TimeoutError — which is a 500 to whoever made the request, so it is
    counted."""
    settings = make_settings(tmp_path, db_pool_size=1, db_max_overflow=1, db_pool_timeout=1)
    db_engine.reset_for_tests()
    held = []
    try:
        db_engine.configure(settings)
        engine = db_engine.get_engine(settings.postgres_url)
        timeouts_before = metrics.DB_POOL_CHECKOUT_TIMEOUTS_TOTAL._value.get()  # noqa: SLF001
        waits_before = _histogram_count(metrics.DB_POOL_CHECKOUT_DURATION_SECONDS)

        held.append(engine.connect())
        assert db_engine.pool_status().free == 1, "the overflow connection is still free"
        held.append(engine.connect())
        samples = _samples(metrics.DB_POOL_COLLECTOR)
        assert _value(samples, "octo_db_pool_checked_out") == 2
        assert _value(samples, "octo_db_pool_checked_in") == 0
        assert _value(samples, "octo_db_pool_overflow") == 1
        assert db_engine.pool_status().free == 0

        with pytest.raises(sa_exc.TimeoutError):
            engine.connect()
        assert metrics.DB_POOL_CHECKOUT_TIMEOUTS_TOTAL._value.get() == timeouts_before + 1  # noqa: SLF001
        # All three checkouts are timed, the one that gave up included: its
        # wait is the tail an operator sees before the errors.
        assert _histogram_count(metrics.DB_POOL_CHECKOUT_DURATION_SECONDS) == waits_before + 3

        for connection in held:
            connection.close()
        held.clear()
        samples = _samples(metrics.DB_POOL_COLLECTOR)
        assert _value(samples, "octo_db_pool_checked_out") == 0
        # The overflow connection is closed on return; the steady one stays.
        assert _value(samples, "octo_db_pool_checked_in") == 1
        assert _value(samples, "octo_db_pool_overflow") == 0
    finally:
        for connection in held:
            connection.close()
        db_engine.reset_for_tests()


def test_one_timed_out_checkout_is_counted_once_even_after_the_overflow_race():
    """``QueuePool._do_get`` calls ``self._do_get()`` again when another thread
    takes the last overflow slot between its two checks, so the override is
    re-entered: one checkout that then times out was counted, and timed, twice
    (review of #334). Only the outermost call observes."""
    pool = db_engine.InstrumentedQueuePool(
        lambda: sqlite3.connect(":memory:", check_same_thread=False),
        pool_size=1,
        max_overflow=1,
        timeout=0.2,
    )
    held = pool.connect()  # the steady connection; overflow is now 0 < 1
    real_inc, raced = pool._inc_overflow, []  # noqa: SLF001

    def racing_inc_overflow():
        if not raced:
            # Another thread opened the overflow connection first.
            raced.append(True)
            pool._overflow = pool._max_overflow  # noqa: SLF001
            return False
        return real_inc()

    pool._inc_overflow = racing_inc_overflow  # noqa: SLF001
    timeouts = metrics.DB_POOL_CHECKOUT_TIMEOUTS_TOTAL._value.get()  # noqa: SLF001
    waits = _histogram_count(metrics.DB_POOL_CHECKOUT_DURATION_SECONDS)
    try:
        with pytest.raises(sa_exc.TimeoutError):
            pool.connect()
        assert raced, "the race path was not taken"
        assert metrics.DB_POOL_CHECKOUT_TIMEOUTS_TOTAL._value.get() - timeouts == 1  # noqa: SLF001
        assert _histogram_count(metrics.DB_POOL_CHECKOUT_DURATION_SECONDS) - waits == 1
    finally:
        held.close()


def test_the_pool_reports_how_many_connections_are_free():
    """SQLAlchemy spells "no overflow limit" as -1. Settings floors it at 0, but
    an unconfigured tool's engine can have it, and ``size + -1`` would read a
    pool with room as a full one."""
    unlimited = db_engine.PoolStatus(
        size=5, max_overflow=-1, timeout=30, checked_out=9, checked_in=0, overflow=4
    )
    assert unlimited.free == float("inf")
    assert db_engine.PoolStatus(
        size=5, max_overflow=10, timeout=30, checked_out=13, checked_in=0, overflow=8
    ).free == 2


def test_a_timed_out_checkout_lands_in_a_finite_bucket():
    """A checkout that gives up has waited a little *longer* than the timeout.
    With the top bucket equal to the default timeout every one of them was in
    +Inf, and no quantile of the wait could be read exactly when the pool was
    in trouble (seen on a 3+2 pool against a local API, #334)."""
    from api.settings import Settings

    finite = [bound for bound in metrics.DB_POOL_CHECKOUT_DURATION_SECONDS._upper_bounds if bound != float("inf")]  # noqa: SLF001
    assert max(finite) > Settings().db_pool_timeout


def _histogram_count(histogram) -> float:
    for family in histogram.collect():
        for sample in family.samples:
            if sample.name.endswith("_count"):
                return sample.value
    raise AssertionError("histogram has no _count sample")


# --- NATS consumer lag ------------------------------------------------------------


class _Subscription:
    def __init__(self, pending: int | None) -> None:
        self._pending = pending

    async def consumer_info(self):
        if self._pending is None:
            raise RuntimeError("broker went away")
        return type("Info", (), {"num_pending": self._pending})()


def _ch_ingest_lag_reporter():
    worker = ch_ingest_worker.ClickHouseIngestWorker(
        nats_url="nats://127.0.0.1:1", clickhouse_url="http://127.0.0.1:1"
    )
    return worker._report_consumer_lag, ch_ingest_worker.CONSUMER_CH_INGEST  # noqa: SLF001


def _webhook_lag_reporter():
    worker = webhook_worker.WebhookFanoutWorker(nats_url="nats://127.0.0.1:1")
    return worker._report_lag, webhook_worker.CONSUMER_WEBHOOK_FANOUT  # noqa: SLF001


@pytest.mark.parametrize("reporter", [_ch_ingest_lag_reporter, _webhook_lag_reporter])
def test_consumer_lag_reports_when_it_was_read(reporter):
    """The pending count alone cannot say a poller stopped: it keeps its last
    value, and Prometheus stamps it with the scrape time. The refresh time next
    to it is what ages — and a read that failed must not move it."""
    report, consumer = reporter()
    before = time.time()
    asyncio.run(report(_Subscription(7)))
    stamped = metrics.NATS_CONSUMER_PENDING_TIMESTAMP.labels(consumer=consumer)._value.get()  # noqa: SLF001
    assert metrics.NATS_CONSUMER_PENDING.labels(consumer=consumer)._value.get() == 7  # noqa: SLF001
    assert before <= stamped <= time.time()

    asyncio.run(report(_Subscription(None)))
    assert metrics.NATS_CONSUMER_PENDING_TIMESTAMP.labels(consumer=consumer)._value.get() == stamped  # noqa: SLF001


# --- the cached scrape-time snapshot -------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _fleet(**overrides) -> agents_service.FleetHeartbeats:
    counts = {
        (kind, state): 0 for kind in agents_service.FLEET_KINDS for state in agents_service.FLEET_STATES
    }
    counts[("scanner", "idle")] = 1
    base = {
        "counts": counts,
        "age_buckets": {kind: [0] * len(agents_service.HEARTBEAT_AGE_BUCKETS) for kind in agents_service.FLEET_KINDS},
        "age_totals": {kind: 0 for kind in agents_service.FLEET_KINDS},
        "age_sums": {kind: 0.0 for kind in agents_service.FLEET_KINDS},
        "age_max": {},
        "stale_seconds": 120,
    }
    base.update(overrides)
    return agents_service.FleetHeartbeats(**base)


def _cluster(**overrides) -> metrics_sources.ClusterSnapshot:
    base = {
        "fleet": _fleet(),
        "jobs_queued": 2,
        "jobs_running": 1,
        "endpoint_devices": {"active": 3, "stale": 1},
    }
    base.update(overrides)
    return metrics_sources.ClusterSnapshot(**base)


def _collector(snapshot, clock, *, busy=lambda: False):
    return metrics.cluster_collector(snapshot=snapshot, clock=clock, pool_too_busy=busy)


def test_the_cluster_snapshot_is_reused_across_scrapes():
    """``/metrics`` answers anyone who can reach it unless OCTO_METRICS_TOKEN is
    set, so a query per scrape would be a query per request an outsider cares to
    send. One per TTL per replica is the whole cost, however often it is asked."""
    calls = []
    clock = _Clock()

    def snapshot():
        calls.append(clock.now)
        return _cluster()

    collector = _collector(snapshot, clock)
    samples = _samples(collector)
    assert _value(samples, "octo_agents", agent_kind="scanner", state="idle") == 1
    assert _value(samples, "octo_jobs_queued") == 2
    assert _value(samples, "octo_jobs_running") == 1
    assert _value(samples, "octo_endpoint_devices", state="active") == 3
    _samples(collector)
    assert len(calls) == 1
    clock.now += metrics.CLUSTER_TTL_SECONDS + 1
    _samples(collector)
    assert len(calls) == 2


def test_series_are_absent_when_the_query_fails():
    """Absent, not frozen: the previous values served forever would draw a
    healthy fleet through a database outage."""
    clock = _Clock()
    answers = [_cluster()]

    def snapshot():
        if not answers:
            raise RuntimeError("database is down")
        return answers.pop()

    collector = _collector(snapshot, clock)
    assert _samples(collector)
    clock.now += metrics.CLUSTER_TTL_SECONDS + 1
    assert _samples(collector) == {}


def test_a_failing_query_is_tried_once_per_ttl_not_once_per_scrape():
    """A failure used to clear the snapshot's timestamp, which is what the TTL
    is measured from — so every request to an unauthenticated endpoint became a
    database attempt and a WARNING line while the query kept failing (review
    of #334). A failed attempt now waits out the TTL like a successful one."""
    calls = []
    clock = _Clock()

    def snapshot():
        calls.append(clock.now)
        raise RuntimeError("statement timeout")

    collector = _collector(snapshot, clock)
    for _ in range(10):
        assert _samples(collector) == {}
    assert len(calls) == 1
    clock.now += metrics.CLUSTER_TTL_SECONDS + 1
    _samples(collector)
    assert len(calls) == 2


def test_the_scrape_does_not_queue_behind_requests_for_a_connection():
    """A busy pool is exactly when the dashboards are being read, and a scrape
    that waited OCTO_DB_POOL_TIMEOUT for a connection would lose the whole
    ``/metrics`` answer — the pool gauges with it — to Prometheus's scrape
    timeout, while taking a connection from a request. The series are served
    from the last snapshot instead, until that is too old to be true."""
    clock = _Clock()
    calls = []
    busy = [False]

    def snapshot():
        calls.append(clock.now)
        return _cluster()

    collector = _collector(snapshot, clock, busy=lambda: busy[0])
    assert _samples(collector)
    busy[0] = True
    clock.now += metrics.CLUSTER_TTL_SECONDS + 1
    assert _samples(collector), "a recent snapshot is still served"
    assert len(calls) == 1, "no query while the pool has no room"
    clock.now += metrics.CLUSTER_MAX_STALE_SECONDS
    assert _samples(collector) == {}, "a snapshot past its shelf life is withdrawn"
    assert len(calls) == 1


@requires_postgres
def test_the_scrape_leaves_a_connection_for_requests(tmp_path):
    """Checking for *one* free connection and then taking it is a race with the
    next request, which then waits OCTO_DB_POOL_TIMEOUT (30 s) — longer than
    Prometheus waits for the scrape (review of #334). The default check wants
    two free, so the scrape's own checkout still leaves one."""
    settings = make_settings(tmp_path, db_pool_size=1, db_max_overflow=1, db_pool_timeout=1)
    db_engine.reset_for_tests()
    calls = []
    try:
        db_engine.configure(settings)
        engine = db_engine.get_engine(settings.postgres_url)
        collector = metrics.cluster_collector(snapshot=lambda: calls.append(1) or _cluster())
        with engine.connect():
            assert db_engine.pool_status().free == 1
            assert _samples(collector) == {}
            assert calls == []
        assert _samples(collector)
        assert calls == [1]
    finally:
        db_engine.reset_for_tests()


def test_a_slow_query_does_not_pile_up_scrapes():
    """Two Prometheus replicas, a retry and a curl can all be in ``/metrics`` at
    once, and each holds one of the API's worker threads while it is there.
    Only one of them runs the query; the others answer from the snapshot."""
    clock = _Clock()
    release = threading.Event()
    entered = threading.Event()
    calls = []

    def snapshot():
        calls.append(clock.now)
        if len(calls) == 2:
            entered.set()
            assert release.wait(10)
        return _cluster()

    collector = _collector(snapshot, clock)
    _samples(collector)
    clock.now += metrics.CLUSTER_TTL_SECONDS + 1
    slow = threading.Thread(target=_samples, args=(collector,), name="slow-scrape")
    slow.start()
    try:
        assert entered.wait(10)
        assert _samples(collector), "the concurrent scrape is answered from the snapshot"
        assert len(calls) == 2
    finally:
        release.set()
        slow.join(10)


def test_a_job_event_makes_this_replicas_next_scrape_reread():
    """The queue is read from the table at scrape time, so every replica agrees
    within one TTL. The replica that just changed it does not have to wait even
    that long: the job paths that used to set the gauges expire the snapshot."""
    clock = _Clock()
    calls = []
    collector = _collector(lambda: calls.append(1) or _cluster(), clock)
    _samples(collector)
    collector.expire()
    _samples(collector)
    assert len(calls) == 2


def test_job_paths_expire_the_shared_snapshot(tmp_path, monkeypatch):
    expired = []
    monkeypatch.setattr(metrics.CLUSTER_COLLECTOR, "expire", lambda: expired.append(1))
    job_store.refresh_job_gauges(make_settings(tmp_path))
    assert expired == [1]


def test_cluster_series_carry_no_unbounded_label():
    """Kind, state and bucket only — no tenant, agent id or hostname. Those are
    the values an attacker-controlled registration would choose, and the number
    of series would be the size of the fleet."""
    collector = _collector(_cluster, _Clock())
    label_names = {
        name
        for family in collector.collect()
        for sample in family.samples
        for name in sample.labels
    }
    assert label_names == {"agent_kind", "state", "le"}


def test_endpoint_devices_are_absent_where_inventory_is_off():
    collector = _collector(lambda: _cluster(endpoint_devices=None), _Clock())
    assert not any(name == "octo_endpoint_devices" for name, _ in _samples(collector))


@requires_postgres
def test_fleet_heartbeats_count_and_age_the_agents_table(tmp_path):
    """One grouped query, against rows written straight into the table so the
    edge cases the API itself refuses — an unknown kind, an unreported status —
    are covered too: they are folded into the fixed vocabulary, never copied
    into a label."""
    settings = make_settings(tmp_path, agent_stale_seconds=120)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    metrics_sources.configure(settings)
    now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    rows = [
        # (id, kind, lifecycle, reported status, age in seconds)
        ("s-idle", "scanner", "active", "idle", 10),
        ("s-busy", "scanner", "active", "busy", 70),
        ("s-stale", "scanner", "active", "busy", 500),
        ("s-disabled", "scanner", "disabled", "idle", 5),
        ("s-quarantined", "scanner", "quarantined", "idle", 99_999),
        ("s-odd", "not-a-kind", "active", "pwned", 40),
        ("e-asleep", "endpoint", "active", "idle", 3 * 86_400),
        ("e-error", "endpoint", "active", "error", 20),
    ]
    with get_session(settings.postgres_url) as session:
        for agent_id, kind, lifecycle, status, age in rows:
            session.add(
                models.Agent(
                    agent_id=agent_id,
                    tenant_id="default",
                    agent_kind=kind,
                    lifecycle_status=lifecycle,
                    status=status,
                    registered_at=now - timedelta(days=30),
                    last_seen_at=now - timedelta(seconds=age),
                )
            )

    snapshot = metrics_sources.cluster_snapshot(now=now)
    assert snapshot is not None
    fleet = snapshot.fleet
    assert set(fleet.counts) == {
        (kind, state) for kind in agents_service.FLEET_KINDS for state in agents_service.FLEET_STATES
    }
    nonzero = {key: value for key, value in fleet.counts.items() if value}
    assert nonzero == {
        ("scanner", "idle"): 2,  # s-idle, and s-odd folded in
        ("scanner", "busy"): 1,
        ("scanner", "stale"): 1,
        ("scanner", "disabled"): 1,
        ("scanner", "quarantined"): 1,
        ("endpoint", "stale"): 1,
        ("endpoint", "error"): 1,
    }
    # Ages cover the agents an operator expects to hear from: the disabled and
    # the quarantined one are silent by decision, not by fault.
    buckets = dict(zip(agents_service.HEARTBEAT_AGE_BUCKETS, fleet.age_buckets["scanner"]))
    assert (buckets[30], buckets[60], buckets[90], buckets[300], buckets[900]) == (1, 2, 3, 3, 4)
    assert fleet.age_totals == {"scanner": 4, "endpoint": 2}
    assert fleet.age_sums["scanner"] == pytest.approx(10 + 70 + 500 + 40, abs=1)
    assert fleet.age_max == {"scanner": pytest.approx(500, abs=1), "endpoint": pytest.approx(3 * 86_400, abs=1)}
    endpoint_buckets = dict(zip(agents_service.HEARTBEAT_AGE_BUCKETS, fleet.age_buckets["endpoint"]))
    assert (endpoint_buckets[30], endpoint_buckets[86_400], endpoint_buckets[604_800]) == (1, 1, 2)
    assert fleet.stale_seconds == 120


def test_the_snapshots_are_quiet_where_nothing_is_configured(monkeypatch):
    """Tools and unit tests import the registry without a database behind it;
    that is nothing to report, not an error to log on every scrape."""
    monkeypatch.setattr(metrics_sources, "_settings", None)
    assert metrics_sources.cluster_snapshot() is None
    assert metrics_sources.tenant_snapshot() is None


@requires_postgres
def test_metrics_endpoint_reports_a_registered_sensor(tmp_path, monkeypatch):
    """Through the real route, registration to exposition."""
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    _expire_scrape_caches()
    registered = client.post(
        "/api/agent/register",
        headers={"Authorization": f"Bearer {TEST_AGENT_TOKEN}"},
        json={"hostname": "edge-1", "version": "0.3.2.1"},
    )
    assert registered.status_code == 200
    body = client.get("/metrics").text
    assert 'octo_agents{agent_kind="scanner",state="idle"} 1.0' in body
    assert 'octo_agents{agent_kind="endpoint",state="stale"} 0.0' in body
    assert 'octo_agent_heartbeat_age_seconds_bucket{agent_kind="scanner",le="30.0"} 1.0' in body
    assert "octo_agent_stale_threshold_seconds 120.0" in body
    assert "edge-1" not in body


@requires_postgres
def test_every_replica_reports_the_queue_the_table_holds(tmp_path, monkeypatch):
    """``octo_jobs_queued`` was set by whichever replica handled the job's last
    event. With two replicas, the scan submitted through one and claimed
    through the other left the first reporting a queued job forever, and
    ``ShapoclyackNoSensorOnline`` paged over an empty queue the next time a
    sensor rebooted (review of #334). The claim below is the other replica: a
    write this process never hears about."""
    settings = make_settings(tmp_path, job_execution_mode="agent")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    job_id = f"job-{uuid4().hex[:12]}"
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id=job_id,
                tenant_id="default",
                status="queued",
                execution="agent",
                queued_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
    job_store.refresh_job_gauges(settings)  # this replica's own submit path
    _expire_scrape_caches()
    assert "octo_jobs_queued 1.0" in client.get("/metrics").text

    with get_session(settings.postgres_url) as session:
        session.execute(update(models.Job).where(models.Job.job_id == job_id).values(status="claimed"))
    _expire_scrape_caches()
    body = client.get("/metrics").text
    assert "octo_jobs_queued 0.0" in body
    assert "octo_jobs_running 1.0" in body


@requires_postgres
def test_endpoint_devices_are_read_from_the_table_at_scrape_time(tmp_path, monkeypatch):
    """Same pattern as the queue: the device gauge moved only on a retention
    sweep (hours apart) or on a System page view in the replica that served
    it, so replicas disagreed and ``max()`` picked whichever was most stale."""
    settings = make_settings(tmp_path, endpoint_stale_hours=48)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        for device_id, last_inventory in (
            ("dev-fresh", now - timedelta(hours=1)),
            ("dev-old", now - timedelta(hours=72)),
            ("dev-never", None),
        ):
            session.add(
                models.EndpointDevice(
                    device_id=device_id,
                    tenant_id="default",
                    agent_id=f"agent-{device_id}",
                    hostname=device_id,
                    agent_version="0.2.0",
                    first_seen=now,
                    last_seen=now,
                    last_inventory_at=last_inventory,
                )
            )
    _expire_scrape_caches()
    body = client.get("/metrics").text
    assert 'octo_endpoint_devices{state="active"} 1.0' in body
    assert 'octo_endpoint_devices{state="stale"} 2.0' in body


@requires_postgres
def test_the_scrape_statement_timeout_does_not_outlive_the_scrape(tmp_path):
    """``set_config(…, true)`` scopes the 2 s cap to the scrape's transaction.
    Session scope would leave it on the pooled connection, and the next
    request to draw that connection — a report, a bulk action — would be
    cancelled at 2 s. Pool of one, so it *is* the same connection."""
    settings = make_settings(tmp_path, db_pool_size=1, db_max_overflow=0, db_pool_timeout=5)
    db_engine.reset_for_tests()
    try:
        db_engine.configure(settings)
        tenants_service.configure(settings)
        tenants_service.load_tenants(settings)
        metrics_sources.configure(settings)
        assert metrics_sources.cluster_snapshot() is not None
        engine = db_engine.get_engine(settings.postgres_url)
        with engine.connect() as connection:
            assert connection.exec_driver_sql("show statement_timeout").scalar() == "0"
        assert db_engine.pool_status().checked_in == 1
    finally:
        db_engine.reset_for_tests()


@requires_postgres
def test_the_scrape_gives_up_behind_a_table_lock(tmp_path):
    """A migration's ``ALTER TABLE agents`` holds an exclusive lock; without the
    cap the scrape would wait for it past Prometheus's timeout, holding a
    worker thread and a connection."""
    settings = make_settings(tmp_path)
    db_engine.reset_for_tests()
    try:
        db_engine.configure(settings)
        tenants_service.configure(settings)
        tenants_service.load_tenants(settings)
        metrics_sources.configure(settings)
        raw = POSTGRES_URL.replace("postgresql+psycopg://", "postgresql://")
        with psycopg.connect(raw) as locker:
            locker.execute("LOCK TABLE agents IN ACCESS EXCLUSIVE MODE")
            started = time.monotonic()
            with pytest.raises(sa_exc.OperationalError):
                metrics_sources.cluster_snapshot()
            elapsed = time.monotonic() - started
            locker.rollback()
        assert 1.5 < elapsed < 5, elapsed
    finally:
        db_engine.reset_for_tests()


# --- opt-in per-tenant series -----------------------------------------------------------


def _seed_finding(session, tenant_id: str, *, severity: str, state: str = "OPEN", due_at=None, exception_until=None):
    now = datetime.now(UTC).replace(tzinfo=None)
    asset_id = f"asset-{tenant_id}"
    if session.get(models.Asset, asset_id) is None:
        session.add(
            models.Asset(asset_id=asset_id, tenant_id=tenant_id, status="active", first_seen=now, last_seen=now)
        )
        session.flush()
    vuln_id = f"vln-{uuid4().hex[:12]}"
    session.add(
        models.Vulnerability(
            vuln_id=vuln_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            finding_key=f"key-{vuln_id}",
            title="seeded",
            severity=severity,
            state=state,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            due_at=due_at,
            exception_until=exception_until,
            created_at=now,
            updated_at=now,
        )
    )


def _seed_scan(session, tenant_id: str, *, status: str, finished_ago: timedelta):
    now = datetime.now(UTC).replace(tzinfo=None)
    session.add(
        models.Job(
            job_id=f"job-{uuid4().hex[:12]}",
            tenant_id=tenant_id,
            status=status,
            queued_at=now - finished_ago - timedelta(minutes=5),
            finished_at=now - finished_ago,
        )
    )


def _tenant(session, tenant_id: str) -> None:
    session.add(
        models.Tenant(
            tenant_id=tenant_id,
            name=tenant_id,
            status="active",
            created_at=datetime.now(UTC).replace(tzinfo=None),
        )
    )
    session.flush()


def test_tenant_series_are_off_by_default():
    """Off unless OCTO_METRICS_TENANT_TOP_N is set: the families are described,
    so the names are reserved, and nothing carries a tenant."""
    assert make_settings(Path("/nonexistent")).metrics_tenant_top_n == 0
    collector = metrics.tenant_collector(snapshot=lambda: None, clock=_Clock(), pool_too_busy=lambda: False)
    assert _samples(collector) == {}
    assert {family.name for family in collector.describe()} == {
        "octo_tenant_open_findings",
        "octo_tenant_sla_breached_findings",
        "octo_tenant_scans_finished_24h",
    }


@requires_postgres
def test_tenant_series_name_only_the_top_tenants_and_fold_the_rest(tmp_path):
    """The tenant label is bounded twice over: at most OCTO_METRICS_TENANT_TOP_N
    tenants by volume keep their own id, everyone else is summed into
    ``_other``, and an id only ever comes from the tenants table and only if it
    passes the rule tenant creation enforces — a legacy row that predates that
    rule is folded, however busy it is."""
    settings = make_settings(tmp_path, metrics_tenant_top_n=2)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    metrics_sources.configure(settings)
    now = datetime.now(UTC).replace(tzinfo=None)
    past, future = now - timedelta(days=1), now + timedelta(days=10)
    with get_session(settings.postgres_url) as session:
        for tenant_id in ("acme", "globex", "initech", "legacy.id"):
            _tenant(session, tenant_id)
        for _ in range(3):
            _seed_finding(session, "acme", severity="critical", due_at=past)
        _seed_finding(session, "acme", severity="high", due_at=past, exception_until=future)
        _seed_finding(session, "acme", severity="low", state="CLOSED", due_at=past)
        for _ in range(2):
            _seed_finding(session, "globex", severity="medium", due_at=future)
        _seed_finding(session, "initech", severity="high", due_at=past)
        for _ in range(9):
            _seed_finding(session, "legacy.id", severity="critical", due_at=past)
        _seed_scan(session, "acme", status="succeeded", finished_ago=timedelta(hours=2))
        _seed_scan(session, "acme", status="failed", finished_ago=timedelta(hours=3))
        _seed_scan(session, "globex", status="succeeded", finished_ago=timedelta(hours=30))
        _seed_scan(session, "initech", status="succeeded", finished_ago=timedelta(hours=1))

    snapshot = metrics_sources.tenant_snapshot(now=now)
    assert snapshot is not None
    labels = {tenant for tenant, _ in snapshot.open_findings}
    assert labels == {"acme", "globex", metrics_sources.TENANT_OTHER}

    assert snapshot.open_findings[("acme", "critical")] == 3
    assert snapshot.open_findings[("acme", "high")] == 1
    assert snapshot.open_findings[("acme", "low")] == 0, "a closed finding is not open"
    assert snapshot.open_findings[("globex", "medium")] == 2
    # initech (1 high) and the legacy id (9 critical) are both _other.
    assert snapshot.open_findings[("_other", "critical")] == 9
    assert snapshot.open_findings[("_other", "high")] == 1

    # Breached: past due and not under an accepted exception.
    assert snapshot.sla_breached == {"acme": 3, "globex": 0, "_other": 10}
    # The last 24 hours only.
    assert snapshot.scans_finished[("acme", "succeeded")] == 1
    assert snapshot.scans_finished[("acme", "failed")] == 1
    assert snapshot.scans_finished[("globex", "succeeded")] == 0
    assert snapshot.scans_finished[("_other", "succeeded")] == 1


def test_tenant_series_carry_a_bounded_vocabulary():
    snapshot = metrics_sources.TenantSnapshot(
        open_findings={("acme", "critical"): 1, ("_other", "critical"): 0},
        sla_breached={"acme": 1, "_other": 0},
        scans_finished={("acme", "succeeded"): 1, ("_other", "succeeded"): 0},
    )
    collector = metrics.tenant_collector(snapshot=lambda: snapshot, clock=_Clock(), pool_too_busy=lambda: False)
    samples = _samples(collector)
    assert _value(samples, "octo_tenant_open_findings", tenant="acme", severity="critical") == 1
    assert _value(samples, "octo_tenant_sla_breached_findings", tenant="_other") == 0
    assert _value(samples, "octo_tenant_scans_finished_24h", tenant="acme", status="succeeded") == 1
    assert {name for _, labels in samples for name, _ in labels} == {"tenant", "severity", "status"}
