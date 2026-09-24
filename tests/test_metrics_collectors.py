"""Scrape-time collectors on ``/metrics`` (#334): process, DB pool, sensor fleet.

The HTTP, job and ingest series are pushed by the code paths they describe.
These three are not: the process view comes from ``/proc``, the pool gauges from
the live SQLAlchemy pool and the fleet from the ``agents`` table, all read when
Prometheus asks. What is pinned here is what an operator's dashboard depends on
— that the series exist, carry only bounded labels, and say the same thing the
database and the pool say.
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import exc as sa_exc

from api.db import engine as db_engine
from api.db import models
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import ch_ingest_worker, metrics
from api.services import tenants as tenants_service
from api.services.integrations import webhook_worker
from tests.conftest import (
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
        held.append(engine.connect())
        samples = _samples(metrics.DB_POOL_COLLECTOR)
        assert _value(samples, "octo_db_pool_checked_out") == 2
        assert _value(samples, "octo_db_pool_checked_in") == 0
        assert _value(samples, "octo_db_pool_overflow") == 1

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


# --- sensor / agent fleet -------------------------------------------------------


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


def test_fleet_collector_reuses_one_query_across_scrapes():
    """``/metrics`` answers anyone who can reach it unless OCTO_METRICS_TOKEN is
    set, so a query per scrape would be a query per request an outsider cares to
    send. One per TTL per replica is the whole cost, however often it is asked."""
    calls = []
    clock = _Clock()

    def snapshot():
        calls.append(clock.now)
        return _fleet()

    collector = metrics.AgentFleetCollector(snapshot=snapshot, clock=clock, pool_saturated=lambda: False)
    assert _value(_samples(collector), "octo_agents", agent_kind="scanner", state="idle") == 1
    _samples(collector)
    assert len(calls) == 1
    clock.now += metrics.AGENT_FLEET_TTL_SECONDS + 1
    _samples(collector)
    assert len(calls) == 2


def test_fleet_series_are_absent_when_the_query_fails():
    """Absent, not frozen: the previous values served forever would draw a
    healthy fleet through a database outage."""
    clock = _Clock()
    answers = [_fleet()]

    def snapshot():
        if not answers:
            raise RuntimeError("database is down")
        return answers.pop()

    collector = metrics.AgentFleetCollector(snapshot=snapshot, clock=clock, pool_saturated=lambda: False)
    assert _samples(collector)
    clock.now += metrics.AGENT_FLEET_TTL_SECONDS + 1
    assert _samples(collector) == {}


def test_fleet_collector_does_not_queue_behind_requests_for_a_connection():
    """A saturated pool is exactly when the dashboards are being read, and a
    scrape that waited OCTO_DB_POOL_TIMEOUT for a connection would lose the
    whole ``/metrics`` answer — the pool gauges with it — to Prometheus's
    scrape timeout, while taking a connection from a request. The fleet is
    served from the last snapshot instead, until that is too old to be true."""
    clock = _Clock()
    calls = []
    saturated = [False]

    def snapshot():
        calls.append(clock.now)
        return _fleet()

    collector = metrics.AgentFleetCollector(
        snapshot=snapshot, clock=clock, pool_saturated=lambda: saturated[0]
    )
    assert _samples(collector)
    saturated[0] = True
    clock.now += metrics.AGENT_FLEET_TTL_SECONDS + 1
    assert _samples(collector), "a recent snapshot is still served"
    assert len(calls) == 1, "no query while the pool has nothing free"
    clock.now += metrics.AGENT_FLEET_MAX_STALE_SECONDS
    assert _samples(collector) == {}, "a snapshot past its shelf life is withdrawn"
    assert len(calls) == 1


def test_a_slow_fleet_query_does_not_pile_up_scrapes():
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
        return _fleet()

    collector = metrics.AgentFleetCollector(snapshot=snapshot, clock=clock, pool_saturated=lambda: False)
    _samples(collector)
    clock.now += metrics.AGENT_FLEET_TTL_SECONDS + 1
    slow = threading.Thread(target=_samples, args=(collector,), name="slow-scrape")
    slow.start()
    try:
        assert entered.wait(10)
        assert _samples(collector), "the concurrent scrape is answered from the snapshot"
        assert len(calls) == 2
    finally:
        release.set()
        slow.join(10)


def test_fleet_series_carry_no_unbounded_label():
    """Kind and state only — no tenant, agent id or hostname. Those are the
    values an attacker-controlled registration would choose, and the number of
    series would be the size of the fleet."""
    collector = metrics.AgentFleetCollector(
        snapshot=_fleet, clock=_Clock(), pool_saturated=lambda: False
    )
    label_names = {
        name
        for family in collector.collect()
        for sample in family.samples
        for name in sample.labels
    }
    assert label_names == {"agent_kind", "state", "le"}


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
    agents_service.configure(settings)
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

    fleet = agents_service.fleet_heartbeats(now=now)
    assert fleet is not None
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


def test_fleet_heartbeats_is_quiet_where_the_service_is_not_configured(monkeypatch):
    """Tools and unit tests import the registry without an agents table behind
    it; that is nothing to report, not an error to log on every scrape."""
    monkeypatch.setattr(agents_service, "_settings", None)
    assert agents_service.fleet_heartbeats() is None


@requires_postgres
def test_metrics_endpoint_reports_a_registered_sensor(tmp_path, monkeypatch):
    """Through the real route, registration to exposition."""
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    metrics.AGENT_FLEET_COLLECTOR.reset_for_tests()
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
