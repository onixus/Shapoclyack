"""Unit tests for NATS ingest gateway helpers (no live broker required)."""

from __future__ import annotations

import io
import tarfile
import threading

import pytest

from api.services import nats_bus, results_ingest
from tests.conftest import POSTGRES_URL, approve_scan_scope, requires_postgres


def _archive(name: str = "findings.json", data: bytes = b'{"ok":true}\n') -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_validate_archive_rejects_traversal():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"x"
        info = tarfile.TarInfo(name="../evil")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    with pytest.raises(results_ingest.IngestError):
        results_ingest.validate_archive(buf.getvalue())


def test_validate_archive_rejects_oversized_expansion():
    """#222: the transport cap bounds the compressed upload, not what it becomes.

    Sizes come from the tar headers, so the refusal happens before extraction
    writes anything into the shared output_dir.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"\0" * 4096
        for index in range(4):
            info = tarfile.TarInfo(name=f"pad-{index}.bin")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    archive = buf.getvalue()

    with pytest.raises(results_ingest.IngestError, match="expands to more than"):
        results_ingest.validate_archive(archive, max_uncompressed_bytes=8192)
    # One byte of headroom over the same archive is accepted.
    results_ingest.validate_archive(archive, max_uncompressed_bytes=4096 * 4)


def test_extract_run_archive_refuses_before_writing(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"\0" * 4096
        info = tarfile.TarInfo(name="pad.bin")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "runs" / "run-1"

    with pytest.raises(results_ingest.IngestError, match="expands to more than"):
        results_ingest.extract_run_archive(buf.getvalue(), dest, max_uncompressed_bytes=1024)
    assert not dest.exists()


def test_ingest_msg_id_stable():
    a = nats_bus.ingest_msg_id(job_id="j1", run_id="r1", archive_sha256="abc")
    b = nats_bus.ingest_msg_id(job_id="j1", run_id="r1", archive_sha256="abc")
    c = nats_bus.ingest_msg_id(job_id="j1", run_id="r1", archive_sha256="abd")
    assert a == b
    assert a != c


def test_publish_raw_results_without_nats(monkeypatch):
    nats_bus.reset_bus_for_tests()
    archive = _archive()
    meta = results_ingest.publish_raw_results(
        nats_url="",
        job_id="job1",
        run_id="run1",
        agent_id="agent1",
        exit_code=0,
        archive_bytes=archive,
    )
    assert meta["published"] is False
    assert meta["msg_id"]
    assert meta["archive_sha256"] == nats_bus.archive_sha256(archive)


def test_nats_bus_close_waits_for_shutdown_and_closes_loop():
    class FakeNatsClient:
        is_closed = False
        drained = False
        closed = False

        async def drain(self):
            self.drained = True

        async def close(self):
            self.closed = True
            self.is_closed = True

    bus = nats_bus.NatsBus(nats_bus.NatsConfig(url="nats://localhost:4222"))
    client = FakeNatsClient()
    ready = threading.Event()

    bus._nc = client  # noqa: SLF001
    bus._js = object()  # noqa: SLF001
    bus._started = True  # noqa: SLF001
    bus._thread.start()  # noqa: SLF001
    bus._loop.call_soon_threadsafe(ready.set)  # noqa: SLF001
    assert ready.wait(timeout=1)

    bus.close()

    assert client.drained
    assert client.closed
    assert not bus._thread.is_alive()  # noqa: SLF001
    assert bus._loop.is_closed()  # noqa: SLF001
    assert bus._nc is None  # noqa: SLF001
    assert bus._js is None  # noqa: SLF001
    assert not bus._started  # noqa: SLF001

    bus.close()


@requires_postgres
def test_claim_specific_job_id(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from api.app import create_app
    from api.settings import Settings
    from api.services import agents as agents_service
    from api.services import tenants as tenants_service

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        allow_scan_start=True,
        job_execution_mode="agent",
        agent_token="test-agent-token",
        jwt_secret="test-secret",
        nats_url="",
        postgres_url=POSTGRES_URL,
    )
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    agents_service.configure(settings)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    client = TestClient(create_app())
    # create_app() seeded the default tenant; scans need its scope (#226).
    approve_scan_scope(settings)

    reg = client.post(
        "/api/agent/register",
        headers={"Authorization": "Bearer test-agent-token"},
        json={"hostname": "w"},
    )
    agent_id = reg.json()["agent_id"]
    login = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "operator-change-me"},
    )
    token = login.json()["access_token"]
    j1 = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "safe"},
    ).json()
    j2 = client.post(
        "/api/jobs",
        headers={"Authorization": f"Bearer {token}"},
        json={"mode": "safe"},
    ).json()

    # Claim the second job specifically (NATS path).
    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}&job_id={j2['job_id']}",
        headers={"Authorization": "Bearer test-agent-token"},
    )
    assert claimed.status_code == 200
    assert claimed.json()["job_id"] == j2["job_id"]

    # First job still queued for generic claim.
    other = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}",
        headers={"Authorization": "Bearer test-agent-token"},
    )
    assert other.status_code == 200
    assert other.json()["job_id"] == j1["job_id"]


class _FlakyJetStream:
    """A JetStream that is unavailable for the first ``unready`` attempts.

    Imitates the state a cold broker is in: enabled, reachable, and answering
    "no responders" until it has finished opening its store.
    """

    def __init__(self, unready: int) -> None:
        self.unready = unready
        self.add_calls = 0

    async def add_stream(self, config=None):
        self.add_calls += 1
        if self.add_calls <= self.unready:
            raise RuntimeError("nats: no responders available for request")
        return None

    async def update_stream(self, config=None):
        raise RuntimeError("nats: no responders available for request")

    async def stream_info(self, name):
        raise RuntimeError("NotFoundError: description='stream not found'")


def _ensure(js, monkeypatch, name: str = "INGEST"):
    import asyncio
    import types

    monkeypatch.setattr(nats_bus.asyncio, "sleep", _no_sleep)
    bus = nats_bus.NatsBus.__new__(nats_bus.NatsBus)
    bus._js = js
    return asyncio.run(bus._ensure_stream(types.SimpleNamespace(name=name)))


async def _no_sleep(_seconds):
    return None


def test_a_stream_that_never_appears_is_an_error_not_a_warning(monkeypatch):
    """The bus must not come up ``_started`` with no stream behind it.

    ``start()`` disables the bus for the process when ``_connect`` raises, and
    that is the correct outcome for an unreachable broker. Returning quietly
    here turned one loud startup failure into an unbounded number of quiet
    publish failures — every event dropped, one ``NoStreamResponseError`` at a
    time, on a bus reporting itself healthy.
    """
    js = _FlakyJetStream(unready=nats_bus._STREAM_ATTEMPTS + 1)
    with pytest.raises(RuntimeError) as excinfo:
        _ensure(js, monkeypatch)

    assert js.add_calls == nats_bus._STREAM_ATTEMPTS
    message = str(excinfo.value)
    assert "INGEST" in message
    # The reason creation failed, not only the flat "stream not found" that
    # stream_info answers with afterwards — that overwrite is what made the
    # original CI failure unreadable.
    assert "no responders" in message


def test_a_stream_that_appears_late_still_comes_up(monkeypatch):
    """A cold JetStream is slow, not broken; the retry budget is for it."""
    js = _FlakyJetStream(unready=3)
    _ensure(js, monkeypatch)
    assert js.add_calls == 4


class _ExistingStream:
    """A JetStream that already holds the stream and refuses to reconcile it.

    The shape a 3-node rollout meets: ``add_stream`` says the stream is there,
    ``update_stream`` refuses (a cluster with fewer peers than the requested
    replicas is the usual reason), and ``stream_info`` answers with whatever
    the stream actually is — R1.
    """

    def __init__(self, num_replicas: int = 1) -> None:
        self.num_replicas = num_replicas

    async def add_stream(self, config=None):
        raise RuntimeError("stream name already in use")

    async def update_stream(self, config=None):
        raise RuntimeError("replicas > 1 not supported in non-clustered mode")

    async def stream_info(self, name):
        import types

        return types.SimpleNamespace(config=types.SimpleNamespace(num_replicas=self.num_replicas))


def _config(name: str = "INGEST", num_replicas: int = 3):
    import types

    return types.SimpleNamespace(name=name, num_replicas=num_replicas)


def test_a_stream_that_cannot_be_reconciled_is_logged(monkeypatch, caplog):
    """The defect: ``update_stream`` failed inside ``except Exception: pass``,
    so an installation that set ``OCTO_NATS_STREAM_REPLICAS=3`` kept its
    existing R1 streams and nothing anywhere said so — the single-copy failure
    the scale-out was bought to prevent, silently intact."""
    import asyncio

    monkeypatch.setattr(nats_bus.asyncio, "sleep", _no_sleep)
    bus = nats_bus.NatsBus.__new__(nats_bus.NatsBus)
    bus._js = _ExistingStream(num_replicas=1)

    with caplog.at_level("WARNING", logger="shapoclyack.nats"):
        asyncio.run(bus._ensure_stream(_config()))

    messages = [record.getMessage() for record in caplog.records]
    assert any("could not be reconciled" in message and "INGEST" in message for message in messages)
    assert any("is R1, not the R3" in message for message in messages)


def test_a_stream_already_at_the_wanted_replicas_is_quiet(monkeypatch, caplog):
    """No warning without a reason for one: the reconcile still failed, but a
    stream that is already R3 is not drift, and a line per stream per start
    would train operators to ignore the one that matters."""
    import asyncio

    monkeypatch.setattr(nats_bus.asyncio, "sleep", _no_sleep)
    bus = nats_bus.NatsBus.__new__(nats_bus.NatsBus)
    bus._js = _ExistingStream(num_replicas=3)

    with caplog.at_level("WARNING", logger="shapoclyack.nats"):
        asyncio.run(bus._ensure_stream(_config()))

    assert not any("is R" in record.getMessage() for record in caplog.records)
