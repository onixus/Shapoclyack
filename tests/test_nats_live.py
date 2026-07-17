"""Live JetStream broker tests (require a reachable NATS with JetStream).

Skipped unless ``OCTO_NATS_URL`` (or ``NATS_URL``) is set. CI sets this via a
``nats`` service container.
"""

from __future__ import annotations

import os
import uuid

import pytest

from api.services import nats_bus
from agent.worker import AgentNatsSession, SUBJECT_JOBS_SCAN

NATS_URL = (os.environ.get("OCTO_NATS_URL") or os.environ.get("NATS_URL") or "").strip()

pytestmark = pytest.mark.skipif(
    not NATS_URL,
    reason="OCTO_NATS_URL / NATS_URL not set (live broker)",
)


@pytest.fixture()
def bus():
    nats_bus.reset_bus_for_tests()
    started = nats_bus.startup_bus(NATS_URL)
    assert started is not None and started._started  # noqa: SLF001
    yield started
    nats_bus.reset_bus_for_tests()


def test_live_stream_bootstrap_and_publish(bus):
    job_id = f"live-{uuid.uuid4().hex[:12]}"
    ok = bus.publish_job_offer({"job_id": job_id, "tenant_id": "default", "mode": "safe"})
    assert ok is True


def test_live_agent_session_pulls_offer(bus):
    expected_job_id = f"live-pull-{uuid.uuid4().hex[:12]}"

    async def _purge() -> None:
        assert bus._js is not None  # noqa: SLF001
        await bus._js.purge_stream("JOBS")  # noqa: SLF001

    bus._call(_purge())  # noqa: SLF001
    assert bus.publish_json(
        SUBJECT_JOBS_SCAN,
        {"job_id": expected_job_id, "tenant_id": "default"},
        msg_id=f"msg-{expected_job_id}",
    )

    class _FakeClient:
        def claim(self, agent_id: str, *, job_id: str | None = None):
            assert agent_id == "agent-live"
            assert job_id == expected_job_id
            return {"job_id": expected_job_id, "run_id": "run-live", "status": "running"}

    session = AgentNatsSession(NATS_URL)
    try:
        session.start()
        claimed = session.pull_and_claim(_FakeClient(), "agent-live", timeout=5.0)
        assert claimed is not None
        assert claimed["job_id"] == expected_job_id
        assert session.pull_and_claim(_FakeClient(), "agent-live", timeout=1.0) is None
        assert session._started and session._nc is not None and session._nc.is_connected  # noqa: SLF001
    finally:
        session.close()


def test_live_ingest_publish(bus):
    import io
    import tarfile

    from api.services import results_ingest

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b'{"ok":true}\n'
        info = tarfile.TarInfo(name="findings.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    archive = buf.getvalue()

    meta = results_ingest.publish_raw_results(
        nats_url=NATS_URL,
        job_id=f"job-{uuid.uuid4().hex[:8]}",
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        agent_id="agent-live",
        exit_code=0,
        archive_bytes=archive,
        tenant_id="default",
    )
    assert meta["published"] is True
    assert meta["msg_id"]
