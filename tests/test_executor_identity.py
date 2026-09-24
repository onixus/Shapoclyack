"""A restarted scanner-executor is the agent it was (#338 review).

The executor was a Deployment with no ``OCTO_AGENT_ID``: every pod start
exchanged the key with no id, the API minted a fresh agent, and the one an
operator had quarantined (#308) or put in a group (#361) was left behind as a
stale row while its replacement scanned, active and ungrouped. A rollout, an
eviction, a node drain or a VPA resize was enough.

It is now a StatefulSet whose pods send their own name as the id. These tests
take the name from the manifest and run the worker's start-up sequence against
the API twice, as a restart would.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.conftest import bearer, login, requires_postgres
from tests.test_agent_identity import _client, _mint_key, _register

pytestmark = requires_postgres

MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "k8s/shapoclyack/base/scanner-executor/statefulset.yaml"
)


def _first_pod_name() -> str:
    """What the executor's first pod sends as its agent id, from the manifest."""
    doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    assert doc["kind"] == "StatefulSet"
    container = next(c for c in doc["spec"]["template"]["spec"]["containers"] if c["name"] == "executor")
    agent_id = next(e for e in container["env"] if e["name"] == "OCTO_AGENT_ID")
    assert agent_id["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    # A StatefulSet names its pods <name>-<ordinal>.
    return f"{doc['metadata']['name']}-0"


def _pod_start(client, key: str, pod: str):
    """What agent/worker.py does on start with OCTO_AGENT_ID set."""
    return client.post("/api/auth/agent/token", json={"provisioning_key": key, "agent_id": pod})


def _fleet(client, admin: str) -> dict[str, str]:
    page = client.get("/api/agents", headers=bearer(admin)).json()
    rows = page["items"] if isinstance(page, dict) else page
    return {row["agent_id"]: row.get("lifecycle_status") for row in rows}


def test_a_restarted_executor_is_the_same_agent(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin, label="scanner-executor")["key"]
    pod = _first_pod_name()

    for _restart in range(2):
        exchanged = _pod_start(client, key, pod)
        assert exchanged.status_code == 200, exchanged.text
        assert _register(client, exchanged.json()["access_token"], "node-a")["agent_id"] == pod

    # One row, reused: no ghost left behind by the first pod.
    assert list(_fleet(client, admin)) == [pod]


def test_a_quarantined_executor_is_still_quarantined_after_a_restart(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin, label="scanner-executor")["key"]
    pod = _first_pod_name()
    started = _pod_start(client, key, pod)
    assert started.status_code == 200, started.text
    _register(client, started.json()["access_token"], "node-a")
    quarantined = client.patch(
        f"/api/agents/{pod}",
        headers=bearer(admin),
        json={"status": "quarantined", "reason": "scanning the wrong segment"},
    )
    assert quarantined.status_code == 200, quarantined.text

    # kubectl rollout restart / eviction / node drain: the same name again.
    restarted = _pod_start(client, key, pod)
    assert restarted.status_code == 403, restarted.text
    assert "quarantined" in restarted.json()["detail"]
    assert _fleet(client, admin) == {pod: "quarantined"}
