"""A restarted scanner-executor is the agent it was, and nobody else can be (#338).

The executor was a Deployment with no ``OCTO_AGENT_ID``: every pod start
exchanged the key with no id, the API minted a fresh agent, and the one an
operator had quarantined (#308) or put in a group (#361) was left behind while
its replacement scanned, active and ungrouped (review round 1).

Round 2 found the first fix too predictable: the id was the bare pod name,
``shapoclyack-scanner-executor-0``, and agent ids are unique across the whole
installation. Any tenant admin could mint a key in their own tenant and
register that name first — in the window between applying the manifests and
enrolling the executor — and the platform's executor was then refused (403,
"registered in another tenant") until a platform admin found and deleted a row
its own tenant cannot see. The id is now the pod name behind a random prefix
generated at enrollment and kept in the executor's Secret next to the key.

These tests take the composition from the manifest and run the worker's
start-up sequence against the API, as a restart, a key rotation and a squatter
would.
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
# What `scripts/dev-up.sh` and the enrollment docs generate: 64 random bits.
PREFIX = "3f9c2a7b1d4e6a80"


def _env(container: dict) -> dict[str, dict]:
    return {e["name"]: e for e in container["env"]}


def _first_pod_name() -> str:
    doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    assert doc["kind"] == "StatefulSet"
    # A StatefulSet names its pods <name>-<ordinal>.
    return f"{doc['metadata']['name']}-0"


def _first_agent_id(prefix: str = PREFIX) -> str:
    """The id the executor's first pod sends, as the manifest composes it."""
    doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    container = next(c for c in doc["spec"]["template"]["spec"]["containers"] if c["name"] == "executor")
    env = _env(container)
    names = [e["name"] for e in container["env"]]
    assert env["POD_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    secret = env["OCTO_AGENT_ID_PREFIX"]["valueFrom"]["secretKeyRef"]
    assert (secret["name"], secret["key"]) == ("shapoclyack-scanner-executor", "agent_id_prefix")
    assert secret.get("optional") is not True
    template = env["OCTO_AGENT_ID"]["value"]
    assert template == "$(OCTO_AGENT_ID_PREFIX)-$(POD_NAME)"
    # $(VAR) expands only from variables defined earlier in the list.
    assert names.index("OCTO_AGENT_ID") > max(names.index("POD_NAME"), names.index("OCTO_AGENT_ID_PREFIX"))
    return template.replace("$(OCTO_AGENT_ID_PREFIX)", prefix).replace("$(POD_NAME)", _first_pod_name())


def _pod_start(client, key: str, agent_id: str):
    """What agent/worker.py does on start with OCTO_AGENT_ID set."""
    return client.post("/api/auth/agent/token", json={"provisioning_key": key, "agent_id": agent_id})


def _fleet(client, admin: str) -> dict[str, str]:
    page = client.get("/api/agents", headers=bearer(admin)).json()
    rows = page["items"] if isinstance(page, dict) else page
    return {row["agent_id"]: row.get("lifecycle_status") for row in rows}


def test_a_restarted_executor_is_the_same_agent(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin, label="scanner-executor")["key"]
    agent_id = _first_agent_id()

    for _restart in range(2):
        exchanged = _pod_start(client, key, agent_id)
        assert exchanged.status_code == 200, exchanged.text
        assert _register(client, exchanged.json()["access_token"], "node-a")["agent_id"] == agent_id

    # One row, reused: no ghost left behind by the first pod.
    assert list(_fleet(client, admin)) == [agent_id]


def test_a_quarantine_outlives_a_restart_and_a_key_rotation(tmp_path, monkeypatch):
    """The prefix lives beside the key but is not the key: rotating the key
    (docs/k8s-hardening.md § Key expiry and rotation) must not hand the
    executor a new id, because a new id is a way out of quarantine."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    old = _mint_key(client, admin, label="scanner-executor")
    agent_id = _first_agent_id()
    started = _pod_start(client, old["key"], agent_id)
    assert started.status_code == 200, started.text
    _register(client, started.json()["access_token"], "node-a")
    quarantined = client.patch(
        f"/api/agents/{agent_id}",
        headers=bearer(admin),
        json={"status": "quarantined", "reason": "scanning the wrong segment"},
    )
    assert quarantined.status_code == 200, quarantined.text

    # kubectl rollout restart / eviction / node drain: the same id again.
    restarted = _pod_start(client, old["key"], agent_id)
    assert restarted.status_code == 403, restarted.text
    assert "quarantined" in restarted.json()["detail"]

    # The rotation procedure: a new key in the Secret, the old one revoked.
    new = _mint_key(client, admin, label="scanner-executor (rotated)")
    revoked = client.post(
        f"/api/tenants/default/provisioning-keys/{old['key_id']}/revoke", headers=bearer(admin)
    )
    assert revoked.status_code in (200, 204), revoked.text
    rotated = _pod_start(client, new["key"], agent_id)
    assert rotated.status_code == 403, rotated.text
    assert _fleet(client, admin) == {agent_id: "quarantined"}


def test_another_tenant_cannot_take_the_executors_name_first(tmp_path, monkeypatch):
    """Review round 2's P1, flipped. The squatter knows everything the
    manifests publish — the StatefulSet's name, so its pods' names — and
    registers under it in its own tenant before the executor is enrolled. The
    executor still starts."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    created = client.post(
        "/api/tenants", headers=bearer(admin), json={"name": "Acme", "tenant_id": "ten_acme"}
    )
    assert created.status_code in (200, 201), created.text
    squat = _pod_start(client, _mint_key(client, admin, tenant_id="ten_acme")["key"], _first_pod_name())
    assert squat.status_code == 200, squat.text
    _register(client, squat.json()["access_token"], "attacker-box")

    started = _pod_start(client, _mint_key(client, admin, label="scanner-executor")["key"], _first_agent_id())
    assert started.status_code == 200, started.text


def test_two_installations_of_the_example_sensor_do_not_collide(tmp_path, monkeypatch):
    """The example sensor for another cluster used the same fixed names, so
    the second tenant to deploy it was refused, and two sites of one tenant
    became one agent. Each enrollment brings its own prefix."""
    example = yaml.safe_load(
        (MANIFEST.parents[2] / "examples/agent-deployment.example.yaml").read_text(encoding="utf-8")
    )
    container = example["spec"]["template"]["spec"]["containers"][0]
    env = _env(container)
    assert env["OCTO_AGENT_ID"]["value"] == "$(OCTO_AGENT_ID_PREFIX)-$(POD_NAME)"
    assert env["OCTO_AGENT_ID_PREFIX"]["valueFrom"]["secretKeyRef"]["name"] == "shapoclyack-agent"
    pod = f"{example['metadata']['name']}-0"

    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    assert client.post(
        "/api/tenants", headers=bearer(admin), json={"name": "Acme", "tenant_id": "ten_acme"}
    ).status_code in (200, 201)
    for tenant, prefix in (("default", "a1b2c3d4e5f60718"), ("ten_acme", "0f1e2d3c4b5a6978")):
        key = _mint_key(client, admin, tenant_id=tenant)["key"]
        started = _pod_start(client, key, f"{prefix}-{pod}")
        assert started.status_code == 200, (tenant, started.text)
