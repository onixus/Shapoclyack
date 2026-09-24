"""The rendered manifests are wired together the way #338 says they are.

tests/test_k8s_pod_security.py holds every pod to its Pod Security level and to
the hardening baseline. That leaves what the review of #338 found could be
broken without failing a single one of those checks: a pod that is perfectly
hardened and cannot work — an executor dialling the API in the wrong namespace,
or in plain HTTP at a TLS listener; a datastore whose read-only image has lost
the one directory it writes; a key that is optional, so the pod starts without
one. Each test below is one such wire, and the mutation that used to survive it
is named in its docstring.

Rendering, and skipping without a renderer, is shared with the Pod Security
module: see ``_render`` there.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

import pytest

from tests.test_k8s_pod_security import (
    API,
    EXECUTOR,
    EXECUTOR_NS,
    LOCAL_SCAN_OVERLAYS,
    REPO_ROOT,
    RENDER_TARGETS,
    Workload,
    _render,
    _workloads,
    requires_kustomize,
)

pytestmark = requires_kustomize

EXECUTOR_SECRET = "shapoclyack-scanner-executor"
API_IMAGE = "ghcr.io/onixus/shapoclyack-api"
# The overlays that take base/local-scan: the API scans for itself (local-scan)
# or not at all (api-readonly), and there is no executor to hand work to.
LOCAL_SCAN_COMPONENT = frozenset({"overlays/local-scan", "overlays/api-readonly"})
# A restore drill: the restored database must not start scanning
# (docs/operations.md), so the executor is deliberately left out.
EXECUTORLESS = frozenset({"overlays/kind-restore"})
# The kind stands load one locally built image, the all-in-one, and point
# every workload at it (scripts/dev-up.sh); building the API image as well
# would double the stand's slowest step for a difference that only matters on
# a cluster somebody else can reach.
ONE_IMAGE_STANDS = frozenset({"overlays/kind-dev", "overlays/kind-enrichment", "overlays/kind-restore"})


def _docs(target: str) -> tuple[dict, ...]:
    return _render(target)


def _one(target: str, kind: str | tuple[str, ...], name: str) -> dict | None:
    kinds = (kind,) if isinstance(kind, str) else kind
    found = [d for d in _docs(target) if d["kind"] in kinds and d["metadata"]["name"] == name]
    assert len(found) <= 1, f"{target}: {len(found)} {kinds}/{name}"
    return found[0] if found else None


def _container(doc: dict, name: str) -> dict:
    spec = doc["spec"]["template"]["spec"]
    return next(c for c in [*spec.get("initContainers", []), *spec["containers"]] if c["name"] == name)


def _env(container: dict) -> dict[str, dict]:
    return {e["name"]: e for e in container.get("env") or []}


def _executor(target: str) -> dict | None:
    return _one(target, ("Deployment", "StatefulSet"), EXECUTOR)


def _api(target: str) -> dict:
    api = _one(target, "Deployment", API)
    assert api is not None, f"{target}: no {API} Deployment"
    return api


def _writable_mounts(workload: Workload, container: dict, doc: dict) -> set[str]:
    spec = workload.pod["spec"]
    writable = {v["name"] for v in spec.get("volumes") or [] if "emptyDir" in v or "persistentVolumeClaim" in v}
    writable |= {t["metadata"]["name"] for t in (doc.get("spec") or {}).get("volumeClaimTemplates") or []}
    return {
        m["mountPath"]
        for m in container.get("volumeMounts") or []
        if m["name"] in writable and not m.get("readOnly")
    }


# --------------------------------------------------------------------------
# The executor and the API it works for
# --------------------------------------------------------------------------


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_api_hands_its_scans_to_an_executor_that_is_there(target: str) -> None:
    """Mutation M1 (base API back to ``local``) passed every Pod Security
    check: an API in local mode without the capabilities is perfectly
    restricted — and every scan it starts dies on EPERM, while the executor
    next to it polls a queue nothing is put on."""
    mode = _env(_container(_api(target), "api"))["OCTO_JOB_EXECUTION_MODE"]["value"]
    executor = _executor(target)
    if target in LOCAL_SCAN_COMPONENT:
        assert mode == "local", target
        assert executor is None, f"{target}: an executor nothing hands work to"
    else:
        assert mode == "agent", f"{target}: the API would run scans itself, without the capabilities"
        assert executor is not None or target in EXECUTORLESS, f"{target}: no executor for the queue"


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_executor_reaches_the_api_it_is_deployed_with(target: str) -> None:
    """Mutations M6 (kind-dev executor back to ``http`` while the API speaks
    only TLS) and M8 (``OCTO_API_URL`` naming another namespace): both render,
    both pass admission, and in both the executor never claims a job."""
    executor = _executor(target)
    if executor is None:
        pytest.skip(f"{target} renders no executor")
    api = _api(target)
    api_env = _env(_container(api, "api"))
    service = _one(target, "Service", API)
    assert service is not None
    url = urlsplit(_env(_container(executor, "executor"))["OCTO_API_URL"]["value"])
    api_ns = api["metadata"]["namespace"]
    assert url.hostname in (f"{API}.{api_ns}.svc", f"{API}.{api_ns}.svc.cluster.local"), url.geturl()
    assert url.port in {p["port"] for p in service["spec"]["ports"]}, url.geturl()

    tls = "OCTO_API_TLS_CERT" in api_env
    assert url.scheme == ("https" if tls else "http"), f"{target}: API TLS={tls}, executor dials {url.scheme}"
    if tls:
        # Verified against a CA the pod actually mounts, not skipped.
        executor_env = _env(_container(executor, "executor"))
        bundle = executor_env.get("OCTO_CA_BUNDLE", {}).get("value", "")
        mounts = [m["mountPath"] for m in _container(executor, "executor").get("volumeMounts") or []]
        assert bundle and any(bundle.startswith(m.rstrip("/") + "/") for m in mounts), bundle


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_executor_key_is_a_required_file_not_an_environment_variable(target: str) -> None:
    """Mutation M5 (the Secret made optional): the pod then starts with no key
    and loops on "OCTO_AGENT_PROVISIONING_KEY is required" instead of waiting,
    named, for the Secret. And the key is a file (#338 review): an environment
    variable is inherited by every tool the scan starts and is never updated
    when the Secret is rotated."""
    executor = _executor(target)
    if executor is None:
        pytest.skip(f"{target} renders no executor")
    container = _container(executor, "executor")
    env = _env(container)
    # The one exception (review round 2): the image the manifests pin predates
    # OCTO_AGENT_PROVISIONING_KEY_FILE, and its worker exits without a key. The
    # same Secret's key, by reference, never a value in the manifest.
    if "OCTO_AGENT_PROVISIONING_KEY" in env:
        ref = env["OCTO_AGENT_PROVISIONING_KEY"]["valueFrom"]["secretKeyRef"]
        assert (ref["name"], ref["key"]) == (EXECUTOR_SECRET, "provisioning_key")
        assert ref.get("optional") is not True
    path = env["OCTO_AGENT_PROVISIONING_KEY_FILE"]["value"]
    mount = next(
        m for m in container["volumeMounts"] if path.startswith(m["mountPath"].rstrip("/") + "/")
    )
    assert mount.get("readOnly") is True
    volume = next(v for v in executor["spec"]["template"]["spec"]["volumes"] if v["name"] == mount["name"])
    secret = volume["secret"]
    assert secret["secretName"] == EXECUTOR_SECRET
    assert secret.get("optional") is not True, "an optional key starts the pod without one"
    assert path.endswith("/provisioning_key")
    # Group-readable for fsGroup 1000, nothing for anyone else, never writable.
    mode = secret.get("defaultMode", 0o644)
    assert mode & 0o227 == 0, oct(mode)


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_executor_keeps_its_identity_across_restarts(target: str) -> None:
    """A Deployment's pod starts under a new name every time, and with no
    ``OCTO_AGENT_ID`` the API mints a new agent for it: a restart undid a
    quarantine (#308), dropped the agent's group (#361) and left a ghost in the
    fleet view. A StatefulSet ordinal is the same after every restart, and the
    worker sends it as its id — which the API refuses to re-issue a token for
    while the agent is quarantined."""
    executor = _executor(target)
    if executor is None:
        pytest.skip(f"{target} renders no executor")
    assert executor["kind"] == "StatefulSet"
    container = _container(executor, "executor")
    env = _env(container)
    order = [e["name"] for e in container["env"]]
    # The pod name alone was predictable and agent ids are installation-wide,
    # so another tenant could register it first (review round 2): behind a
    # random prefix from the executor's own Secret, kept across key rotations.
    assert env["POD_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    prefix = env["OCTO_AGENT_ID_PREFIX"]["valueFrom"]["secretKeyRef"]
    assert (prefix["name"], prefix["key"]) == (EXECUTOR_SECRET, "agent_id_prefix")
    assert prefix.get("optional") is not True
    assert env["OCTO_AGENT_ID"]["value"] == "$(OCTO_AGENT_ID_PREFIX)-$(POD_NAME)"
    assert order.index("OCTO_AGENT_ID") > max(order.index("POD_NAME"), order.index("OCTO_AGENT_ID_PREFIX"))

    labels = executor["spec"]["selector"]["matchLabels"]
    pdbs = [
        d
        for d in _docs(target)
        if d["kind"] == "PodDisruptionBudget"
        and d["metadata"].get("namespace") == EXECUTOR_NS
        and d["spec"]["selector"].get("matchLabels") == labels
    ]
    assert len(pdbs) == 1, f"{target}: {len(pdbs)} PDBs for the executor"
    # Drains are serialised, not blocked: minAvailable at one replica would
    # make every node drain wait on a person.
    assert "minAvailable" not in pdbs[0]["spec"] and pdbs[0]["spec"].get("maxUnavailable") == 1

    for vpa in (d for d in _docs(target) if d["kind"] == "VerticalPodAutoscaler"):
        if vpa["spec"]["targetRef"]["name"] != EXECUTOR:
            continue
        assert vpa["spec"]["targetRef"]["kind"] == "StatefulSet"
        # Auto/Recreate evict a pod to resize it, and an evicted executor
        # drops the scan it is running.
        assert vpa["spec"]["updatePolicy"]["updateMode"] in ("Off", "Initial")


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_executor_asks_the_scheduler_for_the_disk_it_may_fill(target: str) -> None:
    """Its emptyDirs may grow to tens of gigabytes (a run stays on disk until
    the pod goes away); ``sizeLimit`` evicts at that size, but only an
    ephemeral-storage request makes the scheduler look for the room first."""
    executor = _executor(target)
    if executor is None:
        pytest.skip(f"{target} renders no executor")
    container = _container(executor, "executor")
    resources = container.get("resources") or {}
    assert "ephemeral-storage" in (resources.get("requests") or {})
    limit = _quantity((resources.get("limits") or {})["ephemeral-storage"])
    sized = sum(
        _quantity(v["emptyDir"]["sizeLimit"])
        for v in executor["spec"]["template"]["spec"]["volumes"]
        if "emptyDir" in v and "sizeLimit" in v["emptyDir"]
    )
    assert limit >= sized, f"{target}: limit {limit} below the emptyDirs' {sized}"


def _quantity(value: str) -> int:
    match = re.fullmatch(r"(\d+)(Ki|Mi|Gi|Ti)?", str(value))
    assert match, value
    return int(match.group(1)) * {None: 1, "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40}[match.group(2)]


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_a_pod_on_the_host_network_still_resolves_cluster_names(target: str) -> None:
    """Mutation M7: with ``hostNetwork`` and the default ``dnsPolicy`` the pod
    uses the node's resolv.conf, and ``shapoclyack-api.network-scan.svc`` does
    not resolve — the prod executor could reach every host but its API."""
    problems = [
        w.label
        for w in _workloads(_docs(target), target)
        if w.pod["spec"].get("hostNetwork") and w.pod["spec"].get("dnsPolicy") != "ClusterFirstWithHostNet"
    ]
    assert not problems, problems


# --------------------------------------------------------------------------
# The API pod
# --------------------------------------------------------------------------


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_api_runs_the_image_without_the_scanner_toolchain(target: str) -> None:
    """The API no longer scans, so the all-in-one image's setcap'd scanners are
    attack surface in the one pod that holds every credential (#338 review).
    Dockerfile.api is the same API and web console without them. The migration
    runs from the same image, so the two cannot disagree on the schema."""
    api = _api(target)
    if target in LOCAL_SCAN_OVERLAYS or target in ONE_IMAGE_STANDS:
        pytest.skip(f"{target} runs the all-in-one image on purpose")
    for name in ("api", "migrate"):
        image = _container(api, name)["image"]
        assert image.split("@")[0].rsplit(":", 1)[0] == API_IMAGE, f"{target} {name}: {image}"
        assert "@sha256:" in image, f"{target} {name}: not pinned by digest"


def test_production_replaces_a_single_api_rather_than_surging_it() -> None:
    """P2 of the review: overlays/prod no longer pins the API to one node, so a
    surging rollout schedules the new pod wherever there is room, and a
    ReadWriteOnce ``scanner-data`` cannot attach there while the old pod holds
    it (Multi-Attach) — the rollout stalls with the old pod still running the
    old release. ``Recreate`` detaches first."""
    target = "overlays/prod"
    api = _api(target)
    claims = {
        d["metadata"]["name"]: d["spec"].get("accessModes") or []
        for d in _docs(target)
        if d["kind"] == "PersistentVolumeClaim"
    }
    mounted = [
        v["persistentVolumeClaim"]["claimName"]
        for v in api["spec"]["template"]["spec"].get("volumes") or []
        if "persistentVolumeClaim" in v
    ]
    rwo = [c for c in mounted if claims.get(c) == ["ReadWriteOnce"]]
    assert rwo, "the test's premise: prod's API mounts a ReadWriteOnce claim"
    assert api["spec"].get("replicas", 1) == 1
    assert api["spec"]["strategy"] == {"type": "Recreate"}


# --------------------------------------------------------------------------
# Datastores on a read-only root filesystem
# --------------------------------------------------------------------------

# Every path each datastore writes outside its data volume, found by running
# the pinned image under strace with a read-only root (docs/k8s-hardening.md
# § How this is checked). Mutations M2 (postgres' socket directory) and M3
# (ClickHouse's users.d) removed one each and nothing failed.
REQUIRED_WRITABLE: dict[tuple[str, str], frozenset[str]] = {
    ("shapoclyack-postgres", "postgres"): frozenset(
        {"/var/lib/postgresql/data", "/var/run/postgresql", "/tmp"}
    ),
    ("shapoclyack-clickhouse", "clickhouse"): frozenset(
        {"/var/lib/clickhouse", "/etc/clickhouse-server/users.d", "/tmp"}
    ),
    ("shapoclyack-nats", "nats"): frozenset({"/data"}),
}


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_datastores_can_write_where_their_images_write(target: str) -> None:
    docs = _docs(target)
    problems: list[str] = []
    for workload in _workloads(docs, target):
        doc = next(d for d in docs if d["kind"] == workload.kind and d["metadata"]["name"] == workload.name)
        for container in workload.containers():
            needed = REQUIRED_WRITABLE.get((workload.name, container["name"]))
            if not needed:
                continue
            missing = needed - _writable_mounts(workload, container, doc)
            if missing:
                problems.append(f"{workload.label} {container['name']}: {sorted(missing)} not writable")
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_clickhouse_logs_to_the_console_only(target: str) -> None:
    """Mutation M4: the image's config also logs to /var/log/clickhouse-server,
    which the read-only root refuses — and which, writable, was up to 20 GB on
    the container's own layer."""
    config = _one(target, "ConfigMap", "shapoclyack-clickhouse-config")
    if config is None:
        pytest.skip(f"{target} renders no ClickHouse")
    logger = ET.fromstring(config["data"]["config.xml"]).find("logger")
    assert logger is not None
    for element in ("log", "errorlog"):
        node = logger.find(element)
        assert node is not None and node.get("remove") == "remove", element


# --------------------------------------------------------------------------
# The executor's image
# --------------------------------------------------------------------------


def test_the_executor_image_carries_no_setuid_binaries() -> None:
    """The executor needs ``allowPrivilegeEscalation: true`` for the file
    capabilities of naabu and nmap, and that same setting lets a setuid-root
    binary raise the process to uid 0. The Debian base brings su, passwd,
    mount and friends, and openssh-client ssh-keysign; none is used, so the
    final stage clears every setuid and setgid bit after its last package
    install."""
    text = (REPO_ROOT / "Dockerfile.allinone").read_text(encoding="utf-8")
    final = text[text.rindex("\nFROM ") :]
    strip = re.search(r"find / -xdev -perm /6000 -type f -exec chmod a-s \{\} \+", final)
    assert strip, "the final stage does not clear setuid/setgid bits"
    # fping's package falls back to setuid root when its own setcap fails; the
    # image grants the capability itself so the strip cannot take ICMP away.
    fping = re.search(r'setcap cap_net_raw\+ep "\$\(command -v fping\)"', final)
    assert fping and fping.start() < strip.start(), "fping's capability is not set before the strip"
    installs = [m.end() for m in re.finditer(r"apt-get install", final)]
    assert installs and strip.start() > max(installs), "a package installed after the strip may bring one back"
