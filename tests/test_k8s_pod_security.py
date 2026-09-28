"""Every pod the Kubernetes manifests ship meets the hardening baseline (#338).

Two layers, checked separately because they answer different questions:

* Pod Security Standards — what the API server itself admits. Each rendered
  namespace carries a ``pod-security.kubernetes.io/enforce`` level, and every
  pod template in that namespace has to pass it, exactly as PodSecurity
  admission would decide on the Pod. ``_pss_violations`` below is a transcription
  of k8s.io/pod-security-admission's baseline and restricted checks; the API pod
  must pass ``restricted`` in every overlay but the one that opts back into
  local scanning.
* The repository's own baseline, stricter than ``baseline`` and partly outside
  PSS altogether (read-only root filesystem, no service-account token): what
  every new workload in any branch is expected to meet. Deviations are allowed
  only through ``EXCEPTIONS``, each with the reason it exists, and every entry
  there has to be exercised by some manifest and named in docs/k8s-hardening.md
  — an exception nobody uses or nobody documented fails.

Rendering uses ``kubectl kustomize`` (or a standalone ``kustomize``), or reads
what k8s/scripts/validate-kustomize.sh rendered into ``OCTO_K8S_RENDER_DIR`` —
the Jenkins test containers have no kubectl, the stage around them does. With
neither, the render-based tests skip and say so on a laptop, and *fail* under
``OCTO_REQUIRE_INTEGRATION=1``: the CI run that skipped 79 of them in silence
is what let eight mutations of these manifests through review (#338).
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from tests.integration_gate import require_integration

REPO_ROOT = Path(__file__).resolve().parents[1]
K8S = REPO_ROOT / "k8s" / "shapoclyack"
HARDENING_DOC = REPO_ROOT / "docs" / "k8s-hardening.md"

CONTROL_PLANE_NS = "network-scan"
EXECUTOR_NS = "network-scan-executor"
EXECUTOR = "shapoclyack-scanner-executor"
API = "shapoclyack-api"

# Every overlay, discovered the way k8s/scripts/validate-kustomize.sh discovers
# them, so a new one is covered the day it is added.
RENDER_TARGETS = ["base"] + sorted(
    f"overlays/{path.name}" for path in (K8S / "overlays").iterdir() if path.is_dir()
)
# Manifests no kustomization renders: applied by hand, one file at a time.
STATIC_MANIFESTS = sorted((K8S / "examples").glob("*.example.yaml")) + [
    K8S / "base" / "local-scan" / "job-resume.yaml",
]
EXAMPLE_PATCHES = sorted((K8S / "examples").glob("*-patch.yaml"))

# Where the API is allowed to scan for itself. overlays/api-readonly also
# takes base/local-scan, but only for the scan Job/CronJob; its API must not
# get the capabilities, and the test says so by leaving it out of this set.
LOCAL_SCAN_OVERLAYS = frozenset({"overlays/local-scan"})
# Overlays whose network-scan cannot enforce `baseline`, because base/local-scan
# puts NET_RAW pods in it.
PRIVILEGED_CONTROL_PLANE = frozenset({"overlays/local-scan", "overlays/api-readonly"})

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _kustomize_command() -> list[str] | None:
    if shutil.which("kubectl"):
        return ["kubectl", "kustomize"]
    if shutil.which("kustomize"):
        return ["kustomize", "build"]
    return None


RENDER_DIR_VAR = "OCTO_K8S_RENDER_DIR"


def _render_dir() -> Path | None:
    value = os.environ.get(RENDER_DIR_VAR, "").strip()
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def _can_render() -> bool:
    return _render_dir() is not None or _kustomize_command() is not None


requires_kustomize = pytest.mark.skipif(
    not _can_render() and not require_integration(),
    reason=f"neither kubectl nor kustomize on PATH and {RENDER_DIR_VAR} unset: the "
    "rendered manifests cannot be checked here (under OCTO_REQUIRE_INTEGRATION=1 "
    "this fails instead of skipping)",
)


@functools.cache
def _render(target: str) -> tuple[dict, ...]:
    render_dir = _render_dir()
    if render_dir is not None:
        # Every target, or the run fails: a directory rendered before an
        # overlay was added must not quietly leave that overlay unchecked.
        path = render_dir / f"{target}.yaml"
        assert path.is_file(), (
            f"{path} is missing: {RENDER_DIR_VAR} is set, so every target has to be "
            f"rendered into it ({RENDER_DIR_VAR}=<dir> k8s/scripts/validate-kustomize.sh)"
        )
        return tuple(doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc)
    command = _kustomize_command()
    assert command is not None, (
        "OCTO_REQUIRE_INTEGRATION declares the test infrastructure available, but there "
        f"is no kubectl or kustomize on PATH and {RENDER_DIR_VAR} is unset — render the "
        "manifests first (the Jenkinsfile's Tests stage does) or drop the flag"
    )
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [*command, str(K8S / target)],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    assert proc.returncode == 0, f"kustomize {target} failed:\n{proc.stderr}"
    return tuple(doc for doc in yaml.safe_load_all(proc.stdout) if doc)


def _load(path: Path) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


@dataclass(frozen=True)
class Workload:
    source: str
    kind: str
    name: str
    namespace: str | None
    pod: dict

    @property
    def label(self) -> str:
        return f"{self.source}: {self.kind}/{self.name}"

    def containers(self) -> list[dict]:
        spec = self.pod.get("spec") or {}
        return [
            *(spec.get("initContainers") or []),
            *(spec.get("containers") or []),
            *(spec.get("ephemeralContainers") or []),
        ]


def _pod_template(doc: dict) -> dict:
    kind = doc["kind"]
    if kind == "Pod":
        return {"metadata": doc.get("metadata") or {}, "spec": doc.get("spec") or {}}
    if kind == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]
    return doc["spec"]["template"]


def _workloads(docs, source: str) -> list[Workload]:
    return [
        Workload(
            source=source,
            kind=doc["kind"],
            name=doc["metadata"]["name"],
            namespace=(doc.get("metadata") or {}).get("namespace"),
            pod=_pod_template(doc),
        )
        for doc in docs
        if doc.get("kind") in WORKLOAD_KINDS
    ]


def _namespace_labels(docs) -> dict[str, dict[str, str]]:
    return {
        doc["metadata"]["name"]: (doc["metadata"].get("labels") or {})
        for doc in docs
        if doc.get("kind") == "Namespace"
    }


# --------------------------------------------------------------------------
# Pod Security Standards, transcribed from k8s.io/pod-security-admission
# (policy/check_*.go). Levels are cumulative: restricted = baseline + more.
# --------------------------------------------------------------------------

# check_capabilities_baseline.go. NET_RAW is NOT here, which is the whole
# reason the scanner-executor has a namespace of its own.
BASELINE_CAPABILITIES = frozenset({
    "AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
    "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT",
})
# check_sysctls.go, as of the 1.31 policy version.
SAFE_SYSCTLS = frozenset({
    "kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range",
    "net.ipv4.ip_unprivileged_port_start", "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range", "net.ipv4.ip_local_reserved_ports",
    "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes",
})
# check_restrictedVolumes.go
RESTRICTED_VOLUME_TYPES = frozenset({
    "configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
    "persistentVolumeClaim", "projected", "secret",
})
SELINUX_TYPES = frozenset({"", "container_t", "container_init_t", "container_kvm_t", "container_engine_t"})


def _pss_violations(workload: Workload, level: str) -> list[str]:
    """What PodSecurity admission at ``level`` would name for this pod."""
    if level == "privileged":
        return []
    meta = workload.pod.get("metadata") or {}
    spec = workload.pod.get("spec") or {}
    psc = spec.get("securityContext") or {}
    containers = workload.containers()
    out: list[str] = []

    # --- baseline ---
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(field):
            out.append(f"{field}=true")
    windows = [psc.get("windowsOptions") or {}] + [
        (c.get("securityContext") or {}).get("windowsOptions") or {} for c in containers
    ]
    if any(w.get("hostProcess") for w in windows):
        out.append("hostProcess")
    for volume in spec.get("volumes") or []:
        if "hostPath" in volume:
            out.append(f"hostPath volume {volume['name']}")
    for container in containers:
        csc = container.get("securityContext") or {}
        name = container["name"]
        if csc.get("privileged"):
            out.append(f"{name}: privileged")
        for cap in (csc.get("capabilities") or {}).get("add") or []:
            if cap not in BASELINE_CAPABILITIES:
                out.append(f"{name}: non-default capability {cap}")
        for port in container.get("ports") or []:
            if port.get("hostPort"):
                out.append(f"{name}: hostPort {port['hostPort']}")
        if csc.get("procMount") not in (None, "Default"):
            out.append(f"{name}: procMount {csc['procMount']}")
    for sc in [psc] + [c.get("securityContext") or {} for c in containers]:
        seccomp = (sc.get("seccompProfile") or {}).get("type")
        if seccomp == "Unconfined":
            out.append("seccompProfile Unconfined")
        apparmor = (sc.get("appArmorProfile") or {}).get("type")
        if apparmor == "Unconfined":
            out.append("appArmorProfile Unconfined")
        selinux = sc.get("seLinuxOptions") or {}
        if selinux.get("type", "") not in SELINUX_TYPES or selinux.get("user") or selinux.get("role"):
            out.append("seLinuxOptions")
    for key, value in (meta.get("annotations") or {}).items():
        if key.startswith("container.apparmor.security.beta.kubernetes.io/") and not (
            value == "runtime/default" or value.startswith("localhost/")
        ):
            out.append(f"AppArmor annotation {value}")
    for sysctl in psc.get("sysctls") or []:
        if sysctl["name"] not in SAFE_SYSCTLS:
            out.append(f"sysctl {sysctl['name']}")
    if level == "baseline":
        return out

    # --- restricted ---
    for volume in spec.get("volumes") or []:
        kinds = set(volume) - {"name"}
        if not kinds <= RESTRICTED_VOLUME_TYPES:
            out.append(f"volume {volume['name']} of type {sorted(kinds)}")
    pod_non_root = psc.get("runAsNonRoot")
    pod_seccomp = (psc.get("seccompProfile") or {}).get("type")
    if psc.get("runAsUser") == 0:
        out.append("pod runAsUser=0")
    for container in containers:
        csc = container.get("securityContext") or {}
        name = container["name"]
        if csc.get("allowPrivilegeEscalation") is not False:
            out.append(f"{name}: allowPrivilegeEscalation != false")
        non_root = csc.get("runAsNonRoot", pod_non_root)
        if non_root is not True:
            out.append(f"{name}: runAsNonRoot != true")
        if csc.get("runAsUser") == 0:
            out.append(f"{name}: runAsUser=0")
        seccomp = (csc.get("seccompProfile") or {}).get("type") or pod_seccomp
        if seccomp not in ("RuntimeDefault", "Localhost"):
            out.append(f"{name}: seccompProfile not RuntimeDefault/Localhost")
        caps = csc.get("capabilities") or {}
        if "ALL" not in (caps.get("drop") or []):
            out.append(f"{name}: capabilities.drop lacks ALL")
        for cap in caps.get("add") or []:
            if cap != "NET_BIND_SERVICE":
                out.append(f"{name}: capability {cap} beyond NET_BIND_SERVICE")
    return out


def test_the_pss_transcription_catches_what_the_scanner_needs() -> None:
    """The transcription is load-bearing, so pin the two facts #338 turns on:
    NET_RAW alone already fails `baseline` (it is in Docker's default set, not
    in PSS's), and `restricted` refuses allowPrivilegeEscalation."""
    scanner = Workload(
        source="fixture",
        kind="Pod",
        name="scanner",
        namespace=None,
        pod={"spec": {
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "c",
                "securityContext": {
                    "allowPrivilegeEscalation": True,
                    "capabilities": {"drop": ["ALL"], "add": ["NET_RAW"]},
                },
            }],
        }},
    )
    assert _pss_violations(scanner, "baseline") == ["c: non-default capability NET_RAW"]
    assert "c: allowPrivilegeEscalation != false" in _pss_violations(scanner, "restricted")
    assert _pss_violations(scanner, "privileged") == []


# --------------------------------------------------------------------------
# The repository's baseline, and its exceptions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Exception_:
    """Deviations one workload is allowed, and why.

    ``container`` is None for pod-level deviations. ``targets`` limits the
    exception to those render targets / files; None means wherever the
    workload appears.
    """

    kind: str
    name: str
    container: str | None
    deviations: frozenset[str]
    reason: str
    targets: frozenset[str] | None = None


_RAW_SOCKETS = frozenset({
    "capabilities.add=NET_RAW",
    "capabilities.add=NET_ADMIN",
    "allowPrivilegeEscalation!=false",
})
_RAW_SOCKETS_WHY = (
    "naabu/pulse/nmap carry `cap_net_raw,cap_net_admin+eip` file capabilities: "
    "both must be in the bounding set or execve fails with EPERM, and "
    "no_new_privs (allowPrivilegeEscalation: false) makes the kernel ignore them"
)

EXCEPTIONS: tuple[Exception_, ...] = (
    Exception_("StatefulSet", EXECUTOR, "executor", _RAW_SOCKETS, _RAW_SOCKETS_WHY),
    Exception_(
        "StatefulSet", EXECUTOR, None, frozenset({"hostNetwork=true"}),
        "overlays/prod scans from the node's own network on a tainted scanner pool",
        targets=frozenset({"overlays/prod"}),
    ),
    Exception_("StatefulSet", "shapoclyack-agent", "agent", _RAW_SOCKETS,
               "examples/: the scanner-executor for a cluster other than the API's; " + _RAW_SOCKETS_WHY),
    Exception_("Job", "network-scan", "scanner", _RAW_SOCKETS,
               "base/local-scan: scans onto the PVC the API reads; " + _RAW_SOCKETS_WHY),
    Exception_("CronJob", "network-scan-scheduled", "scanner", _RAW_SOCKETS,
               "base/local-scan: scans onto the PVC the API reads; " + _RAW_SOCKETS_WHY),
    Exception_("Job", "network-scan-resume", "scanner", _RAW_SOCKETS,
               "base/local-scan (applied by hand): resumes a local-scan run; " + _RAW_SOCKETS_WHY),
    Exception_(
        "Deployment", API, "api", _RAW_SOCKETS,
        "overlays/local-scan only: OCTO_JOB_EXECUTION_MODE=local runs scanner.main "
        "inside the API container; " + _RAW_SOCKETS_WHY,
        targets=LOCAL_SCAN_OVERLAYS,
    ),
    Exception_(
        "Deployment", "shapoclyack-maddy", "maddy",
        frozenset({"capabilities.add=NET_BIND_SERVICE", "readOnlyRootFilesystem!=true"}),
        "lab-only example: the upstream image runs as root to bind :25, and its write "
        "paths beyond /data are unverified",
    ),
    Exception_(
        "Deployment", "shapoclyack-maddy", None, frozenset({"runAsNonRoot!=true"}),
        "lab-only example: the upstream image has no non-root user",
    ),
)


def _baseline_deviations(workload: Workload) -> dict[str | None, set[str]]:
    """Deviations from the #338 baseline, keyed by container (None = pod)."""
    spec = workload.pod.get("spec") or {}
    psc = spec.get("securityContext") or {}
    containers = workload.containers()
    found: dict[str | None, set[str]] = {None: set()}

    # Explicit on the pod, not inherited from a ServiceAccount: a pod moved to
    # another account must not quietly regain a token.
    if spec.get("automountServiceAccountToken") is not False:
        found[None].add("automountServiceAccountToken!=false")
    if (psc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
        found[None].add("seccompProfile!=RuntimeDefault")
    if psc.get("runAsNonRoot") is not True:
        found[None].add("runAsNonRoot!=true")
    if psc.get("runAsUser") == 0:
        found[None].add("runAsUser=0")
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(field):
            found[None].add(f"{field}=true")
    for volume in spec.get("volumes") or []:
        if "hostPath" in volume:
            found[None].add("hostPath")

    for container in containers:
        csc = container.get("securityContext") or {}
        dev = found.setdefault(container["name"], set())
        if csc.get("allowPrivilegeEscalation") is not False:
            dev.add("allowPrivilegeEscalation!=false")
        if csc.get("readOnlyRootFilesystem") is not True:
            dev.add("readOnlyRootFilesystem!=true")
        if csc.get("privileged"):
            dev.add("privileged=true")
        caps = csc.get("capabilities") or {}
        if caps.get("drop") != ["ALL"]:
            dev.add("capabilities.drop!=[ALL]")
        for cap in caps.get("add") or []:
            dev.add(f"capabilities.add={cap}")
        if csc.get("runAsNonRoot") is False:
            dev.add("runAsNonRoot=false")
        if csc.get("runAsUser") == 0:
            dev.add("runAsUser=0")
        if (csc.get("seccompProfile") or {}).get("type") not in (None, "RuntimeDefault"):
            dev.add("seccompProfile!=RuntimeDefault")
    return {key: value for key, value in found.items() if value}


def _allowed(workload: Workload, container: str | None, target: str) -> tuple[set[str], set[Exception_]]:
    allowed: set[str] = set()
    used: set[Exception_] = set()
    for exc in EXCEPTIONS:
        if (exc.kind, exc.name, exc.container) != (workload.kind, workload.name, container):
            continue
        if exc.targets is not None and target not in exc.targets:
            continue
        allowed |= exc.deviations
        used.add(exc)
    return allowed, used


def _unexcused(workload: Workload, target: str) -> tuple[list[str], set[Exception_]]:
    problems: list[str] = []
    used: set[Exception_] = set()
    for container, deviations in _baseline_deviations(workload).items():
        allowed, exercised = _allowed(workload, container, target)
        used |= {exc for exc in exercised if deviations & exc.deviations}
        for deviation in sorted(deviations - allowed):
            where = f"container {container}" if container else "pod"
            problems.append(f"{workload.label} {where}: {deviation}")
    return problems, used


# --------------------------------------------------------------------------
# Render-based checks
# --------------------------------------------------------------------------


@requires_kustomize
@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_every_pod_is_admitted_by_its_namespaces_enforce_level(target: str) -> None:
    """What the API server would do with each pod, overlay by overlay.

    A workload in a namespace the render does not declare fails too: it lands
    wherever the kubeconfig points, under whatever Pod Security that namespace
    has — the way overlays/agents' old sensor Deployment rendered with no
    namespace at all."""
    docs = _render(target)
    namespaces = _namespace_labels(docs)
    problems: list[str] = []
    for workload in _workloads(docs, target):
        if workload.namespace not in namespaces:
            problems.append(f"{workload.label}: namespace {workload.namespace!r} is not in the render")
            continue
        level = namespaces[workload.namespace].get("pod-security.kubernetes.io/enforce", "privileged")
        for violation in _pss_violations(workload, level):
            problems.append(f"{workload.label} in {workload.namespace} ({level}): {violation}")
    assert not problems, "\n".join(problems)


@requires_kustomize
@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_every_rendered_pod_meets_the_hardened_baseline(target: str) -> None:
    """The contract every workload in every branch is held to, stricter than
    what admission checks: a deviation is either in EXCEPTIONS, with its
    reason, or a failure here."""
    problems: list[str] = []
    for workload in _workloads(_render(target), target):
        problems += _unexcused(workload, target)[0]
    assert not problems, "\n".join(problems)


@requires_kustomize
@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_api_pod_is_restricted_wherever_it_does_not_scan_itself(target: str) -> None:
    """The point of #338: the pod that holds every credential of the control
    plane passes `restricted`, in every overlay except the one that explicitly
    opts back into local scanning — which must then really be local mode, or
    the exception is covering nothing."""
    api = [w for w in _workloads(_render(target), target) if w.kind == "Deployment" and w.name == API]
    assert len(api) == 1, f"{target}: expected one {API} Deployment"
    violations = _pss_violations(api[0], "restricted")
    container = next(c for c in api[0].pod["spec"]["containers"] if c["name"] == "api")
    mode = next(e.get("value") for e in container["env"] if e["name"] == "OCTO_JOB_EXECUTION_MODE")
    if target in LOCAL_SCAN_OVERLAYS:
        assert mode == "local"
        assert violations, f"{target}: local scanning needs the capabilities it no longer has"
    else:
        assert violations == [], f"{target}:\n" + "\n".join(violations)


@requires_kustomize
@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_namespaces_carry_the_documented_pod_security_labels(target: str) -> None:
    namespaces = _namespace_labels(_render(target))
    control_plane = next(
        (labels for name, labels in namespaces.items() if name in (CONTROL_PLANE_NS, "shapoclyack-restore")),
        None,
    )
    assert control_plane is not None, f"{target}: no control-plane Namespace"
    expected_enforce = "privileged" if target in PRIVILEGED_CONTROL_PLANE else "baseline"
    assert control_plane.get("pod-security.kubernetes.io/enforce") == expected_enforce
    assert control_plane.get("pod-security.kubernetes.io/audit") == "restricted"
    assert control_plane.get("pod-security.kubernetes.io/warn") == "restricted"
    if EXECUTOR_NS in namespaces:
        labels = namespaces[EXECUTOR_NS]
        assert labels.get("pod-security.kubernetes.io/enforce") == "privileged"
        assert labels.get("pod-security.kubernetes.io/audit") == "restricted"
        assert labels.get("pod-security.kubernetes.io/warn") == "restricted"


@requires_kustomize
@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_the_unenforced_namespace_holds_the_executor_and_nothing_else(target: str) -> None:
    """network-scan-executor is `privileged` because of one pod. Anything else
    that renders there — or the executor rendering anywhere else, which an
    overlay's plain `namespace:` field would do — breaks the reason it exists."""
    docs = _render(target)
    in_executor_ns = [w for w in _workloads(docs, target) if w.namespace == EXECUTOR_NS]
    assert [(w.kind, w.name) for w in in_executor_ns] in ([], [("StatefulSet", EXECUTOR)])
    executors = [w for w in _workloads(docs, target) if w.name == EXECUTOR]
    assert all(w.namespace == EXECUTOR_NS for w in executors), [w.namespace for w in executors]
    if executors:
        namespaces = _namespace_labels(docs)
        assert EXECUTOR_NS in namespaces
        # Its whole configuration, in its own namespace: the ConfigMap it
        # mounts and the account it runs as.
        kinds = {(d["kind"], d["metadata"]["name"]) for d in docs if d["metadata"].get("namespace") == EXECUTOR_NS}
        assert ("ConfigMap", "scanner-config") in kinds
        assert ("ServiceAccount", "scanner-executor") in kinds


def _runs_scanner_tools(container: dict) -> bool:
    """The API (the image's default command: GET /api/system runs the tools for
    their versions), the sensor and scanner.main — not the migrate, enrichment
    or audit one-shots, which never exec nuclei/naabu/dnsx."""
    command = container.get("command") or []
    return not command or "agent" in command or "scanner.main" in command


@requires_kustomize
@pytest.mark.parametrize("target", RENDER_TARGETS)
def test_shapoclyack_containers_have_somewhere_to_write(target: str) -> None:
    """A read-only image is only a hardening if the process still starts. Our
    containers need /tmp (Starlette spools uploads there, the agent's per-job
    workdir, the enrichment fetchers' mktemp); the ones that run the scanner's
    tools also need $HOME, where nuclei/naabu/dnsx write a config file and exit
    without it."""
    problems: list[str] = []
    for workload in _workloads(_render(target), target):
        spec = workload.pod["spec"]
        writable = {
            v["name"] for v in spec.get("volumes") or [] if "emptyDir" in v or "persistentVolumeClaim" in v
        }
        for container in workload.containers():
            if not container.get("image", "").startswith("ghcr.io/onixus/shapoclyack-"):
                continue
            mounts = {
                m["mountPath"]: m["name"]
                for m in container.get("volumeMounts") or []
                if m["name"] in writable and not m.get("readOnly")
            }
            needed = ["/tmp", "/home/octo"] if _runs_scanner_tools(container) else ["/tmp"]
            for path in needed:
                if path not in mounts:
                    problems.append(f"{workload.label} container {container['name']}: no writable {path}")
    assert not problems, "\n".join(problems)


# --------------------------------------------------------------------------
# Files applied by hand
# --------------------------------------------------------------------------

_STATIC_LEVELS = {CONTROL_PLANE_NS: "baseline", EXECUTOR_NS: "privileged"}


@pytest.mark.parametrize("path", STATIC_MANIFESTS, ids=lambda p: str(p.relative_to(K8S)))
def test_manifests_applied_by_hand_meet_the_baseline(path: Path) -> None:
    """examples/ and job-resume.yaml never pass through an overlay, so nothing
    else renders them. Judged against the namespace they name (network-scan
    when they name none; `kubectl apply -n network-scan` is how every one of
    them is documented), and against `baseline` for a namespace this
    repository does not define."""
    source = str(path.relative_to(K8S))
    problems: list[str] = []
    for workload in _workloads(_load(path), source):
        problems += _unexcused(workload, source)[0]
        level = _STATIC_LEVELS.get(workload.namespace or CONTROL_PLANE_NS, "baseline")
        if path.name == "job-resume.yaml":
            level = "privileged"  # only ever applied beside base/local-scan
        problems += [f"{workload.label} ({level}): {v}" for v in _pss_violations(workload, level)]
    assert not problems, "\n".join(problems)


_WEAKENING = {
    "allowPrivilegeEscalation": True,
    "privileged": True,
    "hostNetwork": True,
    "hostPID": True,
    "hostIPC": True,
    "readOnlyRootFilesystem": False,
    "runAsNonRoot": False,
    "automountServiceAccountToken": True,
}


def _walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield f"{path}.{key}", key, value
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


@pytest.mark.parametrize("path", EXAMPLE_PATCHES, ids=lambda p: p.name)
def test_example_patches_do_not_loosen_the_workloads_they_patch(path: Path) -> None:
    """A strategic-merge patch can undo any of the above from outside the file
    the tests read. The ones in examples/ are copied into overlays by hand, so
    they may add env and read-only mounts, never privileges."""
    problems: list[str] = []
    for doc in _load(path):
        for where, key, value in _walk(doc):
            if key in _WEAKENING and value == _WEAKENING[key]:
                problems.append(f"{path.name}{where}: {key}: {value}")
            if key == "add" and ".capabilities" in where and value:
                problems.append(f"{path.name}{where}: capabilities.add {value}")
            if key == "hostPath":
                problems.append(f"{path.name}{where}: hostPath")
            if key == "seccompProfile" and (value or {}).get("type") == "Unconfined":
                problems.append(f"{path.name}{where}: seccomp Unconfined")
    assert not problems, "\n".join(problems)


# --------------------------------------------------------------------------
# The allowlist itself
# --------------------------------------------------------------------------


def _all_usage() -> set[Exception_]:
    used: set[Exception_] = set()
    # Under the integration flag with no renderer, _render fails and says why,
    # rather than this reporting every render-only exception as unused.
    if _can_render() or require_integration():
        for target in RENDER_TARGETS:
            for workload in _workloads(_render(target), target):
                used |= _unexcused(workload, target)[1]
    for path in STATIC_MANIFESTS:
        source = str(path.relative_to(K8S))
        for workload in _workloads(_load(path), source):
            used |= _unexcused(workload, source)[1]
    return used


@requires_kustomize
def test_every_exception_is_still_needed() -> None:
    """An exception whose workload no longer deviates is a hole waiting for the
    next change to walk through unnoticed. Remove it with the deviation."""
    unused = [exc for exc in EXCEPTIONS if exc not in _all_usage()]
    assert not unused, "\n".join(f"{e.kind}/{e.name} {e.container}: {sorted(e.deviations)}" for e in unused)


def test_every_exception_is_documented() -> None:
    """docs/k8s-hardening.md is where an auditor reads what runs outside the
    baseline; a workload allowed to deviate and not named there is an
    undocumented exception, whatever the reason string above says."""
    text = HARDENING_DOC.read_text(encoding="utf-8")
    missing = sorted({exc.name for exc in EXCEPTIONS if f"`{exc.name}`" not in text})
    assert not missing, f"not named in {HARDENING_DOC.relative_to(REPO_ROOT)}: {missing}"


_WORKLOAD_REF = re.compile(r"`((?:%s)/[a-z0-9-]+)`" % "|".join(sorted(WORKLOAD_KINDS)))


def _documented_workloads() -> set[str]:
    text = HARDENING_DOC.read_text(encoding="utf-8")
    table = text[text.index("\n## Workloads\n") : text.index("\n## Deviations from restricted\n")]
    return set(_WORKLOAD_REF.findall(table))


@requires_kustomize
def test_every_workload_is_in_the_documented_table() -> None:
    """docs/k8s-hardening.md § Workloads says it is the whole list: where each
    pod runs, as whom, and every path it may write. The checks above hold a
    workload another branch adds to the baseline the day it renders (#333's
    ClickHouse backup, #339's bundle loader and inbox pod came in that way);
    this one makes it also say what it writes. Both directions: a row whose
    workload is gone describes a pod nobody runs."""
    rendered: set[str] = set()
    for target in RENDER_TARGETS:
        rendered |= {f"{w.kind}/{w.name}" for w in _workloads(_render(target), target)}
    for path in STATIC_MANIFESTS:
        source = str(path.relative_to(K8S))
        rendered |= {f"{w.kind}/{w.name}" for w in _workloads(_load(path), source)}
    documented = _documented_workloads()
    doc = HARDENING_DOC.relative_to(REPO_ROOT)
    assert not sorted(rendered - documented), f"not in {doc} § Workloads: {sorted(rendered - documented)}"
    assert not sorted(documented - rendered), f"in {doc} § Workloads, rendered nowhere: {sorted(documented - rendered)}"
