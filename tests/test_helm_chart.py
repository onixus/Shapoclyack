"""The Helm chart is the kustomize base in another packaging (#341).

Two layers. The comparison tool (scripts/helm_parity.py) is tested on its own,
with hand-written manifests, because a parity check that cannot fail proves
nothing: each way the chart could drift from the base has a case that must be
caught. The chart itself is then rendered with the real ``helm`` and compared
with the real ``kubectl kustomize`` of k8s/shapoclyack/base, plus one render per
optional feature. Those need ``helm``, and the base render from ``kubectl`` or
from ``OCTO_K8S_RENDER_DIR`` (what the Jenkins cells have). Without them they
skip on a laptop and *fail* under ``OCTO_REQUIRE_HELM=1``, a flag of their own:
the global ``OCTO_REQUIRE_INTEGRATION=1`` that every pytest cell sets must not
turn "this cell has no helm" into a red build (it did, in review of #341).
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
CHART = REPO_ROOT / "charts" / "shapoclyack"
BASE = REPO_ROOT / "k8s" / "shapoclyack" / "base"

_spec = importlib.util.spec_from_file_location("helm_parity", REPO_ROOT / "scripts" / "helm_parity.py")
helm_parity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helm_parity)


# --- the comparison tool ---------------------------------------------------


def _deployment() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "namespace": "ns",
            "labels": {"app.kubernetes.io/managed-by": "kustomize", "app.kubernetes.io/name": "x"},
        },
        "spec": {
            "template": {
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [
                        {
                            "name": "api",
                            "securityContext": {
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                }
            }
        },
    }


def _secret(value: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "s", "namespace": "ns"},
        "data": {"password": base64.b64encode(value.encode()).decode()},
    }


def _compare(tmp_path: Path, left: list[dict], right: list[dict]) -> int:
    (tmp_path / "left.yaml").write_text(yaml.safe_dump_all(left))
    (tmp_path / "right.yaml").write_text(yaml.safe_dump_all(right))
    return helm_parity.compare(str(tmp_path / "left.yaml"), str(tmp_path / "right.yaml"))


def test_parity_ignores_the_generator_label_only(tmp_path):
    chart = _deployment()
    chart["metadata"]["labels"]["app.kubernetes.io/managed-by"] = "Helm"
    chart["metadata"]["labels"]["helm.sh/chart"] = "shapoclyack-0.1.0"
    assert _compare(tmp_path, [_deployment()], [chart]) == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(
            readOnlyRootFilesystem=False
        ),
        lambda d: d["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"].update(
            drop=[]
        ),
        lambda d: d["spec"]["template"]["spec"].update(automountServiceAccountToken=True),
        lambda d: d["metadata"]["labels"].update({"app.kubernetes.io/name": "other"}),
    ],
    ids=["rootfs", "capabilities", "sa-token", "label"],
)
def test_parity_catches_hardening_drift(tmp_path, mutate):
    chart = copy.deepcopy(_deployment())
    mutate(chart)
    assert _compare(tmp_path, [_deployment()], [chart]) == 1


def test_parity_catches_a_missing_and_an_extra_object(tmp_path):
    other = _deployment()
    other["metadata"]["name"] = "other"
    assert _compare(tmp_path, [_deployment(), other], [_deployment()]) == 1
    assert _compare(tmp_path, [_deployment()], [_deployment(), other]) == 1


def test_parity_compares_secret_values_not_their_encoding(tmp_path):
    assert _compare(tmp_path, [_secret("a")], [_secret("a")]) == 0
    assert _compare(tmp_path, [_secret("a")], [_secret("b")]) == 1
    string_data = _secret("a")
    string_data["stringData"] = {"password": string_data.pop("data")["password"]}
    string_data["stringData"]["password"] = "a"
    assert _compare(tmp_path, [_secret("a")], [string_data]) == 0


def test_parity_fails_on_a_duplicated_object(tmp_path):
    assert _compare(tmp_path, [_deployment()], [_deployment(), _deployment()]) == 1
    assert _compare(tmp_path, [_deployment(), _deployment()], [_deployment()]) == 1


def test_sync_removes_stale_files_and_warns_about_unknown_configmaps(tmp_path, capsys):
    chart = tmp_path / "chart"
    (chart / "files" / "nats").mkdir(parents=True)
    (chart / "files" / "nats" / "old.conf").write_text("stale")
    docs = [
        {"kind": "ConfigMap", "metadata": {"name": "shapoclyack-nats-config", "namespace": "network-scan"},
         "data": {"nats.conf": "port: 4222\n"}},
        {"kind": "ConfigMap", "metadata": {"name": "brand-new", "namespace": "network-scan"}, "data": {"a": "b"}},
    ]
    (tmp_path / "k.yaml").write_text(yaml.safe_dump_all(docs))
    assert helm_parity.sync(str(tmp_path / "k.yaml"), str(chart)) == 0
    assert (chart / "files" / "nats" / "nats.conf").read_text() == "port: 4222\n"
    assert not (chart / "files" / "nats" / "old.conf").exists()
    assert "brand-new" in capsys.readouterr().err


# --- the chart, rendered ---------------------------------------------------

PARITY_VALUES = str(CHART / "ci" / "parity-values.yaml")
RENDER_DIR_ENV = "OCTO_K8S_RENDER_DIR"


def _require_helm() -> bool:
    """OCTO_REQUIRE_HELM=1 declares helm available, as the Jenkins cells do."""
    return os.environ.get("OCTO_REQUIRE_HELM", "").strip().lower() in {"1", "true", "yes"}


def _base_render() -> str | None:
    """The kustomize base: rendered here, or by the stage around the test container."""
    if shutil.which("kubectl"):
        return subprocess.run(
            ["kubectl", "kustomize", str(BASE)], check=True, capture_output=True, text=True
        ).stdout
    render_dir = os.environ.get(RENDER_DIR_ENV)
    if render_dir and (Path(render_dir) / "base.yaml").is_file():
        return (Path(render_dir) / "base.yaml").read_text(encoding="utf-8")
    return None


@pytest.fixture(scope="module")
def tools():
    missing = None
    if not shutil.which("helm"):
        missing = "helm is not installed"
    elif _base_render() is None:
        missing = f"neither kubectl nor {RENDER_DIR_ENV}/base.yaml is available"
    if missing is None:
        return
    if _require_helm():
        pytest.fail(f"{missing} (OCTO_REQUIRE_HELM=1)")
    pytest.skip(missing)


def _helm(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "shapoclyack", str(CHART), "--namespace", "network-scan", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def _render(*args: str, parity: bool = True) -> list[dict]:
    """Render with the dev placeholders allowed: without them the chart refuses."""
    extra = ["-f", PARITY_VALUES] if parity else []
    return [d for d in yaml.safe_load_all(_helm(*extra, *args).stdout) if d]


def _kinds(docs: list[dict], kind: str) -> list[dict]:
    return [d for d in docs if d["kind"] == kind]


def _secret_refs(docs: list[dict]) -> set[str]:
    """Every Secret name a workload points at, whatever the field."""
    names: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for key in ("secretKeyRef", "secretRef"):
                if key in node:
                    names.add(node[key]["name"])
            if "secretName" in node:
                names.add(node["secretName"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(docs)
    return names


def test_default_render_equals_the_kustomize_base(tools, tmp_path):
    (tmp_path / "kustomize.yaml").write_text(_base_render())
    (tmp_path / "helm.yaml").write_text(_helm("-f", PARITY_VALUES).stdout)
    assert helm_parity.compare(str(tmp_path / "kustomize.yaml"), str(tmp_path / "helm.yaml")) == 0


# What the parity check has to notice, on the real base objects rather than a
# generic dict: each entry weakens one thing the hardening rests on.
def _api(d):
    return next(o for o in d if o["kind"] == "Deployment" and o["metadata"]["name"] == "shapoclyack-api")


def _pg(d):
    return next(o for o in d if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "shapoclyack-postgres")


def _pg_ctx(d):
    return _pg(d)["spec"]["template"]["spec"]["containers"][0]["securityContext"]


MUTATIONS = {
    "readOnlyRootFilesystem": lambda d: _api(d)["spec"]["template"]["spec"]["containers"][0][
        "securityContext"
    ].update(readOnlyRootFilesystem=False),
    "allowPrivilegeEscalation": lambda d: _pg_ctx(d).update(allowPrivilegeEscalation=True),
    "runAsNonRoot": lambda d: _pg(d)["spec"]["template"]["spec"]["securityContext"].update(runAsNonRoot=False),
    "automount": lambda d: _api(d)["spec"]["template"]["spec"].update(automountServiceAccountToken=True),
    "hostNetwork": lambda d: _api(d)["spec"]["template"]["spec"].update(hostNetwork=True),
    "privileged": lambda d: _pg_ctx(d).update(privileged=True),
    "capabilities": lambda d: _pg_ctx(d)["capabilities"].update(drop=[]),
    "networkpolicy-removed": lambda d: d.remove(next(o for o in d if o["kind"] == "NetworkPolicy")),
    "networkpolicy-widened": lambda d: next(
        o for o in d if o["kind"] == "NetworkPolicy" and "postgres" in o["metadata"]["name"]
    )["spec"].update(ingress=[{}]),
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_parity_catches_each_hardening_weakening_on_the_real_base(tools, tmp_path, name):
    docs = [d for d in yaml.safe_load_all(_base_render()) if d]
    mutated = copy.deepcopy(docs)
    MUTATIONS[name](mutated)
    assert _compare(tmp_path, docs, docs) == 0
    assert _compare(tmp_path, docs, mutated) == 1


def test_helm_lint_strict_passes_with_the_features_on(tools):
    for args in (
        ["-f", PARITY_VALUES],
        ["--set", "ingress.enabled=true", "--set", "externalSecrets.enabled=true"],
    ):
        subprocess.run(
            ["helm", "lint", "--strict", str(CHART), *args], check=True, capture_output=True, text=True
        )


def test_defaults_refuse_to_render_public_placeholder_credentials(tools):
    result = _helm(check=False)
    assert result.returncode != 0
    assert "devPlaceholders" in result.stderr and "existingSecrets" in result.stderr
    # Supplying every credential, or ESO, is accepted without the escape hatch.
    names = ["api", "postgres", "clickhouse", "clickhouseBackup", "nats"]
    own = [x for n in names for x in ("--set", f"existingSecrets.{n}={n}-creds")]
    assert _helm(*own).returncode == 0
    assert _helm("--set", "externalSecrets.enabled=true").returncode == 0
    # One missing credential is enough to refuse, and the message names it.
    partial = _helm(*own[:-2], check=False)
    assert partial.returncode != 0 and "nats" in partial.stderr


def test_several_api_replicas_need_a_shared_volume(tools):
    refused = _helm("-f", PARITY_VALUES, "--set", "replicas.api=3", check=False)
    assert refused.returncode != 0 and "ReadWriteMany" in refused.stderr
    hpa = _helm("-f", PARITY_VALUES, "--set", "api.autoscaling.enabled=true", check=False)
    assert hpa.returncode != 0, "the HPA's maxReplicas counts, not replicas.api"
    ok = _render("--set", "replicas.api=3", "--set", "storage.scannerData.accessMode=ReadWriteMany")
    assert _api(ok)["spec"]["replicas"] == 3
    assert "affinity" not in _api(ok)["spec"]["template"]["spec"], "placement is opt-in"


def test_spread_and_autoscaling_follow_the_prod_ha_overlay(tools):
    docs = _render(
        "--set", "api.spread.enabled=true",
        "--set", "api.autoscaling.enabled=true",
        "--set", "storage.scannerData.accessMode=ReadWriteMany",
    )
    pod = _api(docs)["spec"]["template"]["spec"]
    hard = pod["topologySpreadConstraints"][0]
    assert hard["whenUnsatisfiable"] == "DoNotSchedule" and hard["topologyKey"] == "kubernetes.io/hostname"
    assert "replicas" not in _api(docs)["spec"], "the HPA owns the count"
    hpa = _kinds(docs, "HorizontalPodAutoscaler")[0]
    assert hpa["spec"]["scaleTargetRef"]["name"] == "shapoclyack-api"
    # The spread selector has to match the API pods' labels or it spreads nothing.
    labels = _api(docs)["spec"]["template"]["metadata"]["labels"]
    assert hard["labelSelector"]["matchLabels"].items() <= labels.items()


def test_network_policy_switch_removes_exactly_the_policies(tools):
    assert len(_kinds(_render(), "NetworkPolicy")) == 4
    assert _kinds(_render("--set", "networkPolicy.enabled=false"), "NetworkPolicy") == []


def test_existing_secret_replaces_the_placeholder_and_is_what_pods_read(tools):
    docs = _render("--set", "existingSecrets.api=my-api-creds")
    assert "shapoclyack-api" not in {d["metadata"]["name"] for d in _kinds(docs, "Secret")}
    refs = _secret_refs(_kinds(docs, "Deployment"))
    assert "my-api-creds" in refs
    assert "shapoclyack-api" not in refs


def test_external_secrets_replace_every_generated_secret(tools):
    docs = _render("--set", "externalSecrets.enabled=true", "--set", "existingSecrets.postgres=pg", parity=False)
    external = {d["metadata"]["name"] for d in _kinds(docs, "ExternalSecret")}
    assert external == {
        "shapoclyack-api",
        "shapoclyack-clickhouse",
        "shapoclyack-clickhouse-backup",
        "shapoclyack-nats",
        "shapoclyack-backup",
        "shapoclyack-clickhouse-backup-s3",
        "shapoclyack-scanner-executor",
    }
    # A placeholder next to an ExternalSecret of the same name would fight it.
    assert _kinds(docs, "Secret") == []
    executor = [d for d in _kinds(docs, "ExternalSecret") if "executor" in d["metadata"]["name"]]
    assert {d["metadata"]["namespace"] for d in executor} == {"network-scan-executor"}


def test_ingress_is_off_by_default_and_routes_to_the_api_when_on(tools):
    assert _kinds(_render(), "Ingress") == []
    ingress = _kinds(_render("--set", "ingress.enabled=true"), "Ingress")[0]
    backend = ingress["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]
    assert backend["name"] == "shapoclyack-api"
    assert ingress["spec"]["tls"], "TLS is not optional (#309)"


def test_ingress_without_tls_for_every_host_is_refused(tools):
    no_tls = _helm("-f", PARITY_VALUES, "--set", "ingress.enabled=true", "--set", "ingress.tls=null", check=False)
    assert no_tls.returncode != 0 and "ingress.tls" in no_tls.stderr
    mismatch = _helm(
        "-f", PARITY_VALUES, "--set", "ingress.enabled=true",
        "--set", "ingress.hosts[0].host=other.example.com", check=False,
    )
    assert mismatch.returncode != 0 and "other.example.com" in mismatch.stderr


def test_scalar_knobs_reach_the_workloads(tools):
    docs = _render(
        "--set", "replicas.scannerExecutor=2",
        "--set", "storage.postgres.size=100Gi",
        "--set", "storage.postgres.storageClass=fast",
        "--set", "images.api.tag=other",
        "--set", "images.api.digest=",
        "--set", "resources.api.limits.memory=8Gi",
    )
    container = _api(docs)["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "ghcr.io/onixus/shapoclyack-api:other"
    assert container["resources"]["limits"]["memory"] == "8Gi"
    executor = next(d for d in _kinds(docs, "StatefulSet") if "executor" in d["metadata"]["name"])
    assert executor["spec"]["replicas"] == 2
    claim = _pg(docs)["spec"]["volumeClaimTemplates"][0]["spec"]
    assert claim["resources"]["requests"]["storage"] == "100Gi"
    assert claim["storageClassName"] == "fast"


SWITCHES = {
    "defaults": [],
    "eso-ingress": ["--set", "externalSecrets.enabled=true", "--set", "ingress.enabled=true"],
    "no-netpol": ["--set", "networkPolicy.enabled=false"],
    "ha": [
        "--set", "api.spread.enabled=true", "--set", "api.autoscaling.enabled=true",
        "--set", "storage.scannerData.accessMode=ReadWriteMany",
    ],
    "no-backups": ["--set", "backup.postgres.enabled=false", "--set", "backup.clickhouse.enabled=false"],
}


def _pods(docs):
    """(namespace, name, pod spec, pod labels) for every workload."""
    for kind in ("Deployment", "StatefulSet", "CronJob"):
        for w in _kinds(docs, kind):
            if kind == "CronJob":
                tpl = w["spec"]["jobTemplate"]["spec"]["template"]
            else:
                tpl = w["spec"]["template"]
            yield w["metadata"]["namespace"], w["metadata"]["name"], tpl["spec"], tpl["metadata"]["labels"]


@pytest.mark.parametrize("switch", sorted(SWITCHES))
def test_the_hardening_the_base_has_survives_every_switch(tools, switch):
    docs = _render(*SWITCHES[switch], parity=switch != "eso-ingress")
    for ns, name, pod, _labels in _pods(docs):
        executor = ns == "network-scan-executor"
        ps = pod.get("securityContext", {})
        assert pod["automountServiceAccountToken"] is False, name
        for host_field in ("hostNetwork", "hostPID", "hostIPC"):
            assert not pod.get(host_field), (name, host_field)
        for container in pod["containers"] + pod.get("initContainers", []):
            ctx = container["securityContext"]
            where = (name, container["name"])
            assert ctx.get("runAsNonRoot", ps.get("runAsNonRoot")) is True, where
            assert not ctx.get("privileged"), where
            assert ctx["readOnlyRootFilesystem"] is True, where
            assert ctx["capabilities"]["drop"] == ["ALL"], where
            if executor:
                # The one documented exception (docs/k8s-hardening.md).
                assert set(ctx["capabilities"].get("add", [])) <= {"NET_RAW", "NET_ADMIN"}, where
            else:
                assert ctx["allowPrivilegeEscalation"] is False, where
                assert "add" not in ctx["capabilities"], where


def test_network_policy_selectors_match_the_pods_they_protect_and_admit(tools):
    docs = _render()
    pods = [(ns, labels) for ns, _n, _p, labels in _pods(docs)]

    def selects(ns, selector):
        want = selector.get("matchLabels", {}).items()
        return any(pod_ns == ns and want <= labels.items() for pod_ns, labels in pods)

    policies = _kinds(docs, "NetworkPolicy")
    assert policies
    for policy in policies:
        ns = policy["metadata"]["namespace"]
        assert selects(ns, policy["spec"]["podSelector"]), policy["metadata"]["name"]
        for rule in policy["spec"].get("ingress", []):
            for peer in rule.get("from", []):
                assert selects(ns, peer["podSelector"]), (policy["metadata"]["name"], peer)
