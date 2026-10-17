"""The Helm chart is the kustomize base in another packaging (#341).

Two layers. The comparison tool (scripts/helm_parity.py) is tested on its own,
with hand-written manifests, because a parity check that cannot fail proves
nothing: each way the chart could drift from the base has a case that must be
caught. The chart itself is then rendered with the real ``helm`` and compared
with the real ``kubectl kustomize`` of k8s/shapoclyack/base, plus one render per
optional feature. Those need both binaries; without them they skip on a laptop
and *fail* under ``OCTO_REQUIRE_INTEGRATION=1``, like the other manifest
contracts (tests/test_k8s_pod_security.py).
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.integration_gate import require_integration

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


# --- the chart, rendered ---------------------------------------------------


def _have_tools() -> bool:
    return bool(shutil.which("helm") and shutil.which("kubectl"))


@pytest.fixture(scope="module")
def tools():
    if _have_tools():
        return
    if require_integration():
        pytest.fail("helm and kubectl are required (OCTO_REQUIRE_INTEGRATION=1)")
    pytest.skip("helm or kubectl not installed")


def _render(*args: str) -> list[dict]:
    out = subprocess.run(
        ["helm", "template", "shapoclyack", str(CHART), "--namespace", "network-scan", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [doc for doc in yaml.safe_load_all(out) if doc]


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
    kustomize = subprocess.run(
        ["kubectl", "kustomize", str(BASE)], check=True, capture_output=True, text=True
    ).stdout
    (tmp_path / "kustomize.yaml").write_text(kustomize)
    chart = subprocess.run(
        [
            "helm", "template", "shapoclyack", str(CHART), "--namespace", "network-scan",
            "-f", str(CHART / "ci" / "parity-values.yaml"),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    (tmp_path / "helm.yaml").write_text(chart)
    assert helm_parity.compare(str(tmp_path / "kustomize.yaml"), str(tmp_path / "helm.yaml")) == 0


def test_helm_lint_strict_passes_with_the_features_on(tools):
    for args in (
        [],
        ["--set", "ingress.enabled=true", "--set", "externalSecrets.enabled=true"],
    ):
        subprocess.run(
            ["helm", "lint", "--strict", str(CHART), *args], check=True, capture_output=True, text=True
        )


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
    docs = _render("--set", "externalSecrets.enabled=true", "--set", "existingSecrets.postgres=pg")
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
    assert {d["metadata"]["namespace"] for d in _kinds(docs, "ExternalSecret") if "executor" in d["metadata"]["name"]} == {
        "network-scan-executor"
    }


def test_ingress_is_off_by_default_and_routes_to_the_api_when_on(tools):
    assert _kinds(_render(), "Ingress") == []
    ingress = _kinds(_render("--set", "ingress.enabled=true"), "Ingress")[0]
    backend = ingress["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]
    assert backend["name"] == "shapoclyack-api"
    assert ingress["spec"]["tls"], "TLS is not optional (#309)"


def test_scalar_knobs_reach_the_workloads(tools):
    docs = _render(
        "--set", "replicas.api=3",
        "--set", "storage.postgres.size=100Gi",
        "--set", "storage.postgres.storageClass=fast",
        "--set", "images.api.tag=other",
        "--set", "images.api.digest=",
        "--set", "resources.api.limits.memory=8Gi",
    )
    api = next(d for d in _kinds(docs, "Deployment") if d["metadata"]["name"] == "shapoclyack-api")
    assert api["spec"]["replicas"] == 3
    container = api["spec"]["template"]["spec"]["containers"][0]
    assert container["image"] == "ghcr.io/onixus/shapoclyack-api:other"
    assert container["resources"]["limits"]["memory"] == "8Gi"
    pg = next(d for d in _kinds(docs, "StatefulSet") if d["metadata"]["name"] == "shapoclyack-postgres")
    claim = pg["spec"]["volumeClaimTemplates"][0]["spec"]
    assert claim["resources"]["requests"]["storage"] == "100Gi"
    assert claim["storageClassName"] == "fast"


def test_the_hardening_the_base_has_survives_every_switch(tools):
    """Whatever is toggled, no workload loses its read-only root or its caps drop."""
    docs = _render(
        "--set", "externalSecrets.enabled=true",
        "--set", "ingress.enabled=true",
        "--set", "networkPolicy.enabled=false",
    )
    for kind in ("Deployment", "StatefulSet", "CronJob"):
        for workload in _kinds(docs, kind):
            pod = (
                workload["spec"]["jobTemplate"]["spec"]["template"]["spec"]
                if kind == "CronJob"
                else workload["spec"]["template"]["spec"]
            )
            assert pod["automountServiceAccountToken"] is False, workload["metadata"]["name"]
            for container in pod["containers"] + pod.get("initContainers", []):
                ctx = container["securityContext"]
                assert ctx["readOnlyRootFilesystem"] is True, container["name"]
                assert ctx["capabilities"]["drop"] == ["ALL"], container["name"]
