"""The hand-applied manifests in k8s/shapoclyack/examples/ still fit what base
renders.

Nothing renders these files, so when base moves they go stale quietly. Two ways
this has already happened:

* the audit examples named a namespace, `shapoclyack`, that nothing in the
  repository creates. `kubectl apply -f` failed on it, and had someone created
  it, the forwarder's secretKeyRef to `shapoclyack-nats` could never resolve;
* the sensor's egress example kept the pre-#338 labels and allowed DNS, the API
  and NATS but no scan target. Applied as written, it would have blocked every
  scan, and a dropped probe reads as a host that is down, so nothing reports it.

tests/test_k8s_pod_security.py checks the pods in these files. This module
checks where they land and what their NetworkPolicies let through. The
selector matching below covers only what the manifests use (matchLabels, and
namespaces matched by their `kubernetes.io/metadata.name` label). A policy that
reaches for anything else fails here instead of being misread.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
K8S = REPO_ROOT / "k8s" / "shapoclyack"
EXAMPLES = K8S / "examples"
SENSOR_EGRESS = EXAMPLES / "networkpolicy-agent.example.yaml"
API_INGRESS = EXAMPLES / "networkpolicy-api-ingress.example.yaml"

CONTROL_PLANE_NS = "network-scan"
NS_LABEL = "kubernetes.io/metadata.name"

# Namespaces an example may name although no manifest here creates them: a
# third-party controller's own. The key is the file that needs it.
FOREIGN_NAMESPACES = {
    ("nats-443-ingress.example.yaml", "ingress-nginx"): "ingress-nginx reads its tcp-services ConfigMap there",
}

# RFC 5737 and RFC 3849: never routed, so a placeholder in one of them opens
# nothing if it is applied unchanged.
DOCUMENTATION_PREFIXES = [
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]

# Datastore clients by the Service name in their DSN, and the port their ingress
# policy has to admit (the Services' port and targetPort agree for both).
DATASTORES = {
    "shapoclyack-postgres-client": (K8S / "base" / "postgres" / "service.yaml", 5432),
    "shapoclyack-nats-client": (K8S / "base" / "nats" / "service.yaml", 4222),
}

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


def _load(path: Path) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


def _one(path: Path, kind: str, name: str | None = None) -> dict:
    docs = [d for d in _load(path) if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]
    assert len(docs) == 1, f"{path.relative_to(K8S)}: expected one {kind} {name or ''}, found {len(docs)}"
    return docs[0]


def _pod_template(doc: dict) -> dict:
    if doc["kind"] == "Pod":
        return doc
    if doc["kind"] == "CronJob":
        return doc["spec"]["jobTemplate"]["spec"]["template"]
    return doc["spec"]["template"]


def _pod_labels(path: Path, kind: str, name: str) -> dict[str, str]:
    return _pod_template(_one(path, kind, name))["metadata"]["labels"]


def _defined_namespaces() -> set[str]:
    return {
        _one(K8S / "base" / "namespace.yaml", "Namespace")["metadata"]["name"],
        _one(K8S / "base" / "scanner-executor" / "namespace.yaml", "Namespace")["metadata"]["name"],
    }


EXECUTOR_NS = _one(K8S / "base" / "scanner-executor" / "namespace.yaml", "Namespace")["metadata"]["name"]
EXECUTOR_LABELS = _pod_labels(K8S / "base" / "scanner-executor" / "statefulset.yaml", "StatefulSet",
                              "shapoclyack-scanner-executor")
API_LABELS = _pod_labels(K8S / "base" / "api-deployment.yaml", "Deployment", "shapoclyack-api")
API_PORT = next(
    port["containerPort"]
    for container in _pod_template(_one(K8S / "base" / "api-deployment.yaml", "Deployment"))["spec"]["containers"]
    if container["name"] == "api"
    for port in container.get("ports") or []
    if port.get("name") == "http"
)


# --------------------------------------------------------------------------
# NetworkPolicy semantics, for the subset these manifests use
# --------------------------------------------------------------------------


def _selects(selector: dict | None, labels: dict[str, str]) -> bool:
    """A label selector. None is "no selector"; {} matches everything."""
    assert selector is None or set(selector) <= {"matchLabels"}, f"unsupported selector {selector}"
    wanted = (selector or {}).get("matchLabels") or {}
    return all(labels.get(key) == value for key, value in wanted.items())


def _peer_matches_pod(peer: dict, policy_ns: str, pod_ns: str, pod_labels: dict[str, str]) -> bool:
    if "ipBlock" in peer:
        return False
    ns_selector = peer.get("namespaceSelector")
    # No namespaceSelector: the policy's own namespace. The only namespace label
    # this module knows is the name one the API server puts on every namespace.
    in_ns = pod_ns == policy_ns if ns_selector is None else _selects(ns_selector, {NS_LABEL: pod_ns})
    return in_ns and _selects(peer.get("podSelector"), pod_labels)


def _port_allowed(rule: dict, port: int, protocol: str = "TCP") -> bool:
    ports = rule.get("ports")
    return not ports or any(
        p.get("port") == port and p.get("protocol", "TCP") == protocol for p in ports
    )


def _ingress_admits(
    policies: list[dict], target_ns: str, target_labels: dict[str, str],
    source_ns: str, source_labels: dict[str, str], port: int,
) -> bool:
    """Whether any of ``policies`` lets the source pod in to the target on ``port``."""
    for policy in policies:
        spec = policy["spec"]
        policy_ns = policy["metadata"].get("namespace", CONTROL_PLANE_NS)
        if policy_ns != target_ns or "Ingress" not in spec.get("policyTypes", ["Ingress"]):
            continue
        if not _selects(spec["podSelector"], target_labels):
            continue
        for rule in spec.get("ingress") or []:
            peers = rule.get("from")
            admitted = not peers or any(_peer_matches_pod(p, policy_ns, source_ns, source_labels) for p in peers)
            if admitted and _port_allowed(rule, port):
                return True
    return False


def _network_policies(path: Path) -> list[dict]:
    return [doc for doc in _load(path) if doc["kind"] == "NetworkPolicy"]


def test_the_selector_model_reads_peers_the_way_the_api_server_does() -> None:
    """The ingress checks below are only as good as this reading of a peer; pin
    the two cases the old example got wrong or could have: one peer with both
    selectors is an AND, and a bare `namespaceSelector: {}` is every pod in
    every namespace."""
    both = {"namespaceSelector": {"matchLabels": {NS_LABEL: "a"}}, "podSelector": {"matchLabels": {"c": "x"}}}
    assert _peer_matches_pod(both, "p", "a", {"c": "x"})
    assert not _peer_matches_pod(both, "p", "a", {"c": "y"})
    assert not _peer_matches_pod(both, "p", "b", {"c": "x"})
    assert _peer_matches_pod({"namespaceSelector": {}}, "p", "anything", {})
    assert _peer_matches_pod({"podSelector": {"matchLabels": {"c": "x"}}}, "p", "p", {"c": "x"})
    assert not _peer_matches_pod({"podSelector": {"matchLabels": {"c": "x"}}}, "p", "other", {"c": "x"})


# --------------------------------------------------------------------------
# Where the examples land
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.yaml")), ids=lambda p: p.name)
def test_examples_name_only_namespaces_the_manifests_create(path: Path) -> None:
    defined = _defined_namespaces()
    problems = [
        f"{doc['kind']}/{doc['metadata']['name']}: namespace {ns!r}"
        for doc in _load(path)
        if (ns := (doc.get("metadata") or {}).get("namespace")) is not None
        and ns not in defined
        and (path.name, ns) not in FOREIGN_NAMESPACES
    ]
    assert not problems, f"not one of {sorted(defined)}:\n" + "\n".join(problems)


def _strings(node) -> list[str]:
    if isinstance(node, dict):
        return [s for value in node.values() for s in _strings(value)]
    if isinstance(node, list):
        return [s for value in node for s in _strings(value)]
    return [node] if isinstance(node, str) else []


def _datastore_clients() -> list[tuple[Path, dict, str]]:
    """(file, workload, Service) for every example workload that dials a datastore.

    What it dials is read from the parsed documents, not the text, so a
    commented-out URL (agent-deployment's optional NATS) does not count, and
    from the Secrets in the same file too, where the DSNs live."""
    out = []
    for path in sorted(EXAMPLES.glob("*.example.yaml")):
        docs = _load(path)
        secrets = " ".join(s for d in docs if d["kind"] == "Secret" for s in _strings(d))
        for doc in docs:
            if doc["kind"] not in WORKLOAD_KINDS:
                continue
            text = " ".join(_strings(doc)) + " " + secrets
            out += [(path, doc, service) for service in DATASTORES if service in text]
    return out


@pytest.mark.parametrize(
    "path,workload,service",
    _datastore_clients(),
    ids=lambda v: v.name if isinstance(v, Path) else v["metadata"]["name"] if isinstance(v, dict) else v,
)
def test_example_workloads_are_admitted_to_the_datastores_they_dial(path: Path, workload: dict, service: str) -> None:
    """base/networkpolicy-datastores.yaml admits a closed list of clients. An
    example that dials a datastore has to add itself to that list, in its own
    file, or it applies cleanly and then times out on every connect."""
    service_file, port = DATASTORES[service]
    target = _one(service_file, "Service", service)
    policies = _network_policies(K8S / "base" / "networkpolicy-datastores.yaml") + _network_policies(path)
    namespace = workload["metadata"].get("namespace", CONTROL_PLANE_NS)
    assert _ingress_admits(
        policies,
        target_ns=CONTROL_PLANE_NS,
        target_labels=target["spec"]["selector"],
        source_ns=namespace,
        source_labels=_pod_template(workload)["metadata"]["labels"],
        port=port,
    ), f"{path.name}: {workload['kind']}/{workload['metadata']['name']} in {namespace} is not admitted to {service}:{port}"


# --------------------------------------------------------------------------
# The sensor's egress and the API's ingress
# --------------------------------------------------------------------------


def _sensor_egress_policy() -> dict:
    policies = [p for p in _network_policies(SENSOR_EGRESS) if "Egress" in p["spec"].get("policyTypes", [])]
    assert len(policies) == 1, f"{SENSOR_EGRESS.name}: expected one egress policy"
    return policies[0]


def test_the_sensor_egress_example_selects_the_executor() -> None:
    policy = _sensor_egress_policy()
    assert policy["metadata"]["namespace"] == EXECUTOR_NS
    assert policy["spec"]["podSelector"]["matchLabels"], "an empty podSelector would fence every pod"
    assert _selects(policy["spec"]["podSelector"], EXECUTOR_LABELS)


def test_the_sensor_egress_example_reaches_the_api_in_the_control_plane() -> None:
    """Cross-namespace since #338: a podSelector alone would look for the API
    in network-scan-executor and find nothing."""
    rules = _sensor_egress_policy()["spec"]["egress"]
    assert any(
        _port_allowed(rule, API_PORT)
        and any(_peer_matches_pod(peer, EXECUTOR_NS, CONTROL_PLANE_NS, API_LABELS) for peer in rule.get("to") or [])
        for rule in rules
    ), f"no egress rule reaches the API ({API_LABELS}) in {CONTROL_PLANE_NS} on {API_PORT}"


def test_the_sensor_egress_example_has_a_target_range_rule_to_replace() -> None:
    """A sensor's job is connecting to targets; an egress policy without a rule
    for them blocks every scan, and the scans come back empty rather than
    failing. The rule has to be there, open on every port (a scan profile
    decides the ports, and ICMP has none), and hold documentation prefixes
    only, so that applying the example unchanged opens nothing real. Every
    rule names its destinations: one without `to` would be all of them."""
    rules = _sensor_egress_policy()["spec"]["egress"]
    assert all(rule.get("to") for rule in rules), "an egress rule without `to` allows every destination"
    blocks = [
        (rule, peer["ipBlock"]) for rule in rules for peer in rule["to"] if "ipBlock" in peer
    ]
    target_rules = [rule for rule, _ in blocks if "ports" not in rule]
    assert target_rules, f"{SENSOR_EGRESS.name}: no port-less ipBlock rule for the approved target ranges"
    for _, block in blocks:
        net = ipaddress.ip_network(block["cidr"])
        assert any(net.version == doc.version and net.subnet_of(doc) for doc in DOCUMENTATION_PREFIXES), (
            f"{block['cidr']} is not a documentation prefix: the example would open a real range as shipped"
        )


def test_the_api_ingress_example_admits_the_executor_and_not_its_neighbours() -> None:
    policies = _network_policies(API_INGRESS)
    assert policies and all(p["metadata"]["namespace"] == CONTROL_PLANE_NS for p in policies)

    def admits(namespace: str, labels: dict[str, str]) -> bool:
        return _ingress_admits(policies, CONTROL_PLANE_NS, API_LABELS, namespace, labels, API_PORT)

    assert admits(EXECUTOR_NS, EXECUTOR_LABELS)
    # The old example had a bare `namespaceSelector: {}`, which admitted every
    # pod in the cluster and made its podSelector decorative.
    assert not admits(EXECUTOR_NS, {"app.kubernetes.io/component": "something-else"})
    assert not admits("default", EXECUTOR_LABELS)
