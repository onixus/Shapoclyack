#!/usr/bin/env python3
"""Render the Prometheus Operator wrappers from prometheus-slo.rules.yaml.

The rules file is the source of truth (#186). This writes two PrometheusRule
objects with the same groups:

* ``examples/prometheusrule-slo.example.yaml`` — pinned to ``network-scan``, for
  ``kubectl apply -f`` by operators who wire monitoring by hand;
* ``base/monitoring/prometheusrule-slo.yaml`` — namespace-less, because the
  opt-in ``base/monitoring`` component (#334) sets it with its own transformer.

``tests/test_prometheus_slo_rules.py`` fails if either drifts from the rules.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "shapoclyack/examples/prometheus-slo.rules.yaml"
EXAMPLE = ROOT / "shapoclyack/examples/prometheusrule-slo.example.yaml"
COMPONENT = ROOT / "shapoclyack/base/monitoring/prometheusrule-slo.yaml"

EXAMPLE_HEADER = """# Prometheus Operator PrometheusRule for Shapoclyack SLOs (#186).
#
# NOT part of `base/` — this needs the `monitoring.coreos.com/v1` CRDs, which
# no manifest in this repository installs. Apply it only if you already run
# kube-prometheus-stack (or another Prometheus Operator):
#
#   kubectl -n network-scan apply -f k8s/shapoclyack/examples/prometheusrule-slo.example.yaml
#
# The same object ships in the opt-in `base/monitoring` component (#334), for
# installations that manage it with kustomize — see docs/observability.md.
#
# Groups are generated from prometheus-slo.rules.yaml (the source of truth).
# Re-run k8s/scripts/render-prometheusrule-slo.py after editing that file.
# Without a matching Prometheus `ruleSelector` the object applies cleanly and
# is silently ignored.
#
# For installs without the operator, load prometheus-slo.rules.yaml via
# `rule_files` — see k8s/README.md.
"""

COMPONENT_HEADER = """# Prometheus Operator PrometheusRule for Shapoclyack (#186, #334), as part of
# the opt-in `base/monitoring` component. GENERATED from
# examples/prometheus-slo.rules.yaml by k8s/scripts/render-prometheusrule-slo.py
# — edit that file and re-run the script, never this one.
#
# No namespace here: the component's transformer sets it, so an overlay that
# moves the installation moves the rules with it.
"""


def _rule(groups: list, *, namespace: str | None) -> dict:
    metadata: dict = {"name": "shapoclyack-slo"}
    if namespace:
        metadata["namespace"] = namespace
    metadata["labels"] = {
        "app.kubernetes.io/name": "shapoclyack",
        "app.kubernetes.io/component": "slo",
    }
    return {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": metadata,
        "spec": {"groups": groups},
    }


def main() -> None:
    groups = yaml.safe_load(RULES.read_text(encoding="utf-8"))["groups"]
    for out, header, namespace in (
        (EXAMPLE, EXAMPLE_HEADER, "network-scan"),
        (COMPONENT, COMPONENT_HEADER, None),
    ):
        body = yaml.safe_dump(_rule(groups, namespace=namespace), sort_keys=False, width=100)
        out.write_text(header + body, encoding="utf-8")
        print(f"wrote {out.relative_to(ROOT.parent)}")


if __name__ == "__main__":
    main()
