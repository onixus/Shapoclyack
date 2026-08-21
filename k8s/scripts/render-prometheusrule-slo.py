#!/usr/bin/env python3
"""Render the Prometheus Operator wrapper from prometheus-slo.rules.yaml.

The rules file is the source of truth (#186). This writes
``examples/prometheusrule-slo.example.yaml`` so operators with the CRD can
``kubectl apply`` it without copying groups by hand. ``tests/test_prometheus_slo_rules.py``
fails if the two drift.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "shapoclyack/examples/prometheus-slo.rules.yaml"
OUT = ROOT / "shapoclyack/examples/prometheusrule-slo.example.yaml"

HEADER = """# Prometheus Operator PrometheusRule for Shapoclyack SLOs (#186).
#
# NOT part of `base/` — this needs the `monitoring.coreos.com/v1` CRDs, which
# no manifest in this repository installs. Apply it only if you already run
# kube-prometheus-stack (or another Prometheus Operator):
#
#   kubectl -n network-scan apply -f k8s/shapoclyack/examples/prometheusrule-slo.example.yaml
#
# Groups are generated from prometheus-slo.rules.yaml (the source of truth).
# Re-run k8s/scripts/render-prometheusrule-slo.py after editing that file.
# Without a matching Prometheus `ruleSelector` the object applies cleanly and
# is silently ignored.
#
# For installs without the operator, load prometheus-slo.rules.yaml via
# `rule_files` — see k8s/README.md.
"""


def main() -> None:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    doc = {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "PrometheusRule",
        "metadata": {
            "name": "shapoclyack-slo",
            "namespace": "network-scan",
            "labels": {
                "app.kubernetes.io/name": "shapoclyack",
                "app.kubernetes.io/component": "slo",
            },
        },
        "spec": {"groups": rules["groups"]},
    }
    body = yaml.safe_dump(doc, sort_keys=False, width=100)
    OUT.write_text(HEADER + body, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT.parent)}")


if __name__ == "__main__":
    main()
