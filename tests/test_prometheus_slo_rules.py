"""SLO Prometheus rules stay aligned with exported series (#186)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from api.services import metrics

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "k8s/shapoclyack/examples/prometheus-slo.rules.yaml"
CRD = ROOT / "k8s/shapoclyack/examples/prometheusrule-slo.example.yaml"

# prometheus_client registers these as the first constructor argument.
_EXPORTED = {
    metrics.HTTP_REQUESTS_TOTAL._original_name,
    metrics.HTTP_REQUEST_DURATION_SECONDS._original_name,
    metrics.JOB_DURATION_SECONDS._original_name,
    metrics.NATS_CONSUMER_PENDING._original_name,
    metrics.CH_INGEST_MESSAGES_TOTAL._original_name,
    metrics.ENDPOINT_SUBMISSIONS_TOTAL._original_name,
    metrics.AUTH_ATTEMPTS_TOTAL._original_name,
    metrics.SCHEDULER_IS_LEADER._original_name,
}

_SERIES = re.compile(r"octo_[a-z0-9_]+")


def _load_rules() -> dict:
    return yaml.safe_load(RULES.read_text(encoding="utf-8"))


def test_rules_file_has_every_slo_and_both_scheduler_invariants():
    data = _load_rules()
    alerts = [rule["alert"] for group in data["groups"] for rule in group["rules"]]
    for name in (
        "ShapoclyackApiAvailabilityFastBurn",
        "ShapoclyackApiAvailabilitySlowBurn",
        "ShapoclyackApiReadLatencyP95",
        "ShapoclyackJobCompletionBudget",
        "ShapoclyackJobDurationExceedsHistogram",
        "ShapoclyackClickHouseIngestLag",
        "ShapoclyackClickHouseIngestStale",
        "ShapoclyackClickHouseIngestErrors",
        "ShapoclyackEndpointInventoryAcceptance",
        "ShapoclyackLoginLimiterTripped",
        "ShapoclyackLoginFailuresElevated",
        "ShapoclyackSchedulerSplitBrain",
        "ShapoclyackSchedulerNoLeader",
    ):
        assert name in alerts, name


def test_every_octo_series_in_the_rules_is_exported():
    text = RULES.read_text(encoding="utf-8")
    mentioned = set(_SERIES.findall(text))
    # Histogram rules use the _bucket / _count suffixes.
    families = {name.removesuffix("_bucket").removesuffix("_count") for name in mentioned}
    unknown = families - _EXPORTED
    assert not unknown, f"rules mention series the API does not export: {sorted(unknown)}"


def test_prometheusrule_wrapper_matches_the_rules_file():
    rules = _load_rules()
    crd = yaml.safe_load(CRD.read_text(encoding="utf-8"))
    assert crd["kind"] == "PrometheusRule"
    assert crd["metadata"]["namespace"] == "network-scan"
    assert crd["spec"]["groups"] == rules["groups"]


def test_scheduler_alerts_require_the_series_to_exist():
    """Absent scrape must not look like 'no leader'."""
    text = RULES.read_text(encoding="utf-8")
    assert "count(octo_scheduler_is_leader) > 0" in text
    assert "for: 5m" in text
    assert "for: 10m" in text
