"""Dashboards, rules and the metric catalogue stay true to the code (#334).

A dashboard or an alert that names a series the API does not export — or a
label the series does not carry — does not fail anywhere: the panel is empty
and the alert never fires, which reads exactly like a healthy installation.
These checks are what makes such a rename fail CI instead. PromQL *syntax* is
checked by promtool in k8s/scripts/validate-prometheus-rules.sh; this module
checks *meaning* against the registry.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from tests import metric_catalogue

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "k8s/shapoclyack/base/grafana-dashboards"
DASHBOARDS = sorted(DASHBOARD_DIR.glob("*.json"))
RULES = ROOT / "k8s/shapoclyack/examples/prometheus-slo.rules.yaml"

#: Series every replica reports identically, because they are counted in a
#: shared table (or are configuration) rather than in the process. sum() over
#: replicas multiplies them by the replica count; max() is the honest
#: aggregation. Most say so in their help text, which is where the derived half
#: comes from; these four predate that convention (docs/slo.md says it of the
#: job gauges).
CLUSTER_WIDE = frozenset(
    {
        "octo_jobs_queued",
        "octo_jobs_running",
        "octo_endpoint_devices",
        "octo_nats_consumer_pending",
        "octo_agent_stale_threshold_seconds",
    }
) | {family.name for family in metric_catalogue.families().values() if family.cluster_wide}

#: Labels no series may carry: each is unbounded, or chosen by whoever sends
#: the request (#334, docs/observability.md § Label bounds).
FORBIDDEN_LABELS = frozenset(
    {"tenant", "tenant_id", "agent_id", "hostname", "host", "user", "username", "asset_id", "ip", "url"}
)

_MATCHER = re.compile(r"(\w+)\s*(?:=~|!~|!=|=)\s*\"")
_SELECTOR = re.compile(r"\b((?:octo|process|python)_[a-z0-9_]*[a-z0-9])\s*\{([^}]*)\}")
_GROUPING = re.compile(r"\b(?:by|without)\s*\(([^)]*)\)")
_LEGEND = re.compile(r"\{\{\s*(\w+)\s*\}\}")
_SUM_OF = re.compile(r"\bsum\s*(?:by\s*\([^)]*\)\s*)?\(\s*((?:octo)_[a-z0-9_]*[a-z0-9])\b")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _queries(board: dict) -> list[tuple[str, str, str]]:
    """``(panel title, expr, legendFormat)`` for every panel target."""
    return [
        (panel["title"], target["expr"], target.get("legendFormat", ""))
        for panel in board["panels"]
        for target in panel.get("targets", [])
    ]


def _variable_queries(board: dict) -> list[str]:
    return [
        variable["query"]
        for variable in board["templating"]["list"]
        if variable["type"] == "query"
    ]


def _rule_expressions() -> list[tuple[str, str]]:
    data = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    return [
        (rule.get("alert") or rule.get("record"), rule["expr"])
        for group in data["groups"]
        for rule in group["rules"]
    ]


def _label_problems(expr: str, legend: str = "") -> list[str]:
    """Labels ``expr`` names that none of its series carries.

    Deliberately coarse for grouping and legends — a ``by (…)`` clause may name
    a label of any series in the expression — and exact for matchers, which
    belong to the series they are attached to.
    """
    index = metric_catalogue.sample_index()
    problems = []
    available = set(metric_catalogue.TARGET_LABELS)
    for name in metric_catalogue.SERIES_NAME.findall(expr):
        family = index.get(name)
        if family is not None:
            available |= family.labels
            if name.endswith("_bucket"):
                available.add("le")
    for name, matchers in _SELECTOR.findall(expr):
        family = index.get(name)
        if family is None:
            continue  # reported by the series check
        allowed = family.labels | metric_catalogue.TARGET_LABELS | ({"le"} if name.endswith("_bucket") else set())
        problems += [f"{name}{{{label}=…}}" for label in _MATCHER.findall(matchers) if label not in allowed]
    for grouping in _GROUPING.findall(expr):
        labels = {label.strip() for label in grouping.split(",") if label.strip()}
        problems += [f"by ({label})" for label in sorted(labels - available)]
    problems += [f"legend {{{{{label}}}}}" for label in _LEGEND.findall(legend) if label not in available]
    return problems


# --- dashboards --------------------------------------------------------------


def test_both_dashboards_exist():
    assert {path.name for path in DASHBOARDS} == {
        "shapoclyack-platform.json",
        "shapoclyack-product.json",
    }


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda path: path.stem)
def test_every_series_a_dashboard_queries_is_exported(path):
    board = _load(path)
    texts = [expr for _, expr, _ in _queries(board)] + _variable_queries(board)
    unknown = set().union(*(metric_catalogue.unknown_series(text) for text in texts))
    assert not unknown, f"{path.name} queries series /metrics does not export: {sorted(unknown)}"
    # And the one series from outside the registry is Prometheus's own.
    bare = {
        name
        for text in texts
        for name in re.findall(r"\b([a-z_]+)\s*\{", text)
        if not metric_catalogue.SERIES_NAME.fullmatch(name)
    }
    assert bare <= metric_catalogue.PROMETHEUS_SERIES


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda path: path.stem)
def test_every_label_a_dashboard_names_exists(path):
    problems = {
        title: found
        for title, expr, legend in _queries(_load(path))
        if (found := _label_problems(expr, legend))
    }
    assert not problems, f"{path.name}: {problems}"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda path: path.stem)
def test_cluster_wide_series_are_never_summed_across_replicas(path):
    """Every replica reports the same agents/jobs/outbox tables, so a sum() of
    one of these over the replicas shows N times the truth, where N is however
    many replicas the HPA is running at that moment."""
    summed = {
        (title, name)
        for title, expr, _ in _queries(_load(path))
        for name in _SUM_OF.findall(expr)
        if name in CLUSTER_WIDE
    }
    assert not summed, f"{path.name} sums cluster-wide series: {sorted(summed)}"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda path: path.stem)
def test_dashboards_are_portable_and_well_formed(path):
    """Importable on any Grafana and loadable by the sidecar: the data source is
    a variable rather than one installation's uid, ids and uids are unique, and
    no two panels are drawn on top of each other."""
    board = _load(path)
    assert board["uid"] == path.stem
    assert board["id"] is None
    assert "shapoclyack" in board["tags"]
    variables = {variable["name"]: variable for variable in board["templating"]["list"]}
    assert variables["datasource"]["type"] == "datasource"
    assert variables["datasource"]["query"] == "prometheus"
    # One job at a time: an API scraped by both the pod annotations and a
    # ServiceMonitor arrives under two jobs, and "All" would count it twice.
    assert variables["job"]["multi"] is False
    assert variables["job"]["includeAll"] is False

    ids = [panel["id"] for panel in board["panels"]]
    assert len(ids) == len(set(ids))
    cells: dict[tuple[int, int], str] = {}
    for panel in board["panels"]:
        grid = panel["gridPos"]
        assert grid["x"] >= 0 and grid["x"] + grid["w"] <= 24, panel["title"]
        for x in range(grid["x"], grid["x"] + grid["w"]):
            for y in range(grid["y"], grid["y"] + grid["h"]):
                assert (x, y) not in cells, f"{panel['title']!r} overlaps {cells[(x, y)]!r}"
                cells[(x, y)] = panel["title"]
        if panel["type"] in ("row", "text"):
            continue
        assert panel["datasource"] == {"type": "prometheus", "uid": "${datasource}"}, panel["title"]
        assert panel["description"], f"{panel['title']!r} has no description"
        for target in panel["targets"]:
            assert target["datasource"] == panel["datasource"], panel["title"]


def test_the_dashboards_component_ships_every_dashboard_to_the_sidecar():
    component = yaml.safe_load((DASHBOARD_DIR / "kustomization.yaml").read_text(encoding="utf-8"))
    assert component["kind"] == "Component"
    shipped = set()
    for generator in component["configMapGenerator"]:
        options = generator["options"]
        # The sidecar's default label and value.
        assert options["labels"]["grafana_dashboard"] == "1"
        # A hashed name leaves the previous revision behind on every edit: two
        # ConfigMaps with one dashboard uid, which provisioning refuses.
        assert options["disableNameSuffixHash"] is True
        shipped.update(generator["files"])
    assert shipped == {path.name for path in DASHBOARDS}


def test_product_dashboard_is_installation_wide():
    """No series carries a tenant label, so the product dashboard can have no
    tenant variable — one would filter on nothing and show every tenant's
    numbers under a single customer's name."""
    board = _load(DASHBOARD_DIR / "shapoclyack-product.json")
    names = {variable["name"] for variable in board["templating"]["list"]}
    assert not names & {"tenant", "tenant_id"}
    assert "tenant" not in json.dumps([target for panel in board["panels"] for target in panel.get("targets", [])])


# --- rules -------------------------------------------------------------------


def test_every_label_an_alert_names_exists():
    problems = {name: found for name, expr in _rule_expressions() if (found := _label_problems(expr))}
    assert not problems, problems


def test_cluster_wide_series_are_never_summed_in_the_rules():
    summed = {
        (name, series)
        for name, expr in _rule_expressions()
        for series in _SUM_OF.findall(expr)
        if series in CLUSTER_WIDE
    }
    assert not summed, sorted(summed)


# --- the registry itself -------------------------------------------------------


def test_no_series_carries_an_unbounded_label():
    """The rule the fleet series were designed around, applied to all of them:
    a label per tenant, agent, host or user is a series per tenant, agent, host
    or user — and for several of those, whoever sends the request picks it."""
    offending = {
        family.name: sorted(family.labels & FORBIDDEN_LABELS)
        for family in metric_catalogue.families().values()
        if family.labels & FORBIDDEN_LABELS
    }
    assert not offending, offending
