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
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests import metric_catalogue

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "k8s/shapoclyack/base/grafana-dashboards"
DASHBOARDS = sorted(DASHBOARD_DIR.glob("*.json"))
RULES = ROOT / "k8s/shapoclyack/examples/prometheus-slo.rules.yaml"
CATALOGUE = ROOT / "docs/observability.md"

#: Series every replica reports alike, because they come from a shared table
#: or a shared broker rather than from the process. sum() over replicas
#: multiplies them by the replica count; max() is the honest aggregation. The
#: help texts say "Cluster-wide" (or "max(), not sum()"), which is where most
#: of this comes from; the consumer lag predates that convention.
CLUSTER_WIDE = frozenset({"octo_nats_consumer_pending"}) | {
    family.name for family in metric_catalogue.families().values() if family.cluster_wide
}

#: Labels no series may carry: each is unbounded, or chosen by whoever sends
#: the request (#334, docs/observability.md § Label bounds).
FORBIDDEN_LABELS = frozenset(
    {"tenant", "tenant_id", "agent_id", "hostname", "host", "user", "username", "asset_id", "ip", "url"}
)
#: The one exception: the opt-in tenant series, whose ``tenant`` label is
#: capped at OCTO_METRICS_TENANT_TOP_N ids plus ``_other``.
TENANT_FAMILIES = frozenset(metric_catalogue.tenant_family_names())

_MATCHER = re.compile(r"(\w+)\s*(?:=~|!~|!=|=)\s*\"")
_SELECTOR = re.compile(r"\b((?:octo|process|python)_[a-z0-9_]*[a-z0-9])\s*\{([^}]*)\}")
_GROUPING = re.compile(r"\b(?:by|without)\s*\(([^)]*)\)")
_LEGEND = re.compile(r"\{\{\s*(\w+)\s*\}\}")
_SUM_OF = re.compile(r"\bsum\s*(?:by\s*\([^)]*\)\s*)?\(\s*((?:octo)_[a-z0-9_]*[a-z0-9])\b")


def _summed_cluster_wide(expr: str) -> set[str]:
    """Cluster-wide families ``expr`` hands straight to ``sum()``.

    By family: a query names samples (``…_bucket``), and the set above holds
    family names, so comparing the two directly let every histogram through.
    """
    index = metric_catalogue.sample_index()
    return {
        index[name].name
        for name in _SUM_OF.findall(expr)
        if name in index and index[name].name in CLUSTER_WIDE
    }


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


def test_the_three_dashboards_exist():
    assert {path.name for path in DASHBOARDS} == {
        "shapoclyack-platform.json",
        "shapoclyack-product.json",
        "shapoclyack-tenants.json",
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
        for name in _summed_cluster_wide(expr)
    }
    assert not summed, f"{path.name} sums cluster-wide series: {sorted(summed)}"


def test_the_sum_check_sees_the_samples_of_a_cluster_wide_family():
    """The check compared sample names against family names, so a histogram's
    ``_bucket`` passed whatever it was summed over (review of #334)."""
    assert _summed_cluster_wide(
        'histogram_quantile(0.95, sum by (le) (octo_agent_heartbeat_age_seconds_bucket{job="a"}))'
    ) == {"octo_agent_heartbeat_age_seconds"}
    assert _summed_cluster_wide("sum(octo_jobs_queued)") == {"octo_jobs_queued"}
    assert _summed_cluster_wide("sum by (tenant) (octo_tenant_open_findings)") == {
        "octo_tenant_open_findings"
    }
    assert not _summed_cluster_wide('sum(max by (state) (octo_agents{agent_kind="scanner"}))')
    assert not _summed_cluster_wide("sum(rate(octo_http_requests_total[5m]))")
    assert not _summed_cluster_wide("sum(octo_db_pool_checked_out)"), "per replica: sum is right"


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


def test_the_components_leave_the_namespace_to_the_including_overlay():
    """A component's namespace transformer applies to everything the including
    kustomization renders, not just to what the component adds: an overlay over
    an installation moved to another namespace that took these components was
    rendered into network-scan in full — a second installation on apply
    (review of #334)."""
    for component in ("monitoring", "grafana-dashboards"):
        directory = ROOT / "k8s/shapoclyack/base" / component
        kustomization = yaml.safe_load((directory / "kustomization.yaml").read_text(encoding="utf-8"))
        assert kustomization["kind"] == "Component"
        assert "namespace" not in kustomization, component
        for resource in kustomization.get("resources", []):
            for document in yaml.safe_load_all((directory / resource).read_text(encoding="utf-8")):
                assert "namespace" not in document["metadata"], f"{component}/{resource}"
    # The overlay that includes them names it — with an unsetOnly transformer,
    # not `namespace:`, which would also move #338's scanner-executor out of
    # network-scan-executor (tests/test_k8s_pod_security.py).
    overlay_dir = ROOT / "k8s/shapoclyack/overlays/prod-ha-monitoring"
    overlay = yaml.safe_load((overlay_dir / "kustomization.yaml").read_text(encoding="utf-8"))
    assert "namespace" not in overlay
    assert overlay["transformers"] == ["namespace-transformer.yaml"]
    transformer = yaml.safe_load((overlay_dir / "namespace-transformer.yaml").read_text(encoding="utf-8"))
    assert transformer["kind"] == "NamespaceTransformer"
    assert transformer["metadata"]["namespace"] == "network-scan"
    assert transformer["unsetOnly"] is True


def _render_with_components(tmp_path: Path, *, namespace: str | None) -> list[dict]:
    """An installation moved to scanner-prod by one overlay, the two
    components added by a second one — with or without a namespace of its own.

    The installation is ``overlays/local-scan``: since #338 every other overlay
    spans two namespaces (the scanner-executor has its own), and a plain
    ``namespace:`` over one of them does not render at all — both Namespace
    objects become scanner-prod. local-scan is the one topology still in a
    single namespace, which is what this reproduction needs; the two-namespace
    case is ``test_the_components_leave_the_executor_where_it_is``.
    """
    shapoclyack = ROOT / "k8s/shapoclyack"
    moved = tmp_path / "moved"
    with_monitoring = tmp_path / "with-monitoring"
    moved.mkdir(exist_ok=True)
    with_monitoring.mkdir(exist_ok=True)
    (moved / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
        "namespace: scanner-prod\n"
        f"resources:\n  - {os.path.relpath(shapoclyack / 'overlays/local-scan', moved)}\n",
        encoding="utf-8",
    )
    (with_monitoring / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
        + (f"namespace: {namespace}\n" if namespace else "")
        + "resources:\n  - ../moved\ncomponents:\n"
        f"  - {os.path.relpath(shapoclyack / 'base/monitoring', with_monitoring)}\n"
        f"  - {os.path.relpath(shapoclyack / 'base/grafana-dashboards', with_monitoring)}\n",
        encoding="utf-8",
    )
    rendered = subprocess.run(
        ["kubectl", "kustomize", str(with_monitoring)], capture_output=True, text=True, check=True
    ).stdout
    return [document for document in yaml.safe_load_all(rendered) if document]


_COMPONENT_KINDS = {"ServiceMonitor", "PrometheusRule"}


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="needs kubectl (kustomize)")
def test_the_components_do_not_move_the_installation_that_includes_them(tmp_path):
    """The reviewer's reproduction, rendered: the second overlay sets no
    namespace. With a namespace in the components, every object of the
    scanner-prod installation was rendered into network-scan."""
    documents = _render_with_components(tmp_path, namespace=None)
    installation = {
        document["metadata"].get("namespace")
        for document in documents
        if document["kind"] not in _COMPONENT_KINDS
        and not document["metadata"]["name"].startswith("shapoclyack-dashboard-")
        and document["kind"] != "Namespace"
    }
    assert installation == {"scanner-prod"}


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="needs kubectl (kustomize)")
def test_an_overlay_that_names_its_namespace_gets_the_components_there(tmp_path):
    documents = _render_with_components(tmp_path, namespace="scanner-prod")
    namespaces = {
        document["metadata"].get("namespace") for document in documents if document["kind"] != "Namespace"
    }
    assert namespaces == {"scanner-prod"}
    assert _COMPONENT_KINDS <= {document["kind"] for document in documents}


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="needs kubectl (kustomize)")
def test_the_components_leave_the_executor_where_it_is():
    """overlays/prod-ha-monitoring over an installation in two namespaces
    (#338): what the components add lands beside the API, and the
    scanner-executor stays in network-scan-executor. With `namespace:` in the
    overlay the render failed outright, both Namespace objects renamed to
    network-scan."""
    rendered = subprocess.run(
        ["kubectl", "kustomize", str(ROOT / "k8s/shapoclyack/overlays/prod-ha-monitoring")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    where = {
        (document["kind"], document["metadata"]["name"]): document["metadata"].get("namespace")
        for document in yaml.safe_load_all(rendered)
        if document
    }
    added = {
        key: namespace
        for key, namespace in where.items()
        if key[0] in _COMPONENT_KINDS or key[1].startswith("shapoclyack-dashboard-")
    }
    assert {kind for kind, _ in added} == _COMPONENT_KINDS | {"ConfigMap"}
    assert set(added.values()) == {"network-scan"}
    assert where[("Deployment", "shapoclyack-api")] == "network-scan"
    assert where[("StatefulSet", "shapoclyack-scanner-executor")] == "network-scan-executor"
    assert {name for kind, name in where if kind == "Namespace"} == {"network-scan", "network-scan-executor"}


def test_product_dashboard_is_installation_wide():
    """No series carries a tenant label, so the product dashboard can have no
    tenant variable — one would filter on nothing and show every tenant's
    numbers under a single customer's name."""
    board = _load(DASHBOARD_DIR / "shapoclyack-product.json")
    names = {variable["name"] for variable in board["templating"]["list"]}
    assert not names & {"tenant", "tenant_id"}
    assert "tenant" not in json.dumps([target for panel in board["panels"] for target in panel.get("targets", [])])


def test_the_tenants_dashboard_reads_only_the_capped_series():
    """Per-tenant panels exist only where a tenant label does: the opt-in
    series. Anything else on this board would be an installation-wide number
    under a tenant's name."""
    board = _load(DASHBOARD_DIR / "shapoclyack-tenants.json")
    variables = {variable["name"]: variable for variable in board["templating"]["list"]}
    assert "octo_tenant_open_findings" in variables["tenant"]["query"]
    index = metric_catalogue.sample_index()
    named = {
        index[name].name
        for _, expr, _ in _queries(board)
        for name in metric_catalogue.SERIES_NAME.findall(expr)
    }
    assert named and named <= TENANT_FAMILIES


def test_the_failed_share_panel_leaves_cancelled_scans_out_like_slo_3():
    """SLO 3 does not count an operator's stop against the success ratio; the
    panel that cites it divided by cancelled scans too, so a tenant that
    cancels a lot looked healthier than it was (review of #334)."""
    board = _load(DASHBOARD_DIR / "shapoclyack-tenants.json")
    [expr] = [expr for title, expr, _ in _queries(board) if title == "Failed share of scans by tenant"]
    numerator, denominator = expr.split(" / ")
    assert 'status="failed"' in numerator
    assert 'status=~"succeeded|failed"' in denominator


# --- rules -------------------------------------------------------------------


def test_every_label_an_alert_names_exists():
    problems = {name: found for name, expr in _rule_expressions() if (found := _label_problems(expr))}
    assert not problems, problems


def test_consumer_matchers_name_a_consumer_the_api_reports():
    """``octo_nats_consumer_pending`` is labelled with the durable's name, and
    that name has changed before (``octo-ch-ingest`` became
    ``octo-ch-ingest-results`` with the narrowed filter). A matcher on the old
    name selects nothing, so both SLO 5 alerts sat in the rules unable to fire
    — the series check above cannot see that, because the series exists."""
    from api.services import ch_ingest_worker
    from api.services.integrations import webhook_worker

    reported = {
        ch_ingest_worker.CONSUMER_CH_INGEST,
        webhook_worker.CONSUMER_WEBHOOK_FANOUT,
        webhook_worker.CONSUMER_AUDIT_FANOUT,
    }
    sources = {
        RULES.name: RULES.read_text(encoding="utf-8"),
        "docs/slo.md": (ROOT / "docs/slo.md").read_text(encoding="utf-8"),
        **{path.name: path.read_text(encoding="utf-8") for path in DASHBOARDS},
    }
    named = {
        (source, consumer)
        for source, text in sources.items()
        for consumer in re.findall(r'consumer\\?="([^"\\]+)', text)
    }
    assert {consumer for _, consumer in named} <= reported, sorted(
        pair for pair in named if pair[1] not in reported
    )


def test_cluster_wide_series_are_never_summed_in_the_rules():
    summed = {
        (name, series)
        for name, expr in _rule_expressions()
        for series in _summed_cluster_wide(expr)
    }
    assert not summed, sorted(summed)


def _fake_tool(directory: Path, name: str, version: str) -> Path:
    tool = directory / name
    tool.write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$(basename "$0") $*" >> "{directory}/calls.log"\n'
        f'if [[ "${{1:-}}" == "--version" ]]; then echo "promtool, version {version} (branch: HEAD)"; fi\n',
        encoding="utf-8",
    )
    tool.chmod(0o755)
    return tool


def _run_rules_script(bin_dir: Path, **env: str) -> subprocess.CompletedProcess:
    base = {key: value for key, value in os.environ.items() if key not in ("PROMTOOL", "PROMTOOL_IMAGE")}
    base["PATH"] = f"{bin_dir}:{base['PATH']}"
    return subprocess.run(
        [str(ROOT / "k8s/scripts/validate-prometheus-rules.sh")],
        env={**base, **env},
        capture_output=True,
        text=True,
    )


def test_the_rules_script_uses_a_local_promtool_only_at_the_pinned_version(tmp_path):
    """A promtool on PATH was used whatever its version, so a local pass could
    mean a different parser from CI's pinned image (review of #334). It is now
    used only at the pinned version; otherwise the pinned image runs. docker is
    faked here too, so nothing is pulled."""
    _fake_tool(tmp_path, "promtool", "2.40.0")
    _fake_tool(tmp_path, "docker", "0")
    _run_rules_script(tmp_path)
    calls = (tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "promtool --version" in calls
    assert "promtool check" not in calls
    assert "docker run" in calls

    (tmp_path / "calls.log").unlink()
    _fake_tool(tmp_path, "promtool", "2.54.1")
    result = _run_rules_script(tmp_path)
    calls = (tmp_path / "calls.log").read_text(encoding="utf-8")
    assert result.returncode == 0, result.stderr
    assert "promtool check rules" in calls
    assert "promtool test rules" in calls
    assert "docker" not in calls


def test_an_explicit_promtool_at_another_version_is_refused(tmp_path):
    tool = _fake_tool(tmp_path, "promtool-other", "2.40.0")
    result = _run_rules_script(tmp_path, PROMTOOL=str(tool))
    assert result.returncode != 0
    assert "2.54.1" in result.stderr
    assert "check" not in (tmp_path / "calls.log").read_text(encoding="utf-8")


def test_a_promtool_that_is_not_there_is_named_not_swallowed(tmp_path):
    """``set -e`` ended the script inside the version probe: exit 127 and not
    a word about which promtool was missing (review of #334)."""
    missing = tmp_path / "nowhere" / "promtool"
    result = _run_rules_script(tmp_path, PROMTOOL=str(missing))
    assert result.returncode == 1
    assert str(missing) in result.stderr
    assert "unknown" in result.stderr


# --- the registry itself -------------------------------------------------------


def _unbounded_labels(families) -> dict[str, list[str]]:
    """``{family: forbidden labels it carries}``; ``tenant`` only on the capped series."""
    offending = {}
    for family in families:
        forbidden = FORBIDDEN_LABELS - ({"tenant"} if family.name in TENANT_FAMILIES else set())
        if family.labels & forbidden:
            offending[family.name] = sorted(family.labels & forbidden)
    return offending


def test_no_series_carries_an_unbounded_label():
    """The rule the fleet series were designed around, applied to all of them:
    a label per tenant, agent, host or user is a series per tenant, agent, host
    or user — and for several of those, whoever sends the request picks it."""
    offending = _unbounded_labels(metric_catalogue.families().values())
    assert not offending, offending
    assert TENANT_FAMILIES, "the tenant collector describes no families"


def test_the_label_check_allows_a_tenant_only_on_the_capped_series():
    family = metric_catalogue.Family
    assert _unbounded_labels([family("octo_jobs_queued", "gauge", frozenset({"tenant"}), "")]) == {
        "octo_jobs_queued": ["tenant"]
    }
    assert _unbounded_labels([family("octo_agents", "gauge", frozenset({"hostname", "state"}), "")]) == {
        "octo_agents": ["hostname"]
    }
    assert not _unbounded_labels(
        [family("octo_tenant_open_findings", "gauge", frozenset({"tenant", "severity"}), "")]
    )


# --- docs/observability.md ---------------------------------------------------------


def test_the_catalogue_names_only_exported_series():
    unknown = metric_catalogue.unknown_series(
        CATALOGUE.read_text(encoding="utf-8"), family_names=True
    )
    assert not unknown, f"docs/observability.md names series the API does not export: {sorted(unknown)}"


def test_the_catalogue_covers_every_exported_family():
    """Adding a series means saying in the catalogue what its labels are bounded by."""
    text = CATALOGUE.read_text(encoding="utf-8")
    mentioned = set(metric_catalogue.SERIES_NAME.findall(text))
    missing = sorted(
        family.name
        for family in metric_catalogue.families().values()
        if family.name.startswith("octo_")
        and not mentioned & {family.name, *family.sample_names}
    )
    assert not missing, f"docs/observability.md does not describe: {missing}"
