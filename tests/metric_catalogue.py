"""What ``GET /metrics`` can expose, as names and label sets (#334).

Shared by the checks that keep the alert rules, the Grafana dashboards and
docs/observability.md from naming a series the API does not export. Derived from
the registry rather than listed by hand: a hand-written list is one more thing
that drifts, which is the failure these checks exist to catch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from prometheus_client.metrics import MetricWrapperBase

from api.services import agents as agents_service
from api.services import metrics, metrics_sources

#: Labels Prometheus attaches to every scraped series itself; a query may name
#: them whatever the metric declares.
TARGET_LABELS = frozenset({"job", "instance", "namespace", "pod", "service", "endpoint", "container"})

#: Series outside the registry that the dashboards may use: Prometheus's own
#: per-target health series.
PROMETHEUS_SERIES = frozenset({"up"})

_SUFFIXES = {
    "counter": ("_total", "_created"),
    "gauge": ("",),
    "histogram": ("_bucket", "_count", "_sum", "_created"),
    "gaugehistogram": ("_bucket", "_gcount", "_gsum"),
    "summary": ("", "_count", "_sum", "_created"),
    "info": ("_info",),
    "unknown": ("",),
}

#: A series name as it appears in PromQL or prose: the three prefixes the API
#: exports under. Label values such as ``octo-ch-ingest`` do not match.
SERIES_NAME = re.compile(r"\b(?:octo|process|python)_[a-z0-9_]*[a-z0-9]")


@dataclass(frozen=True)
class Family:
    name: str
    type: str
    labels: frozenset[str]
    documentation: str

    @property
    def sample_names(self) -> tuple[str, ...]:
        return tuple(self.name + suffix for suffix in _SUFFIXES[self.type])

    @property
    def cluster_wide(self) -> bool:
        """Whether its help text says every replica reports the same value."""
        return "Cluster-wide" in self.documentation or "max(), not sum()" in self.documentation


def _populated_cluster() -> metrics_sources.ClusterSnapshot:
    fleet = agents_service.FleetHeartbeats(
        counts={(k, s): 1 for k in agents_service.FLEET_KINDS for s in agents_service.FLEET_STATES},
        age_buckets={k: [1] * len(agents_service.HEARTBEAT_AGE_BUCKETS) for k in agents_service.FLEET_KINDS},
        age_totals=dict.fromkeys(agents_service.FLEET_KINDS, 1),
        age_sums=dict.fromkeys(agents_service.FLEET_KINDS, 1.0),
        age_max=dict.fromkeys(agents_service.FLEET_KINDS, 1.0),
        stale_seconds=120,
    )
    return metrics_sources.ClusterSnapshot(
        fleet=fleet, jobs_queued=1, jobs_running=1, endpoint_devices={"active": 1, "stale": 1}
    )


def _populated_tenants() -> metrics_sources.TenantSnapshot:
    labels = ("acme", metrics_sources.TENANT_OTHER)
    return metrics_sources.TenantSnapshot(
        open_findings={(t, s): 1 for t in labels for s in metrics_sources.TENANT_SEVERITIES},
        sla_breached=dict.fromkeys(labels, 1),
        scans_finished={(t, s): 1 for t in labels for s in metrics_sources.TENANT_SCAN_STATUSES},
    )


#: What each scrape-snapshot collector is rendered from here, so its families
#: carry the labels they would carry on a live /metrics.
_EXAMPLE_SNAPSHOTS = {
    id(metrics.CLUSTER_COLLECTOR): _populated_cluster,
    id(metrics.TENANT_COLLECTOR): _populated_tenants,
}


def tenant_family_names() -> set[str]:
    """The families of the opt-in per-tenant collector — the only ones with ``tenant``."""
    return {family.name for family in metrics.TENANT_COLLECTOR.describe()}


def families() -> dict[str, Family]:
    """Every family the registry exports, keyed by family name, with its labels.

    Collectors are read through ``describe()`` where they have one, so nothing
    here touches a database. Label sets come from the metric objects for the
    pushed series (a labelled metric with no child yet has no samples to read
    them from) and from an example snapshot for the scrape-time collectors,
    whose families carry no samples without one.
    """
    out: dict[str, Family] = {}
    # Private, but the registry has no public list of its collectors.
    for collector in list(metrics.REGISTRY._collector_to_names):  # noqa: SLF001
        if id(collector) in _EXAMPLE_SNAPSHOTS:
            described = collector.render(_EXAMPLE_SNAPSHOTS[id(collector)]())
        elif isinstance(collector, MetricWrapperBase):
            described = list(collector.describe())
        elif hasattr(collector, "describe"):
            described = list(collector.describe())
        else:
            described = list(collector.collect())
        for family in described:
            if isinstance(collector, MetricWrapperBase):
                labels = frozenset(collector._labelnames)  # noqa: SLF001
            else:
                labels = frozenset(
                    name for sample in family.samples for name in sample.labels if name != "le"
                )
            out[family.name] = Family(family.name, family.type, labels, family.documentation)
    return out


def sample_index() -> dict[str, Family]:
    """``{sample name: family}`` for every name a query may use."""
    return {sample: family for family in families().values() for sample in family.sample_names}


def unknown_series(text: str, *, family_names: bool = False) -> set[str]:
    """Series named in ``text`` that the API does not export.

    PromQL must name a sample (``…_bucket``, ``…_total``): a histogram's bare
    family name selects nothing. Prose names families, so ``family_names``
    accepts those too.
    """
    known = set(sample_index())
    if family_names:
        known |= set(families())
    return {name for name in SERIES_NAME.findall(text) if name not in known}
