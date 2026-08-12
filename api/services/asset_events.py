"""Asset-level event bus (ROADMAP P2 / Phase 10.2).

Phase 10.1 made ``scanner/pipeline/report_diff.py`` emit a normalized
``events: [{"kind": ...}]`` list into each run's ``diff.json``, and
``api/services/assets.py`` log a ``decommissioned_host`` on the manual
transition. Nothing consumed either: the events existed only inside a run
artifact and a pod log. This module publishes them to JetStream so 10.3
(webhooks, ticketing) has something to subscribe to.

Subject: ``events.asset.{tenant_id}.{kind}``

The tenant token sits *before* the kind on purpose. A routing policy is
per-tenant first ("page the acme on-call for new criticals"), so the common
subscription is ``events.asset.acme.>``; a cross-tenant consumer still gets
``events.asset.*.new_cve``. Putting the kind first would have made the
per-tenant case a client-side filter over every other tenant's traffic.

**Where this publishes from, and why it is not** ``scanner/pipeline/alerts.py``
(which the roadmap named): ``alerts.py`` runs inside the scanner, which is also
the agent's payload. It has no tenant context — the tenant is a property of the
job, resolved by the API — and in agent mode it would need broker credentials
handed to every remote worker. Publishing from the API's post-run hook instead
covers both execution paths from one place (local ``_run_job`` and agent
``complete_job`` both land in ``jobs.py``), keeps NATS an API-side concern, and
means an event carries the tenant the API actually authorized. ``alerts.py``
keeps its per-run SMTP/webhook summary — that is a different product surface
(a human digest), not the machine event stream.

Delivery is best-effort by design: a scan whose results are on disk and whose
assets are registered must not be reported as failed because the broker was
unreachable. The events stay in ``diff.json``, so a missed publish is a missed
notification, not lost data.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.services import metrics, nats_bus

LOG = logging.getLogger("shapoclyack.asset_events")

# The five kinds Phase 10.1 defines. An unknown kind is dropped rather than
# published: the subject token comes from this value, so an unvalidated kind
# would let a scanner artifact create arbitrary subjects.
EVENT_KINDS = (
    "new_asset",
    "new_open_port",
    "new_cve",
    "cert_expiring",
    "decommissioned_host",
)

# A run that first discovers a /16 legitimately produces tens of thousands of
# new_asset events. Publishing all of them turns one scan into an alert storm
# and a JetStream backlog, so a run is capped and the overflow is counted and
# logged rather than silently dropped. diff.json keeps the full list.
DEFAULT_MAX_EVENTS_PER_RUN = 1000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def event_id(tenant_id: str, event: dict[str, Any]) -> str:
    """Stable identity for one occurrence, used as the JetStream ``Nats-Msg-Id``.

    Derived from the event's own content rather than randomised, so a results
    upload replayed by the P1.5 idempotency path — or a run re-imported by an
    operator — republishes the same ids and JetStream drops the duplicates
    inside the stream's duplicate window. ``run_id`` is deliberately part of
    the hash: the same finding seen by a *later* run is a new occurrence
    (report_diff only emits it when it is newly added), and collapsing those
    would suppress a re-appearance after remediation.
    """
    parts = [
        tenant_id,
        str(event.get("run_id") or ""),
        str(event.get("kind") or ""),
        str(event.get("host") or ""),
        str(event.get("port") or ""),
        str(event.get("cve") or event.get("script_id") or event.get("issue_kind") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:48]


def build_events(
    diff: dict[str, Any],
    *,
    tenant_id: str,
    run_id: str,
    job_id: str | None = None,
    max_events: int = DEFAULT_MAX_EVENTS_PER_RUN,
) -> tuple[list[dict[str, Any]], int]:
    """Turn a run's ``diff.json`` into publishable envelopes.

    Returns ``(envelopes, dropped)`` — ``dropped`` is how many events the
    ``max_events`` cap cut, so the caller can log an honest number instead of
    reporting a truncated list as the whole change set.

    The envelope keeps the raw 10.1 event under ``data`` verbatim rather than
    flattening it: a ``new_cve`` carries severity/cvss/epss fields a
    ``new_open_port`` does not, and a consumer that wants them should not have
    to guess which top-level keys belong to which kind.
    """
    raw = diff.get("events")
    if not isinstance(raw, list):
        return [], 0

    envelopes: list[dict[str, Any]] = []
    dropped = 0
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "")
        if kind not in EVENT_KINDS:
            LOG.debug("Skipping asset event with unknown kind %r (run=%s)", kind, run_id)
            continue
        if len(envelopes) >= max(1, max_events):
            dropped += 1
            continue
        data = {key: value for key, value in item.items() if key != "kind"}
        envelope = {
            "kind": kind,
            "tenant_id": tenant_id,
            "run_id": run_id,
            "job_id": job_id,
            "host": item.get("host"),
            "port": item.get("port"),
            "occurred_at": _now_iso(),
            "source": "run_diff",
            "data": data,
        }
        envelope["event_id"] = event_id(tenant_id, {**item, "run_id": run_id})
        envelopes.append(envelope)
    return envelopes, dropped


def publish_events(
    nats_url: str,
    envelopes: list[dict[str, Any]],
) -> int:
    """Publish envelopes to ``events.asset.{tenant}.{kind}``. Returns the count published.

    Never raises: every failure path is counted on
    ``octo_asset_events_published_total{outcome="error"}`` and logged.
    """
    if not envelopes:
        return 0
    bus = nats_bus.get_bus(nats_url)
    if bus is None:
        for envelope in envelopes:
            metrics.ASSET_EVENTS_PUBLISHED_TOTAL.labels(
                kind=envelope["kind"], outcome="skipped"
            ).inc()
        return 0

    published = 0
    for envelope in envelopes:
        kind = envelope["kind"]
        try:
            ok = bus.publish_asset_event(envelope)
        except Exception:  # noqa: BLE001
            LOG.exception("Asset event publish raised (kind=%s run=%s)", kind, envelope.get("run_id"))
            ok = False
        outcome = "published" if ok else "error"
        metrics.ASSET_EVENTS_PUBLISHED_TOTAL.labels(kind=kind, outcome=outcome).inc()
        published += int(ok)
    return published


def load_run_diff(run_dir: Path) -> dict[str, Any]:
    """Read ``diff.json`` from a finished run. Missing/unparseable → ``{}``.

    A first-ever run has no previous run to diff against and so writes no
    ``diff.json`` at all — that is the normal no-events case, not an error.
    """
    path = run_dir / "diff.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        LOG.warning("Unreadable diff.json at %s; no asset events published", path, exc_info=True)
        return {}
    return raw if isinstance(raw, dict) else {}


def publish_run_events(
    *,
    nats_url: str,
    run_dir: Path,
    tenant_id: str,
    run_id: str,
    job_id: str | None = None,
    max_events: int = DEFAULT_MAX_EVENTS_PER_RUN,
) -> int:
    """Read a run's diff and publish its asset events. Returns the count published."""
    if not nats_url:
        return 0
    envelopes, dropped = build_events(
        load_run_diff(run_dir),
        tenant_id=tenant_id,
        run_id=run_id,
        job_id=job_id,
        max_events=max_events,
    )
    if dropped:
        LOG.warning(
            "Run %s produced more than %s asset events; %s not published (see diff.json for the full set)",
            run_id,
            max_events,
            dropped,
        )
    published = publish_events(nats_url, envelopes)
    if published:
        LOG.info(
            "Published %s/%s asset events for run %s (tenant=%s)",
            published,
            len(envelopes),
            run_id,
            tenant_id,
        )
    return published


def publish_asset_status_event(
    *,
    nats_url: str,
    tenant_id: str,
    kind: str,
    asset_id: str,
    host: str | None = None,
    data: dict[str, Any] | None = None,
) -> bool:
    """Publish a single non-run event (the 10.1 ``decommissioned_host`` case).

    Unlike run events this one has no ``run_id`` — it originates at an operator
    write, not a scan — so its id is keyed on the asset and kind instead. A
    repeated PATCH cannot reach here: ``assets.update_asset`` only calls it on
    the actual status transition.
    """
    if not nats_url or kind not in EVENT_KINDS:
        return False
    envelope = {
        "kind": kind,
        "tenant_id": tenant_id,
        "run_id": None,
        "job_id": None,
        "asset_id": asset_id,
        "host": host,
        "port": None,
        "occurred_at": _now_iso(),
        "source": "operator",
        "data": data or {},
    }
    envelope["event_id"] = hashlib.sha256(
        f"{tenant_id}|{asset_id}|{kind}|{envelope['occurred_at']}".encode("utf-8")
    ).hexdigest()[:48]
    return publish_events(nats_url, [envelope]) == 1
