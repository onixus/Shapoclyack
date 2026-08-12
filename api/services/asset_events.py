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
import time
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

# Order the cap keeps when a run overflows it. report_diff.py emits events in
# artifact order — every new_asset, then ports, then CVEs — so a plain head-cap
# let a scope expansion fill all 1000 slots with bare host discoveries and drop
# every new_cve behind them, which is the one kind the alert bus exists for.
# Ranked most to least actionable; ties keep report_diff's order, which already
# sorts vulnerabilities by severity.
_KIND_PRIORITY = {
    "new_cve": 0,
    "cert_expiring": 1,
    "decommissioned_host": 2,
    "new_open_port": 3,
    "new_asset": 4,
}

# Bounds on the publish loop. It runs inside the agent's result-upload request
# and inside the local scan thread, both of which hold a job that is not
# terminal until it returns: with a broker that accepts the connection but
# fails every publish, an uncapped 1000-envelope loop would keep that job in
# flight for many minutes. A publish that has to be abandoned is exactly the
# case diff.json exists for.
DEFAULT_PUBLISH_DEADLINE_SECONDS = 30.0
# Consecutive failures after which the broker is treated as demonstrably
# unavailable and the rest of the batch is abandoned without being tried.
_FAILURE_STREAK_ABORT = 3
# One retry, not publish_json's default three: an event is best-effort and
# content-deduped, so a slow retry ladder costs the job more than the event is
# worth.
_PUBLISH_RETRIES = 1


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
        # A host can newly expose tcp/443 and udp/443 in one run (scan mode
        # ``tcp_udp``); without the protocol both occurrences hash the same and
        # JetStream would drop the second as a duplicate while the publisher
        # reported success.
        str(event.get("protocol") or ""),
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

    accepted: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "")
        if kind not in EVENT_KINDS:
            LOG.debug("Skipping asset event with unknown kind %r (run=%s)", kind, run_id)
            continue
        accepted.append(item)

    limit = max(1, max_events)
    dropped = max(0, len(accepted) - limit)
    if dropped:
        # Stable sort: within a kind, report_diff's ordering (severity-first for
        # vulnerabilities) is preserved.
        accepted.sort(key=lambda item: _KIND_PRIORITY.get(str(item.get("kind")), len(_KIND_PRIORITY)))
        accepted = accepted[:limit]

    envelopes: list[dict[str, Any]] = []
    for item in accepted:
        kind = str(item["kind"])
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
    *,
    deadline_seconds: float = DEFAULT_PUBLISH_DEADLINE_SECONDS,
) -> int:
    """Publish envelopes to ``events.asset.{tenant}.{kind}``. Returns the count published.

    Never raises, and never runs longer than ``deadline_seconds``: every failure
    path is counted on ``octo_asset_events_published_total`` (``error`` for a
    publish that was attempted and failed, ``skipped`` for one abandoned with
    the broker unreachable) and logged. The caller holds a job that stays
    non-terminal until this returns, so an unbounded loop over a broker that
    accepts connections but fails publishes would be paid for by the job, not
    by the event.
    """
    if not envelopes:
        return 0
    bus = nats_bus.get_bus(nats_url)
    if bus is None:
        _count_abandoned(envelopes)
        return 0

    started = time.monotonic()
    published = 0
    failure_streak = 0
    for index, envelope in enumerate(envelopes):
        if failure_streak >= _FAILURE_STREAK_ABORT:
            LOG.warning(
                "Abandoning %s asset events after %s consecutive publish failures",
                len(envelopes) - index,
                failure_streak,
            )
            _count_abandoned(envelopes[index:])
            break
        if time.monotonic() - started > deadline_seconds:
            LOG.warning(
                "Asset event publish exceeded %.0fs; abandoning %s of %s events",
                deadline_seconds,
                len(envelopes) - index,
                len(envelopes),
            )
            _count_abandoned(envelopes[index:])
            break
        kind = envelope["kind"]
        try:
            ok = bus.publish_asset_event(envelope, retries=_PUBLISH_RETRIES)
        except Exception:  # noqa: BLE001
            LOG.exception("Asset event publish raised (kind=%s run=%s)", kind, envelope.get("run_id"))
            ok = False
        metrics.ASSET_EVENTS_PUBLISHED_TOTAL.labels(
            kind=kind, outcome="published" if ok else "error"
        ).inc()
        published += int(ok)
        failure_streak = 0 if ok else failure_streak + 1
    return published


def _count_abandoned(envelopes: list[dict[str, Any]]) -> None:
    for envelope in envelopes:
        metrics.ASSET_EVENTS_PUBLISHED_TOTAL.labels(
            kind=envelope.get("kind", "unknown"), outcome="skipped"
        ).inc()


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
    write, not a scan — so its id is keyed on the asset and kind instead. It
    deliberately excludes the timestamp: ``update_asset`` locks the row, so two
    concurrent PATCHes produce one transition, but a lock is a database
    guarantee and this is the publish side of it — a timestamped id would make
    JetStream accept both messages for one logical transition and hand a
    consumer two tickets. The 24h duplicate window is also why a decommission,
    reversal and second decommission inside one day collapses to one event; a
    status that flaps that fast is not a change worth paging on twice.
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
        f"{tenant_id}|{asset_id}|{kind}".encode("utf-8")
    ).hexdigest()[:48]
    return publish_events(nats_url, [envelope]) == 1
