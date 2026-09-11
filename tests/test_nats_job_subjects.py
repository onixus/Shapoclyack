"""Per-tenant job subjects and durable consumers (no live broker required).

The subject an offer lands on decides which agents are woken by it, and since
#361 which agents may be: a job addressed to an agent group is offered on that
group's own subject. These pin the naming on both sides of the wire — the API
publishes to ``jobs.scan.{tenant}[.{group}]`` and the agent, which cannot
import ``api``, derives exactly the same names.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent import worker
from api.services import nats_bus


@pytest.mark.parametrize(
    ("tenant_id", "subject", "durable"),
    [
        ("default", "jobs.scan.default", "octo-agents-default"),
        ("", "jobs.scan.default", "octo-agents-default"),
        ("acme-eu", "jobs.scan.acme-eu", "octo-agents-acme-eu"),
    ],
)
def test_subject_and_consumer_are_named_for_the_tenant(tenant_id, subject, durable):
    assert nats_bus.jobs_scan_subject(tenant_id) == subject
    assert nats_bus.jobs_consumer_name(tenant_id) == durable


def test_a_tenant_id_that_is_not_a_subject_token_is_hashed_not_mangled():
    """``.`` is a subject separator, so an id carrying one cannot be used raw.

    Collapsing it to ``_`` (what an ad-hoc sanitiser does) is not injective:
    ``acme.eu`` and ``acme_eu`` would share a subject and a durable consumer,
    which is the same failure as having no per-tenant split at all.
    """
    dotted = nats_bus.jobs_scan_subject("acme.eu")
    underscored = nats_bus.jobs_scan_subject("acme_eu")

    assert dotted != underscored
    assert dotted.startswith("jobs.scan.h_")
    # Still a single subject token: no separator, no wildcard.
    assert dotted.count(".") == 2
    assert nats_bus.jobs_consumer_name("acme.eu") != nats_bus.jobs_consumer_name("acme_eu")
    assert "." not in nats_bus.jobs_consumer_name("acme.eu")


@pytest.mark.parametrize("tenant_id", ["default", "", "acme-eu", "acme.eu", "h_x", "Ten_1"])
def test_the_agent_derives_the_same_names_as_the_api(tenant_id):
    """The encoder is duplicated in agent/worker.py because the agent ships
    without the ``api`` package. A drift between the two copies is silent: the
    agent binds a consumer whose filter no offer ever matches, and every job
    for that tenant sits in the stream until it ages out."""
    assert worker.jobs_scan_subject(tenant_id) == nats_bus.jobs_scan_subject(tenant_id)
    assert worker.jobs_consumer_name(tenant_id) == nats_bus.jobs_consumer_name(tenant_id)


class _RecordingJetStream:
    def __init__(self) -> None:
        self.consumers: list[tuple[str, Any]] = []

    async def add_consumer(self, stream, config):
        self.consumers.append((stream, config))


def _bus_with(js) -> nats_bus.NatsBus:
    bus = nats_bus.NatsBus(nats_bus.NatsConfig(url="nats://localhost:4222"))
    bus._js = js  # noqa: SLF001
    bus._started = True  # noqa: SLF001
    # No background loop in these tests: run the coroutine inline instead.
    bus._call = lambda coro, timeout=15.0: asyncio.run(coro)  # noqa: SLF001
    return bus


def test_the_offer_goes_to_the_tenants_subject_and_creates_its_consumer():
    js = _RecordingJetStream()
    bus = _bus_with(js)
    published: list[tuple[str, dict]] = []
    bus.publish_json = lambda subject, payload, **kwargs: (  # type: ignore[method-assign]
        published.append((subject, payload)) or True
    )

    assert bus.publish_job_offer({"job_id": "job-1", "tenant_id": "acme-eu"}) is True

    assert published[0][0] == "jobs.scan.acme-eu"
    stream, config = js.consumers[0]
    assert stream == nats_bus.STREAM_JOBS
    assert config.durable_name == "octo-agents-acme-eu"
    assert config.filter_subject == "jobs.scan.acme-eu"


def test_the_consumer_is_created_once_per_tenant_not_once_per_offer():
    js = _RecordingJetStream()
    bus = _bus_with(js)
    bus.publish_json = lambda subject, payload, **kwargs: True  # type: ignore[method-assign]

    bus.publish_job_offer({"job_id": "job-1", "tenant_id": "acme-eu"})
    bus.publish_job_offer({"job_id": "job-2", "tenant_id": "acme-eu"})
    bus.publish_job_offer({"job_id": "job-3", "tenant_id": "other"})

    assert [config.durable_name for _stream, config in js.consumers] == [
        "octo-agents-acme-eu",
        "octo-agents-other",
    ]


def test_a_job_addressed_to_a_group_goes_to_that_groups_subject_and_consumer():
    """#361 on the wire. One consumer per tenant meant the offer for the card
    segment's scan was delivered to whichever of the tenant's agents polled
    first, and it sorted that out only at HTTP claim time — after it had read
    the body."""
    js = _RecordingJetStream()
    bus = _bus_with(js)
    published: list[tuple[str, dict, dict]] = []
    bus.publish_json = lambda subject, payload, **kwargs: (  # type: ignore[method-assign]
        published.append((subject, payload, kwargs.get("headers") or {})) or True
    )

    bus.publish_job_offer({"job_id": "job-1", "tenant_id": "acme-eu", "agent_group": "pci"})

    subject, _payload, headers = published[0]
    assert subject == "jobs.scan.acme-eu.pci"
    assert headers["agent_group"] == "pci"
    stream, config = js.consumers[0]
    assert stream == nats_bus.STREAM_JOBS
    assert config.durable_name == "octo-agents-acme-eu-pci"
    assert config.filter_subject == "jobs.scan.acme-eu.pci"


def test_an_ungrouped_job_keeps_the_subject_it_has_today():
    """The upgrade path: an agent that is in no group must keep the consumer it
    is already bound to, or every job of every existing installation stops."""
    js = _RecordingJetStream()
    bus = _bus_with(js)
    published: list[str] = []
    bus.publish_json = lambda subject, payload, **kwargs: (  # type: ignore[method-assign]
        published.append(subject) or True
    )

    bus.publish_job_offer({"job_id": "job-1", "tenant_id": "acme-eu", "agent_group": None})

    assert published == ["jobs.scan.acme-eu"]
    assert js.consumers[0][1].filter_subject == "jobs.scan.acme-eu"


@pytest.mark.parametrize("group", ["pci", "ops-eu", "Group.1"])
def test_the_agent_derives_the_same_group_names_as_the_api(group):
    tenant = "acme.eu"
    assert worker.jobs_scan_subject(tenant, group) == nats_bus.jobs_scan_subject(tenant, group)
    assert worker.jobs_consumer_name(tenant, group) == nats_bus.jobs_consumer_name(tenant, group)


def test_a_broker_that_refuses_the_consumer_still_gets_the_offer():
    """Fail-soft: the agent creates the same durable when it binds, so a race
    with another API replica must not turn into an undelivered job."""

    class _Refusing:
        async def add_consumer(self, stream, config):
            raise RuntimeError("consumer already exists")

    bus = _bus_with(_Refusing())
    published: list[str] = []
    bus.publish_json = lambda subject, payload, **kwargs: (  # type: ignore[method-assign]
        published.append(subject) or True
    )

    assert bus.publish_job_offer({"job_id": "job-1", "tenant_id": "acme-eu"}) is True
    assert published == ["jobs.scan.acme-eu"]


def test_tls_options_are_empty_without_configuration(monkeypatch):
    for name in ("CA", "CERT", "KEY", "HOSTNAME"):
        monkeypatch.delenv(f"OCTO_NATS_TLS_{name}", raising=False)
    assert nats_bus.tls_connect_options() == {}
    assert worker.tls_connect_options() == {}


def test_tls_options_build_a_verifying_context(monkeypatch):
    """Naming a hostname must not be a way to turn verification off."""
    monkeypatch.setenv("OCTO_NATS_TLS_HOSTNAME", "nats.example.com")
    for name in ("CA", "CERT", "KEY"):
        monkeypatch.delenv(f"OCTO_NATS_TLS_{name}", raising=False)

    options = nats_bus.tls_connect_options()

    assert options["tls_hostname"] == "nats.example.com"
    assert options["tls"].check_hostname is True
    assert options["tls"].verify_mode.name == "CERT_REQUIRED"
    assert worker.tls_connect_options()["tls_hostname"] == "nats.example.com"
