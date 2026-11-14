"""Sensor brand-watch claim loop. HTTP and observe are injected; no dnsx, no network."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent import worker
from agent.brand_watch_runner import poll_once, run_claimed_job, sensor_resolvers

PUBLIC = "203.0.113.10"
PRIVATE = "10.0.0.5"


class FakeClient:
    def __init__(self, job=None, *, claim_error: Exception | None = None, post_error: Exception | None = None):
        self.job = job
        self.claim_error = claim_error
        self.post_error = post_error
        self.claims: list[str] = []
        self.results: list[tuple[str, list]] = []
        self.released: list[str] = []
        self.scans: list = []

    def claim_brand_watch(self, agent_id: str):
        self.claims.append(agent_id)
        if self.claim_error is not None:
            raise self.claim_error
        return self.job

    def post_brand_watch_result(self, job_id: str, observations: list):
        if self.post_error is not None:
            raise self.post_error
        self.results.append((job_id, observations))
        return {"id": job_id, "status": "done"}

    def release_brand_watch(self, job_id: str):
        self.released.append(job_id)
        return {"id": job_id, "released": True}

    def claim(self, agent_id: str, **kwargs):
        self.scans.append(agent_id)
        return None


def _dns_row(name: str, *, status: str = "resolving", a=None, aaaa=None) -> dict:
    return {
        "unicode": name,
        "punycode": name,
        "ns": ["ns1.example"],
        "a": list(a or []),
        "aaaa": list(aaaa or []),
        "mx_present": False,
        "rcode": "NOERROR",
        "status": status,
    }


def _observe_dns(names, output_dir, *, resolvers):
    return [_dns_row(name, a=[PUBLIC]) for name in names]


def _refuse(address: str) -> str | None:
    if address.startswith("10.") or address.startswith("192.168.") or address == "127.0.0.1":
        return "private_address"
    return None


def test_capability_is_advertised_next_to_the_existing_ones():
    assert "brand_watch" in worker.CAPABILITIES
    assert worker.CAPABILITIES[:4] == (
        "scan_policy",
        "config_overlay.v1",
        "config_overlay.v2",
        "config_overlay.v3",
    )


def test_204_claims_nothing_and_posts_nothing(tmp_path: Path):
    client = FakeClient(None)
    assert poll_once(
        client,
        "sensor-1",
        config_path=tmp_path / "missing.yaml",
        observe_dns=_observe_dns,
        observe_http=lambda *a, **k: pytest.fail("http"),
        refuse_reason=_refuse,
        resolvers=[],
    ) is False
    assert client.claims == ["sensor-1"]
    assert client.results == []
    assert client.scans == []


def test_dns_only_does_not_open_http(tmp_path: Path):
    seen = {}

    def observe_dns(names, output_dir, *, resolvers):
        seen["resolvers"] = list(resolvers)
        seen["names"] = list(names)
        return [_dns_row(name, a=[PUBLIC]) for name in names]

    def observe_http(*args, **kwargs):
        pytest.fail("dns_only must not open HTTP")

    client = FakeClient({
        "id": "bwj_1",
        "mode": "dns_only",
        "payload": {"names": ["lookalike.example"]},
    })
    assert poll_once(
        client,
        "sensor-1",
        config_path=tmp_path / "missing.yaml",
        observe_dns=observe_dns,
        observe_http=observe_http,
        refuse_reason=_refuse,
        resolvers=["192.0.2.53"],
    ) is True
    assert seen["resolvers"] == ["192.0.2.53"]
    assert seen["names"] == ["lookalike.example"]
    job_id, observations = client.results[0]
    assert job_id == "bwj_1"
    assert observations[0]["status"] == "resolving"
    assert observations[0]["a"] == [PUBLIC]
    assert client.scans == []


def test_http_allowed_only_for_resolving_public_address():
    calls: list[str] = []

    def observe_dns(names, output_dir, *, resolvers):
        return [
            _dns_row("public.example", a=[PUBLIC]),
            _dns_row("private.example", a=[PRIVATE]),
            _dns_row("silent.example", status="registered", a=[]),
            _dns_row("nx.example", status="unregistered", a=[]),
        ]

    def observe_http(request, **kwargs):
        calls.append(request.name)
        return {"live": True, "address": request.address, "status_code": 200}

    rows = run_claimed_job(
        {
            "id": "bwj_2",
            "mode": "http_allowed",
            "payload": {"names": ["public.example", "private.example", "silent.example", "nx.example"]},
        },
        config_path=Path("missing.yaml"),
        observe_dns=observe_dns,
        observe_http=observe_http,
        refuse_reason=_refuse,
        resolvers=["192.0.2.53"],
    )
    assert calls == ["public.example"]
    by_name = {row["unicode"]: row for row in rows}
    assert by_name["public.example"]["live"] is True
    assert by_name["public.example"]["a"] == [PUBLIC]
    assert "live" not in by_name["private.example"]
    assert by_name["silent.example"]["status"] == "registered"
    assert by_name["nx.example"]["status"] == "unregistered"


def test_failed_observe_is_posted_as_unanswered():
    def observe_dns(names, output_dir, *, resolvers):
        raise RuntimeError("dnsx missing")

    client = FakeClient({
        "id": "bwj_3",
        "mode": "http_allowed",
        "payload": {"names": ["lookalike.example"]},
    })
    assert poll_once(
        client,
        "sensor-1",
        config_path=Path("missing.yaml"),
        observe_dns=observe_dns,
        observe_http=lambda *a, **k: pytest.fail("http after dns failure"),
        refuse_reason=_refuse,
        resolvers=[],
    ) is True
    _, observations = client.results[0]
    assert observations == [{
        "unicode": "lookalike.example",
        "punycode": "lookalike.example",
        "ns": [],
        "a": [],
        "aaaa": [],
        "mx_present": False,
        "rcode": None,
        "status": "unanswered",
    }]


def test_http_failure_is_posted_as_unanswered_and_does_not_raise():
    def observe_http(request, **kwargs):
        raise RuntimeError("connection refused")

    client = FakeClient({
        "id": "bwj_4",
        "mode": "http_allowed",
        "payload": {"names": ["lookalike.example"]},
    })
    assert poll_once(
        client,
        "sensor-1",
        config_path=Path("missing.yaml"),
        observe_dns=_observe_dns,
        observe_http=observe_http,
        refuse_reason=_refuse,
        resolvers=["192.0.2.53"],
    ) is True
    _, observations = client.results[0]
    assert observations[0]["status"] == "unanswered"
    assert observations[0]["a"] == [PUBLIC]
    assert "http_error" not in observations[0]


def test_claim_and_post_errors_do_not_escape():
    claiming = FakeClient(claim_error=RuntimeError("api down"))
    assert poll_once(
        claiming,
        "sensor-1",
        config_path=Path("missing.yaml"),
        observe_dns=_observe_dns,
        observe_http=lambda *a, **k: {},
        refuse_reason=_refuse,
        resolvers=[],
    ) is False

    posting = FakeClient(
        {"id": "bwj_5", "mode": "dns_only", "payload": {"names": ["lookalike.example"]}},
        post_error=RuntimeError("api down"),
    )
    assert poll_once(
        posting,
        "sensor-1",
        config_path=Path("missing.yaml"),
        observe_dns=_observe_dns,
        observe_http=lambda *a, **k: pytest.fail("dns_only"),
        refuse_reason=_refuse,
        resolvers=[],
    ) is True
    assert posting.results == []
    assert posting.released == ["bwj_5"]
    assert posting.scans == []


def test_empty_resolver_list_is_passed_through_not_replaced():
    seen = {}

    def observe_dns(names, output_dir, *, resolvers):
        seen["resolvers"] = list(resolvers)
        return [_dns_row(item, status="unanswered") for item in names]

    run_claimed_job(
        {"id": "bwj_6", "mode": "dns_only", "payload": {"names": ["lookalike.example"]}},
        config_path=Path("does-not-exist.yaml"),
        observe_dns=observe_dns,
        observe_http=lambda *a, **k: pytest.fail("dns_only"),
        refuse_reason=_refuse,
        resolvers=[],
    )
    assert seen["resolvers"] == []


def test_missing_config_yields_no_resolvers(tmp_path: Path):
    assert sensor_resolvers(tmp_path / "no-such.yaml") == []


def test_poll_loop_calls_brand_watch_when_no_scan_job(monkeypatch):
    source = Path(worker.__file__).read_text(encoding="utf-8")
    claim_at = source.index("job = client.claim(agent_id)")
    window = source[claim_at:claim_at + 1400]
    assert "poll_in_background" in window
    assert window.index("if job is None:") < window.index("poll_in_background")
    assert 'import_module("scanner.brand_watch.sensor_hooks")' in window
    assert "except ImportError:" in window
    assert "brand_watch" in worker.CAPABILITIES
