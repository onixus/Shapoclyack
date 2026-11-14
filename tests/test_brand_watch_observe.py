"""Brand-watch M1 DNS observation. No HTTP, no mixed dnsx record types."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from scanner.brand_watch import observe as observe_module
from scanner.brand_watch.observe import observe_dns
from scanner.pipeline import dnsx as dnsx_module
from scanner.pipeline.dnsx import DnsxError

RESOLVERS = ["192.0.2.53"]
RESOLVER_FLAG = "192.0.2.53:53"
_RECORD_FLAGS = ("-a", "-aaaa", "-ns", "-soa", "-mx")
_SHAPE = {"unicode", "punycode", "ns", "a", "aaaa", "mx_present", "rcode", "status"}


def _record_flags(argv: list[str]) -> list[str]:
    return [flag for flag in argv if flag in _RECORD_FLAGS or flag in {"-cname", "-txt", "-ptr"}]


class _FakeDnsx:
    def __init__(self, answers: dict[str, dict]) -> None:
        self.answers = answers
        self.argvs: list[list[str]] = []

    def __call__(self, command, timeout, retries, **kwargs):  # noqa: ANN001
        assert command[0] == "dnsx", command
        self.argvs.append(list(command))
        out = Path(command[command.index("-o") + 1])
        flag = _record_flags(command)
        assert len(flag) == 1, command
        row = self.answers.get(flag[0])
        text = ""
        if row is not None:
            text = json.dumps(row) + "\n"
        out.write_text(text, encoding="utf-8")


def _install(monkeypatch, answers: dict[str, dict]) -> _FakeDnsx:
    fake = _FakeDnsx(answers)
    monkeypatch.setattr(dnsx_module, "run_command", fake)
    return fake


def _ns_without_a() -> dict[str, dict]:
    return {
        "-a": {"host": "lookalike.example", "status_code": "NXDOMAIN", "a": []},
        "-aaaa": {"host": "lookalike.example", "status_code": "NXDOMAIN", "aaaa": []},
        "-ns": {
            "host": "lookalike.example",
            "status_code": "NOERROR",
            "ns": ["ns1.registry.example."],
        },
        "-soa": {
            "host": "lookalike.example",
            "status_code": "NOERROR",
            "soa": [{"ns": "ns1.registry.example."}],
        },
        "-mx": {
            "host": "lookalike.example",
            "status_code": "NOERROR",
            "mx": ["10 secret-mailbox.example."],
        },
    }


def test_ns_without_a_is_registered_not_silence(tmp_path: Path, monkeypatch):
    fake = _install(monkeypatch, _ns_without_a())

    rows = observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)

    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "registered"
    assert row["a"] == []
    assert row["aaaa"] == []
    assert row["ns"] == ["ns1.registry.example"]
    assert row["mx_present"] is True
    assert "secret-mailbox.example" not in json.dumps(row)
    assert row["rcode"] == "NXDOMAIN"
    assert fake.argvs


def test_soa_without_a_is_registered(tmp_path: Path, monkeypatch):
    answers = _ns_without_a()
    answers["-ns"] = {"host": "lookalike.example", "status_code": "NXDOMAIN", "ns": []}
    answers["-mx"] = {"host": "lookalike.example", "status_code": "NXDOMAIN", "mx": []}
    _install(monkeypatch, answers)

    row = observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)[0]

    assert row["status"] == "registered"
    assert row["ns"] == []
    assert row["mx_present"] is False


def test_result_shape_is_idempotent(tmp_path: Path, monkeypatch):
    _install(monkeypatch, _ns_without_a())

    first = observe_dns(["Lookalike.example."], tmp_path, resolvers=RESOLVERS)
    second = observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)

    assert first == second
    assert set(first[0]) == _SHAPE
    assert first[0]["unicode"] == "lookalike.example"
    assert first[0]["punycode"] == "lookalike.example"
    assert isinstance(first[0]["mx_present"], bool)
    assert isinstance(first[0]["ns"], list)
    assert isinstance(first[0]["a"], list)
    assert isinstance(first[0]["aaaa"], list)


def test_record_types_are_not_mixed_and_resolvers_are_the_callers(tmp_path: Path, monkeypatch):
    fake = _install(monkeypatch, _ns_without_a())

    observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)

    seen: list[str] = []
    assert len(fake.argvs) == 5
    for argv in fake.argvs:
        assert argv[0] == "dnsx"
        flags = _record_flags(argv)
        assert len(flags) == 1
        seen.append(flags[0])
        assert argv[argv.index("-r") + 1] == RESOLVER_FLAG
        assert "http" not in " ".join(argv).lower()
    assert seen == list(_RECORD_FLAGS)


def test_no_http_client_is_imported_or_called(tmp_path: Path, monkeypatch):
    imported = set(observe_module.__dict__) | set(getattr(observe_module, "__annotations__", {}))
    for banned in ("httpx", "requests", "urllib", "httplib", "nuclei", "aiohttp"):
        assert banned not in imported
    assert inspect.getmodule(observe_dns).__name__ == "scanner.brand_watch.observe"
    fake = _install(monkeypatch, _ns_without_a())

    observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)

    assert fake.argvs
    assert all(argv[0] == "dnsx" for argv in fake.argvs)


def test_missing_dnsx_is_unanswered_not_a_batch_crash(tmp_path: Path, monkeypatch):
    def missing(command, timeout, retries, **kwargs):  # noqa: ANN001
        raise FileNotFoundError("dnsx")

    monkeypatch.setattr(dnsx_module, "run_command", missing)

    rows = observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)

    assert rows == [
        {
            "unicode": "lookalike.example",
            "punycode": "lookalike.example",
            "ns": [],
            "a": [],
            "aaaa": [],
            "mx_present": False,
            "rcode": None,
            "status": "unanswered",
        }
    ]


def test_dnsx_error_does_not_raise(tmp_path: Path, monkeypatch):
    def broken(*args, **kwargs):  # noqa: ANN001
        raise DnsxError("dnsx a lookup failed")

    monkeypatch.setattr(observe_module, "dnsx_query", broken)

    rows = observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)

    assert [row["status"] for row in rows] == ["unanswered"]


def test_resolving_when_an_address_is_present(tmp_path: Path, monkeypatch):
    answers = _ns_without_a()
    answers["-a"] = {"host": "lookalike.example", "status_code": "NOERROR", "a": ["203.0.113.10"]}
    _install(monkeypatch, answers)

    row = observe_dns(["lookalike.example"], tmp_path, resolvers=RESOLVERS)[0]

    assert row["status"] == "resolving"
    assert row["a"] == ["203.0.113.10"]
    assert row["rcode"] == "NOERROR"
