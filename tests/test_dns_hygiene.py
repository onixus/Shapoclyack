"""Zone hygiene for the org's own domains (org_profile M2, #182)."""

from __future__ import annotations

import itertools
import json
import logging
import socket
import struct
import subprocess
import types
from pathlib import Path

import pytest

from scanner.pipeline import dns_hygiene
from scanner.pipeline.config_schema import DnsHygieneConfig
from scanner.pipeline.dns_hygiene import (
    _classify_caa,
    _classify_ns,
    _classify_soa,
    _parse_caa,
    _parse_soa,
    _probe_axfr,
    check_dns_hygiene,
)

_TYPE_A, _TYPE_NS, _TYPE_SOA, _TYPE_TXT, _TYPE_AXFR = 1, 2, 6, 16, 252

#: Compression pointer to the question name, right after the 12-byte header.
#: Real servers write every apex owner name this way.
_APEX = b"\xc0\x0c"


def _wire_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _rr(owner: bytes, rrtype: int, rdata: bytes) -> bytes:
    return owner + struct.pack("!HHIH", rrtype, 1, 300, len(rdata)) + rdata


def _soa(owner: bytes = _APEX) -> bytes:
    rdata = (
        _wire_name("ns1.example.com")
        + _wire_name("hostmaster.example.com")
        + struct.pack("!IIIII", 2026092501, 7200, 900, 1_209_600, 300)
    )
    return _rr(owner, _TYPE_SOA, rdata)


def _message(query_id: int, answers: list[bytes], *, rcode: int = 0) -> bytes:
    """One length-prefixed AXFR response for example.com, as sent over TCP."""
    question = _wire_name("example.com") + struct.pack("!HH", _TYPE_AXFR, 1)
    header = struct.pack("!HHHHHH", query_id, 0x8400 | rcode, 1, len(answers), 0, 0)
    body = header + question + b"".join(answers)
    return struct.pack("!H", len(body)) + body


#: Names and data a transfer of example.com hands out. None may reach a log.
ZONE_SECRETS = ("internal-db.example.com", "vpn.example.com", "s3cr3t-verification-token")


def _zone_records() -> list[bytes]:
    return [
        _rr(_APEX, _TYPE_NS, _wire_name("ns1.example.com")),
        _rr(_wire_name("internal-db.example.com"), _TYPE_A, bytes([10, 0, 0, 7])),
        _rr(_wire_name("vpn.example.com"), _TYPE_TXT, b"\x19s3cr3t-verification-token"),
    ]


def _open_zone(query_id: int) -> bytes:
    return _message(query_id, [_soa(), *_zone_records(), _soa()])


class _FakeNameserver:
    """Stands in for ``socket.create_connection`` and records every dial.

    ``respond`` gets the query ID the probe chose and returns the whole TCP
    stream the server sends back. The stream is handed out in 7-byte pieces,
    so a reader that expects one message per ``recv`` fails here as well.
    ``end`` is what the reader meets after the last byte: a clean EOF, a read
    timeout, a reset, or some other socket error. Every timeout the probe sets
    is recorded, because a fake that ignores them cannot show the deadline.
    """

    _ENDINGS = {
        "timeout": lambda: TimeoutError("timed out"),
        "reset": lambda: ConnectionResetError(54, "Connection reset by peer"),
        "unreachable": lambda: OSError(65, "No route to host"),
    }

    def __init__(self, respond, *, end: str = "eof") -> None:
        self.respond = respond
        self.end = end
        self.dialled: list[tuple[str, int]] = []
        self.queries: list[bytes] = []
        self.connect_timeouts: list[float | None] = []
        self.read_timeouts: list[float | None] = []

    def create_connection(self, address, timeout=None, source_address=None):
        self.dialled.append(address)
        self.connect_timeouts.append(timeout)
        return _FakeSocket(self)


class _FakeSocket:
    def __init__(self, server: _FakeNameserver) -> None:
        self._server = server
        self._pending = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def settimeout(self, value) -> None:
        self._server.read_timeouts.append(value)

    def close(self) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self._server.queries.append(data)
        (query_id,) = struct.unpack_from("!H", data, 2)
        self._pending = self._server.respond(query_id)

    def recv(self, size: int) -> bytes:
        if not self._pending and self._server.end != "eof":
            raise _FakeNameserver._ENDINGS[self._server.end]()
        piece = min(size, 7)
        chunk, self._pending = self._pending[:piece], self._pending[piece:]
        return chunk


def _serve(monkeypatch, respond, *, end: str = "eof") -> _FakeNameserver:
    """Answer the probe's TCP connection from ``respond``.

    The probe dials a gated IP literal and nothing else, so it may neither
    resolve a name nor hand the job to dnsx -- which, given ``-resolver X``,
    chased the zone's NS set on its own and dialled addresses nobody checked.
    """
    server = _FakeNameserver(respond, end=end)
    monkeypatch.setattr(socket, "create_connection", server.create_connection)
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: pytest.fail("the AXFR probe resolved a name")
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("the AXFR probe started a subprocess")
    )
    return server


def _no_dialling(monkeypatch) -> None:
    def explode(*args, **kwargs):
        raise AssertionError("no zone transfer may be attempted against a private address")

    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(subprocess, "run", explode)


def _patch_dnsx(
    monkeypatch,
    *,
    ns: dict | None = None,
    soa: dict | None = None,
    caa: dict | None = None,
    addresses: dict | None = None,
) -> None:
    """Answer every dnsx wrapper from canned records.

    Same convention as ``test_domain_monitor.py``: the module attribute is
    replaced and the fake repeats the keyword-only signature exactly, so a
    changed signature fails the test instead of silently passing.
    """

    def fake_ns(domains, output_dir, *, timeout, retries):
        return dict(ns or {})

    def fake_soa(domains, output_dir, *, timeout, retries):
        return dict(soa or {})

    def fake_caa(domains, output_dir, *, timeout, retries):
        return dict(caa or {})

    def fake_a_aaaa(names, output_dir, *, kind, timeout, retries):
        return {name: dict((addresses or {}).get(name, {})) for name in names}

    monkeypatch.setattr(dns_hygiene, "_run_dnsx_ns", fake_ns)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_soa", fake_soa)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_caa", fake_caa)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_a_aaaa", fake_a_aaaa)


def _kinds(result: dict) -> set[str]:
    return {finding["kind"] for finding in result["findings"]}


def test_dns_hygiene_disabled(tmp_path: Path):
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "dns_hygiene.disabled"
    assert (tmp_path / "dns_hygiene.json").exists()
    assert (tmp_path / "dns_hygiene_findings.txt").exists()


def test_dns_hygiene_no_domains(tmp_path: Path):
    result = check_dns_hygiene([], DnsHygieneConfig(enabled=True), tmp_path)
    assert result["skipped_reason"] == "no_domains"
    assert (tmp_path / "dns_hygiene.json").exists()


def test_dns_hygiene_truncates_at_max_domains(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    result = check_dns_hygiene(
        ["a.example", "b.example"],
        DnsHygieneConfig(enabled=True, max_domains=1),
        tmp_path,
    )
    assert result["truncated"] is True
    assert result["seed_domains"] == ["a.example"]
    assert set(result["domains"]) == {"a.example"}


def test_ns_set_is_capped_per_domain(tmp_path: Path, monkeypatch):
    many = [f"ns{index}.provider.example" for index in range(dns_hygiene.MAX_NS_PER_DOMAIN + 5)]
    _patch_dnsx(monkeypatch, ns={"example.com": {"ns": many}})
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    record = result["domains"]["example.com"]
    assert len(record["nameservers"]) == dns_hygiene.MAX_NS_PER_DOMAIN
    assert record["nameservers_truncated"] is True
    assert result["truncated"] is True


def test_ns_single_point_and_lame_delegation():
    _, findings = _classify_ns("example.com", ["ns1.example.com"], {"ns1.example.com": ["1.1.1.1"]})
    assert [f["kind"] for f in findings] == ["ns_single_point"]
    assert findings[0]["reason"] == "single_ns"

    _, findings = _classify_ns(
        "example.com",
        ["ns1.a.example", "ns2.b.example"],
        {"ns1.a.example": ["203.0.113.1"], "ns2.b.example": []},
    )
    kinds = {f["kind"] for f in findings}
    assert "ns_lame_delegation" in kinds
    assert "ns_single_point" not in kinds


def test_ns_diverse_set_has_no_finding():
    block, findings = _classify_ns(
        "example.com",
        ["ns1.a.example", "ns2.b.example"],
        {"ns1.a.example": ["203.0.113.1"], "ns2.b.example": ["198.51.100.1"]},
    )
    assert findings == []
    # The source is named, and it is not ASN: this stage performs no ASN lookup.
    assert block["source"] == "ns_parent_domain_and_ip_prefix"


def test_soa_missing_and_timer_range():
    assert [f["kind"] for f in _classify_soa("example.com", None, [])] == ["soa_missing"]

    sane = {"mname": "ns1.example.com", "timers": {"refresh": 7200, "expire": 1_209_600}}
    assert _classify_soa("example.com", sane, ["ns1.example.com"]) == []

    broken = {"mname": "ns9.other.example", "timers": {"expire": 600}}
    kinds = {f["kind"] for f in _classify_soa("example.com", broken, ["ns1.example.com"])}
    assert kinds == {"soa_mname_not_in_ns", "soa_timers_out_of_range"}


def test_parse_soa_accepts_object_and_string():
    parsed = _parse_soa({"soa": [{"ns": "NS1.Example.com.", "refresh": 7200, "serial": 5}]})
    assert parsed == {"mname": "ns1.example.com", "serial": 5, "timers": {"refresh": 7200}}
    assert _parse_soa({"soa": ["ns1.example.com."]}) == {"mname": "ns1.example.com", "timers": {}}
    assert _parse_soa({}) is None


def test_caa_missing_and_wildcard_unrestricted():
    assert [f["kind"] for f in _classify_caa("example.com", _parse_caa({}))] == ["caa_missing"]

    only_issue = _parse_caa({"caa": ['0 issue "letsencrypt.org"']})
    assert only_issue["issuers"] == ["letsencrypt.org"]
    assert [f["kind"] for f in _classify_caa("example.com", only_issue)] == [
        "caa_wildcard_unrestricted"
    ]

    narrow = _parse_caa({"caa": ['0 issue "letsencrypt.org"', '0 issuewild ";"']})
    assert _classify_caa("example.com", narrow) == []


def test_dnssec_source_is_the_rdap_flag(tmp_path: Path, monkeypatch):
    (tmp_path / "ownership.json").write_text(
        json.dumps({"domains": {"example.com": {"dnssec": False}}}), encoding="utf-8"
    )
    _patch_dnsx(monkeypatch, ns={"example.com": {"ns": ["ns1.a.example", "ns2.b.example"]}})
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    dnssec = result["domains"]["example.com"]["dnssec"]
    assert dnssec == {
        "status": "absent",
        "delegation_signed": False,
        "source": "rdap_registry",
        "reason": None,
    }
    assert "dnssec_absent" in _kinds(result)


def test_dnssec_is_not_checked_without_ownership(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch, ns={"example.com": {"ns": ["ns1.a.example", "ns2.b.example"]}})
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    dnssec = result["domains"]["example.com"]["dnssec"]
    # No data must never turn into "ok" and never into a finding either.
    assert dnssec["status"] == "not_checked"
    assert dnssec["reason"] == "no_rdap_secure_dns"
    assert "dnssec_absent" not in _kinds(result)


def test_wildcard_needs_every_probe_to_resolve(tmp_path: Path, monkeypatch):
    resolved: dict[str, dict] = {}

    def fake_a_aaaa(names, output_dir, *, kind, timeout, retries):
        if kind != "wildcard":
            return {}
        # Only the first probe label answers -- that is a name collision, not
        # a wildcard, and must not be reported as one.
        return {sorted(names)[0]: {"a": ["203.0.113.5"]}} if not resolved else resolved

    _patch_dnsx(monkeypatch)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_a_aaaa", fake_a_aaaa)
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    assert result["domains"]["example.com"]["wildcard"]["present"] is False
    assert "wildcard_a_record" not in _kinds(result)

    def fake_all(names, output_dir, *, kind, timeout, retries):
        return {name: {"a": ["203.0.113.5"]} for name in names} if kind == "wildcard" else {}

    monkeypatch.setattr(dns_hygiene, "_run_dnsx_a_aaaa", fake_all)
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    assert result["domains"]["example.com"]["wildcard"]["present"] is True
    assert "wildcard_a_record" in _kinds(result)


def test_axfr_is_off_by_default(tmp_path: Path, monkeypatch):
    config = DnsHygieneConfig(enabled=True)
    assert config.axfr_probe is False

    def explode(*args, **kwargs):
        raise AssertionError("AXFR must not run unless axfr_probe is enabled")

    _patch_dnsx(
        monkeypatch,
        ns={"example.com": {"ns": ["ns1.a.example", "ns2.b.example"]}},
        addresses={"ns1.a.example": {"a": ["93.184.216.34"]}, "ns2.b.example": {"a": ["8.8.8.8"]}},
    )
    monkeypatch.setattr(dns_hygiene, "_probe_axfr", explode)

    result = check_dns_hygiene(["example.com"], config, tmp_path)
    axfr = result["domains"]["example.com"]["axfr"]
    assert axfr == {"status": "disabled", "reason": "axfr_probe.disabled", "nameservers": []}
    assert result["axfr_probe"] is False


def test_axfr_refuses_a_nameserver_on_a_private_address(monkeypatch):
    _no_dialling(monkeypatch)

    probe = _probe_axfr("example.com", "ns1.example.com", ["10.0.0.5"], timeout=5)
    assert probe["status"] == "refused"
    assert probe["reason"] == "ns_address_not_public"
    assert probe["records"] == 0


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "192.168.1.1",
        # An NS record answering with an IPv6 address that NAT64, 6to4 or the
        # kernel delivers to private IPv4 space is the same TCP/53 connection
        # into the agent's network as the plain IPv4 address.
        pytest.param("64:ff9b::a00:5", id="nat64-wkp-rfc1918"),
        pytest.param("64:ff9b::7f00:1", id="nat64-wkp-loopback"),
        pytest.param("64:ff9b::a9fe:a9fe", id="nat64-wkp-metadata"),
        pytest.param("64:ff9b:1::808:808", id="nat64-local-use"),
        pytest.param("::ffff:0:a00:5", id="siit-ipv4-translated"),
        pytest.param("2002:a00:5::1", id="6to4-rfc1918"),
        pytest.param("::a00:5", id="ipv4-compatible-rfc1918"),
        pytest.param("::ffff:10.0.0.5", id="ipv4-mapped-rfc1918"),
    ],
)
def test_axfr_refuses_every_non_public_address_class(monkeypatch, address: str):
    _no_dialling(monkeypatch)
    assert _probe_axfr("example.com", "ns.example.com", [address], timeout=5)["status"] == "refused"


def test_axfr_refuses_a_nameserver_with_one_private_address_among_public_ones(monkeypatch):
    _no_dialling(monkeypatch)
    probe = _probe_axfr("example.com", "ns.example.com", ["93.184.216.34", "10.0.0.5"], timeout=5)
    assert probe["status"] == "refused"


def test_axfr_dials_only_the_gated_address(monkeypatch):
    """One TCP connection, to the address that passed the gate, and nothing else.

    ``dnsx -axfr -resolver X`` asked X for the zone's NS set, resolved those
    names through X and opened TCP/53 to every answer before trying X itself;
    none of them had passed ``is_public_address``. The zone below names such a
    nameserver with loopback glue, and the probe must not follow it.
    """

    def respond(query_id: int) -> bytes:
        return _message(
            query_id,
            [
                _soa(),
                _rr(_APEX, _TYPE_NS, _wire_name("ns.elsewhere.example")),
                _rr(_wire_name("ns.elsewhere.example"), _TYPE_A, bytes([127, 0, 0, 2])),
                _soa(),
            ],
        )

    server = _serve(monkeypatch, respond)
    probe = _probe_axfr(
        "example.com", "ns1.example.com", ["93.184.216.34", "8.8.4.4"], timeout=5
    )
    assert server.dialled == [("93.184.216.34", 53)]
    assert probe == {"nameserver": "ns1.example.com", "status": "open", "reason": None, "records": 2}
    # A plain AXFR query for the zone itself: no recursion wanted, no EDNS.
    (query,) = server.queries
    assert struct.unpack_from("!H", query)[0] == len(query) - 2
    assert query[4:] == (
        struct.pack("!HHHHH", 0, 1, 0, 0, 0)
        + _wire_name("example.com")
        + struct.pack("!HH", _TYPE_AXFR, 1)
    )


def test_axfr_dials_an_ipv6_nameserver_by_the_checked_address(monkeypatch):
    server = _serve(monkeypatch, lambda query_id: _message(query_id, [], rcode=5))
    probe = _probe_axfr(
        "example.com", "ns1.example.com", ["2001:0500:008f:0000:0000:0000:0000:0053"], timeout=5
    )
    # dnsx needed "[addr]:53" -- an unbracketed "2001:500:8f::53:53" is itself
    # a valid IPv6 literal for a different host. A socket address has no such
    # ambiguity: the dial is the parsed address that passed the gate.
    assert server.dialled == [("2001:500:8f::53", 53)]
    assert probe["status"] == "closed"


@pytest.mark.parametrize(
    ("rcode", "reason"),
    [
        (5, "rcode_refused"),
        (9, "rcode_notauth"),
        (1, "rcode_formerr"),
        (4, "rcode_notimp"),
        (3, "rcode_nxdomain"),
    ],
)
def test_axfr_refused_transfer_is_closed_not_open(
    tmp_path: Path, monkeypatch, rcode: int, reason: str
):
    """dnsx 1.2.3 printed a JSON line under ``-json`` for a refused transfer too,
    and that line was counted as one record: every reachable nameserver that
    said no came out as ``open`` with a critical ``axfr_open`` finding."""
    _serve(monkeypatch, lambda query_id: _message(query_id, [], rcode=rcode))
    _patch_dnsx(
        monkeypatch,
        ns={"example.com": {"ns": ["ns1.a.example"]}},
        addresses={"ns1.a.example": {"a": ["93.184.216.34"]}},
    )
    result = check_dns_hygiene(
        ["example.com"], DnsHygieneConfig(enabled=True, axfr_probe=True), tmp_path
    )
    probe = result["domains"]["example.com"]["axfr"]["nameservers"][0]
    assert probe == {"nameserver": "ns1.a.example", "status": "closed", "reason": reason, "records": 0}
    assert "axfr_open" not in _kinds(result)


@pytest.mark.parametrize(
    ("respond", "reason"),
    [
        # NOERROR with an empty answer section, another way of saying no.
        (lambda query_id: _message(query_id, []), "empty_answer"),
        # Accepts the connection and hangs up without a word.
        (lambda query_id: b"", "connection_closed"),
        # A "transfer" of nothing but the SOA discloses nothing a SOA query
        # would not.
        (lambda query_id: _message(query_id, [_soa(), _soa()]), "soa_only"),
    ],
)
def test_axfr_other_refusals_are_closed(monkeypatch, respond, reason: str):
    _serve(monkeypatch, respond)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe == {"nameserver": "ns1.example.com", "status": "closed", "reason": reason, "records": 0}


def test_axfr_counts_the_records_between_the_two_soas(monkeypatch):
    """RFC 5936: the zone comes framed by its SOA, possibly over many messages.

    dnsx 1.2.3 put a successful transfer under ``axfr.chain[].all``, which the
    old counter did not know, so any real zone was reported as one record.
    """
    records = [_rr(_APEX, _TYPE_NS, _wire_name(f"ns{i}.example.com")) for i in (1, 2)] + [
        _rr(_wire_name(f"host{i}.example.com"), _TYPE_A, bytes([93, 184, 216, i]))
        for i in range(1, 6)
    ]

    def respond(query_id: int) -> bytes:
        return (
            _message(query_id, [_soa(), *records[:3]])
            + _message(query_id, records[3:6])
            + _message(query_id, [records[6], _soa()])
            # Past the closing SOA the transfer is over; this is not counted.
            + _message(query_id, [_rr(_wire_name("late.example.com"), _TYPE_A, b"\x01\x02\x03\x04")])
        )

    _serve(monkeypatch, respond)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe == {"nameserver": "ns1.example.com", "status": "open", "reason": None, "records": 7}


@pytest.mark.parametrize(
    ("end", "reason"),
    [
        ("eof", "transfer_incomplete"),
        ("timeout", "transfer_incomplete"),
        ("reset", "transfer_incomplete"),
        ("unreachable", "connection_error"),
    ],
)
def test_axfr_cut_short_after_zone_data_is_still_open(monkeypatch, end: str, reason: str):
    """Records past the opening SOA were handed out however the stream ended.
    The count is then a lower bound, and ``reason`` says so."""
    _serve(monkeypatch, lambda query_id: _message(query_id, [_soa(), *_zone_records()]), end=end)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe == {
        "nameserver": "ns1.example.com",
        "status": "open",
        "reason": reason,
        "records": 3,
    }


def test_axfr_transfer_is_capped_on_this_side(monkeypatch):
    monkeypatch.setattr(dns_hygiene, "MAX_AXFR_BYTES", 400)
    many = [_rr(_wire_name(f"h{i}.example.com"), _TYPE_A, b"\x01\x02\x03\x04") for i in range(20)]

    def respond(query_id: int) -> bytes:
        return _message(query_id, [_soa(), *many[:5]]) + b"".join(
            _message(query_id, [record]) for record in many[5:]
        ) + _message(query_id, [_soa()])

    _serve(monkeypatch, respond)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe["status"] == "open"
    assert probe["reason"] == "transfer_capped"
    assert 5 <= probe["records"] < 20


@pytest.mark.parametrize(
    ("respond", "end", "reason"),
    [
        (lambda query_id: b"", "timeout", "timeout"),
        # A reset before any answer may come from a middlebox on this side of
        # the wire; unlike a clean hang-up it says nothing about the server.
        (lambda query_id: b"", "reset", "connection_reset"),
        # SERVFAIL is "could not answer", not "no": a secondary that has not
        # loaded the zone says it too. So does an RCODE nobody named here.
        (lambda query_id: _message(query_id, [], rcode=2), "eof", "rcode_servfail"),
        (lambda query_id: _message(query_id, [], rcode=6), "eof", "rcode_6"),
        # The first message cut mid-way: the server had started to answer,
        # so this is not a refusal, however the stream ended.
        (lambda query_id: _open_zone(query_id)[:120], "eof", "transfer_incomplete"),
        (lambda query_id: _open_zone(query_id)[:120], "reset", "transfer_incomplete"),
        (lambda query_id: _open_zone(query_id)[:1], "eof", "transfer_incomplete"),
        # Only the opening SOA, then silence: nothing disclosed, nothing refused.
        (lambda query_id: _message(query_id, [_soa()]), "timeout", "transfer_incomplete"),
        # Opens with something other than the zone's SOA.
        (lambda query_id: _message(query_id, _zone_records()), "eof", "malformed_response"),
        # The SOA of some other zone.
        (
            lambda query_id: _message(query_id, [_soa(_wire_name("other.example")), _soa()]),
            "eof",
            "malformed_response",
        ),
        # Not an answer to this query.
        (lambda query_id: _open_zone(query_id ^ 0xFFFF), "eof", "malformed_response"),
        # A compression pointer to itself (first answer starts at offset 29).
        (
            lambda query_id: _message(query_id, [_rr(b"\xc0\x1d", _TYPE_SOA, b"")]),
            "eof",
            "malformed_response",
        ),
        # RDLENGTH past the end of the message.
        (
            lambda query_id: _message(query_id, [_APEX + struct.pack("!HHIH", _TYPE_SOA, 1, 0, 500)]),
            "eof",
            "malformed_response",
        ),
    ],
)
def test_axfr_unusable_answers_are_errors(monkeypatch, respond, end: str, reason: str):
    """``error`` means the nameserver could not be checked -- never "closed"."""
    _serve(monkeypatch, respond, end=end)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert (probe["status"], probe["reason"], probe["records"]) == ("error", reason, 0)


def test_axfr_a_trickling_peer_cannot_outlive_the_deadline(monkeypatch):
    """The budget is wall-clock over the whole transfer, not per read: a
    server that keeps sending is cut off at the deadline, not at EOF."""
    # Every read of the clock costs 10 ms: the 5 s budget lasts ~500 reads.
    ticks = itertools.count(0.0, 0.01)
    monkeypatch.setattr(
        dns_hygiene, "time", types.SimpleNamespace(perf_counter=lambda: next(ticks))
    )
    record = _rr(_wire_name("h.example.com"), _TYPE_A, b"\x01\x02\x03\x04")
    endless = 20_000

    _serve(
        monkeypatch,
        lambda query_id: _message(query_id, [_soa()]) + _message(query_id, [record]) * endless,
    )
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe["status"] == "open"
    assert probe["reason"] == "transfer_incomplete"
    assert 0 < probe["records"] < endless


def test_axfr_every_socket_wait_is_bounded_by_what_is_left_of_the_budget(monkeypatch):
    """Connect and every read get the remaining budget as their own timeout.

    Checking the clock between reads is not enough: without a socket timeout
    a connect to a dead address waits out the OS SYN timeout (minutes), and a
    peer that stalls mid-read holds the probe for as long as it likes.
    """
    ticks = itertools.count(100.0, 0.01)
    monkeypatch.setattr(
        dns_hygiene, "time", types.SimpleNamespace(perf_counter=lambda: next(ticks))
    )
    server = _serve(monkeypatch, _open_zone)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe["status"] == "open"

    (connect_timeout,) = server.connect_timeouts
    assert connect_timeout is not None and 0 < connect_timeout <= 5
    reads = server.read_timeouts
    assert reads and all(value is not None and 0 < value <= 5 for value in reads)
    # Each read gets less than the one before: it is the budget left, not a
    # fresh per-read allowance.
    assert all(later < earlier for earlier, later in zip(reads, reads[1:]))


def test_axfr_unreachable_nameserver_is_an_error_not_closed(monkeypatch):
    def refuse(address, timeout=None, source_address=None):
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setattr(socket, "create_connection", refuse)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe == {
        "nameserver": "ns1.example.com",
        "status": "error",
        "reason": "connect_failed",
        "records": 0,
    }


def test_axfr_never_raises_on_a_truncated_message(monkeypatch):
    """The answer is written by the scanned party, and an exception here would
    take the whole stage down. Every prefix of a real transfer must parse to a
    status, never to a traceback."""
    full = _open_zone(0)[2:]
    for cut in range(len(full)):
        body = full[:cut]

        def respond(query_id: int, body: bytes = body) -> bytes:
            patched = struct.pack("!H", query_id) + body[2:] if len(body) >= 2 else body
            return struct.pack("!H", len(patched)) + patched

        _serve(monkeypatch, respond)
        probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
        assert probe["status"] in {"closed", "error"}, (cut, probe)


def test_axfr_never_writes_the_zone_to_the_log_or_the_artifact(
    tmp_path: Path, monkeypatch, caplog
):
    _serve(monkeypatch, _open_zone)
    _patch_dnsx(
        monkeypatch,
        ns={"example.com": {"ns": ["ns1.a.example"]}},
        addresses={"ns1.a.example": {"a": ["93.184.216.34"]}},
    )

    with caplog.at_level(logging.DEBUG):
        result = check_dns_hygiene(
            ["example.com"],
            DnsHygieneConfig(enabled=True, axfr_probe=True),
            tmp_path,
        )

    logged = "\n".join(record.getMessage() for record in caplog.records)
    artifact = (tmp_path / "dns_hygiene.json").read_text(encoding="utf-8")
    for secret in ZONE_SECRETS:
        assert secret not in logged
        assert secret not in artifact
    # The fact and the count survive; the zone does not.
    assert "zone transfer succeeded for example.com" in logged
    probe = result["domains"]["example.com"]["axfr"]["nameservers"][0]
    assert probe == {"nameserver": "ns1.a.example", "status": "open", "reason": None, "records": 3}
    assert "axfr_open" in _kinds(result)


def test_domain_with_no_dns_answer_is_not_checked(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    record = result["domains"]["example.com"]
    assert record["status"] == "not_checked"
    assert record["reason"] == "no_dns_answer"


def test_truncated_ns_list_does_not_accuse_the_soa_mname():
    """`soa_mname_not_in_ns` on a truncated NS set is a finding about our cap.

    The zone may well list the MNAME past MAX_NS_PER_DOMAIN in the set we kept,
    so with an incomplete list its absence says nothing.
    """
    soa = {"mname": "ns99.example.com", "timers": {}}
    kept = [f"ns{i}.example.com" for i in range(1, 11)]

    complete = dns_hygiene._classify_soa("example.com", soa, kept)
    assert [f["kind"] for f in complete] == ["soa_mname_not_in_ns"]

    truncated = dns_hygiene._classify_soa(
        "example.com", soa, kept, nameservers_complete=False
    )
    assert truncated == []
