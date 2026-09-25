"""The dnsx JSONL wrapper shared by the org_profile DNS stages (M2, #182).

The stages mock this module out, so it is the one layer of M2 that no other
test exercises -- and it is the layer every real run depends on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.pipeline import dnsx
from scanner.pipeline.dnsx import DnsxError, query

RESOLVERS = ["192.0.2.53:53"]


def _fake_run(output: str, *, calls: list[list[str]] | None = None):
    def run_command(command, timeout, retries):
        if calls is not None:
            calls.append(command)
        Path(command[command.index("-o") + 1]).write_text(output, encoding="utf-8")
        return None

    return run_command


def _query(tmp_path: Path, names: list[str], *, kind: str = "ns", resolvers=RESOLVERS):
    return query(
        names,
        tmp_path,
        stage="s",
        kind=kind,
        flags=[f"-{kind}"],
        timeout=5,
        retries=0,
        resolvers=resolvers,
    )


def test_empty_name_list_runs_nothing(tmp_path: Path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("dnsx must not run for an empty target list")

    monkeypatch.setattr(dnsx, "run_command", explode)
    assert _query(tmp_path, []) == {}


def test_records_are_keyed_by_normalised_host(tmp_path: Path, monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(
        dnsx,
        "run_command",
        _fake_run('{"host": "Example.COM.", "ns": ["ns1.example.com"]}\n\n', calls=calls),
    )

    records = query(
        ["example.com"],
        tmp_path,
        stage="dns_hygiene",
        kind="ns",
        flags=["-ns"],
        timeout=7,
        retries=1,
        resolvers=RESOLVERS,
    )

    assert records == {"example.com": {"host": "Example.COM.", "ns": ["ns1.example.com"]}}
    assert calls[0][:2] == ["dnsx", "-l"]
    assert "-ns" in calls[0] and "-json" in calls[0] and "-silent" in calls[0]
    # Each record type gets its own target/output pair under the stage directory.
    assert (tmp_path / "dns_hygiene" / "ns_targets.txt").read_text(encoding="utf-8") == "example.com\n"


def test_unparseable_line_does_not_lose_the_batch(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.setattr(
        dnsx, "run_command", _fake_run('not json\n{"host": "a.example", "ns": []}\n["list"]\n')
    )
    records = _query(tmp_path, ["a.example"])
    assert set(records) == {"a.example"}
    assert "unparseable" in caplog.text


def test_missing_output_file_is_not_an_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(dnsx, "run_command", lambda command, timeout, retries: None)
    assert _query(tmp_path, ["a.example"], kind="txt") == {}


def test_tool_failure_becomes_dnsx_error(tmp_path: Path, monkeypatch):
    def boom(command, timeout, retries):
        raise FileNotFoundError("dnsx")

    monkeypatch.setattr(dnsx, "run_command", boom)
    # Not a bare FileNotFoundError: _run_stage would turn that into
    # StageFailureError and end the run from inside a fail-soft control.
    with pytest.raises(DnsxError, match="txt lookup failed"):
        _query(tmp_path, ["a.example"], kind="txt")


# --- which resolvers dnsx is told to ask ------------------------------------
#
# dnsx 1.2.3 without -r does not read /etc/resolv.conf: it asks eight public
# resolvers (dnsx.DefaultResolvers in upstream libs/dnsx/dnsx.go). Every test
# below is about -r being there, and being the right list.


def _resolv_conf(tmp_path: Path, monkeypatch, text: str) -> Path:
    path = tmp_path / "resolv.conf"
    path.write_text(text, encoding="utf-8")
    monkeypatch.setattr(dnsx, "RESOLV_CONF", path)
    return path


def test_command_pins_the_whole_argv(tmp_path: Path):
    argv = dnsx.command(
        tmp_path / "t.txt",
        ["-a", "-aaaa"],
        tmp_path / "o.jsonl",
        resolvers=["10.0.0.53", "[fd00::53]:5353"],
    )
    assert argv == [
        "dnsx",
        "-l",
        str(tmp_path / "t.txt"),
        "-r",
        "10.0.0.53:53,[fd00::53]:5353",
        "-a",
        "-aaaa",
        "-json",
        "-silent",
        "-o",
        str(tmp_path / "o.jsonl"),
    ]


def test_query_passes_the_configured_resolvers(tmp_path: Path, monkeypatch):
    # A system resolver that must not be used when the config names one.
    _resolv_conf(tmp_path, monkeypatch, "nameserver 10.96.0.10\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(dnsx, "run_command", _fake_run("", calls=calls))

    _query(tmp_path, ["a.example"], resolvers=["192.0.2.53", "192.0.2.54:5353"])

    argv = calls[0]
    assert argv[argv.index("-r") + 1] == "192.0.2.53:53,192.0.2.54:5353"
    assert argv.count("-r") == 1


def test_empty_config_means_the_first_system_nameserver(tmp_path: Path, monkeypatch, caplog):
    """What libc asks, not every nameserver line.

    libc falls back to the second nameserver only when the first does not
    answer; dnsx rotates over its whole -r list. Passing the backup 8.8.8.8
    on would send about half the target names to it.
    """
    _resolv_conf(
        tmp_path,
        monkeypatch,
        "# generated by NetworkManager\n"
        "search corp.example\n"
        "; nameserver 192.0.2.1\n"
        "nameserver 10.8.0.1\n"
        "nameserver 8.8.8.8\n"
        "options ndots:1\n",
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(dnsx, "run_command", _fake_run("", calls=calls))

    with caplog.at_level("INFO", logger="shapoclyack.dnsx"):
        _query(tmp_path, ["a.example"], resolvers=[])

    argv = calls[0]
    assert argv[argv.index("-r") + 1] == "10.8.0.1:53"
    # Said out loud, so an operator who counted on the backup finds out why.
    assert "8.8.8.8:53" in caplog.text


def test_an_ipv6_first_nameserver_is_bracketed(tmp_path: Path, monkeypatch):
    _resolv_conf(tmp_path, monkeypatch, "nameserver fd00:10:96::a\nnameserver 10.96.0.10\n")
    assert dnsx.system_resolvers() == ["[fd00:10:96::a]:53"]


@pytest.mark.parametrize(
    "options",
    [
        pytest.param("options ndots:2 rotate\n", id="one-options-line"),
        # glibc accumulates options lines; a later one does not undo rotate.
        pytest.param("options rotate\noptions ndots:5\n", id="rotate-then-another-line"),
    ],
)
def test_options_rotate_passes_up_to_three_like_libc(tmp_path: Path, monkeypatch, options):
    _resolv_conf(
        tmp_path,
        monkeypatch,
        "nameserver 10.0.0.1\n"
        "nameserver fd00::53\n"
        "nameserver 10.0.0.2\n"
        "nameserver 10.0.0.3\n" + options,
    )
    # libc rotates here too, over at most MAXNS (3) servers.
    assert dnsx.system_resolvers() == ["10.0.0.1:53", "[fd00::53]:53", "10.0.0.2:53"]


def test_rotate_caps_the_lines_before_dropping_repeats(tmp_path: Path, monkeypatch):
    """glibc keeps the first three lines, repeats included (checked on glibc
    2.41): the 8.8.8.8 on line four is never asked, so it must not be here."""
    _resolv_conf(
        tmp_path,
        monkeypatch,
        "options rotate\n"
        "nameserver 10.0.0.1\n"
        "nameserver 10.0.0.1\n"
        "nameserver 10.0.0.2\n"
        "nameserver 8.8.8.8\n",
    )
    assert dnsx.system_resolvers() == ["10.0.0.1:53", "10.0.0.2:53"]


def test_a_nameserver_with_a_port_is_skipped_like_libc(tmp_path: Path, monkeypatch):
    # resolv.conf has no port syntax; glibc skips the line and uses the next.
    _resolv_conf(tmp_path, monkeypatch, "nameserver 10.0.0.5:5353\nnameserver 10.0.0.6\n")
    assert dnsx.system_resolvers() == ["10.0.0.6:53"]


def test_the_backup_notice_is_logged_once_not_per_batch(tmp_path: Path, monkeypatch, caplog):
    _resolv_conf(tmp_path, monkeypatch, "nameserver 10.0.0.1\nnameserver 10.0.0.2\n")
    with caplog.at_level("INFO", logger="shapoclyack.dnsx"):
        for _ in range(3):
            assert dnsx.system_resolvers() == ["10.0.0.1:53"]
    assert caplog.text.count("backup nameserver") == 1


def test_resolv_conf_is_read_at_each_run(tmp_path: Path, monkeypatch):
    path = _resolv_conf(tmp_path, monkeypatch, "nameserver 10.0.0.1\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(dnsx, "run_command", _fake_run("", calls=calls))

    _query(tmp_path, ["a.example"], resolvers=[])
    path.write_text("nameserver 10.0.0.2\n", encoding="utf-8")
    _query(tmp_path, ["a.example"], resolvers=[])

    assert [argv[argv.index("-r") + 1] for argv in calls] == ["10.0.0.1:53", "10.0.0.2:53"]


def test_an_unparseable_nameserver_line_is_skipped(tmp_path: Path, monkeypatch, caplog):
    _resolv_conf(tmp_path, monkeypatch, "nameserver dns.corp.example\nnameserver 10.0.0.1\n")
    assert dnsx.system_resolvers() == ["10.0.0.1:53"]
    assert "dns.corp.example" in caplog.text


@pytest.mark.parametrize(
    "resolv_conf",
    [
        pytest.param("search corp.example\noptions ndots:1\n", id="no-nameserver-line"),
        pytest.param("nameserver dns.corp.example\n", id="only-an-unparseable-one"),
        pytest.param(None, id="no-file"),
    ],
)
def test_no_nameserver_means_the_local_one_never_no_dash_r(
    tmp_path: Path, monkeypatch, resolv_conf
):
    """resolv.conf(5): with no nameserver the local machine's is used. Leaving
    -r off instead would hand the names to dnsx's public list."""
    if resolv_conf is None:
        monkeypatch.setattr(dnsx, "RESOLV_CONF", tmp_path / "missing")
    else:
        _resolv_conf(tmp_path, monkeypatch, resolv_conf)
    calls: list[list[str]] = []
    monkeypatch.setattr(dnsx, "run_command", _fake_run("", calls=calls))

    _query(tmp_path, ["a.example"], resolvers=[])

    argv = calls[0]
    assert argv[argv.index("-r") + 1] == "127.0.0.1:53"
