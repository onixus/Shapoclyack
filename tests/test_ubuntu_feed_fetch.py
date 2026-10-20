"""Complete compressed USN refresh keeps bounded IO and last-good publication."""
import bz2
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

from api.services.advisories import fetch, ubuntu

FIXTURE = Path(__file__).parent / "fixtures/advisories/ubuntu-usn-sample.json"


def opener_for(body, seen=None):
    def opener(request, timeout):
        if seen is not None:
            seen.append((request.full_url, timeout))
        return io.BytesIO(body)
    return opener


@pytest.mark.parametrize("compressed", [False, True])
def test_complete_ubuntu_mirror_normalizes_identically(monkeypatch, tmp_path, compressed):
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    raw = FIXTURE.read_bytes()
    mirror = tmp_path / ("mirror.bz2" if compressed else "mirror.json")
    mirror.write_bytes(bz2.compress(raw) if compressed else raw)
    monkeypatch.setenv("UBUNTU_USN_URL", mirror.as_uri())
    target = tmp_path / "advisories.json"
    count = fetch.refresh("ubuntu", path=target)
    result = json.loads(target.read_bytes())
    expected = list(ubuntu.normalize_usn_json(json.loads(raw)))
    assert result["entries"] == expected
    assert count == len(expected)
    assert result["origin_url"] == mirror.as_uri()


def test_official_source_uses_compressed_complete_database():
    assert fetch.UBUNTU_USN_URL.endswith("/database.json.bz2")
    assert fetch.DEFAULT_MAX_BYTES == 128 * 1024 * 1024


@pytest.mark.parametrize("body", [b"{}", bz2.compress(b"{}")])
def test_transfer_limit_is_independent_of_decoded_limit(body):
    with pytest.raises(fetch.FetchTooLargeError, match="byte ceiling"):
        fetch.fetch_json("https://example/feed", opener=opener_for(body),
                         max_bytes=len(body)-1, max_decoded_bytes=999, allow_bzip2=True)


def test_compression_bomb_stops_before_accumulating_expanded_payload():
    body = bz2.compress(b" " * 2_000_000)
    with pytest.raises(fetch.FetchTooLargeError, match="decoded byte ceiling"):
        fetch.fetch_json("https://example/feed", opener=opener_for(body),
                         max_bytes=10000, max_decoded_bytes=1024, allow_bzip2=True)


@pytest.mark.parametrize("body", [bz2.compress(b"{}")[:-1], bz2.compress(b"{}") + b"garbage",
                                   bz2.compress(b"{}") + bz2.compress(b"{}")])
def test_truncated_or_trailing_bzip2_is_not_a_complete_feed(body):
    with pytest.raises(RuntimeError):
        fetch.fetch_json("https://example/feed", opener=opener_for(body), allow_bzip2=True)


def test_socket_timeout_and_total_deadline(monkeypatch):
    seen = []
    ticks = iter([0, 0, 2])
    monkeypatch.setattr(fetch.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="deadline"):
        fetch.fetch_json("https://example/feed", timeout=7, deadline_seconds=1,
                         opener=opener_for(b"{}", seen))
    assert seen == [("https://example/feed", 1)]


@pytest.mark.parametrize("bad", [bz2.compress(b"{}")[0:-1], bz2.compress(b"not json"), bz2.compress(b"\xff\xff"),
                                  bz2.compress(b"{}")[0:15]])
def test_failed_cli_keeps_dataset_and_manifest(monkeypatch, tmp_path, bad):
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    mirror = tmp_path / "feed.bz2"
    mirror.write_bytes(bad)
    monkeypatch.setenv("UBUNTU_USN_URL", mirror.as_uri())
    target = tmp_path / "ubuntu.json"
    manifest = tmp_path / "manifest.json"
    target.write_bytes(b"last good corpus")
    manifest.write_bytes(b"last good manifest")
    spec = importlib.util.spec_from_file_location("ubuntu_cli", Path(__file__).parents[1] / "scripts/fetch-advisories.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    monkeypatch.setattr(sys, "argv", ["fetch-advisories.py", "ubuntu", "-o", str(target)])
    assert cli.main() == cli.EXIT_FAILED
    assert target.read_bytes() == b"last good corpus"
    assert manifest.read_bytes() == b"last good manifest"
    assert not target.with_suffix(".json.fetch").exists()


def test_explicit_cli_transfer_cap_applies_to_msrc(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("ubuntu_cli", Path(__file__).parents[1] / "scripts/fetch-advisories.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    seen = []
    def refresh(**kwargs):
        seen.append(kwargs["max_bytes"])
        raise fetch.FetchTooLargeError("limit")
    monkeypatch.setattr(fetch, "refresh_msrc", refresh)
    monkeypatch.setattr(sys, "argv", ["fetch-advisories.py", "msrc", "-o", str(tmp_path / "out"), "--max-bytes", "7"])
    assert cli.main() == cli.EXIT_FAILED
    assert seen == [7]


def test_fragmented_bzip_magic_and_socket_deadline(monkeypatch):
    encoded = bz2.compress(b'{"complete":true}')
    class Socket:
        timeouts = []
        def settimeout(self, value):
            self.timeouts.append(value)
    sock = Socket()
    class Response(io.BytesIO):
        fp = type("FP", (), {"raw": type("Raw", (), {"_sock": sock})()})()
        def read(self, size=-1):
            raise AssertionError("HTTP must use read1 for trickling responses")
        def read1(self, size=-1):
            return super().read(min(size, 1))
    monkeypatch.setattr(fetch.time, "monotonic", lambda: 10)
    assert fetch.fetch_json("https://example/feed", opener=lambda *a, **k: Response(encoded),
                            allow_bzip2=True, timeout=60, deadline_seconds=1) == {"complete": True}
    assert sock.timeouts and all(value == 1 for value in sock.timeouts)


def test_ubuntu_specific_limits_do_not_change_debian(monkeypatch, tmp_path):
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    monkeypatch.delenv("UBUNTU_USN_URL", raising=False)
    seen = []
    def read(url, **kwargs):
        seen.append(kwargs)
        return {}
    monkeypatch.setattr(fetch, "fetch_json", read)
    fetch.refresh("debian", path=tmp_path / "debian.json")
    fetch.refresh("ubuntu", path=tmp_path / "ubuntu.json")
    assert seen[0]["max_bytes"] == seen[0]["max_decoded_bytes"] == fetch.DEFAULT_MAX_BYTES
    assert seen[0]["allow_bzip2"] is False
    assert seen[1]["max_bytes"] == fetch.DEFAULT_MAX_BYTES
    assert seen[1]["max_decoded_bytes"] == fetch.UBUNTU_MAX_DECODED_BYTES
