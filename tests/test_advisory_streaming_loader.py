"""The streaming, bucket-packed advisory loader must say what ``json.loads`` + one
object per entry said: same records, same lookups, same digest, same errors."""

from __future__ import annotations

import hashlib
import json
import random

import pytest

from api.services.advisories import base


def reference_digest(records) -> str:
    return hashlib.sha256(
        "\n".join(
            sorted(
                f"{r.release}|{r.source_package}|{','.join(r.cve_ids)}|{r.state}|"
                f"{r.fixed_version or ''}|{r.advisory_id}"
                for r in records
            )
        ).encode("utf-8")
    ).hexdigest()[:16]


def reference_records(payload, provider="p"):
    updated = str(payload.get("updated") or "") or None
    out = []
    for raw in payload.get("entries") or ():
        record = base._coerce_record(raw, provider=provider, feed_date=updated)
        if record is not None:
            out.append(record)
    return out


def random_entries(rng, n, packages=("openssl", "curl", "a", "lib-x")):
    entries = []
    for i in range(n):
        entry = {
            "advisory_id": rng.choice([f"USN-{i}-1", "", None]),
            "cve_ids": rng.choice(
                [["CVE-2024-%d" % i], ["cve-2024-1", "CVE-2024-1", " "], "CVE-2024-9", [], 5]
            ),
            "release": rng.choice(["Focal", " jammy ", "bullseye", "", None]),
            "source_package": rng.choice(list(packages) + ["", None]),
            "fixed_version": rng.choice(["1.0-1", "", None, "2:1.1~rc1-3"]),
            "severity": rng.choice(["High", "", None, "low"]),
            "state": rng.choice(["resolved", "open", "not_affected", "bogus", None]),
            "url": rng.choice([None, "", "https://x/y é"]),
        }
        if rng.random() < 0.05:
            entries.append(rng.choice([None, 3, 1234567890123, -0.5e10, True, "str", []]))
        else:
            entries.append(entry)
    return entries


@pytest.fixture(params=[64, 1 << 20])
def chunk(request, monkeypatch):
    monkeypatch.setattr(base, "_CHUNK_CHARS", request.param)
    return request.param


@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize("meta_first", [True, False])
@pytest.mark.parametrize("pipes", [False, True])
def test_loader_matches_the_reference(tmp_path, chunk, seed, meta_first, pipes):
    rng = random.Random(seed)
    entries = random_entries(
        rng, 300, ("openssl", "a", "a|b", "a|0") if pipes else ("openssl", "curl", "a")
    )
    meta = {"source": "s", "updated": "2026-10-01", "origin_url": "u", "version": 1}
    payload = {**meta, "entries": entries} if meta_first else {"entries": entries, **meta}
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(payload, indent=rng.choice([None, 2])), encoding="utf-8")

    data = base._load_dataset(path, provider="p")
    expected = reference_records(payload)

    assert data.error is None and data.present
    assert len(data.records) == len(expected) and bool(data.records) == bool(expected)
    assert sorted(map(repr, data.records)) == sorted(map(repr, expected))
    assert data.digest == reference_digest(expected)
    assert data.releases == tuple(sorted({r.release for r in expected}))
    assert (data.source, data.updated, data.origin_url) == ("s", "2026-10-01", "u")
    groups: dict = {}
    for record in expected:
        groups.setdefault((record.release, record.source_package), []).append(record)
    assert len(data.index) == len(groups)
    for key, group in groups.items():
        assert data.lookup(*key) == tuple(group)
    assert data.lookup("nope", "nope") == ()


def test_digest_survives_a_pipe_in_a_package_name(tmp_path):
    # "a|b" makes the bucket prefix "x|a|b|" extend "x|a|": the sort must fall
    # back to sorting whole lines.
    payload = {
        "entries": [
            {"cve_ids": ["CVE-1-1"], "release": "x", "source_package": "a", "fixed_version": "1"},
            {"cve_ids": ["CVE-1-2"], "release": "x", "source_package": "a|b", "fixed_version": "1"},
            {"cve_ids": ["CVE-1-3"], "release": "x", "source_package": "a", "fixed_version": "2"},
            {"cve_ids": ["CVE-1-4"], "release": "x", "source_package": "a|0", "fixed_version": "1"},
        ]
    }
    path = tmp_path / "f.json"
    path.write_text(json.dumps(payload))
    assert base._load_dataset(path, provider="p").digest == reference_digest(
        reference_records(payload)
    )


def test_digest_ignores_order_and_refetch_date(tmp_path):
    entries = random_entries(random.Random(3), 100)
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"updated": "1", "entries": entries}))
    b.write_text(json.dumps({"updated": "2", "entries": entries[::-1]}))
    assert (
        base._load_dataset(a, provider="p").digest
        == base._load_dataset(b, provider="p").digest
    )


def test_a_changed_statement_moves_the_digest(tmp_path):
    entry = {"cve_ids": ["CVE-1-1"], "release": "x", "source_package": "p", "fixed_version": "1"}
    digests = set()
    for fixed in ("1", "2"):
        path = tmp_path / f"{fixed}.json"
        path.write_text(json.dumps({"entries": [{**entry, "fixed_version": fixed}]}))
        digests.add(base._load_dataset(path, provider="p").digest)
    assert len(digests) == 2


@pytest.mark.parametrize(
    "text, error",
    [
        ("", "invalid JSON"),
        ("   ", "invalid JSON"),
        ("{", "invalid JSON"),
        ('{"entries": [', "invalid JSON"),
        ('{"entries": [{}', "invalid JSON"),
        ('{"entries": [{},]}', "invalid JSON"),
        ('{"entries": []} x', "invalid JSON"),
        ('{"a" 1}', "invalid JSON"),
        ("{'a': 1}", "invalid JSON"),
        ('﻿{"entries": []}', "invalid JSON"),
        ("[]", "not an object"),
        ("12", "not an object"),
        ('"x"', "not an object"),
        ('{"entries": {"a": 1}}', "entries is not a list"),
        ('{"entries": "abc"}', "entries is not a list"),
        ('{"entries": 7}', "entries is not a list"),
        ('{"entries": [], "entries": 7}', "entries is not a list"),
    ],
)
def test_malformed_documents_are_unavailable(tmp_path, chunk, text, error):
    path = tmp_path / "f.json"
    path.write_text(text, encoding="utf-8")
    data = base._load_dataset(path, provider="p")
    assert data.present and not data.records and data.error.startswith(error)
    assert with_json_loads_agrees(text, error)


def with_json_loads_agrees(text, error):
    try:
        payload = json.loads(text)
    except ValueError:
        return error == "invalid JSON"
    if not isinstance(payload, dict):
        return error == "not an object"
    entries = payload.get("entries") or ()
    return (error == "entries is not a list") == (not isinstance(entries, (list, tuple)))


@pytest.mark.parametrize("empty", ["null", "[]", "{}", '""', "0", "false"])
def test_falsy_entries_are_an_empty_dataset_not_an_error(tmp_path, empty):
    path = tmp_path / "f.json"
    path.write_text('{"entries": %s, "updated": "d"}' % empty)
    data = base._load_dataset(path, provider="p")
    assert data.present and data.error is None and not data.records
    assert data.updated == "d"


def test_a_repeated_entries_key_replaces_the_earlier_list(tmp_path):
    one = {"cve_ids": ["CVE-1-1"], "release": "x", "source_package": "p", "fixed_version": "1"}
    path = tmp_path / "f.json"
    path.write_text('{"entries": [%s], "entries": []}' % json.dumps(one))
    data = base._load_dataset(path, provider="p")
    assert not data.records and not data.index and data.releases == ()
    assert data.digest == reference_digest([])


def test_invalid_utf8_and_lone_surrogates_are_unavailable(tmp_path):
    path = tmp_path / "f.json"
    path.write_bytes(b'{"entries": [\xff]}')
    assert base.load_dataset(path, provider="p").error == "invalid advisory document"
    path.write_text(
        '{"entries": [{"cve_ids": ["CVE-1-1"], "release": "x", '
        '"source_package": "p", "fixed_version": "\\ud800"}]}'
    )
    assert base.load_dataset(path, provider="p").error == "invalid advisory document"


def test_decoded_records_are_the_same_objects_while_cached(tmp_path):
    path = tmp_path / "f.json"
    path.write_text(json.dumps({"entries": random_entries(random.Random(1), 50)}))
    data = base._load_dataset(path, provider="p")
    key = next(iter(data.index))
    assert data.lookup(*key) is data.lookup(*key)


def loads_error(text):
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return exc
    return None


def streamed_error(path, provider="p"):
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            for _ in base._stream_document(stream):
                pass
    except json.JSONDecodeError as exc:
        return exc
    return None


def _broken_documents():
    body = json.dumps(
        {"entries": [{"cve_ids": ["CVE-1-1"], "release": "x", "source_package": "p"}] * 3,
         "updated": "d"},
        indent=2,
    )
    docs = [body[:cut] for cut in range(len(body))]  # every truncation
    docs += [
        body + " x", body + "\n\n  }", body.replace(",", ";", 4),
        '{\n  "a": 1,\n  "b" 2\n}', '{\n"entries": [\n{},\n]\n}', '{\n"a":\n\n}',
        '﻿{}', "", "  \n ", '{"entries": [1 2]}', '{"entries": [1}', '{"a": 1 "b": 2}',
        '{"a": 1,}', "\n\n[1,\n2,\n", '{"s": "unterminated\n',
    ]
    return docs


@pytest.mark.parametrize("size", [7, 1 << 20])
def test_error_positions_match_json_loads(tmp_path, monkeypatch, size):
    monkeypatch.setattr(base, "_CHUNK_CHARS", size)
    path = tmp_path / "f.json"
    checked = 0
    for text in _broken_documents():
        expected = loads_error(text)
        path.write_text(text, encoding="utf-8", newline="")
        got = streamed_error(path)
        if expected is None:
            assert got is None or text.lstrip()[:1] != "{", text
            continue
        assert got is not None, text
        assert (got.msg, got.pos, got.lineno, got.colno) == (
            expected.msg, expected.pos, expected.lineno, expected.colno,
        ), text
        assert str(got) == str(expected)
        checked += 1
    assert checked > 200


def test_the_dataset_error_carries_the_file_position(tmp_path, monkeypatch):
    monkeypatch.setattr(base, "_CHUNK_CHARS", 7)
    path = tmp_path / "f.json"
    text = '{\n  "entries": [\n    {},\n    {"a": }\n  ]\n}'
    path.write_text(text)
    data = base._load_dataset(path, provider="p")
    assert data.error == f"invalid JSON: {loads_error(text)}"


def _big_dataset(tmp_path, n=40):
    path = tmp_path / "big.json"
    path.write_text(json.dumps({"entries": random_entries(random.Random(9), n)}))
    return base._load_dataset(path, provider="p")


def test_indexing_records_does_not_decode_everything(tmp_path):
    data = _big_dataset(tmp_path, 400)
    everything = list(data.records)
    assert len(everything) > 50
    decoded = []
    real = data.records._store._decode
    data.records._store.bucket = lambda key: decoded.append(key) or real(key)
    assert data.records[0] == everything[0]
    assert len(decoded) == 1 < len(data.index)
    assert data.records[-1] == everything[-1]
    assert data.records[3:9] == tuple(everything[3:9])
    assert data.records[::7] == tuple(everything[::7])
    assert data.records[10**6:] == ()
    with pytest.raises(IndexError):
        data.records[len(everything)]
    with pytest.raises(IndexError):
        data.records[-len(everything) - 1]
    with pytest.raises(NotImplementedError):
        data.records[::-1]
    with pytest.raises(TypeError):
        data.records["x"]


def test_a_replaced_dataset_is_freed_without_a_gc_pass(tmp_path):
    import gc
    import weakref

    from api.services.advisories.ubuntu import UbuntuAdvisoryProvider

    path = tmp_path / "f.json"
    path.write_text(json.dumps({"entries": random_entries(random.Random(2), 60)}))
    provider = UbuntuAdvisoryProvider(path)
    dataset = provider.dataset()
    key = next(iter(dataset.index))
    dataset.lookup(*key)  # populate the bucket cache
    store = weakref.ref(dataset.index._store)
    del dataset
    gc.disable()
    try:
        provider.reload()
        assert store() is None
    finally:
        gc.enable()
