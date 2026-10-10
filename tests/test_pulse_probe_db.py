"""The probe database Pulse runs with: base, validation, wiring (#546, ADR 0002)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path

import pytest

from scanner.pipeline import pulse_probe as pp
from scanner.pipeline import pulse_probe_db as pdb

FIXTURES = Path(__file__).parent / "fixtures" / "pulse_probe_db"
UPSTREAM = FIXTURES / "probes.v1.3.0.json"
#: sha256 of GenDec v1.3.0 ``src/scanner/probes.json`` (also in probes.json.LICENSE).
UPSTREAM_SHA256 = "ee2c2c71e9c0c04ecbabdc3abb195f35acfe35477b56834bb451304c4ffa1a1a"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The base is GenDec's, and ours only adds to it
# --------------------------------------------------------------------------


def test_pinned_upstream_copy_is_the_v130_file():
    assert hashlib.sha256(UPSTREAM.read_bytes()).hexdigest() == UPSTREAM_SHA256
    assert UPSTREAM_SHA256 in (pp.PROBE_DB.parent / "probes.json.LICENSE").read_text(encoding="utf-8")


def test_our_database_only_adds_to_upstream():
    upstream, ours = _load(UPSTREAM)["probes"], _load(pp.PROBE_DB)["probes"]
    assert [p["name"] for p in ours[: len(upstream)]] == [p["name"] for p in upstream], (
        "upstream probes must stay first and in order; new probes go after them"
    )
    for old, new in zip(upstream, ours, strict=False):
        for key in ("ports", "rarity", "payload", "payload_hex"):
            assert new.get(key) == old.get(key), f"{old['name']}: {key} differs from upstream"
        assert new["matches"][: len(old["matches"])] == old["matches"], (
            f"{old['name']}: upstream matches must be an unchanged prefix; add ours after them"
        )
    assert len({p["name"] for p in ours}) == len(ours), "probe names must be unique"
    for probe in ours[len(upstream) :]:
        assert "\\x" not in probe.get("payload", ""), (
            f"{probe['name']}: Pulse 1.3.0 sends a '\\xNN' in 'payload' literally; use payload_hex"
        )


def test_our_database_is_valid_and_every_pattern_compiles():
    info = pdb.load_probe_db(pp.PROBE_DB)
    upstream = _load(UPSTREAM)["probes"]
    assert info.probes >= len(upstream)
    assert info.matches >= sum(len(p["matches"]) for p in upstream)
    assert info.sha256 == hashlib.sha256(pp.PROBE_DB.read_bytes()).hexdigest()
    for probe in _load(pp.PROBE_DB)["probes"]:
        for rule in probe["matches"]:
            re.compile(rule["pattern"])


# --------------------------------------------------------------------------
# Validation: what Pulse would silently drop, we refuse to hand over
# --------------------------------------------------------------------------


def _db(*patterns: str, **probe_extra) -> str:
    probe = {"name": "t", "ports": [1], "rarity": 1, "payload": "", "matches": [{"pattern": p} for p in patterns]}
    probe.update(probe_extra)
    return json.dumps({"version": "x", "probes": [probe]})


@pytest.mark.parametrize(
    "text, why",
    [
        ("{not json", "not valid JSON"),
        ("[]", "top level"),
        (json.dumps({"version": "x", "probes": [{"ports": [1]}]}), "name"),
        (_db("(?=x)y"), "unsupported group"),
        (_db("(?<!a)b"), "unsupported group"),
        (_db("(a)\\1"), "back-reference"),
        (_db("(unclosed"), "bad pattern"),
        (_db("x", ports=[70000]), "ports"),
        (_db("x", payload_hex="abc"), "payload_hex"),
        (_db("x", rarity="high"), "rarity"),
    ],
)
def test_validation_rejects_what_pulse_would_drop(text: str, why: str):
    with pytest.raises(pdb.ProbeDbError, match=why):
        pdb.validate_probe_db_text(text)


def test_validation_accepts_what_pulse_accepts():
    # An escaped backslash before a digit and a class holding '(?=' are not look-around.
    version, probes, matches = pdb.validate_probe_db_text(_db(r"\\1", r"[(?=]x", r"^[NS]$", payload_hex="00ff"))
    assert (version, probes, matches) == ("x", 1, 3)


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------


def _flag(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def _command(**overrides):
    args = dict(
        bin_path="pulse", hosts_file=Path("/tmp/h"), ports=[22], concurrency=10, rate=0, adaptive=False,
        host_parallel=0, timeout_ms=800, banner=True, os_detect=False, cve=False, cve_online=False,
        syn=False, checkpoint=None, max_hosts=10,
    )  # fmt: skip
    args.update(overrides)
    return pp.build_pulse_command(**args)


def test_command_passes_our_probe_database():
    assert Path(_flag(_command(), "--probe-db")) == pp.PROBE_DB


@pytest.mark.parametrize("content", ["{bad", _db("(?=x)y")])
def test_an_invalid_database_is_left_off_the_command_and_said_so(tmp_path, monkeypatch, caplog, content):
    bad = tmp_path / "probes.json"
    bad.write_text(content, encoding="utf-8")
    monkeypatch.setattr(pp, "PROBE_DB", bad)
    with caplog.at_level(logging.WARNING):
        cmd = _command()
    assert "--probe-db" not in cmd
    assert "embedded rules" in caplog.text


class _Completed:
    def __init__(self, stdout: str, stderr: str = ""):
        self.stdout, self.stderr, self.returncode = stdout, stderr, 0


_ONE = '{"open": [{"ip": "10.0.0.1", "port": 22, "service": "ssh"}]}'


def _run(tmp_path, monkeypatch, *, stderr: str = ""):
    seen: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        seen.append(command)
        return _Completed(_ONE, stderr)

    monkeypatch.setattr(pp, "run_command", fake_run_command)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    out = tmp_path / "out"
    pp.run_pulse_probe(["10.0.0.1:22/tcp", "10.0.0.2:22/tcp"], output_dir=out, chunk_hosts=1)
    raw = json.loads((out / "pulse" / "raw.json").read_text(encoding="utf-8"))
    return seen, raw["adapter"]


def test_run_records_which_probe_database_it_used(tmp_path, monkeypatch):
    seen, adapter = _run(tmp_path, monkeypatch)
    assert all(Path(_flag(c, "--probe-db")) == pp.PROBE_DB for c in seen)
    assert adapter["probe_db"] == str(pp.PROBE_DB)
    assert adapter["probe_db_sha256"] == hashlib.sha256(pp.PROBE_DB.read_bytes()).hexdigest()
    assert adapter["probe_db_version"] == _load(pp.PROBE_DB)["version"]
    assert adapter["probe_db_skipped"] is None
    assert adapter["probe_db_fallback"] == []


def test_run_records_why_the_probe_database_was_skipped_once(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(pp, "PROBE_DB", tmp_path / "gone.json")
    seen, adapter = _run(tmp_path, monkeypatch)
    assert len(seen) == 2 and all("--probe-db" not in c for c in seen)
    assert adapter["probe_db"] is None and "cannot read" in adapter["probe_db_skipped"]
    assert caplog.text.count("not used") == 1


def test_run_notices_when_pulse_fell_back_to_its_embedded_set(tmp_path, monkeypatch, caplog):
    line = "  probe-db  /x/probes.json: bad pattern — using the embedded set"
    with caplog.at_level(logging.WARNING):
        _, adapter = _run(tmp_path, monkeypatch, stderr=f"noise\n{line}\n")
    assert adapter["probe_db_fallback"] == [line.strip()]
    assert "did not use our probe database" in caplog.text


# --------------------------------------------------------------------------
# Rules replayed against banners seen on the stand
# --------------------------------------------------------------------------


def emulate(db: dict, probe_name: str, response: str) -> dict | None:
    """Apply one probe's rules to a response the way probe_db.rs ``match_response`` does.

    First non-soft rule that matches (``regex.captures``, unanchored search)
    wins; failing that, the first soft match; ``$N`` expands to capture N (an
    absent group is empty), the result is trimmed. Python's ``re`` stands in
    for Rust's ``regex`` (same for the constructs ``rust_incompatibility``
    lets through). Not a proof about the engine: tests/fixtures/pulse_probe_db/
    observed_banners.json says what a live Pulse reported for the same bytes.
    """
    probe = next(p for p in db["probes"] if p["name"] == probe_name)
    soft_hit = None
    for rule in probe["matches"]:
        found = re.search(rule["pattern"], response)
        if not found:
            continue

        def expand(template: str) -> str:
            def capture(ref: re.Match[str]) -> str:
                index = int(ref.group(1))
                return (found.group(index) or "") if index <= found.re.groups else ""

            return re.sub(r"\$(\d)", capture, template).strip()

        outcome = {
            "service": rule.get("service", ""),
            "product": expand(rule.get("product", "")),
            "version": expand(rule.get("version", "")),
            "soft": rule.get("soft", False),
        }
        if not outcome["soft"]:
            return outcome
        soft_hit = soft_hit or outcome
    return soft_hit


def _observed():
    return _load(FIXTURES / "observed_banners.json")["observed"]


@pytest.mark.parametrize("case", _observed(), ids=lambda c: f"{c['probe']}:{c['port']}")
def test_observed_responses_are_recognised(case):
    db = _load(pp.PROBE_DB)
    probe = next(p for p in db["probes"] if p["name"] == case["probe"])
    assert not probe["ports"] or case["port"] in probe["ports"]
    got = emulate(db, case["probe"], case["response"])
    assert got is not None and not got["soft"]
    assert {k: got[k] for k in case["expect"]} == case["expect"]


def test_the_postgres_rule_is_ours_and_the_stock_database_misses_it():
    # Why the rule exists: stock postgres-startup sends its SSLRequest as the
    # literal text "\x00\x00..." (Pulse 1.3.0 does not decode \x in 'payload')
    # and its '^[NER]\x00' needs a second byte a real server's 'N' lacks.
    stock = _load(UPSTREAM)
    assert emulate(stock, "postgres-startup", "N") is None
    ours = _load(pp.PROBE_DB)
    probe = next(p for p in ours["probes"] if p["name"] == "postgres-sslrequest")
    assert probe["payload_hex"] == "0000000804d2162f"
