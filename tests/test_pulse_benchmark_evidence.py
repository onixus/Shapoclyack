"""Historical engine samples remain independently auditable after Jenkins expiry."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "pulse_summary", ROOT / "scripts/summarize-pulse-engine.py"
)
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def test_historical_raw_samples_reproduce_published_metrics():
    folder = ROOT / "docs/benchmarks/pulse-engine-20260929"
    samples = json.loads((folder / "results.json").read_text())
    computed = {(r["scenario"], r["variant"]): r for r in SUMMARY.summarize(samples)}
    for old in json.loads((folder / "summary.json").read_text()):
        row = computed[old["scenario"], old["variant"]]
        assert row["median_seconds"] == old["duration_median_sec"]
        assert row["median_packets"] == old["packets_median"]
        assert row["median_wire_bytes"] == old["pcap_bytes_median"]
        assert row["processes"] == old["processes"]
        assert row["command_pairs"] == old["command_pairs"]
    assert computed["partial_closed", "after"]["unresolved_hosts"] == [("127.20.0.3",)]
    assert computed["partial_closed", "before"]["unresolved_hosts"] == [()]


@pytest.mark.parametrize(
    "broken", ["drop", "coverage", "duplicate", "service", "os", "tls"]
)
def test_summary_refuses_incomplete_evidence(broken):
    samples = json.loads(
        (ROOT / "docs/benchmarks/pulse-engine-20260929/results.json").read_text()
    )
    if broken == "drop":
        samples[0]["capture_dropped_packets"] = 1
    elif broken == "coverage":
        samples[0]["coverage_assertions_passed"] = False
    elif broken == "service":
        samples[0]["services"][0]["product"] = "changed"
    elif broken == "os":
        samples[0]["os"][0]["family"] = "changed"
    elif broken == "tls":
        samples[0]["tls"] = []
    else:
        samples[0]["repeat"] = samples[2]["repeat"]
    with pytest.raises(ValueError):
        SUMMARY.summarize(samples)


def test_real_engine_runner_rejects_external_network_before_spawn(
    tmp_path, monkeypatch
):
    import hashlib
    import struct

    spec = importlib.util.spec_from_file_location(
        "pulse_engine_runner", ROOT / "scripts/benchmark-pulse-engine.py"
    )
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    binary = tmp_path / "pulse"
    binary.write_bytes(b"fixture-binary")
    monkeypatch.setattr(runner, "Path", lambda _: binary)
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runner.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    monkeypatch.setattr(
        runner.fcntl,
        "ioctl",
        lambda *_: b"\x00" * 16 + struct.pack("H", 1) + b"\x00" * 238,
    )
    with pytest.raises(ValueError, match="network none"):
        runner.verify_binary(hashlib.sha256(binary.read_bytes()).hexdigest())
    with pytest.raises(ValueError, match="SHA-256"):
        runner.verify_binary("0" * 64)


def test_current_engine_capture_and_exact_endpoint_budget(tmp_path):
    import tarfile

    folder = ROOT / "docs/benchmarks/pulse-engine-20261015"
    samples = json.loads((folder / "results.json").read_text())
    assert len(samples) == 30
    assert json.loads(json.dumps(SUMMARY.summarize(samples))) == json.loads(
        (folder / "summary.json").read_text()
    )
    spec = importlib.util.spec_from_file_location(
        "pulse_engine_runner", ROOT / "scripts/benchmark-pulse-engine.py"
    )
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    with tarfile.open(folder / "raw-outputs.tar.gz") as archive:
        names = archive.getnames()
        assert not any(
            Path(n).is_absolute() or ".." in Path(n).parts or n.endswith("key.pem")
            for n in names
        )
        for row in samples:
            name = f"{row['scenario']}-{row['repeat']}-{row['variant']}"
            capture = tmp_path / "traffic.pcap"
            capture.write_bytes(archive.extractfile(f"{name}/traffic.pcap").read())
            assert runner.pcap_stats(capture) == row["packets"]
            if row["variant"] == "after":
                assert len(row["planned_command_pairs"]) == 3
                assert row["probe_processes"] == (
                    1 if row["scenario"] == "homogeneous" else 3
                )
                assert row["unresolved_hosts"] == (
                    ["127.20.0.3"] if row["scenario"] == "partial_closed" else []
                )
