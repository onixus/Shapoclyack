"""Image builds reuse a verified NVD corpus without contacting the API."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import nvd_snapshot

ROOT = Path(__file__).resolve().parents[1]


def snapshot_bytes():
    return json.dumps({"version": "4.0", "source": "nvd-api-2.0", "updated": "2026-10-22",
                       "entries": {f"CVE-2026-{i:05}": {"score": 7.5} for i in range(1000)}}).encode()


def test_parked_snapshot_roundtrip_and_tampering(tmp_path):
    source, target = tmp_path / "download.json", tmp_path / "cvss4.json"
    source.write_bytes(snapshot_bytes())
    nvd_snapshot.park(source, target)
    assert nvd_snapshot.verify(target)["updated"] == "2026-10-22"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(ValueError, match="checksum"):
        nvd_snapshot.verify(target)


@pytest.mark.parametrize("invalid", [b"not JSON", b'{}', b'[]', b'{"source":"nvd-api-2.0","version":"4.0","updated":"2026-10-22","entries":{}}'])
def test_invalid_download_leaves_previous_snapshot_untouched(tmp_path, invalid):
    source, target = tmp_path / "download.json", tmp_path / "cvss4.json"
    source.write_bytes(snapshot_bytes())
    nvd_snapshot.park(source, target)
    previous = target.read_bytes(), target.with_suffix(".sha256").read_bytes()
    source.write_bytes(invalid)
    with pytest.raises((ValueError, KeyError)):
        nvd_snapshot.park(source, target)
    assert previous == (target.read_bytes(), target.with_suffix(".sha256").read_bytes())


def test_committed_snapshot_is_verified():
    nvd_snapshot.verify(ROOT / "scanner/data/cvss4/cvss4.json")


@pytest.mark.parametrize("fetch", [None, "false", "true"])
def test_build_skip_makes_no_nvd_request_and_runtime_still_refreshes(tmp_path, fetch):
    """Run the real orchestrator with recording feed fixtures, no network."""
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ["fetch-enrichment.sh", "enrichment_manifest.py", "feed_fetch.py"]:
        shutil.copy(ROOT / "scripts" / name, scripts / name)
    for relative in ["agent/__init__.py", "agent/egress.py", "agent/runtime/__init__.py", "agent/runtime/egress.py"]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, target)
    seed = tmp_path / "scanner/data/cvss4"
    seed.mkdir(parents=True)
    (seed / "cvss4.json").write_bytes(snapshot_bytes())
    marker = tmp_path / "nvd-request"
    (scripts / "fetch-cvss4-db.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('called')\n"
    )
    # Other independent feeds fail quickly; their result must not hide the NVD assertion.
    for name in ["fetch-geoip-db.sh", "fetch-asn-db.sh", "fetch-epss-db.sh", "fetch-kev-db.sh"]:
        stub = scripts / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)
    data = tmp_path / "output"
    env = {k: v for k, v in os.environ.items() if not k.startswith("OCTO_")}
    env.update(OCTO_ENRICHMENT_DIR=str(data), OCTO_ENRICHMENT_SEED_DIR=str(tmp_path / "scanner/data"))
    if fetch is not None:
        env["OCTO_CVSS4_FETCH_ENABLED"] = fetch
    result = subprocess.run(["bash", str(scripts / "fetch-enrichment.sh")], env=env,
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode in (1, 2), result.stderr
    assert marker.exists() is (fetch != "false")
    assert (data / "enrichment-manifest.json").exists(), result.stderr
    manifest = json.loads((data / "enrichment-manifest.json").read_text())
    assert manifest["datasets"]["cvss4"]["origin"] == ("seed" if fetch == "false" else "fetch")
    assert (data / "cvss4/cvss4.json").read_bytes() == snapshot_bytes()


@pytest.mark.parametrize("name", ["Dockerfile", "Dockerfile.allinone"])
def test_image_builds_default_to_snapshot_and_validate_it(name):
    text = (ROOT / name).read_text()
    assert "ARG NVD_FETCH=0" in text
    assert 'export OCTO_CVSS4_FETCH_ENABLED="${NVD_FETCH}"' in text
    assert "python3 scripts/nvd_snapshot.py verify /opt/shapoclyack/seed-data/cvss4/cvss4.json" in text


def test_api_build_also_checks_the_snapshot():
    assert "python3 scripts/nvd_snapshot.py verify" in (ROOT / "Dockerfile.api").read_text()
