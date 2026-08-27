"""Build-time enrichment data: provenance manifest and the vulscan refresh.

Both cover the same defect from two ends (#246). A third-party feed going down
during an image build is tolerated on purpose — and that tolerance had turned
into silence: the fetches printed FAILED, the build stayed green, and nothing in
or on the image said which data it had actually ended up with.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.enrichment_manifest import (
    EXIT_DEGRADED,
    EXIT_NO_DATA,
    EXIT_OK,
    build_manifest,
    verdict,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_overlays(root: Path, *, epss_entries: int = 5000, kev_entries: int = 500) -> Path:
    """A data directory holding every required overlay, sized like a real one."""
    data = root / "data"
    (data / "epss").mkdir(parents=True)
    (data / "kev").mkdir(parents=True)
    (data / "cvss4").mkdir(parents=True)
    (data / "exploit").mkdir(parents=True)
    (data / "epss" / "epss-overlay.json").write_text(
        json.dumps(
            {
                "version": 1,
                "source": "first-epss",
                "updated": "2026-08-26",
                "entries": {f"CVE-2026-{i:05d}": 0.1 for i in range(epss_entries)},
            }
        ),
        encoding="utf-8",
    )
    (data / "kev" / "kev-overlay.json").write_text(
        json.dumps(
            {
                "version": 1,
                "source": "cisa-kev",
                "updated": "2026-08-25",
                "entries": [f"CVE-2026-{i:05d}" for i in range(kev_entries)],
            }
        ),
        encoding="utf-8",
    )
    (data / "cvss4" / "cvss4.json").write_text(
        json.dumps(
            {
                "version": "4.0",
                "source": "nvd-api-2.0",
                "updated": "2026-08-07",
                "entries": {f"CVE-2026-{i:05d}": {"score": 7.5} for i in range(2000)},
            }
        ),
        encoding="utf-8",
    )
    (data / "exploit" / "exploit-overlay.json").write_text(
        json.dumps(
            {
                "source": "exploit-db+metasploit",
                "entries": {f"CVE-2026-{i:05d}": {"maturity": "proof_of_concept"} for i in range(2000)},
            }
        ),
        encoding="utf-8",
    )
    return data


def test_unreachable_source_is_a_warning_not_a_failure(tmp_path):
    """The build must survive a feed being down: the previous data is still
    there and still usable, which is the whole reason the fetches are non-fatal."""
    data = _write_overlays(tmp_path)

    manifest = build_manifest(data, refreshed={"kev"}, failed={"epss"})

    assert verdict(manifest) == EXIT_DEGRADED
    # …but it is no longer indistinguishable from a healthy build: the dataset
    # whose fetch failed says so, by name.
    assert manifest["datasets"]["epss"]["origin"] == "stale"
    assert manifest["datasets"]["kev"]["origin"] == "fetch"


def test_stub_overlay_is_not_usable_data(tmp_path):
    """A three-CVE EPSS overlay is what the image used to ship while the build
    stayed green (#246). It scores every finding blind, so it is a build
    failure, not a warning."""
    data = _write_overlays(tmp_path, epss_entries=3)

    manifest = build_manifest(data, refreshed=set(), failed={"epss"})

    assert verdict(manifest) == EXIT_NO_DATA
    assert manifest["datasets"]["epss"]["usable"] is False
    assert "3 entries" in manifest["datasets"]["epss"]["error"]


def test_missing_required_overlay_is_not_usable_data(tmp_path):
    data = _write_overlays(tmp_path)
    (data / "kev" / "kev-overlay.json").unlink()

    manifest = build_manifest(data, refreshed={"epss"}, failed=set())

    assert verdict(manifest) == EXIT_NO_DATA
    assert manifest["datasets"]["kev"]["origin"] == "missing"


def test_manifest_records_date_and_source_of_each_dataset(tmp_path):
    """Age alone cannot tell a fresh corpus from a baseline nothing ever
    replaced — the origin fields are what carry that into GET /api/system."""
    data = _write_overlays(tmp_path)
    (data / "geoip").mkdir()
    (data / "geoip" / "geoip.mmdb").write_bytes(b"\x00" * 32)

    manifest = build_manifest(
        data,
        refreshed={"epss", "kev", "cvss4", "geoip"},
        failed=set(),
        sources={"geoip": "dbip"},
    )

    epss = manifest["datasets"]["epss"]
    assert epss["source"] == "first-epss"
    assert epss["updated"] == "2026-08-26"
    assert epss["entries"] == 5000
    assert epss["origin"] == "fetch"
    # A provider chosen at fetch time leaves no trace in a .mmdb, so it is
    # recorded by the caller that made the choice.
    assert manifest["datasets"]["geoip"]["source"] == "dbip"
    # exploit has no fetch step in the daily refresh: it ships as committed data
    # and must say so rather than claiming a fetch it never had.
    assert manifest["datasets"]["exploit"]["origin"] == "seed"


def test_geoip_absence_never_fails_a_build(tmp_path):
    """There is no redistributable .mmdb seed, so a build without one is a
    supported configuration — geoip/asn are reported, never required."""
    data = _write_overlays(tmp_path)

    manifest = build_manifest(data, refreshed={"epss", "kev", "cvss4"}, failed={"geoip", "asn"})

    assert verdict(manifest) == EXIT_DEGRADED
    assert manifest["datasets"]["geoip"]["required"] is False


def test_manifest_cli_writes_the_sidecar_and_returns_the_verdict(tmp_path):
    data = _write_overlays(tmp_path)

    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(REPO_ROOT / "scripts" / "enrichment_manifest.py"),
         "--dir", str(data), "--refreshed", "epss,kev,cvss4"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == EXIT_DEGRADED, proc.stderr  # geoip/asn absent
    written = json.loads((data / "enrichment-manifest.json").read_text(encoding="utf-8"))
    assert written["datasets"]["epss"]["origin"] == "fetch"
    assert written["generated_at"]


def test_manifest_cli_is_ok_when_everything_refreshed(tmp_path):
    data = _write_overlays(tmp_path)
    for name in ("geoip", "asn"):
        (data / name).mkdir()
        (data / name / f"{name}.mmdb").write_bytes(b"\x00" * 32)

    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(REPO_ROOT / "scripts" / "enrichment_manifest.py"),
         "--dir", str(data), "--refreshed", "epss,kev,cvss4,exploit,geoip,asn"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == EXIT_OK, proc.stdout + proc.stderr


def test_cvss4_fetcher_is_importable_as_a_script(tmp_path):
    """`python3 scripts/fetch-cvss4-db.py` puts scripts/ on sys.path, not the
    repo root, so `from scanner.pipeline.cvss4 import …` raised before the
    fetcher parsed a single argument. In the image build that surfaced only as
    "==> cvss4: FAILED (continuing)", which read like one more 403 (#246)."""
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(REPO_ROOT / "scripts" / "fetch-cvss4-db.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    assert "ModuleNotFoundError" not in proc.stderr


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_vulscan_fetch_falls_back_past_a_challenge_page(tmp_path):
    """www.computec.ch answers every non-browser client with a Cloudflare
    challenge, which is what took all eight databases down at once. The fetch
    must move on to the next mirror — and must never accept an HTML page as a
    database, which is the failure mode a 200-serving portal would produce."""
    databases = [
        "cve", "exploitdb", "openvas", "osvdb",
        "scipvuldb", "securityfocus", "securitytracker", "xforce",
    ]
    blocked = tmp_path / "blocked"
    mirror = tmp_path / "mirror"
    blocked.mkdir()
    mirror.mkdir()
    for db in databases:
        (blocked / f"{db}.csv").write_text("<!DOCTYPE html><html>Attention Required</html>", encoding="utf-8")
        (mirror / f"{db}.csv").write_text(f"1;{db} entry;;;\n", encoding="utf-8")
    out = tmp_path / "out"

    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", str(REPO_ROOT / "scripts" / "fetch-vulscan-db.sh"), "-o", str(out)],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin",
             "VULSCAN_BASE_URLS": f"file://{blocked} file://{mirror}"},
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    for db in databases:
        assert (out / f"{db}.csv").read_text(encoding="utf-8").startswith("1;")
