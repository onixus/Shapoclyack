"""The package revision is a field of its own, from the scanner to the matcher (#546)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import advisories, asset_services, cpe_ranges
from api.services import retro_match as rm
from scanner.pipeline import distro_revision
from scanner.pipeline.pulse_probe import parse_pulse_json
from scanner.pipeline.service_schema import ServiceRecord
from tests.conftest import make_settings, requires_postgres

REPO_ROOT = Path(__file__).resolve().parent.parent
SEED = REPO_ROOT / "scanner" / "data" / "nvd-cpe" / "nvd-cpe-ranges.json"

SSH_UBUNTU = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13"
SSH_DEBIAN = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10"


def _open(**row) -> dict:
    return {"open": [{"ip": "10.0.0.1", "port": 22, "service": "ssh", "product": "OpenSSH", **row}]}


def _parse(payload: dict) -> ServiceRecord:
    return parse_pulse_json(payload)[0][0]


# --------------------------------------------------------------------------
# Scanner side
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version, banner, expected",
    [
        ("8.2p1", SSH_UBUNTU, ("ubuntu", "4ubuntu0.13")),
        ("9.2p1", SSH_DEBIAN, ("debian", "2+deb12u10")),
        ("9.9", "SSH-2.0-OpenSSH_9.9", ("", "")),
        # nmap glues the revision to the version.
        ("8.2p1 Ubuntu 4ubuntu0.5", "Ubuntu Linux; protocol 2.0", ("ubuntu", "4ubuntu0.5")),
        # The Server line names the distribution; the PHP package suffix on the
        # X-Powered-By line is another package's and is never read.
        (
            "1.18.0",
            "HTTP/1.1 200 OK | Server: nginx/1.18.0 (Ubuntu) | X-Powered-By: PHP/7.4.3-4ubuntu2.19",
            ("ubuntu", ""),
        ),
        # A page body that mentions Debian says nothing about the listener.
        ("2.4.62", "HTTP/1.1 200 OK | Server: Apache/2.4.62 | <html>Debian Default Page</html>", ("", "")),
        ("", "", ("", "")),
    ],
)
def test_the_revision_is_read_off_the_listeners_own_greeting(version, banner, expected):
    assert distro_revision.for_service(version, banner) == expected


def test_pulse_json_keeps_the_version_and_fills_the_revision():
    ubuntu = _parse(_open(version="8.2p1", banner=SSH_UBUNTU))
    assert (ubuntu.version, ubuntu.distro, ubuntu.distro_revision) == ("8.2p1", "ubuntu", "4ubuntu0.13")
    debian = _parse(_open(version="9.2p1", banner=SSH_DEBIAN))
    assert (debian.version, debian.distro, debian.distro_revision) == ("9.2p1", "debian", "2+deb12u10")
    plain = _parse(_open(version="9.9", banner="SSH-2.0-OpenSSH_9.9"))
    assert (plain.distro, plain.distro_revision) == ("", "")


def test_pulses_own_fields_win_and_are_not_mixed_with_the_banner():
    # Forward-compatible with GenDec#33.
    own = _parse(_open(version="8.2p1", banner=SSH_UBUNTU, distro="Ubuntu", distro_revision="4ubuntu0.99"))
    assert (own.distro, own.distro_revision) == ("ubuntu", "4ubuntu0.99")
    # A distribution without a revision: the banner supplies it for the same distribution...
    half = _parse(_open(version="8.2p1", banner=SSH_UBUNTU, distro="ubuntu"))
    assert (half.distro, half.distro_revision) == ("ubuntu", "4ubuntu0.13")
    # ...and never one that belongs to another.
    other = _parse(_open(version="8.2p1", banner=SSH_UBUNTU, distro="debian"))
    assert (other.distro, other.distro_revision) == ("debian", "")


def test_a_services_json_written_before_the_fields_still_validates():
    old = {"ip": "10.0.0.1", "port": 22, "service": "ssh", "product": "OpenSSH", "version": "8.2p1"}
    record = ServiceRecord.model_validate(old)
    assert (record.distro, record.distro_revision) == ("", "")


# --------------------------------------------------------------------------
# Matcher side
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def seed() -> cpe_ranges.CpeRangeDataset:
    return cpe_ranges.load_dataset(SEED)


def _verdicts(fingerprint, dataset) -> dict[str, tuple[str, str]]:
    outcome = rm.match(fingerprint, dataset, lookup=advisories.get_provider)
    return {m.cve: (m.verdict, m.confidence) for m in outcome.matches}


def test_the_matcher_reads_the_field_not_the_banner(seed):
    """Pulse's shape: version 9.2p1, the revision only in the structured field."""
    at_fix = rm.Fingerprint(product="OpenSSH", version="9.2p1", distro="debian", distro_revision="2+deb12u3")
    below = rm.Fingerprint(product="OpenSSH", version="9.2p1", distro="debian", distro_revision="2+deb12u1")
    assert _verdicts(at_fix, seed)["CVE-2024-6387"] == ("fixed", "vendor_advisory")
    assert _verdicts(below, seed)["CVE-2024-6387"] == ("vulnerable", "vendor_advisory")
    # What the field replaces: the same listener without it is a bare range hit.
    bare = rm.Fingerprint(product="OpenSSH", version="9.2p1")
    assert _verdicts(bare, seed)["CVE-2024-6387"][1] == "version_range"


def test_the_structured_field_is_preferred_and_the_banner_is_the_fallback():
    keys = ("a:openbsd:openssh",)
    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
    both = rm.Fingerprint(
        product="OpenSSH", version="8.9p1", banner=banner, distro="ubuntu", distro_revision="3ubuntu0.6"
    )
    assert rm.own_hint(both, keys, None) == rm.DistroHint("ubuntu", None, "3ubuntu0.6")
    old_row = rm.Fingerprint(product="OpenSSH", version="8.9p1", banner=banner)
    assert rm.own_hint(old_row, keys, None) == rm.DistroHint("ubuntu", None, "3ubuntu0.1")
    # A distribution without a revision does not hide one the banner states.
    only_distro = rm.Fingerprint(product="OpenSSH", version="8.9p1", banner=banner, distro="ubuntu")
    assert rm.own_hint(only_distro, keys, None) == rm.DistroHint("ubuntu", None, "3ubuntu0.1")
    # And it is itself a hint when the banner states nothing.
    bare = rm.Fingerprint(product="Apache httpd", version="2.4.41", distro="ubuntu")
    assert rm.own_hint(bare, ("a:apache:http_server",), None) == rm.DistroHint("ubuntu")


def test_one_grammar_serves_the_scanner_and_the_matcher():
    for text in (SSH_UBUNTU, SSH_DEBIAN, "8.2p1 Ubuntu 4ubuntu0.5", "9.2p1 Debian 2+deb12u3", "7.4.3-4ubuntu2.19"):
        found = distro_revision.read(text)
        hint = rm.distro_hint(text)
        assert found is not None and (hint.distro, hint.revision) == found


# --------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------


@requires_postgres
def test_the_fields_reach_asset_services_and_a_new_revision_requeues(tmp_path):
    from api.services import tenants as tenants_service

    dataset = tmp_path / "nvd-cpe.json"
    shutil.copy(SEED, dataset)
    settings = make_settings(tmp_path)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)

    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps([{"host": "10.0.0.1"}]), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    record = _parse(_open(version="8.2p1", banner=SSH_UBUNTU))
    (run_dir / "services.json").write_text(json.dumps([record.model_dump(mode="json")]), encoding="utf-8")
    from api.services import assets as assets_service

    assets_service.upsert_assets_from_run(settings, tenant_id="default", run_id="run-1")
    assert asset_services.record_run(settings, tenant_id="default", run_id="run-1")["created"] == 1

    with get_session(settings.postgres_url) as session:
        row = session.scalars(select(models.AssetService)).one()
        assert (row.version, row.distro, row.distro_revision) == ("8.2p1", "ubuntu", "4ubuntu0.13")
        assert asset_services.to_dict(row)["distro_revision"] == "4ubuntu0.13"
        # The matcher is handed the field.
        from api.services import retro_findings

        fp = retro_findings._fingerprint(row)  # noqa: SLF001
        assert (fp.distro, fp.distro_revision) == ("ubuntu", "4ubuntu0.13")
        row.matched_dataset_version = "marker"

    # The same version rebuilt as a newer package revision is a new fingerprint.
    run2 = settings.output_dir / "runs" / "run-2"
    run2.mkdir(parents=True)
    (run2 / "alive_hosts.json").write_text(json.dumps([{"host": "10.0.0.1"}]), encoding="utf-8")
    (run2 / "vulnerabilities.json").write_text("[]", encoding="utf-8")
    newer = _parse(_open(version="8.2p1", banner=SSH_UBUNTU.replace("4ubuntu0.13", "4ubuntu0.14")))
    (run2 / "services.json").write_text(json.dumps([newer.model_dump(mode="json")]), encoding="utf-8")
    assert asset_services.record_run(settings, tenant_id="default", run_id="run-2")["changed"] == 1
    with get_session(settings.postgres_url) as session:
        row = session.scalars(select(models.AssetService)).one()
        assert row.distro_revision == "4ubuntu0.14" and row.matched_dataset_version is None
