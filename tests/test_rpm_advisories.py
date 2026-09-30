"""RPM providers: vendor import, exact applicability, unknowns and atomic refresh."""
from __future__ import annotations

import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defusedxml.common import DefusedXmlException

from api.services import advisories, package_identity as identity, software_cve_match as matcher
from api.services.advisories import alas, rhel, rpm_import, rpm_normalize as normalize, suse
from api.services.advisories.coverage import snapshot_provider

FIXTURES = Path(__file__).parent / "fixtures/advisories/rpm"
RH_PRODUCT = "BaseOS-9.2.0.Z.E4S"
SU_PRODUCT = "SUSE Linux Enterprise Server 12 SP5"
PROVIDERS = {"rhel": rhel.RhelAdvisoryProvider, "suse": suse.SuseAdvisoryProvider, "alas": alas.AlasAdvisoryProvider}
DEVICES = {
    "rhel": dict(os_name="Red Hat Enterprise Linux", os_version="9.2"),
    "suse": dict(os_name="SUSE Linux Enterprise Server", os_version="12.5"),
    "alas": dict(os_name="Amazon Linux", os_version="2023.6.20241031"),
}


def xml(release="2023", *, arch="x86_64", epoch="1", name="libExample", version="1.0", revision=None):
    revision = revision or f"5.amzn{release}.0.1"
    return f'''<updates><update from="security@amazon.com" status="final" type="security">
      <id>opaque-advisory-id</id><updated date="2026-09-01 10:00:00"/><severity>Important</severity>
      <references><reference type="cve" id="CVE-2026-10001"/>
        <reference type="bugzilla" id="123"/></references>
      <pkglist><collection><package name="{name}" epoch="{epoch}" version="{version}"
        release="{revision}" arch="{arch}"/></collection></pkglist>
      </update></updates>'''.encode()


def manifest(tmp_path, vendor, content=None, **binding):
    if content is None:
        content = xml() if vendor == "alas" else (FIXTURES / f"{vendor}-reduced.json").read_bytes()
    source = tmp_path / ("updateinfo.xml" if vendor == "alas" else "advisory.json")
    source.write_bytes(content)
    row = dict(path=source.name, url=f"https://vendor.example.test/{source.name}",
               sha256=hashlib.sha256(content).hexdigest(), release="2023" if vendor == "alas" else "9.2" if vendor == "rhel" else "12.5")
    row.update(dict(repository="core") if vendor == "alas" else dict(product_ids=[RH_PRODUCT if vendor == "rhel" else SU_PRODUCT]))
    row.update(binding)
    path = tmp_path / "sources.json"
    path.write_text(json.dumps(dict(version=1, vendor=vendor, sources=[row])))
    return path


def installed(name, version, arch="x86_64", source="rpm"):
    return dict(name=name, version=version, architecture=arch, source=source)


def match(provider, vendor="alas", packages=None, **device):
    return matcher.match_software(
        device=dict(os_family="linux", device_id="d1", latest_snapshot_id="s1", **(DEVICES[vendor] | device)),
        software=packages if packages is not None else [installed("libExample", "1:1.0-1.amzn2023.0.1")],
        provider_for=lambda _: provider,
    )


def imported(tmp_path, vendor="alas", content=None, **binding):
    path = manifest(tmp_path, vendor, content, **binding)
    output = tmp_path / "out.json"
    rpm_import.import_manifest(path, output)
    return PROVIDERS[vendor](output)


@pytest.mark.parametrize(("name", "version", "distro", "release"), [
    ("Red Hat Enterprise Linux", "9.2", "rhel", "9.2"),
    ("RHEL", "8.10", "rhel", "8.10"), ("Red Hat Enterprise Linux Server", "7.9", "rhel", "7.9"),
    ("SUSE Linux Enterprise Server", "15.6", "sles", "15.6"),
    ("SLES", "12-SP5", "sles", "12.5"), ("SLES 15 SP6", "15", "sles", "15.6"),
    ("Amazon Linux", "2", "amazonlinux", "2"),
    ("Amazon Linux 2023", "2023.6.20241031", "amazonlinux", "2023"),
])
def test_rpm_identity_preserves_release_boundaries(name, version, distro, release):
    ctx = identity.resolve_distro(os_family="linux", os_name=name, os_version=version)
    assert (ctx.distro, ctx.release, ctx.supported, ctx.reason) == (distro, release, True, None)


@pytest.mark.parametrize("name", ["Rocky Linux", "AlmaLinux", "CentOS", "Fedora", "openSUSE Leap", "Oracle Linux"])
def test_derivatives_are_not_implicitly_bound_to_another_vendor(name):
    ctx = identity.resolve_distro(os_family="linux", os_name=name, os_version="9.2")
    assert not ctx.supported
    assert ctx.reason == "unsupported_distro"


@pytest.mark.parametrize(("vendor", "name", "below", "fixed", "count"), [
    ("rhel", "curl", "7.76.1-23.el9_2.7", "7.76.1-23.el9_2.8", 3),
    ("suse", "ucode-intel", "20240910-143.0", "20240910-143.1", 2),
    ("alas", "libExample", "1:1.0-4.amzn2023.0.1", "1:1.0-5.amzn2023.0.1", 1),
])
def test_real_csaf_and_alas_shapes_round_trip_into_matching(tmp_path, vendor, name, below, fixed, count):
    provider = imported(tmp_path, vendor)
    assert provider.entry_count() == count
    assert provider.status()["error"] is None
    for version, expected in ((below, "vulnerable"), (fixed, "fixed")):
        result = match(provider, vendor, [installed(name, version)])
        assert result.packages_assessed == result.packages_total == 1
        assert result.packages_unassessed == 0
        assert {r.status for r in result.candidates} == {expected}
        for row in result.candidates:
            assert row.provider == provider.name
            assert row.evidence["architecture"] == "x86_64"
            assert len(row.evidence["source_sha256"]) == 64
            assert row.feed_date == row.evidence["source_updated"]
            assert row.evidence["product_id"]
            assert row.evidence["assessment_scope"] == "installed_binary_rpm"
            assert row.evidence["source_package_lookup"] == "exact"


@pytest.mark.parametrize("version,expected", [
    ("1.0-999.amzn2023.0.1", "vulnerable"),
    ("1:1.0-5.amzn2023.0.1", "fixed"), ("2:0.1-1.amzn2023.0.1", "fixed"),
    ("1:1.0~rc1-9.amzn2023.0.1", "vulnerable"), ("1:1.0^git1-1.amzn2023.0.1", "fixed"),
])
def test_rpm_epoch_backport_tilde_and_caret(tmp_path, version, expected):
    row, = match(imported(tmp_path), packages=[installed("libExample", version)]).candidates
    assert row.status == expected


@pytest.mark.parametrize("item,reason", [
    (installed("libexample", "1.0-1.amzn2023"), "rpm_package_not_covered"),
    (installed("libExample-devel", "1.0-1.amzn2023"), "rpm_package_not_covered"),
    (installed("libExample", "1.0-1.amzn2023", "aarch64"), "rpm_architecture_not_covered"),
    (installed("libExample", "1.0-1.amzn2023", None), "rpm_architecture_unknown"),
    (installed("libExample", "1.0-1.amzn2023", "noarch"), "rpm_architecture_not_covered"),
    (installed("libExample", "1.0-1.module+stream.amzn2023"), "rpm_module_context_required"),
    (installed("libExample", "1.0"), "unparsable_version"),
    (installed("libExample", "1.0-1.amzn2023.x86_64"), "unparsable_version"),
    (installed("libExample", "1.0-1.amzn2023", source="dpkg"), "package_distro_mismatch"),
])
def test_uncertain_rpm_subjects_never_count_as_assessed(tmp_path, item, reason):
    result = match(imported(tmp_path), packages=[item])
    row, = result.candidates
    assert (row.status, row.unknown_reason, row.cve_id) == ("unknown", reason, "")
    assert result.packages_assessed == 0 and result.packages_unassessed == 1


def test_noarch_is_exact_not_a_wildcard(tmp_path):
    provider = imported(tmp_path, content=xml(arch="noarch"))
    assert match(provider, packages=[installed("libExample", "1.0-1.amzn2023", "noarch")]).packages_assessed == 1
    assert match(provider).packages_assessed == 0


def test_conflicting_branch_thresholds_are_unknown(tmp_path):
    provider = imported(tmp_path)
    payload = json.loads(provider.path().read_text())
    duplicate = payload["entries"][0] | {"fixed_version": "1:1.0-8.amzn2023.0.1"}
    payload["entries"].append(duplicate)
    provider.path().write_text(json.dumps(payload))
    row, = match(provider).candidates
    assert row.unknown_reason == "rpm_advisory_ambiguous"


def test_unsupported_releases_missing_data_and_recovery(tmp_path):
    provider = PROVIDERS["alas"](tmp_path / "out.json")
    assert match(provider).candidates[0].unknown_reason == "no_advisory_data"
    rpm_import.import_manifest(manifest(tmp_path, "alas"), provider.path())
    assert match(provider).packages_assessed == 1
    assert match(provider, os_version="2").candidates[0].unknown_reason == "advisory_release_not_covered"
    provider.path().unlink()
    assert match(provider).candidates[0].unknown_reason == "no_advisory_data"


def test_rpm_snapshot_preserves_case_provenance_and_one_stat(tmp_path, monkeypatch):
    provider = imported(tmp_path)
    original = provider._stat_key
    calls = []
    monkeypatch.setattr(provider, "_stat_key", lambda p: (calls.append(p), original(p))[1])
    view = snapshot_provider(provider)
    provider.path().unlink()
    provider.reload()
    assert view.case_sensitive_packages
    assert len(view.advisories_for(release="2023", source_package="libExample")) == 1
    assert view.advisories_for(release="2023", source_package="libexample") == ()
    result = match(view, packages=[installed("libExample", "1.0-1.amzn2023") for _ in range(2000)])
    assert result.packages_assessed == 2000 and len(result.candidates) == 1
    assert calls == [provider.path()]


def test_csaf_recommendation_needs_vendor_fix(tmp_path):
    p = json.loads((FIXTURES / "suse-reduced.json").read_text())
    for v in p["vulnerabilities"]:
        v["remediations"] = []
    with pytest.raises(ValueError, match="too few"):
        imported(tmp_path, "suse", json.dumps(p).encode())


@pytest.mark.parametrize("vendor,products,release", [
    ("rhel", ["absent"], "9.2"),
    ("rhel", [RH_PRODUCT], "9.3"),
    ("suse", [SU_PRODUCT], "15.5"),
    ("suse", ["SUSE Linux Enterprise Server for SAP Applications 12 SP5"], "12.5"),
])
def test_csaf_wrong_product_or_release_is_refused(tmp_path, vendor, products, release):
    with pytest.raises(ValueError):
        imported(tmp_path, vendor, product_ids=products, release=release)


def test_rhel_cpe_major_can_be_explicitly_bound_to_a_minor():
    product = {"product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::baseos"}}
    normalize._validate_platform(product, vendor="rhel", release="9.6")
    with pytest.raises(ValueError):
        normalize._validate_platform(product, vendor="rhel", release="8.10")


@pytest.mark.parametrize("repository", [None, "", "extras", "livepatch", "corretto8"])
def test_alas_does_not_guess_extra_or_livepatch_channels(tmp_path, repository):
    with pytest.raises(ValueError, match="core repository"):
        imported(tmp_path, repository=repository)


def test_alas_major_release_cannot_be_misbound(tmp_path):
    with pytest.raises(ValueError, match="release/architecture"):
        imported(tmp_path, content=xml(release="2"))
    provider = imported(tmp_path, content=xml(release="2"), release="2")
    result = match(provider, os_version="2", packages=[installed("libExample", "1.0-1.amzn2")])
    assert result.candidates[0].status == "vulnerable"


def test_xml_entities_are_refused(tmp_path):
    with pytest.raises(DefusedXmlException):
        imported(tmp_path, content=b'<!DOCTYPE updates [<!ENTITY x SYSTEM "file:///etc/passwd">]><updates>&x;</updates>')


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(vendor="rhel"),
    lambda p: p.update(format="unknown"),
    lambda p: p["entries"][0].update(architecture="src"),
    lambda p: p["entries"][0].update(fixed_version="1.0"),
    lambda p: p["entries"][0].update(source_sha256="0"),
    lambda p: p["entries"][0].update(source_url="https://user:secret@vendor.test/feed"),
    lambda p: p["entries"].append({}),
])
def test_runtime_rejects_whole_invalid_rpm_datasets(tmp_path, mutation):
    provider = imported(tmp_path)
    p = json.loads(provider.path().read_text())
    mutation(p)
    provider.path().write_text(json.dumps(p))
    provider.reload()
    assert not provider.available()
    assert provider.status()["error"]
    assert match(provider).candidates[0].unknown_reason == "no_advisory_data"


@pytest.mark.parametrize("corrupt", [b'\xff', b'{', b'[' * 5000, b'{}'])
def test_corrupt_import_keeps_the_previous_dataset(tmp_path, corrupt):
    provider = imported(tmp_path)
    before = provider.path().read_bytes()
    path = manifest(tmp_path, "rhel", corrupt)
    with pytest.raises((ValueError, UnicodeError, RecursionError)):
        rpm_import.import_manifest(path, provider.path())
    assert provider.path().read_bytes() == before
    assert not list(tmp_path.glob("*.tmp"))


def test_import_checks_raw_digest_and_protects_inputs(tmp_path):
    path = manifest(tmp_path, "alas")
    p = json.loads(path.read_text())
    p["sources"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError, match="checksum"):
        rpm_import.import_manifest(path, tmp_path / "out.json")
    path = manifest(tmp_path, "alas")
    with pytest.raises(ValueError, match="replace an input"):
        rpm_import.import_manifest(path, path)


def test_compressed_sources_are_bounded_and_checksums_cover_raw_bytes(tmp_path, monkeypatch):
    path = manifest(tmp_path, "alas")
    p = json.loads(path.read_text())
    content = gzip.compress(xml())
    (tmp_path / "updateinfo.xml.gz").write_bytes(content)
    p["sources"][0].update(path="updateinfo.xml.gz", sha256=hashlib.sha256(content).hexdigest())
    path.write_text(json.dumps(p))
    assert rpm_import.import_manifest(path, tmp_path / "out.json")["entries"] == 1
    monkeypatch.setattr(rpm_import, "MAX_SOURCE_BYTES", len(content) + 1)
    with pytest.raises(ValueError, match="expanded advisory"):
        rpm_import.import_manifest(path, tmp_path / "out.json")


def test_shrink_is_explicit_and_import_is_idempotent(tmp_path):
    provider = imported(tmp_path)
    path = tmp_path / "sources.json"
    before = provider.path().read_bytes()
    rpm_import.import_manifest(path, provider.path())
    assert provider.path().read_bytes() == before
    path = manifest(tmp_path, "alas", xml(name="OtherPackage"))
    with pytest.raises(ValueError, match="drop existing coverage"):
        rpm_import.import_manifest(path, provider.path())
    assert provider.path().read_bytes() == before
    assert rpm_import.import_manifest(path, provider.path(), allow_shrink=True)["entries"] == 1


@pytest.mark.parametrize("relative", ["../escape.xml", "/etc/passwd", "link.xml"])
def test_source_paths_do_not_escape_manifest_directory(tmp_path, relative):
    path = manifest(tmp_path, "alas")
    (tmp_path / "link.xml").symlink_to(tmp_path / "updateinfo.xml")
    p = json.loads(path.read_text())
    p["sources"][0]["path"] = relative
    path.write_text(json.dumps(p))
    with pytest.raises(ValueError):
        rpm_import.import_manifest(path, tmp_path / "out.json")


def test_cli_works_from_another_directory_without_network(tmp_path):
    path = manifest(tmp_path, "alas")
    script = Path(__file__).resolve().parents[1] / "scripts/import-rpm-advisories.py"
    proc = subprocess.run([sys.executable, str(script), str(path), "-o", str(tmp_path / "out.json")],
                          cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["entries"] == 1


def test_rpm_match_evidence_uses_existing_storage_contract(tmp_path):
    result = match(imported(tmp_path))
    from datetime import UTC, datetime
    payload, = matcher._match_payloads(tenant_id="tenant-a", device_id="d1", result=result, matched_at=datetime.now(UTC))
    row = matcher._row_to_dict(SimpleNamespace(**payload))
    assert payload["tenant_id"] == "tenant-a" and row["snapshot_id"] == "s1"
    assert row["evidence"]["assessment_scope"] == "installed_binary_rpm"
    assert row["provider"] == "amazon-alas"


def test_new_providers_are_available_to_registry_and_airgap_manifest(tmp_path, monkeypatch):
    for vendor, cls in PROVIDERS.items():
        p = tmp_path / f"{vendor}.json"
        monkeypatch.setenv(cls.env_var, str(p))
        assert advisories.get_provider(cls.distro).path() == p
        assert advisories.get_provider(cls.distro).status()["error"] == "missing"
    from scripts import enrichment_manifest, enrichment_bundle
    for suffix in PROVIDERS:
        relative = enrichment_manifest._JSON_DATASETS[f"advisories_{suffix}"][0]
        assert relative in enrichment_bundle.dataset_paths()


@pytest.mark.parametrize("version,name", [
    ("15", "SLES 12 SP5"), ("12", "SLES 15 SP6"),
    ("15.6.9", "SLES"), ("unknown", "SLES 15 SP6"),
])
def test_conflicting_or_malformed_sles_version_is_not_guessed(version, name):
    ctx = identity.resolve_distro(os_family="linux", os_name=name, os_version=version)
    assert not ctx.supported and ctx.reason == "unknown_release"


@pytest.mark.parametrize("change", [
    lambda p: p["document"]["publisher"].update(namespace="https://other.test"),
    lambda p: p["document"]["tracking"].update(status="draft"),
    lambda p: p["product_tree"]["relationships"][0].update(product_reference="absent"),
])
def test_bad_selected_csaf_metadata_is_not_a_silent_empty_feed(tmp_path, change):
    payload = json.loads((FIXTURES / "suse-reduced.json").read_text())
    change(payload)
    with pytest.raises(ValueError):
        imported(tmp_path, "suse", json.dumps(payload).encode())


def test_purl_epoch_mismatch_is_refused():
    product = dict(name="curl-1:7.76.1-2.el9.x86_64", product_identification_helper={
        "purl": "pkg:rpm/redhat/curl@7.76.1-2.el9?arch=x86_64",
    })
    with pytest.raises(ValueError, match="disagree"):
        normalize._rpm_component(product, vendor="rhel")
    product["product_identification_helper"]["purl"] += "&epoch=1"
    assert normalize._rpm_component(product, vendor="rhel") == ("curl", "1:7.76.1-2.el9", "x86_64")


def test_suse_nevra_fallback_and_source_rpm_boundary():
    assert normalize._rpm_component(dict(name="libExample-devel-1:2.0-3.4.x86_64"), vendor="suse") == (
        "libExample-devel", "1:2.0-3.4", "x86_64",
    )
    assert normalize._rpm_component(dict(name="libExample-devel-1:2.0-3.4.src"), vendor="suse") is None


def test_conflicting_csaf_status_is_refused(tmp_path):
    payload = json.loads((FIXTURES / "suse-reduced.json").read_text())
    vulnerability = payload["vulnerabilities"][0]
    vulnerability["product_status"]["known_not_affected"] = vulnerability["product_status"]["recommended"]
    with pytest.raises(ValueError, match="conflicting"):
        imported(tmp_path, "suse", json.dumps(payload).encode())


def test_vendor_output_mixup_retains_previous_dataset(tmp_path):
    provider = imported(tmp_path, "suse")
    before = provider.path().read_bytes()
    with pytest.raises(ValueError, match="different vendor"):
        rpm_import.import_manifest(manifest(tmp_path, "alas"), provider.path())
    assert provider.path().read_bytes() == before
