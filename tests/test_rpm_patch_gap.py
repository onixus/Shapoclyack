"""RPM package grammar alone does not choose the upgrade command."""
from types import SimpleNamespace

import pytest

from api.services import patch_gap


@pytest.mark.parametrize("distro,release,prefix", [
    ("sles", "12.5", "sudo zypper refresh && sudo zypper update"),
    ("sles", "15.6", "sudo zypper refresh && sudo zypper update"),
    ("rhel", "7.9", "sudo yum update"),
    ("rhel", "8.10", "sudo dnf upgrade"),
    ("rhel", "9.2", "sudo dnf upgrade"),
    ("rhel", "10", "sudo dnf upgrade"),
    ("amazonlinux", "2", "sudo yum update"),
    ("amazonlinux", "2023", "sudo dnf upgrade"),
])
def test_rpm_commands_use_distribution_and_release(distro, release, prefix):
    assert patch_gap.upgrade_command("rpm", ["curl"], distro=distro, release=release) == prefix + " curl"
    row = SimpleNamespace(installed_package="curl", source_package="curl", purl="pkg:rpm/vendor/curl@1.0-1",
                          fixed_version="1.0-2", installed_version="1.0-1", cve_id="CVE-2026-10001",
                          severity="high", distro=distro, distro_release=release)
    gaps, _ = patch_gap._build_gaps([row])
    assert gaps[0]["upgrade_command"] == prefix + " curl"


@pytest.mark.parametrize("distro,release", [("unknown", "1"), ("rhel", None), ("amazonlinux", "1")])
def test_unknown_rpm_context_does_not_guess_a_manager(distro, release):
    assert patch_gap.upgrade_command("rpm", ["curl"], distro=distro, release=release) is None
