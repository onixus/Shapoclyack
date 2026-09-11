"""Live ``naabu -sn`` tests (require the real binary, privileged).

Skipped unless ``OCTO_NAABU_LIVE`` is set, the same way ``test_nats_live.py``
is gated on a broker URL: everywhere else in the suite ``naabu`` is a stub that
records argv, which is exactly why a flag set naabu refuses to start on got
through code review and two green runs of 2845 tests. Host discovery needs raw
sockets, so this only passes inside the scanner image (or a host with the
capability); set the variable there — CI does it in the image smoke stage.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from scanner.pipeline.probe_ladder import build_naabu_sn_command

LIVE = os.environ.get("OCTO_NAABU_LIVE", "").strip()

pytestmark = pytest.mark.skipif(
    not LIVE or shutil.which("naabu") is None,
    reason="OCTO_NAABU_LIVE not set, or naabu is not on PATH (live binary)",
)


@pytest.fixture()
def targets_file(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("127.0.0.1\n", encoding="utf-8")
    return path


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        command, capture_output=True, text=True, timeout=120, check=False
    )


@pytest.mark.parametrize(
    "exclude_ports",
    [[], [443], [80, 443]],
    ids=["avoid-list-takes-neither", "avoid-list-takes-one", "avoid-list-takes-both"],
)
def test_the_built_host_discovery_command_starts(targets_file, exclude_ports):
    """Every shape the avoid-list leaves the command in has to be one naabu
    will run, not only the one a reviewer read. ``-sn -pe …`` without ``-wn``
    exits 1 on "discovery probes were provided but host discovery is disabled"
    before a packet is sent, and the stage reads that as a dead estate."""
    result = _run(
        build_naabu_sn_command(targets_file, rate=1000, retries=1, exclude_ports=exclude_ports)
    )
    assert result.returncode == 0, result.stderr
    assert "FTL" not in result.stderr


def test_spelling_the_probes_out_finds_what_naabu_defaults_find(targets_file):
    """The probes are named to drop an avoided port from them, not to weaken
    host discovery: with nothing avoided the set is the one
    ``configureHostDiscovery`` picks unasked, and it has to behave like it."""
    spelled = _run(build_naabu_sn_command(targets_file, rate=1000, retries=1))
    defaults = _run(
        ["naabu", "-list", str(targets_file), "-sn", "-silent", "-rate", "1000", "-retries", "1"]
    )
    assert defaults.returncode == 0, defaults.stderr
    assert spelled.returncode == 0, spelled.stderr
    assert sorted(spelled.stdout.split()) == sorted(defaults.stdout.split())
