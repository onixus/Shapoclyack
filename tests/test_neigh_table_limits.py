"""scripts/neigh-table-limits.sh: sizing, check/apply consistency, atomicity.

The script runs through subprocess against a fake proc tree (NEIGH_PROC_ROOT),
so no root, no kernel change and no Linux are needed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "neigh-table-limits.sh"


def _proc(tmp_path: Path, v4=(128, 512, 1024), v6=(128, 512, 1024)) -> Path:
    root = tmp_path / "proc"
    for fam, vals in (("ipv4", v4), ("ipv6", v6)):
        if vals is None:
            continue
        d = root / "sys" / "net" / fam / "neigh" / "default"
        d.mkdir(parents=True, exist_ok=True)
        for i, v in enumerate(vals, 1):
            (d / f"gc_thresh{i}").write_text(f"{v}\n")
    return root


def _run(tmp_path: Path, *args: str, proc: Path | None = None):
    env = {
        **os.environ,
        "NEIGH_PROC_ROOT": str(proc or _proc(tmp_path)),
        "NEIGH_PERSIST_FILE": str(tmp_path / "neigh.conf"),
    }
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _vals(proc: Path, fam="ipv4") -> list[int]:
    d = proc / "sys" / "net" / fam / "neigh" / "default"
    return [int((d / f"gc_thresh{i}").read_text()) for i in (1, 2, 3)]


def test_apply_sizes_from_hosts(tmp_path):
    proc = _proc(tmp_path)
    r = _run(tmp_path, "--apply", "--hosts", "5000", proc=proc)
    assert r.returncode == 0, r.stderr
    assert _vals(proc) == [2048, 8192, 16384]  # 2N=10000 -> 16384
    assert "lost on reboot" in r.stderr


def test_hosts_minimum_target_is_4096(tmp_path):
    proc = _proc(tmp_path)
    assert _run(tmp_path, "--apply", "--hosts", "10", proc=proc).returncode == 0
    assert _vals(proc) == [512, 2048, 4096]


def test_never_lowers_without_force(tmp_path):
    proc = _proc(tmp_path, v4=(1000, 5000, 20000))
    r = _run(tmp_path, "--apply", "--thresh3", "4096", proc=proc)
    assert r.returncode == 0, r.stderr
    assert _vals(proc) == [1000, 5000, 20000]
    assert "keep net.ipv4.neigh.default.gc_thresh3=20000" in r.stdout
    _run(tmp_path, "--apply", "--thresh3", "4096", "--force", proc=proc)
    assert _vals(proc) == [512, 2048, 4096]


def test_persist_is_idempotent(tmp_path):
    first = _run(tmp_path, "--persist", "--hosts", "5000")
    assert first.returncode == 0, first.stderr
    conf = tmp_path / "neigh.conf"
    body = conf.read_text()
    assert "net.ipv4.neigh.default.gc_thresh3 = 16384" in body
    second = _run(tmp_path, "--persist", "--hosts", "5000")
    assert f"unchanged {conf}" in second.stdout
    assert conf.read_text() == body


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("1023", False),
        ("1024", True),
        ("1048576", True),
        ("1048577", False),
        ("abc", False),
    ],
)
def test_thresh3_bounds(tmp_path, value, ok):
    r = _run(tmp_path, "--persist", "--thresh3", value)
    assert (r.returncode == 0) is ok, r.stderr
    if not ok:
        assert r.returncode == 2


def test_force_lowers_thresh3_minimum(tmp_path):
    assert _run(tmp_path, "--persist", "--thresh3", "64", "--force").returncode == 0


@pytest.mark.parametrize("t2", [512, 8192])
@pytest.mark.parametrize("t3", [1024, 4096, 16384])
def test_check_agrees_with_apply(tmp_path, t2, t3):
    """check is red exactly when apply has something to raise."""
    proc = _proc(tmp_path, v4=(512, t2, t3))  # thresh1 already at its target
    check = _run(tmp_path, "--check", "--hosts", "1000", proc=proc)
    apply_ = _run(tmp_path, "--apply", "--hosts", "1000", proc=proc)
    assert apply_.returncode == 0, apply_.stderr
    needs_raise = t3 < 4096 or t2 < 2048
    assert check.returncode == (1 if needs_raise else 0), check.stdout
    changed = [ln for ln in apply_.stdout.splitlines() if ln.startswith("changed ")]
    assert bool(changed) is needs_raise


def test_check_thresh3_1024_hosts_1000_fails(tmp_path):
    r = _run(tmp_path, "--check", "--hosts", "1000")
    assert r.returncode == 1
    assert "gc_thresh3=4096" in r.stdout


def test_check_fails_on_low_thresh2_alone(tmp_path):
    proc = _proc(tmp_path, v4=(128, 512, 8192))
    assert _run(tmp_path, "--check", "--hosts", "1000", proc=proc).returncode == 1


def test_apply_ipv6_missing_changes_nothing(tmp_path):
    proc = _proc(tmp_path, v6=None)
    before = _vals(proc)
    r = _run(tmp_path, "--apply", "--ipv6", "--hosts", "5000", "--persist", proc=proc)
    assert r.returncode == 4
    assert _vals(proc) == before
    assert not (tmp_path / "neigh.conf").exists()


def test_persist_ipv6_missing_writes_nothing(tmp_path):
    r = _run(
        tmp_path,
        "--persist",
        "--ipv6",
        "--hosts",
        "5000",
        proc=_proc(tmp_path, v6=None),
    )
    assert r.returncode == 4
    assert not (tmp_path / "neigh.conf").exists()


def test_check_tolerates_missing_ipv6(tmp_path):
    r = _run(tmp_path, "--check", "--ipv6", proc=_proc(tmp_path, v6=None))
    assert r.returncode == 0
    assert "ipv6: unavailable" in r.stdout


def test_ipv4_keys_missing_is_exit_4(tmp_path):
    assert _run(tmp_path, "--check", proc=tmp_path / "empty").returncode == 4


def test_usage_error_exit_2(tmp_path):
    assert _run(tmp_path, "--bogus").returncode == 2


@pytest.mark.skipif(sys.platform != "darwin", reason="exercises the non-Linux branch")
def test_unsupported_platform_exit_3():
    env = {k: v for k, v in os.environ.items() if k != "NEIGH_PROC_ROOT"}
    r = subprocess.run(
        ["bash", str(SCRIPT), "--check"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 3
