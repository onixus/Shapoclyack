"""Rhai plugins are git content: installed from one or more repositories, not baked into images."""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.pipeline import pulse_plugin_content as content
from scanner.pipeline import pulse_plugins, pulse_probe
from scanner.pipeline.config_schema import PulseProbeConfig

OFFICIAL = "fn name() { \"shapo_one\" }\nfn run() { }\n"
CUSTOM = "fn name() { \"acme_banner\" }\nfn run() { }\n"
REPLACEMENT = "fn name() { \"shapo_one\" }\nfn run() { /* other */ }\n"


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "pulse-plugins",
        "GIT_AUTHOR_EMAIL": "pulse-plugins@example.com",
        "GIT_COMMITTER_NAME": "pulse-plugins",
        "GIT_COMMITTER_EMAIL": "pulse-plugins@example.com",
    }
    done = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env)
    return done.stdout.strip()


def _repo(path: Path, files: dict[str, str]) -> str:
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    for name, body in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-q", "-m", "plugins")
    return _git(path, "rev-parse", "HEAD")


def _source(name: str, repo: Path, commit: str, *, path: str = "", ref: str | None = None) -> content.PulsePluginSource:
    return content.PulsePluginSource(name=name, repo=repo.as_uri(), ref=ref or commit, commit=commit, path=path)


def test_materialize_keeps_the_earlier_file_and_drops_a_symlink_and_a_bad_name(tmp_path: Path):
    official = tmp_path / "official"
    official.mkdir()
    (official / "shapo_one.rhai").write_text(OFFICIAL, encoding="utf-8")
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "shapo_one.rhai").write_text(REPLACEMENT, encoding="utf-8")
    (custom / "acme_banner.rhai").write_text(CUSTOM, encoding="utf-8")
    (custom / "not a name.rhai").write_text("x", encoding="utf-8")
    (custom / "linked.rhai").symlink_to(custom / "acme_banner.rhai")
    # The oversized file is in the official tree so a lone custom still installs.
    (official / "huge.rhai").write_bytes(b"a" * (content.MAX_PLUGIN_BYTES + 1))

    dest = tmp_path / "out"
    receipt = content.materialize(
        [
            {"name": "official", "root": str(official), "repo": content.OFFICIAL_REPO, "ref": "v1", "commit": "a" * 40, "path": ""},
            {"name": "acme", "root": str(custom), "repo": "https://git.example/acme/plugins.git", "ref": "v1", "commit": "b" * 40, "path": ""},
        ],
        dest,
    )
    assert (dest / "shapo_one.rhai").read_text(encoding="utf-8") == OFFICIAL
    assert (dest / "acme_banner.rhai").is_file()
    assert not (dest / "huge.rhai").exists()
    assert not (dest / "linked.rhai").exists()
    assert {row["name"] for row in receipt["collisions"]} == {"shapo_one"}
    assert receipt["collisions"][0]["kept"] == "official"
    assert {row["name"] for row in receipt["skipped"]} >= {"not a name", "linked", "huge"}
    assert content.content_summary(dest)["sources"][1]["repo"] == "https://git.example/acme/plugins.git"


def test_materialize_refuses_an_empty_result_and_leaves_the_destination(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "huge.rhai").write_bytes(b"a" * (content.MAX_PLUGIN_BYTES + 1))
    dest = tmp_path / "plugins"
    dest.mkdir()
    (dest / "keep.rhai").write_text("stay\n", encoding="utf-8")
    with pytest.raises(content.PulseContentError, match="not an empty directory"):
        content.materialize(
            [{"name": "official", "root": str(source), "repo": content.OFFICIAL_REPO, "ref": "v1", "commit": "a" * 40, "path": ""}],
            dest,
        )
    assert (dest / "keep.rhai").read_text(encoding="utf-8") == "stay\n"


def test_fetch_installs_official_and_custom_plugins_and_a_bad_pin_keeps_the_old_tree(tmp_path: Path):
    official_repo = tmp_path / "official.git"
    official_commit = _repo(official_repo, {"plugins/shapo_one.rhai": OFFICIAL})
    custom_repo = tmp_path / "custom.git"
    custom_commit = _repo(custom_repo, {"acme_banner.rhai": CUSTOM, "shapo_one.rhai": REPLACEMENT})
    dest = tmp_path / "pulse-plugins"
    receipt = content.fetch_plugins(
        dest,
        [
            _source("official", official_repo, official_commit, path="plugins"),
            _source("acme", custom_repo, custom_commit),
        ],
    )
    assert (dest / "shapo_one.rhai").read_text(encoding="utf-8") == OFFICIAL
    assert (dest / "acme_banner.rhai").read_text(encoding="utf-8") == CUSTOM
    assert content.content_mismatch(
        dest,
        [
            _source("official", official_repo, official_commit, path="plugins"),
            _source("acme", custom_repo, custom_commit),
        ],
    ) is None
    assert receipt["sources"][0]["commit"] == official_commit

    with pytest.raises(content.PulseContentError, match="not"):
        content.fetch_plugins(dest, [_source("official", official_repo, "c" * 40, path="plugins", ref="main")])
    assert (dest / "acme_banner.rhai").is_file()
    assert content.read_receipt(dest)["sources"][0]["commit"] == official_commit


def test_fetch_script_reads_a_scan_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "plugins.git"
    commit = _repo(repo, {"acme_banner.rhai": CUSTOM})
    config = tmp_path / "scan.yaml"
    config.write_text(
        "service_probe:\n  pulse:\n    plugin_sources:\n"
        f"      - name: acme\n        repo: {repo.as_uri()}\n        ref: {commit}\n        path: \"\"\n",
        encoding="utf-8",
    )
    dest = tmp_path / "installed"
    monkeypatch.delenv("PULSE_PLUGINS_SOURCES", raising=False)
    env = os.environ.copy()
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"] = str(Path(sys.executable).parent.parent)
    done = subprocess.run(
        ["bash", "scripts/fetch-pulse-plugins.sh", "--config", str(config), str(dest)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert done.returncode == 0, done.stderr
    assert (dest / "acme_banner.rhai").is_file()
    assert "acme@" in done.stdout


def test_a_missing_ref_is_refused_and_images_do_not_copy_the_scripts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PULSE_PLUGINS_REF", raising=False)
    monkeypatch.delenv("PULSE_PLUGINS_SOURCES", raising=False)
    with pytest.raises(content.PulseContentError, match="PULSE_PLUGINS_REF"):
        content.sources_from_env()
    ignored = Path(".dockerignore").read_text(encoding="utf-8")
    assert "scanner/pipeline/pulse_data/plugins" in ignored
    for name in ("Dockerfile", "Dockerfile.allinone", "Dockerfile.api"):
        text = Path(name).read_text(encoding="utf-8")
        assert "pulse_data/plugins" not in text
        assert not any(line.startswith("RUN") and "fetch-pulse-plugins" in line for line in text.splitlines())


def test_plugin_source_urls_reject_credentials_and_plain_http():
    with pytest.raises(ValidationError):
        content.PulsePluginSource(name="acme", repo="http://git.example/plugins.git", ref="v1")
    with pytest.raises(ValidationError):
        content.PulsePluginSource(name="acme", repo="https://user:secret@git.example/plugins.git", ref="v1")
    with pytest.raises(ValidationError):
        content.PulsePluginSource(name="acme", repo="https://git.example/plugins.git", ref="v1", path="../secret")
    content.PulsePluginSource(name="acme", repo="git@git.example:sec/plugins.git", ref="v1")
    with pytest.raises(ValidationError, match="query or a fragment"):
        content.PulsePluginSource(name="acme", repo="https://git.example/plugins.git?token=secret", ref="v1")
    with pytest.raises(ValidationError, match="query or a fragment"):
        content.PulsePluginSource(name="acme", repo="https://git.example/plugins.git#fragment", ref="v1")
    with pytest.raises(ValidationError, match="unique"):
        PulseProbeConfig(
            plugin_sources=[
                {"name": "acme", "repo": "https://git.example/a.git", "ref": "v1"},
                {"name": "acme", "repo": "https://git.example/b.git", "ref": "v1"},
            ]
        )


def test_the_file_cap_stops_without_installing_one_more_or_failing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(content, "MAX_FILES", 2)
    first = tmp_path / "first"
    first.mkdir()
    (first / "shapo_one.rhai").write_text(OFFICIAL, encoding="utf-8")
    (first / "shapo_two.rhai").write_text("fn name() { \"shapo_two\" }\n", encoding="utf-8")
    second = tmp_path / "second"
    second.mkdir()
    (second / "acme_banner.rhai").write_text(CUSTOM, encoding="utf-8")
    (second / "acme_extra.rhai").write_text("fn name() { \"acme_extra\" }\n", encoding="utf-8")
    dest = tmp_path / "out"
    receipt = content.materialize(
        [
            {"name": "official", "root": str(first), "repo": content.OFFICIAL_REPO, "ref": "v1", "commit": "a" * 40, "path": ""},
            {"name": "acme", "root": str(second), "repo": "https://git.example/acme.git", "ref": "v1", "commit": "b" * 40, "path": ""},
        ],
        dest,
    )
    assert sorted(path.name for path in dest.glob("*.rhai")) == ["shapo_one.rhai", "shapo_two.rhai"]
    assert [row["reason"] for row in receipt["skipped"]] == ["more than 2 plugin files"]
    assert receipt["skipped"][0]["source"] == "acme"
    assert {row["name"] for row in receipt["sources"]} == {"official", "acme"}


def test_an_oversized_plugin_is_skipped_before_it_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "huge.rhai").write_bytes(b"a" * (content.MAX_PLUGIN_BYTES + 1))
    (source / "shapo_one.rhai").write_text(OFFICIAL, encoding="utf-8")
    reads: list[str] = []
    original = Path.read_bytes

    def spy(self: Path) -> bytes:
        reads.append(self.name)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", spy)
    dest = tmp_path / "out"
    receipt = content.materialize(
        [{"name": "official", "root": str(source), "repo": content.OFFICIAL_REPO, "ref": "v1", "commit": "a" * 40, "path": ""}],
        dest,
    )
    assert "huge.rhai" not in reads
    assert "shapo_one.rhai" in reads
    assert not (dest / "huge.rhai").exists()
    assert {row["name"] for row in receipt["skipped"]} == {"huge"}


def test_materialize_refuses_a_root_that_leaves_the_checkout(tmp_path: Path):
    work = tmp_path / "clone"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "acme_x.rhai").write_text(CUSTOM, encoding="utf-8")
    (work / "a").symlink_to(outside, target_is_directory=True)
    dest = tmp_path / "out"
    with pytest.raises(content.PulseContentError, match="symlink"):
        content.materialize(
            [{
                "name": "acme",
                "root": str(work / "a"),
                "work": str(work),
                "repo": "https://git.example/acme.git",
                "ref": "v1",
                "commit": "b" * 40,
                "path": "a",
            }],
            dest,
        )
    assert not list(dest.glob("*.rhai"))


def test_a_mismatch_does_not_repeat_userinfo(tmp_path: Path):
    dest = tmp_path / "plugins"
    dest.mkdir()
    (dest / content.RECEIPT_NAME).write_text(
        json.dumps(
            {
                "sources": [{
                    "name": "acme",
                    "repo": "ssh://git.example/plugins.git",
                    "ref": "v1",
                    "commit": "a" * 40,
                    "path": "",
                }]
            }
        ),
        encoding="utf-8",
    )
    source = content.PulsePluginSource(name="acme", repo="ssh://git@git.example/other.git", ref="v9")
    message = content.content_mismatch(dest, [source])
    assert message is not None
    assert "git@" not in message
    assert "ssh://git.example/other.git @ v9" in message


def test_read_trace_plugin_reads_only_the_directory_it_was_given(tmp_path: Path):
    custom = tmp_path / "custom"
    custom.mkdir()
    body = b"fn name() { \"shapo_http_trace\" }\nfn run() { /* custom */ }\n"
    (custom / content.TRACE_PLUGIN_NAME).write_bytes(body)
    assert content.read_trace_plugin(custom) == body
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        content.read_trace_plugin(empty)


def test_directory_resolution_prefers_the_env_then_the_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pulse_plugins, "PLUGINS_DIR", tmp_path / "shipped")
    (tmp_path / "shipped").mkdir()
    (tmp_path / "shipped" / "shapo_one.rhai").write_text(OFFICIAL, encoding="utf-8")
    monkeypatch.delenv("OCTO_PULSE_PLUGINS_DIR", raising=False)
    assert content.default_plugin_directory() == tmp_path / "shipped"
    monkeypatch.setenv("OCTO_PULSE_PLUGINS_DIR", str(tmp_path / "content"))
    assert content.default_plugin_directory() == tmp_path / "content"
    monkeypatch.delenv("OCTO_PULSE_PLUGINS_DIR", raising=False)
    monkeypatch.setattr(pulse_plugins, "PLUGINS_DIR", tmp_path / "missing")
    monkeypatch.setattr(content, "CONTENT_DIR", tmp_path / "image-content")
    assert content.default_plugin_directory() == tmp_path / "image-content"


def test_a_run_refuses_plugins_when_the_receipt_does_not_match_the_config(tmp_path: Path):
    repo = tmp_path / "plugins.git"
    commit = _repo(repo, {"acme_banner.rhai": CUSTOM})
    dest = tmp_path / "installed"
    content.fetch_plugins(dest, [_source("acme", repo, commit)])
    other = content.PulsePluginSource(name="other", repo="https://git.example/other.git", ref="v9")
    out = pulse_probe.run_pulse_probe(
        [],
        output_dir=tmp_path / "run",
        plugins=True,
        plugins_dir=str(dest),
        plugin_sources=[other],
        retry_settle_seconds=0,
        observation_receipts_enabled=False,
    )
    receipt = json.loads((out / "raw.json").read_text(encoding="utf-8"))["adapter"]["plugins"]
    assert receipt["active"] is False
    assert receipt["loaded"] == []
    assert "other" in receipt["unavailable"] or "do not match" in receipt["unavailable"]
    assert receipt["content"]["sources"][0]["name"] == "acme"


def test_a_matching_receipt_is_what_the_run_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "plugins.git"
    commit = _repo(repo, {"acme_banner.rhai": CUSTOM})
    dest = tmp_path / "installed"
    source = _source("acme", repo, commit)
    content.fetch_plugins(dest, [source])
    monkeypatch.setattr(pulse_probe, "_pulse_available", lambda _binary: False)
    out = pulse_probe.run_pulse_probe(
        [],
        output_dir=tmp_path / "run",
        plugins=True,
        plugins_dir=str(dest),
        plugin_sources=[source],
        retry_settle_seconds=0,
        observation_receipts_enabled=False,
    )
    receipt = json.loads((out / "raw.json").read_text(encoding="utf-8"))["adapter"]["plugins"]
    # No pulse binary: the file is offered, not loaded. The source still matches.
    assert receipt["unavailable"] is None
    assert receipt["offered_digest"]
    assert receipt["content"]["sources"] == [
        {"name": "acme", "repo": repo.as_uri(), "ref": commit, "commit": commit, "path": ""}
    ]


def _stage_dirs(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    seen: list[Path] = []
    real = tempfile.mkdtemp

    def spy(*args, **kwargs):
        if kwargs.get("dir") is not None:
            seen.append(Path(kwargs["dir"]))
        return real(*args, **kwargs)

    monkeypatch.setattr(content.tempfile, "mkdtemp", spy)
    return seen


def test_a_mount_is_staged_inside_the_destination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "plugins.git"
    commit = _repo(repo, {"acme_banner.rhai": CUSTOM})
    dest = tmp_path / "pulse-plugins"
    dest.mkdir()
    (dest / "old.rhai").write_text("old\n", encoding="utf-8")
    seen = _stage_dirs(monkeypatch)
    monkeypatch.setattr(content, "_is_mountpoint", lambda _path: True)
    content.fetch_plugins(dest, [_source("acme", repo, commit)])
    assert seen == [dest]
    assert (dest / "acme_banner.rhai").read_text(encoding="utf-8") == CUSTOM
    assert not (dest / "old.rhai").exists()
    assert not [path for path in dest.iterdir() if path.name.startswith(".pulse-plugins.")]


def test_an_unwritable_parent_is_staged_inside_the_destination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "plugins.git"
    commit = _repo(repo, {"acme_banner.rhai": CUSTOM})
    parent = tmp_path / "volume"
    parent.mkdir()
    dest = parent / "pulse-plugins"
    dest.mkdir()
    (dest / "old.rhai").write_text("old\n", encoding="utf-8")
    seen = _stage_dirs(monkeypatch)
    monkeypatch.setattr(content, "_is_mountpoint", lambda _path: False)
    real_access = os.access

    def access(path, mode, *, follow_symlinks=True):
        if Path(path) == parent and mode == os.W_OK:
            return False
        return real_access(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(content.os, "access", access)
    content.fetch_plugins(dest, [_source("acme", repo, commit)])
    assert seen == [dest]
    assert (dest / "acme_banner.rhai").read_text(encoding="utf-8") == CUSTOM
    assert not (dest / "old.rhai").exists()
    assert not [path for path in dest.iterdir() if path.name.startswith(".pulse-plugins.")]


def test_a_symlink_in_the_checkout_cannot_install_files_from_outside(tmp_path: Path):
    outside = tmp_path / "outside" / "plugins"
    outside.mkdir(parents=True)
    (outside / "acme_x.rhai").write_text(CUSTOM, encoding="utf-8")
    repo = tmp_path / "repo.git"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "keep.txt").write_text("ok\n", encoding="utf-8")
    (repo / "a").symlink_to(outside.parent, target_is_directory=True)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "link")
    commit = _git(repo, "rev-parse", "HEAD")
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep.rhai").write_text("stay\n", encoding="utf-8")
    with pytest.raises(content.PulseContentError, match="symlink"):
        content.fetch_plugins(dest, [_source("acme", repo, commit, path="a/plugins")])
    assert (dest / "keep.rhai").read_text(encoding="utf-8") == "stay\n"
    assert not (dest / "acme_x.rhai").exists()


def test_a_failed_cross_device_copy_restores_the_previous_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    dest = tmp_path / "plugins"
    dest.mkdir()
    (dest / "keep.rhai").write_text("stay\n", encoding="utf-8")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "new.rhai").write_text("new\n", encoding="utf-8")
    monkeypatch.setattr(content, "_is_mountpoint", lambda _path: False)
    original = Path.rename
    calls = {"n": 0}

    def rename(self: Path, target):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError(errno.EXDEV, "cross device")
        return original(self, target)

    def copy_fails(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(Path, "rename", rename)
    monkeypatch.setattr(content.shutil, "copytree", copy_fails)
    with pytest.raises(OSError, match="disk full"):
        content._swap_in(staging, dest)
    assert (dest / "keep.rhai").read_text(encoding="utf-8") == "stay\n"
    assert not (dest / "new.rhai").exists()
    assert not list(tmp_path.glob(".pulse-plugins.old.*"))
