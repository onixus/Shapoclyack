"""Rhai plugin content installed from git, not from the image.

Release images do not contain ``scanner/pipeline/pulse_data/plugins``. That
tree is the official content in this repository. ``scripts/fetch-pulse-plugins.sh``
checks one or more repositories out and installs a flat directory of
``*.rhai`` files (default ``/var/lib/shapoclyack/pulse-plugins``). A sensor
reads that directory. A development checkout still uses the tree in the
repository when the content directory has not been installed.

A later source cannot replace a file an earlier source already installed.
The first source is the one the operator trusts. Symlinks, odd names and
oversized files are left out of the directory Pulse is given.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

CONTENT_DIR = Path("/var/lib/shapoclyack/pulse-plugins")
RECEIPT_NAME = ".shapoclyack-plugins.json"
TRACE_PLUGIN_NAME = "shapo_http_trace.rhai"
OFFICIAL_REPO = "https://github.com/onixus/Shapoclyack.git"
OFFICIAL_PATH = "scanner/pipeline/pulse_data/plugins"

MAX_SOURCES = 8
MAX_FILES = 400
MAX_PLUGIN_BYTES = 65_536
GIT_TIMEOUT_SECONDS = 180

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PLUGIN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
_SCP_REPO = re.compile(r"^git@[A-Za-z0-9._-]+:[A-Za-z0-9._~/-]+$")


class PulseContentError(RuntimeError):
    """The plugin directory was not replaced."""


class PulsePluginSource(BaseModel):
    """One git repository of ``*.rhai`` files. Credentials stay out of the URL."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,40}$")
    repo: str
    ref: str
    commit: str = ""
    path: str = ""

    @field_validator("repo")
    @classmethod
    def _repo(cls, value: str) -> str:
        return validate_repo(value)

    @field_validator("ref")
    @classmethod
    def _ref(cls, value: str) -> str:
        if not _REF.fullmatch(value) or ".." in value.split("/"):
            raise ValueError("plugin ref must be a branch, tag or commit without '..'")
        return value

    @field_validator("commit", mode="before")
    @classmethod
    def _commit(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        value = value.strip().lower()
        if value and not _COMMIT.fullmatch(value):
            raise ValueError("plugin commit must be a full 40-character id")
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return validate_subpath(value)


def validate_repo(url: str) -> str:
    """Accept ``https``, ``ssh``, ``file`` and ``git@host:path``.

    A password, a query and a fragment are refused. A query is where a token
    usually sits, and a mismatch would otherwise copy that URL into the scan
    artifact.
    """
    url = url.strip()
    if not url or any(char in url for char in " \t\r\n\x00"):
        raise ValueError("plugin repo must be a single URL")
    if url.startswith("-"):
        raise ValueError("plugin repo must not look like an option")
    if url.startswith("git@"):
        if not _SCP_REPO.fullmatch(url) or ".." in url.split(":", 1)[1].split("/"):
            raise ValueError("plugin repo must look like git@host:path")
        return url
    parts = urlsplit(url)
    if parts.scheme not in {"https", "ssh", "file"}:
        raise ValueError("plugin repo must use https, ssh, file, or git@host:path")
    if parts.password or (parts.username and parts.username != "git"):
        raise ValueError("plugin repo must not carry credentials")
    if parts.query or parts.fragment:
        raise ValueError("plugin repo must not carry a query or a fragment")
    if parts.scheme == "file":
        if parts.netloc not in {"", "localhost"} or not parts.path.startswith("/"):
            raise ValueError("a file plugin repo must be an absolute file:// path")
        return url
    if not parts.hostname or not parts.path or parts.path == "/":
        raise ValueError("plugin repo is missing a host or a path")
    return url


def validate_subpath(value: str) -> str:
    """A relative directory inside the repository. Empty means the root."""
    if value == "":
        return value
    if value.startswith("/") or "\\" in value:
        raise ValueError("plugin source path must be relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or not _SEGMENT.fullmatch(part) for part in parts):
        raise ValueError("plugin source path must be relative segments without '..'")
    return value


def redact_repo(url: str) -> str:
    """Drop userinfo and the query string before a repo is printed or recorded."""
    if url.startswith("git@"):
        return url
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port else host
    return parts._replace(netloc=netloc, query="", fragment="").geturl()


def default_plugin_directory() -> Path:
    """Where a run reads plugins when the config does not name a directory.

    ``OCTO_PULSE_PLUGINS_DIR`` wins. Otherwise the scripts in the checkout win,
    so tests and a local run keep using the git tree. An image has neither the
    tree nor the variable, and then the content directory is the one that
    ``fetch-pulse-plugins.sh`` fills.
    """
    configured = os.environ.get("OCTO_PULSE_PLUGINS_DIR", "").strip()
    if configured:
        return Path(configured)
    from scanner.pipeline import pulse_plugins

    shipped = pulse_plugins.PLUGINS_DIR
    if _has_rhai(shipped):
        return shipped
    return CONTENT_DIR


def read_trace_plugin(directory: Path | None = None) -> bytes:
    """Bytes of ``shapo_http_trace`` from the one directory a scan would use.

    ``directory`` is that path and the only file that is opened. ``None``
    follows ``default_plugin_directory()`` (the environment, then a checkout
    that contains plugins, then the content directory). A missing file is
    not replaced by a copy from somewhere else: the hash would no longer be
    the one the scan stored.
    """
    root = default_plugin_directory() if directory is None else directory
    path = root / TRACE_PLUGIN_NAME
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(TRACE_PLUGIN_NAME)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FileNotFoundError(TRACE_PLUGIN_NAME) from exc


def _has_rhai(root: Path) -> bool:
    if not root.is_dir():
        return False
    return any(path.is_file() and not path.is_symlink() for path in root.glob("*.rhai"))


def sources_from_env() -> list[PulsePluginSource]:
    """The single official source named by ``PULSE_PLUGINS_*``.

    ``PULSE_PLUGINS_REF`` is required. There is no floating default branch.
    The official repository is the default repo, and its plugin directory is
    the default path. A different repo defaults to its own root.
    """
    repo = os.environ.get("PULSE_PLUGINS_REPO", "").strip() or OFFICIAL_REPO
    ref = os.environ.get("PULSE_PLUGINS_REF", "").strip()
    if not ref:
        raise PulseContentError(
            "PULSE_PLUGINS_REF is required (a tag or a full commit). "
            "Images do not ship the Rhai plugins; scripts/fetch-pulse-plugins.sh installs them."
        )
    path = os.environ.get("PULSE_PLUGINS_PATH")
    if path is None:
        path = OFFICIAL_PATH if repo.rstrip("/") == OFFICIAL_REPO else ""
    name = os.environ.get("PULSE_PLUGINS_NAME", "").strip() or "official"
    return [
        PulsePluginSource(
            name=name,
            repo=repo,
            ref=ref,
            commit=os.environ.get("PULSE_PLUGINS_COMMIT", ""),
            path=path,
        )
    ]


def sources_from_config(path: Path) -> list[PulsePluginSource]:
    """``service_probe.pulse.plugin_sources`` from a scan config file."""
    import yaml

    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(document, dict):
        raise PulseContentError(f"{path} is not a mapping")
    pulse = (document.get("service_probe") or {}).get("pulse") or {}
    raw = pulse.get("plugin_sources") or []
    if not isinstance(raw, list):
        raise PulseContentError("service_probe.pulse.plugin_sources must be a list")
    if not raw:
        return []
    return _validate_sources(raw)


def sources_from_file(path: Path) -> list[PulsePluginSource]:
    """A JSON list of plugin sources, the whole set to install."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise PulseContentError(f"{path} must be a JSON list")
    return _validate_sources(raw)


def _validate_sources(raw: Sequence[Any]) -> list[PulsePluginSource]:
    from pydantic import ValidationError

    if len(raw) > MAX_SOURCES:
        raise PulseContentError(f"at most {MAX_SOURCES} plugin sources")
    try:
        sources = [PulsePluginSource.model_validate(item) for item in raw]
    except ValidationError as exc:
        line = exc.errors()[0]
        loc = ".".join(str(part) for part in line.get("loc", ()))
        raise PulseContentError(f"{loc}: {line.get('msg', exc)}") from exc
    names = [source.name for source in sources]
    if len(names) != len(set(names)):
        raise PulseContentError("plugin source names must be unique")
    if not sources:
        raise PulseContentError("plugin source list is empty")
    return sources


def resolve_sources(*, config: Path | None = None, sources_file: Path | None = None) -> list[PulsePluginSource]:
    """Sources for one fetch. A file, a scan config, or the environment, not two of them.

    A scan config whose ``plugin_sources`` list is empty falls through to
    ``PULSE_PLUGINS_*``, so the shipped config can be named and the pin passed
    in the environment.
    """
    env_file = os.environ.get("PULSE_PLUGINS_SOURCES", "").strip()
    if sources_file is None and env_file:
        sources_file = Path(env_file)
    if sources_file is not None and config is not None:
        raise PulseContentError("pass either PULSE_PLUGINS_SOURCES or --config, not both")
    if sources_file is not None:
        return sources_from_file(sources_file)
    if config is not None:
        listed = sources_from_config(config)
        if listed:
            return listed
    return sources_from_env()


def materialize(checkouts: Sequence[Mapping[str, str]], dest: Path) -> dict[str, Any]:
    """Copy accepted ``*.rhai`` files into an empty ``dest`` and write the receipt.

    ``checkouts`` are already on disk. Each mapping has ``name``, ``root``,
    ``repo``, ``ref``, ``commit`` and ``path``. ``work``, when present, is the
    clone; a root that leaves it through a symlink is refused. Earlier sources
    win a name. Once ``MAX_FILES`` entries have been recorded, one further
    file is noted and the rest are left out. The fetch still succeeds.
    """
    if not checkouts:
        raise PulseContentError("no plugin checkouts to install")
    if len(checkouts) > MAX_SOURCES:
        raise PulseContentError(f"at most {MAX_SOURCES} plugin sources")
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise PulseContentError(f"{dest} is not an empty directory")

    installed: dict[str, dict[str, str]] = {}
    collisions: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    source_rows: list[dict[str, Any]] = []
    capped = False
    for item in checkouts:
        source = PulsePluginSource.model_validate(
            {
                "name": item["name"],
                "repo": item["repo"],
                "ref": item["ref"],
                "commit": item["commit"],
                "path": item.get("path") or "",
            }
        )
        if not _COMMIT.fullmatch(source.commit):
            raise PulseContentError(f"{source.name}: checkout has no resolved commit")
        raw_root = Path(item["root"])
        work = Path(item["work"]) if item.get("work") else None
        if work is not None:
            _contained_checkout(raw_root, work, source.name)
            root = raw_root
            boundary = work.resolve()
        else:
            root = raw_root.resolve()
            if not root.is_dir():
                raise PulseContentError(f"{source.name}: {root} is not a directory")
            boundary = root
        taken = 0
        seen = 0
        if not capped:
            for path in sorted(root.glob("*.rhai")):
                seen += 1
                if seen > MAX_FILES or len(installed) + len(skipped) + len(collisions) >= MAX_FILES:
                    skipped.append(
                        {
                            "name": path.stem,
                            "source": source.name,
                            "reason": f"more than {MAX_FILES} plugin files",
                        }
                    )
                    capped = True
                    break
                decision = _consider(path, boundary, source.name, installed)
                if decision[0] == "installed":
                    installed[path.stem] = {
                        "name": path.stem,
                        "sha256": decision[1],
                        "source": source.name,
                        "bytes": decision[2],
                    }
                    taken += 1
                else:
                    (collisions if decision[0] == "collision" else skipped).append(decision[1])
        source_rows.append(
            {
                "name": source.name,
                "repo": redact_repo(source.repo),
                "ref": source.ref,
                "commit": source.commit,
                "path": source.path,
                "files": taken,
            }
        )
    if not installed:
        raise PulseContentError("no .rhai plugins were accepted")
    for name in sorted(installed):
        row = installed[name]
        target = dest / f"{name}.rhai"
        target.write_bytes(row.pop("bytes"))
        os.chmod(target, 0o644)
    receipt = {
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sources": source_rows,
        "files": [{key: installed[name][key] for key in ("name", "sha256", "source")} for name in sorted(installed)],
        "collisions": collisions,
        "skipped": skipped,
    }
    receipt_path = dest / RECEIPT_NAME
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(receipt_path, 0o644)
    os.chmod(dest, 0o755)
    return receipt


def _consider(
    path: Path, root: Path, source: str, installed: Mapping[str, Mapping[str, str]]
) -> tuple[str, Any]:
    name = path.stem
    if path.is_symlink() or not path.is_file():
        return "skipped", {"name": name, "source": source, "reason": "not a regular file"}
    if not _PLUGIN_NAME.fullmatch(name):
        return "skipped", {"name": name, "source": source, "reason": "plugin name is not accepted"}
    try:
        resolved = path.resolve()
    except OSError:
        return "skipped", {"name": name, "source": source, "reason": "unreadable"}
    if not resolved.is_relative_to(root):
        return "skipped", {"name": name, "source": source, "reason": "outside the source directory"}
    try:
        size = path.stat().st_size
    except OSError:
        return "skipped", {"name": name, "source": source, "reason": "unreadable"}
    if size > MAX_PLUGIN_BYTES:
        return "skipped", {"name": name, "source": source, "reason": f"larger than {MAX_PLUGIN_BYTES} bytes"}
    try:
        blob = path.read_bytes()
    except OSError:
        return "skipped", {"name": name, "source": source, "reason": "unreadable"}
    if len(blob) > MAX_PLUGIN_BYTES:
        return "skipped", {"name": name, "source": source, "reason": f"larger than {MAX_PLUGIN_BYTES} bytes"}
    if name in installed:
        return "collision", {
            "name": name,
            "source": source,
            "kept": installed[name]["source"],
            "reason": f"already installed from {installed[name]['source']}",
        }
    return "installed", hashlib.sha256(blob).hexdigest(), blob


def read_receipt(directory: Path | None) -> dict[str, Any] | None:
    if directory is None:
        return None
    path = directory / RECEIPT_NAME
    if path.is_symlink() or not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    return document


def content_summary(directory: Path | None) -> dict[str, Any] | None:
    """The git identity recorded next to the plugins, without the file list."""
    receipt = read_receipt(directory)
    if receipt is None:
        return None
    sources = []
    for row in receipt.get("sources") or []:
        if not isinstance(row, dict):
            continue
        sources.append({key: row.get(key) for key in ("name", "repo", "ref", "commit", "path")})
    collisions = []
    for row in receipt.get("collisions") or []:
        if isinstance(row, dict) and row.get("name") and row.get("source"):
            collisions.append(f"{row['name']}:{row['source']}")
    return {"sources": sources, "collisions": collisions}


def content_mismatch(directory: Path | None, sources: Sequence[Any]) -> str | None:
    """Why ``sources`` are not what is installed, or ``None`` when they match.

    An empty commit on a source accepts whatever commit the fetch resolved.
    A set commit must be that commit: a moved tag is then refused.
    """
    if not sources:
        return None
    if directory is None:
        return "plugin content is not installed"
    receipt = read_receipt(directory)
    if receipt is None:
        return f"no plugin receipt in {directory}; run scripts/fetch-pulse-plugins.sh"
    got = receipt.get("sources")
    if not isinstance(got, list) or len(got) != len(sources):
        return "installed plugin sources do not match the configured list"
    for expected, actual in zip(sources, got, strict=True):
        if not isinstance(actual, dict):
            return "installed plugin receipt is unreadable"
        name, repo, ref, commit, path = _expected_fields(expected)
        if actual.get("name") != name or actual.get("repo") != redact_repo(repo) or actual.get("ref") != ref:
            return f"installed plugin source {name!r} is not {redact_repo(repo)} @ {ref}"
        if actual.get("path") != path:
            return f"installed plugin source {name!r} path is not {path or '/'}"
        resolved = str(actual.get("commit") or "")
        if not _COMMIT.fullmatch(resolved):
            return f"installed plugin source {name!r} has no commit"
        if commit and resolved != commit:
            return f"installed plugin source {name!r} is {resolved}, not {commit}"
    return None


def _expected_fields(source: Any) -> tuple[str, str, str, str, str]:
    if isinstance(source, PulsePluginSource):
        return source.name, source.repo, source.ref, source.commit, source.path
    if isinstance(source, Mapping):
        model = PulsePluginSource.model_validate(dict(source))
        return model.name, model.repo, model.ref, model.commit, model.path
    raise PulseContentError("plugin source is not a mapping")


def fetch_plugins(dest: Path, sources: Sequence[PulsePluginSource]) -> dict[str, Any]:
    """Clone ``sources``, install into ``dest``, and leave ``dest`` untouched on failure.

    The stage directory is a sibling of ``dest`` when the parent can hold it,
    so the swap is one rename. A mount, and a parent this process cannot write
    (an image leaves ``/var/lib/shapoclyack`` root-owned and writable only on
    the leaf), is staged inside ``dest`` under a ``.pulse-plugins.`` name the
    swap skips. ``rename`` across that mount would fail with ``EXDEV`` and the
    directory would stay empty.
    """
    sources = _validate_sources([source.model_dump() for source in sources])
    created = not dest.exists()
    dest.mkdir(parents=True, exist_ok=True)
    stage_in_dest = _is_mountpoint(dest) or not os.access(dest.parent, os.W_OK)
    stage_parent = dest if stage_in_dest else dest.parent
    staging = Path(tempfile.mkdtemp(prefix=".pulse-plugins.", dir=stage_parent))
    try:
        checkouts: list[dict[str, str]] = []
        for source in sources:
            checkout = staging / "src" / source.name
            root, commit = _checkout(checkout, source)
            checkouts.append(
                {
                    "name": source.name,
                    "root": str(root),
                    "work": str(checkout),
                    "repo": source.repo,
                    "ref": source.ref,
                    "commit": commit,
                    "path": source.path,
                }
            )
        out = staging / "out"
        out.mkdir()
        receipt = materialize(checkouts, out)
        _swap_in(out, dest)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if created:
            try:
                dest.rmdir()
            except OSError:
                pass
        raise
    shutil.rmtree(staging, ignore_errors=True)
    return receipt


def _checkout(work: Path, source: PulsePluginSource) -> tuple[Path, str]:
    work.parent.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", str(work)])
    fetch = _git(
        ["-C", str(work), "fetch", "-q", "--depth", "1", "--no-tags", "--", source.repo, source.ref],
        timeout=GIT_TIMEOUT_SECONDS,
    )
    if fetch.returncode != 0:
        detail = _git_detail(fetch)
        raise PulseContentError(f"{source.name}: fetch of {source.ref} from {redact_repo(source.repo)} failed{detail}")
    checkout = _git(["-C", str(work), "checkout", "-q", "--detach", "FETCH_HEAD"])
    if checkout.returncode != 0:
        raise PulseContentError(f"{source.name}: checkout of {source.ref} failed")
    commit = _git(["-C", str(work), "rev-parse", "HEAD"], check=True).stdout.strip().lower()
    if not _COMMIT.fullmatch(commit):
        raise PulseContentError(f"{source.name}: resolved revision is not a commit")
    if _COMMIT.fullmatch(source.ref) and commit != source.ref.lower():
        raise PulseContentError(f"{source.name}: {source.ref} resolved to {commit}")
    if source.commit and commit != source.commit:
        raise PulseContentError(
            f"{source.name}: {source.ref} on {redact_repo(source.repo)} is {commit}, not {source.commit}"
        )
    root = work if not source.path else work / source.path
    _contained_checkout(root, work, source.name)
    return root, commit


def _contained_checkout(root: Path, work: Path, source: str) -> None:
    """Raise when ``root`` is not a real directory inside the clone ``work``.

    Git checks out symlinks. A later component of ``path`` can be a real
    directory reached through an earlier symlink, so ``is_dir()`` is true and
    ``is_symlink()`` on the final component is false. Resolving that path
    leaves the clone, and a less-trusted repository would then install every
    flat ``*.rhai`` from the outside directory.
    """
    current = root
    for _ in range(64):
        if current.is_symlink():
            raise PulseContentError(f"{source}: {root} leaves the checkout through a symlink")
        if current == work:
            break
        parent = current.parent
        if parent == current:
            raise PulseContentError(f"{source}: {root} is outside the checkout")
        current = parent
    else:
        raise PulseContentError(f"{source}: {root} is outside the checkout")
    try:
        resolved = root.resolve()
        boundary = work.resolve()
    except OSError as exc:
        raise PulseContentError(f"{source}: {root} is not a directory in the checkout") from exc
    if not resolved.is_dir() or not resolved.is_relative_to(boundary):
        raise PulseContentError(f"{source}: {root} is outside the checkout")


def _git(args: list[str], *, timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess[str]:
    command = ["git", "-c", "advice.detachedHead=false", "-c", "init.defaultBranch=main", *args]
    try:
        done = subprocess.run(  # noqa: S603 - argv list, git itself
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PulseContentError("git is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise PulseContentError("git timed out") from exc
    if check and done.returncode != 0:
        raise PulseContentError(_git_detail(done) or "git failed")
    return done


def _git_detail(done: subprocess.CompletedProcess[str]) -> str:
    text = (done.stderr or done.stdout or "").strip()
    if not text:
        return ""
    line = text.splitlines()[-1].strip()
    return f": {line[:300]}"


def _swap_in(staging: Path, dest: Path) -> None:
    """Put ``staging`` in place of ``dest``. A failure puts the previous tree back.

    A stage directory that lives inside ``dest`` cannot be swapped by renaming
    ``dest``: the new tree would move with it. The same in-place swap is used
    for a mount, where renaming the directory itself is not possible.
    """
    if _is_mountpoint(dest) or _is_inside(staging, dest):
        _swap_contents(staging, dest)
        return
    old: Path | None = None
    if dest.exists():
        old = dest.with_name(f".pulse-plugins.old.{os.getpid()}")
        dest.rename(old)
    try:
        staging.rename(dest)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            if old is not None and not dest.exists():
                old.rename(dest)
            raise
        try:
            shutil.copytree(staging, dest, dirs_exist_ok=False)
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            if old is not None and not dest.exists():
                old.rename(dest)
            raise
        shutil.rmtree(staging, ignore_errors=True)
        if old is not None:
            shutil.rmtree(old, ignore_errors=True)
        return
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        return child.resolve().is_relative_to(parent.resolve())
    except (OSError, ValueError):
        return False


def _is_mountpoint(path: Path) -> bool:
    if not path.is_dir():
        return False
    mountpoint = shutil.which("mountpoint")
    if mountpoint:
        done = subprocess.run([mountpoint, "-q", str(path)], check=False)  # noqa: S603
        return done.returncode == 0
    try:
        return path.stat().st_dev != path.parent.stat().st_dev
    except OSError:
        return False


def _swap_contents(staging: Path, dest: Path) -> None:
    """Replace the entries of a mount point. Not atomic; the old tree is restored on failure."""
    aside = dest / f".pulse-plugins.old.{os.getpid()}"
    aside.mkdir()
    moved: list[Path] = []
    try:
        for entry in _entries(dest, aside.name):
            target = aside / entry.name
            entry.rename(target)
            moved.append(target)
        for entry in _entries(staging, ""):
            entry.rename(dest / entry.name)
    except OSError as exc:
        for entry in list(dest.iterdir()):
            if entry.name == aside.name:
                continue
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
        for entry in moved:
            entry.rename(dest / entry.name)
        shutil.rmtree(aside, ignore_errors=True)
        raise PulseContentError(f"could not replace the mount point {dest}") from exc
    shutil.rmtree(aside, ignore_errors=True)


def _entries(root: Path, skip: str) -> list[Path]:
    return [path for path in root.iterdir() if path.name != skip and not path.name.startswith(".pulse-plugins.")]


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Install Rhai Pulse plugins from git")
    parser.add_argument("command", choices=("sources", "fetch"))
    parser.add_argument("--dest", type=Path, default=CONTENT_DIR)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        sources = resolve_sources(config=args.config)
        if args.command == "sources":
            json.dump([source.model_dump() for source in sources], sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        receipt = fetch_plugins(args.dest, sources)
    except (PulseContentError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"pulse-plugins: {exc}", file=sys.stderr)
        return 2 if isinstance(exc, PulseContentError) and "PULSE_PLUGINS_REF" in str(exc) else 1
    shown = ", ".join(f"{row['name']}@{row['commit'][:12]}" for row in receipt["sources"])
    print(f"pulse-plugins: {shown} installed under {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
