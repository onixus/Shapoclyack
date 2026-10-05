#!/usr/bin/env python3
"""Build the sensor bundle a native sensor updates from (#363).

    python3 scripts/sensor_bundle.py build --out dist/sensor-bundle [--revision SHA]

writes two files into ``--out``:

* ``shapoclyack-sensor-<version>.tar.gz`` -- the ``agent`` package, the
  files git tracks in it only (``--whole-tree`` for a source that is not a
  checkout), regular files only, ``__pycache__`` left out. Reproducible: sorted members, owner
  0:0, fixed modes, mtime 0 in the tar headers and in the gzip header, so the
  same tree gives the same bytes and the same sha256 on any machine.
* ``sensor-bundle.json`` -- the manifest the release key signs: schema,
  version (the ``__version__`` literal in ``agent/__init__.py``), archive name,
  sha256 and size, and the source revision when given.

Signing is ``scripts/build-sensor-bundle.sh``, with cosign and the release key;
this script holds no key and needs nothing outside the standard library, so it
runs on the Jenkins host as it is.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "shapoclyack.sensor-bundle/v1"
MANIFEST_NAME = "sensor-bundle.json"
_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)


def package_version(source: Path) -> str:
    match = _VERSION_RE.search((source / "__init__.py").read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"no __version__ literal in {source / '__init__.py'}")
    return match.group(1)


def _tracked(source: Path) -> list[Path]:
    """The files git tracks under ``source``; a :class:`SystemExit` outside a checkout.

    Not a walk of the directory: a working copy also holds what was never
    committed -- an ``.env`` with a development key, editor and merge
    leftovers -- and the bundle is signed with the release key and installed
    on every sensor.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(source), "ls-files", "-z", "--", "."],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise SystemExit(
            f"cannot run git to list {source}: {exc}; pass --whole-tree to bundle every file under it"
        ) from exc
    if result.returncode != 0:
        raise SystemExit(
            f"{source} is not in a git checkout ({result.stderr.decode(errors='replace').strip()}); "
            "build from the release tag, or pass --whole-tree to bundle every file under it"
        )
    return [source / name for name in result.stdout.decode("utf-8").split("\0") if name]


def _files(source: Path, *, whole_tree: bool = False) -> list[Path]:
    found = []
    candidates = source.rglob("*") if whole_tree else _tracked(source)
    for path in sorted(candidates):
        rel = path.relative_to(source)
        if "__pycache__" in rel.parts or path.suffix in (".pyc", ".pyo"):
            continue
        if path.is_symlink():
            raise SystemExit(f"{path} is a symlink; a bundle carries regular files only")
        if path.is_file():
            found.append(path)
    return found


def build_archive(source: Path, *, whole_tree: bool = False) -> bytes:
    """The ``agent/`` tree as a reproducible ``.tar.gz``."""
    files = _files(source, whole_tree=whole_tree)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        dirs = sorted({p.relative_to(source).parent for p in files} | {Path(".")})
        for rel in dirs:
            info = tarfile.TarInfo(str(Path("agent") / rel) if str(rel) != "." else "agent")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            tar.addfile(info)
        for path in files:
            data = path.read_bytes()
            info = tarfile.TarInfo(str(Path("agent") / path.relative_to(source)))
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0, filename="") as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def build(source: Path, out_dir: Path, *, revision: str = "", whole_tree: bool = False) -> dict:
    version = package_version(source)
    archive_name = f"shapoclyack-sensor-{version}.tar.gz"
    archive = build_archive(source, whole_tree=whole_tree)
    manifest = {
        "schema": SCHEMA,
        "version": version,
        "archive": archive_name,
        "sha256": hashlib.sha256(archive).hexdigest(),
        "size": len(archive),
    }
    if revision:
        manifest["revision"] = revision
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / archive_name).write_bytes(archive)
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build", help="write the archive and its unsigned manifest")
    build_cmd.add_argument("--source", type=Path, default=ROOT / "agent")
    build_cmd.add_argument("--out", type=Path, default=ROOT / "dist" / "sensor-bundle")
    build_cmd.add_argument("--revision", default="", help="source revision to record")
    build_cmd.add_argument(
        "--whole-tree",
        action="store_true",
        help="bundle every file under --source, not only the ones git tracks "
        "(a source that is not a git checkout)",
    )
    args = parser.parse_args(argv)
    manifest = build(args.source, args.out, revision=args.revision, whole_tree=args.whole_tree)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
