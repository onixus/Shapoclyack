#!/usr/bin/env python3
"""Build the sensor bundle a native sensor updates from (#363).

    python3 scripts/sensor_bundle.py build --out dist/sensor-bundle [--revision SHA]

writes two files into ``--out``:

* ``shapoclyack-sensor-<version>.tar.gz`` -- the ``agent`` package, regular
  files only, ``__pycache__`` left out. Reproducible: sorted members, owner
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


def _files(source: Path) -> list[Path]:
    found = []
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source)
        if "__pycache__" in rel.parts or path.suffix in (".pyc", ".pyo"):
            continue
        if path.is_symlink():
            raise SystemExit(f"{path} is a symlink; a bundle carries regular files only")
        if path.is_file():
            found.append(path)
    return found


def build_archive(source: Path) -> bytes:
    """The ``agent/`` tree as a reproducible ``.tar.gz``."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        dirs = sorted({p.relative_to(source).parent for p in _files(source)} | {Path(".")})
        for rel in dirs:
            info = tarfile.TarInfo(str(Path("agent") / rel) if str(rel) != "." else "agent")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            tar.addfile(info)
        for path in _files(source):
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


def build(source: Path, out_dir: Path, *, revision: str = "") -> dict:
    version = package_version(source)
    archive_name = f"shapoclyack-sensor-{version}.tar.gz"
    archive = build_archive(source)
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
    args = parser.parse_args(argv)
    manifest = build(args.source, args.out, revision=args.revision)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
