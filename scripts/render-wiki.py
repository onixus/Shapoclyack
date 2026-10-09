#!/usr/bin/env python3
"""Render repository wiki sources for GitHub Wiki without network access."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'(?P<prefix>\]\()(?P<target><[^>]+>|[^\s)]+)(?P<suffix>(?:\s+"[^"]*")?\))')


def repository_url(value: str) -> str:
    """Accept HTTPS and the SSH origin formats GitHub uses."""
    if value.startswith("git@"):
        value = "https://" + value[4:].replace(":", "/", 1)
    elif value.startswith("ssh://git@"):
        value = "https://" + value[len("ssh://git@"):]
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or len(parsed.path.strip("/").split("/")) != 2):
        raise argparse.ArgumentTypeError("Expected an HTTPS or SSH owner/repository origin")
    return value.rstrip("/").removesuffix(".git")


def render_page(text: str, source: Path, pages: dict[Path, str], repo_url: str, ref: str) -> str:
    def replace(match: re.Match) -> str:
        target = match["target"].strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)
        path = (source.parent / unquote(parsed.path)).resolve()
        relative = path.relative_to(ROOT)
        if not path.exists():
            raise ValueError(f"{source.name}: missing link target {target}")
        if path in pages:
            url = quote(pages[path])
        else:
            kind = "tree" if path.is_dir() else "blob"
            url = f"{repo_url}/{kind}/{quote(ref, safe='')}/{quote(relative.as_posix())}"
        if parsed.query:
            url += "?" + parsed.query
        if parsed.fragment:
            url += "#" + parsed.fragment
        return match["prefix"] + url + match["suffix"]

    # Examples in fenced code blocks are not navigation links.
    output = []
    fence = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            output.append(line)
        else:
            output.append(line if fence else LINK.sub(replace, line))
    return "".join(output)


def render(output: Path, repo_url: str, ref: str) -> None:
    sources = sorted((ROOT / "docs/wiki").glob("*.md"))
    pages = {path.resolve(): "Home" if path.name == "README.md" else path.stem for path in sources}
    if len(set(pages.values())) != len(pages):
        raise ValueError("Duplicate wiki page name: README.md already renders as Home.md")
    rendered = {pages[path.resolve()] + ".md": render_page(
        path.read_text(encoding="utf-8"), path, pages, repo_url, ref,
    ) for path in sources}
    output.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (output / name).write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo-url", type=repository_url, required=True)
    parser.add_argument("--ref", default="main", help="Revision for links back to repository files")
    args = parser.parse_args()
    if not args.ref:
        parser.error("--ref must not be empty")
    output = args.output.resolve()
    if output == ROOT or output.is_relative_to(ROOT / "docs/wiki"):
        parser.error("--output must not overwrite repository wiki sources")
    try:
        render(output, args.repo_url, args.ref)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Wiki rendering failed: {exc}\n")


if __name__ == "__main__":
    main()
