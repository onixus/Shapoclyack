#!/usr/bin/env bash
# Render docs/wiki/ locally, or publish it to the origin's GitHub Wiki.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT=""
REF="main"
usage() {
    echo "Usage: $0 [--output DIRECTORY] [--ref REVISION]"
    echo "--output renders locally without cloning, committing or pushing."
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|--ref)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "Missing value for $1" >&2
                exit 2
            fi
            if [[ "$1" == --output ]]; then OUTPUT="$2"; else REF="$2"; fi
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

ORIGIN_URL="$(git -C "$REPO_DIR" config --get remote.origin.url || true)"
if [[ -z "$ORIGIN_URL" ]]; then
    echo "Error: git remote.origin.url is not set." >&2
    exit 1
fi

render() {
    python3 "$REPO_DIR/scripts/render-wiki.py" --output "$1" --repo-url "$ORIGIN_URL" --ref "$REF"
}
if [[ -n "$OUTPUT" ]]; then
    render "$OUTPUT"
    echo "Wiki rendered to $OUTPUT"
    exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
# Validate and render before making any network calls.
render "$TMP_DIR/rendered"
ORIGIN_URL="${ORIGIN_URL%/}"
WIKI_URL="${ORIGIN_URL%.git}.wiki.git"
if ! git clone "$WIKI_URL" "$TMP_DIR/wiki"; then
    echo "Enable GitHub Wiki, create its initial page, and check repository access." >&2
    exit 1
fi
cp "$TMP_DIR/rendered/"*.md "$TMP_DIR/wiki/"
git -C "$TMP_DIR/wiki" add -- '*.md'
if git -C "$TMP_DIR/wiki" diff --staged --quiet; then
    echo "Wiki is already up to date."
else
    git -C "$TMP_DIR/wiki" commit -m "docs(wiki): update role guides and navigation"
    # Push the branch actually cloned; a failed push is not a branch probe.
    git -C "$TMP_DIR/wiki" push origin HEAD
    echo "Wiki published."
fi
