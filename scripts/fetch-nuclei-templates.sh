#!/usr/bin/env bash
# Refresh nuclei's template pack beyond whatever was bundled at the pinned
# NUCLEI_TEMPLATES_REF commit in Dockerfile/Dockerfile.allinone.
#
# Two modes.
#
# Upstream (default): nuclei's own supported update mechanism
# (-update-templates), which downloads the latest signed nuclei-templates
# release into the given directory — no separate checksum bookkeeping needed
# here, nuclei verifies the release itself. Requires the `nuclei` binary on PATH
# and a way out to GitHub.
#
# Mirror (#339): with NUCLEI_TEMPLATES_REPO set, templates come from that git
# repository instead — an internal mirror of projectdiscovery/nuclei-templates,
# over https, ssh or file:// — at NUCLEI_TEMPLATES_REF (a tag or a full commit
# id; required, because "whatever the mirror's default branch is today" is not
# a pin). NUCLEI_TEMPLATES_COMMIT, when set, is the commit that ref must resolve
# to: a tag on a mirror can be moved, a commit id cannot. nuclei is never asked
# to update anything in this mode, so it never reaches for the internet. The
# checkout is staged beside the destination and swapped in only once it is
# complete and verified; the resolved commit is recorded in
# <dest>/.shapoclyack-templates.json. OCTO_HTTPS_PROXY and OCTO_CA_BUNDLE apply
# (the bundle is added to the system trust store, as everywhere else).
#
# Usage:
#   ./scripts/fetch-nuclei-templates.sh                      # -> /usr/share/nuclei-templates
#   ./scripts/fetch-nuclei-templates.sh /path/to/templates
#   NUCLEI_TEMPLATES_REPO=https://git.internal/mirrors/nuclei-templates.git \
#   NUCLEI_TEMPLATES_REF=v10.2.8 \
#   NUCLEI_TEMPLATES_COMMIT=<40-hex commit> \
#     ./scripts/fetch-nuclei-templates.sh /data/nuclei-templates
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-/usr/share/nuclei-templates}"
REPO="${NUCLEI_TEMPLATES_REPO:-}"

if [[ -z "$REPO" ]]; then
  if ! command -v nuclei >/dev/null 2>&1; then
    echo "nuclei binary not found on PATH — skipping template refresh" >&2
    exit 1
  fi

  mkdir -p "$DEST"
  if nuclei -update-templates -update-template-dir "$DEST" -disable-update-check -silent; then
    echo "nuclei-templates refreshed under $DEST"
  else
    echo "nuclei-templates refresh FAILED — keeping existing templates under $DEST" >&2
    exit 1
  fi
  exit 0
fi

REF="${NUCLEI_TEMPLATES_REF:-}"
PIN="$(printf '%s' "${NUCLEI_TEMPLATES_COMMIT:-}" | tr '[:upper:]' '[:lower:]')"
SHOWN_REPO="$(python3 "$HERE/feed_fetch.py" redact "$REPO")"
if [[ -z "$REF" ]]; then
  echo "error: NUCLEI_TEMPLATES_REPO is set but NUCLEI_TEMPLATES_REF is not; name a tag or a commit" >&2
  exit 2
fi
if [[ -n "$PIN" && ! "$PIN" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: NUCLEI_TEMPLATES_COMMIT must be a full 40-character commit id" >&2
  exit 2
fi

PARENT="$(dirname "$DEST")"
mkdir -p "$PARENT"
# Beside the destination, so the swap below is a rename on one filesystem.
STAGING="$(mktemp -d "$PARENT/.nuclei-templates.XXXXXX")"
OLD=""
cleanup() {
  rm -rf "$STAGING"
  [[ -n "$OLD" ]] && rm -rf "$OLD"
}
trap cleanup EXIT

# Same proxy and trust store as every other feed. git reads https_proxy itself;
# GIT_SSL_CAINFO *replaces* its store, so it is handed the system store with the
# internal root appended rather than the root alone.
if [[ -n "${OCTO_HTTPS_PROXY:-}" ]]; then
  export https_proxy="$OCTO_HTTPS_PROXY"
fi
if [[ -n "${OCTO_CA_BUNDLE:-}" ]]; then
  if ! python3 "$HERE/feed_fetch.py" ca-bundle -o "$STAGING.ca.pem"; then
    echo "error: OCTO_CA_BUNDLE=$OCTO_CA_BUNDLE is not usable" >&2
    exit 1
  fi
  export GIT_SSL_CAINFO="$STAGING.ca.pem"
  trap 'cleanup; rm -f "$STAGING.ca.pem"' EXIT
fi

git_q() { git -c advice.detachedHead=false -c init.defaultBranch=main "$@"; }

echo "==> nuclei-templates: ${SHOWN_REPO} @ ${REF}"
# A shallow fetch of exactly one ref: a tag, a branch, or a commit id (every
# git server since protocol v2 serves a reachable commit by id). No --tags, no
# history — the pack is the only thing that is wanted from the mirror.
if ! git_q init -q "$STAGING" \
  || ! git_q -C "$STAGING" fetch -q --depth 1 --no-tags "$REPO" "$REF" \
  || ! git_q -C "$STAGING" checkout -q --detach FETCH_HEAD; then
  echo "nuclei-templates: fetch of ${REF} from ${SHOWN_REPO} FAILED — keeping existing templates under $DEST" >&2
  exit 1
fi
COMMIT="$(git -C "$STAGING" rev-parse HEAD)"
if [[ "$REF" =~ ^[0-9a-fA-F]{40}$ && "$COMMIT" != "$(printf '%s' "$REF" | tr '[:upper:]' '[:lower:]')" ]]; then
  echo "error: ${REF} resolved to ${COMMIT}; refusing" >&2
  exit 1
fi
if [[ -n "$PIN" && "$COMMIT" != "$PIN" ]]; then
  echo "error: ${REF} on ${SHOWN_REPO} is ${COMMIT}, not the pinned NUCLEI_TEMPLATES_COMMIT ${PIN}; refusing" >&2
  exit 1
fi
if [[ -z "$(find "$STAGING" -path "$STAGING/.git" -prune -o -name '*.yaml' -print -quit)" ]]; then
  echo "error: ${SHOWN_REPO} @ ${REF} holds no templates (*.yaml); refusing to replace $DEST" >&2
  exit 1
fi
rm -rf "$STAGING/.git"
python3 - "$STAGING/.shapoclyack-templates.json" "$SHOWN_REPO" "$REF" "$COMMIT" <<'PY'
import json, sys
from datetime import datetime, timezone

out, repo, ref, commit = sys.argv[1:5]
with open(out, "w", encoding="utf-8") as fh:
    json.dump(
        {
            "repo": repo,
            "ref": ref,
            "commit": commit,
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        fh,
        indent=2,
        sort_keys=True,
    )
    fh.write("\n")
PY
chmod -R a+rX "$STAGING"

# Two renames, never a copy over the live tree: a scan reading templates sees
# either the old pack or the new one, and a failure between them puts the old
# one back.
if [[ -e "$DEST" ]]; then
  OLD="$PARENT/.nuclei-templates.old.$$"
  if ! mv "$DEST" "$OLD"; then
    OLD=""
    echo "error: could not move $DEST aside" >&2
    exit 1
  fi
fi
if ! mv "$STAGING" "$DEST"; then
  [[ -n "$OLD" ]] && mv "$OLD" "$DEST" && OLD=""
  echo "error: could not move the new templates into $DEST; the previous ones are back in place" >&2
  exit 1
fi
echo "nuclei-templates: ${SHOWN_REPO} @ ${REF} (${COMMIT}) installed under $DEST"
