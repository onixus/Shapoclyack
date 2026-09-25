#!/usr/bin/env bash
# Shared "talk to a GenDec release" helpers, sourced by scripts/install-pulse.sh
# and scripts/pulse-pin.sh. Not executable on its own.
#
# The caller sets, before calling any of these (they are read at call time, so
# sourcing may come first):
#   REPO    owner/repo of the GenDec repository
#   VERSION release tag, with the leading v
#   TOKEN   GitHub token, or "" for the public path
#   tmp     a scratch directory it owns
#
# No `set -x` in anything that sources this: the token would be traced.

# Print the API url of a named asset from a release JSON document on stdin.
asset_api_url() {
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg name "$1" '.assets[] | select(.name == $name) | .url'
  else
    python3 -c '
import json, sys
name = sys.argv[1]
print(next((a["url"] for a in json.load(sys.stdin).get("assets", []) if a.get("name") == name), ""))
' "$1"
  fi
}

# Exit code for "not on the release" -- the only case where skipping the
# checksum is a sane answer -- as opposed to a download that merely failed
# and should be retried. Decided on the HTTP status, not curl's exit code:
# with -f curl reports a 404 as 22 over HTTP/1.1 but as 56 over HTTP/2.
readonly RC_NO_ASSET=44

http_get() {  # http_get <url> <dest> [curl header args...]
  local url="$1" dest="$2" code
  shift 2
  code="$(curl -sSL "$@" -o "$dest" -w '%{http_code}' "$url")" || return 1
  case "$code" in
    2??) return 0 ;;
    404) rm -f "$dest"; return "$RC_NO_ASSET" ;;
    *) echo "HTTP ${code} from ${url}" >&2; rm -f "$dest"; return 1 ;;
  esac
}

release_json=""
fetch_asset() {  # fetch_asset <asset name> <dest path>
  local asset_name="$1" dest="$2" asset_url rc=0
  if [[ -n "$TOKEN" ]]; then
    # Private repos: releases/download/<tag>/<name> answers 404 even with a
    # valid token (that path only serves public repos and browser sessions).
    # Resolve the numeric asset id through the API, then fetch the asset
    # endpoint with Accept: application/octet-stream.
    if [[ -z "$release_json" ]]; then
      http_get "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" "${tmp}/release.json" \
        -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" || rc=$?
      if [[ "$rc" == "$RC_NO_ASSET" ]]; then
        echo "no release ${VERSION} in ${REPO} (or the token cannot see it)" >&2
        return "$RC_NO_ASSET"
      elif [[ "$rc" != 0 ]]; then
        return "$rc"
      fi
      release_json="$(cat "${tmp}/release.json")"
    fi
    asset_url="$(printf '%s' "$release_json" | asset_api_url "$asset_name")"
    if [[ -z "$asset_url" || "$asset_url" == "null" ]]; then
      echo "release ${VERSION} of ${REPO} has no asset named ${asset_name}" >&2
      return "$RC_NO_ASSET"
    fi
    echo "==> downloading ${asset_name} (private release, via API)"
    http_get "$asset_url" "$dest" \
      -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/octet-stream"
  else
    local url="https://github.com/${REPO}/releases/download/${VERSION}/${asset_name}"
    echo "==> downloading ${url}"
    # The public path cannot tell a missing asset from a missing release (or a
    # private one without a token); a 404 is "no asset" either way.
    http_get "$url" "$dest"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

