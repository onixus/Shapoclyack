#!/usr/bin/env bash
# Fail when the Pulse version a release would ship is not the latest GenDec
# release.
#
#   GH_TOKEN=… scripts/check-pulse-latest.sh v1.3.0
#
# The owner's rule is that every release ships the latest Pulse. Pins are
# bumped by hand (scripts/pulse-pin.sh), so without this a release silently
# ships whatever was newest the last time somebody looked. Jenkinsfile.publish
# runs it before Build & push; a developer can run it any time.
#
# "Latest" is GitHub's own notion: the newest non-draft, non-prerelease
# release. A GenDec alpha/beta never makes the check fail.
#
# Exit codes: 0 up to date; 1 outdated; 2 usage; 3 could not ask GitHub
# (network, token cannot see the repo) -- the answer is unknown, not "fine".
#
# Reads the token from GH_TOKEN or GITHUB_TOKEN, only to send it as a header:
# it is never echoed, and there is no `set -x`.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $(basename "$0") <pulse version in use, e.g. v1.3.0>" >&2
  exit 2
fi
VERSION="v${VERSION#v}"

REPO="${PULSE_GITHUB_REPO:-onixus/GenDec}"
TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

auth=()
[[ -n "$TOKEN" ]] && auth=(-H "Authorization: Bearer ${TOKEN}")

code="$(curl -sS -L ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" \
  -o "${tmp}/latest.json" -w '%{http_code}' \
  "https://api.github.com/repos/${REPO}/releases/latest")" || code="000"
if [[ "$code" != "200" ]]; then
  echo "could not read the latest ${REPO} release (HTTP ${code}); check network and GH_TOKEN/GITHUB_TOKEN -- the repository is private" >&2
  exit 3
fi

latest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("tag_name",""))' "${tmp}/latest.json")"
if [[ -z "$latest" ]]; then
  echo "the latest-release answer from ${REPO} has no tag_name" >&2
  exit 3
fi

if [[ "$latest" == "$VERSION" ]]; then
  echo "Pulse ${VERSION} is the latest ${REPO} release"
  exit 0
fi

cat >&2 <<EOF
Pulse ${VERSION} is not the latest ${REPO} release (latest: ${latest}).
Releases ship the latest Pulse. To bump:
  GITHUB_TOKEN=… scripts/pulse-pin.sh ${latest}
then replace the lines in scripts/pulse-pinned.sha256 and change PULSE_VERSION
in Dockerfile, Dockerfile.allinone, scripts/install-pulse.sh,
Jenkinsfile.publish and .github/workflows/docker-publish.yml in the same
commit (tests/test_pulse_supply_chain.py checks they agree), and verify the
adapter against ${latest} (docs/pulse-backend.md).
EOF
exit 1
