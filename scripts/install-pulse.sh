#!/usr/bin/env bash
# Install Pulse CLI for Shapoclyack service_probe backend.
# Usage:
#   scripts/install-pulse.sh                 # build from GenDec main
#   PULSE_REF=v0.2.0 scripts/install-pulse.sh
#   PULSE_REPO=/path/to/GenDec scripts/install-pulse.sh
set -euo pipefail

DEST="${PULSE_DEST:-/usr/local/bin/pulse}"
REF="${PULSE_REF:-main}"
REPO_URL="${PULSE_GIT_URL:-https://github.com/onixus/GenDec.git}"
LOCAL_REPO="${PULSE_REPO:-}"

if [[ -n "$LOCAL_REPO" ]]; then
  echo "==> building Pulse from $LOCAL_REPO"
  (cd "$LOCAL_REPO" && cargo build --release)
  BIN="$LOCAL_REPO/target/release/pulse"
else
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  echo "==> cloning $REPO_URL @ $REF"
  git clone --depth 1 --branch "$REF" "$REPO_URL" "$TMP/pulse" 2>/dev/null \
    || git clone --depth 1 "$REPO_URL" "$TMP/pulse"
  if [[ "$REF" != "main" && "$REF" != "master" ]]; then
    git -C "$TMP/pulse" fetch --depth 1 origin "refs/tags/$REF:refs/tags/$REF" 2>/dev/null || true
    git -C "$TMP/pulse" checkout "$REF" 2>/dev/null || true
  fi
  echo "==> cargo build --release"
  (cd "$TMP/pulse" && cargo build --release)
  BIN="$TMP/pulse/target/release/pulse"
fi

install -m 0755 "$BIN" "$DEST"
echo "==> installed $DEST ($($DEST --version 2>/dev/null || echo ok))"
echo "    set OCTO_SERVICE_BACKEND=pulse  or  service_probe.backend: pulse"
