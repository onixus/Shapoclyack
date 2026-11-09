#!/bin/bash
# Put a full NVD CPE dataset into the release build context, before docker build.
#
# Unit tests load the committed 8-product seed. Fetching inside an image build
# or a test run walks NVD for hours, so neither does. Jenkinsfile.publish calls
# the copy in .release-tooling (the pipeline revision, so an older tag still
# has the script) once per real release, then builds. root below is that copy's
# tree, so the job sets OCTO_NVD_CPE_RELEASE_DEST and OCTO_NVD_CPE_RELEASE_BACKUP
# onto the tag checkout. --restore puts the seed bytes back so the job
# workspace does not keep the harvest.
#
# After installation the same harvest is the client's, with their own key:
#   NVD_API_KEY=... OCTO_NVD_CPE_FETCH_ENABLED=true \
#     python3 scripts/fetch-nvd-cpe.py --full
# The daily CronJob stays incremental. It does not run this script.
#
# The key is read from NVD_API_KEY_FILE, else /run/secrets/nvd_api_key, else
# $HOME/.nvd-api-key. It is not printed. An empty result refuses; an anonymous
# harvest is not started.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
dest="${OCTO_NVD_CPE_RELEASE_DEST:-$root/scanner/data/nvd-cpe/nvd-cpe-ranges.json}"
backup="${OCTO_NVD_CPE_RELEASE_BACKUP:-$root/.publish/nvd-cpe-seed.json}"

if [ "${1:-}" = "--restore" ]; then
  if [ -f "$backup" ]; then
    cp "$backup" "$dest"
    rm -f "$backup"
  fi
  exit 0
fi

if [ "${1:-}" != "" ]; then
  echo "usage: scripts/stage-release-nvd-cpe.sh [--restore]" >&2
  exit 2
fi

# OCTO_NVD_CPE_KEY_PATHS replaces the candidate list (one path per line). Tests
# set it so a developer key on this machine is not read.
if [ -n "${OCTO_NVD_CPE_KEY_PATHS+x}" ]; then
  candidates=$OCTO_NVD_CPE_KEY_PATHS
else
  candidates="${NVD_API_KEY_FILE:-}
/run/secrets/nvd_api_key
${HOME}/.nvd-api-key"
fi
nvd_key=""
while IFS= read -r candidate; do
  if [ -n "$candidate" ] && [ -s "$candidate" ]; then
    nvd_key=$candidate
    break
  fi
done <<EOF
$candidates
EOF
if [ -z "$nvd_key" ]; then
  echo "release NVD CPE harvest needs a key file: NVD_API_KEY_FILE, /run/secrets/nvd_api_key, or \$HOME/.nvd-api-key" >&2
  exit 1
fi

key=$(tr -d '[:space:]' < "$nvd_key")
if [ -z "$key" ]; then
  echo "NVD API key file is empty" >&2
  exit 1
fi

mkdir -p "$(dirname "$backup")" "$(dirname "$dest")"
if [ ! -f "$backup" ]; then
  if [ -f "$dest" ]; then
    cp "$dest" "$backup"
  fi
fi

export NVD_API_KEY="$key"
unset key
OCTO_NVD_CPE_FETCH_ENABLED=true python3 "$root/scripts/fetch-nvd-cpe.py" --full -o "$dest"
unset NVD_API_KEY
