#!/usr/bin/env bash
set -euo pipefail
binary=${1:?usage: smoke.sh BINARY TAG COMMIT}
tag=${2:?}
commit=${3:?}
"$binary" version -json | jq -e --arg tag "$tag" --arg commit "$commit" \
  '.version == $tag and .commit == $commit and .built_with == "go1.26.11"'
"$binary" targets -json
"$binary" help build > /dev/null
