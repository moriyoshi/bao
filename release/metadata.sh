#!/usr/bin/env bash
set -euo pipefail
# Run in a Git checkout. Output is also suitable for GITHUB_OUTPUT.
tag=${1:?usage: metadata.sh vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]}
if [[ ! $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
  echo "Invalid release tag: $tag" >&2
  exit 1
fi
prerelease=false
if [[ ${tag%%+*} == *-* ]]; then
  prerelease=true
  identifiers=${tag%%+*}
  identifiers=${identifiers#*-}
  IFS=. read -r -a parts <<< "$identifiers"
  for part in "${parts[@]}"; do
    if [[ $part =~ ^[0-9]+$ && ${#part} -gt 1 && $part == 0* ]]; then
      echo 'Numeric prerelease identifiers must not start with zero' >&2
      exit 1
    fi
  done
fi
# v0.0.0 is reserved for exercising the release pipeline without advertising
# a stable release, even when its publication is explicitly requested.
if [[ $tag == v0.0.0 ]]; then prerelease=true; fi
commit=$(git rev-parse --verify "refs/tags/$tag^{commit}")
[[ $(git rev-parse HEAD) == "$commit" ]] || { echo 'Checkout does not match release tag' >&2; exit 1; }
printf 'tag=%s\ncommit=%s\nepoch=%s\nprerelease=%s\n' "$tag" "$commit" "$(git show -s --format=%ct "$commit")" "$prerelease"
